//! The app lock: the PIN or password that opens the app, the
//! biometric prompt that may stand in for it, and the delays after
//! wrong guesses.

use std::time::Instant;

use crate::error::{CoreError, CoreResult};
use crate::lock::{self, AppLock, LockKind, LockVerdict};

use super::WalletManager;

impl WalletManager {
    /// The lock in place, without its hash.
    pub async fn app_lock(&self) -> Option<AppLock> {
        self.state
            .lock()
            .await
            .payload
            .settings
            .app_lock
            .clone()
            .map(|mut lock| {
                lock.secret = None;
                lock
            })
    }

    /// Sets a lock, or replaces the secret of the one in place. Replacing
    /// asks for the current secret: an unlocked phone in the wrong hands
    /// must not be able to change the PIN into one its holder knows.
    pub async fn set_app_lock(
        &self,
        kind: LockKind,
        secret: &str,
        current: Option<&str>,
    ) -> CoreResult<()> {
        lock::validate_secret(kind, secret)?;
        let existing = self.state.lock().await.payload.settings.app_lock.clone();
        if let Some(existing) = &existing {
            self.require_current(existing, current).await?;
        }
        let stored = lock::hash_secret(secret)?;
        self.state.lock().await.commit(|payload| {
            let previous = payload.settings.app_lock.take();
            payload.settings.app_lock = Some(AppLock {
                kind,
                biometric: previous.as_ref().is_some_and(|p| p.biometric),
                secret: Some(stored),
            });
            Ok(())
        })
    }

    /// Removes the lock. The current secret is required, for the same
    /// reason as above.
    pub async fn clear_app_lock(&self, current: &str) -> CoreResult<()> {
        let existing = self.existing_lock().await?;
        self.require_current(&existing, Some(current)).await?;
        self.state.lock().await.commit(|payload| {
            payload.settings.app_lock = None;
            Ok(())
        })
    }

    /// Tries a secret against the lock. Failures are counted and, past
    /// three, delayed: the verdict says how long before the next try
    /// is even looked at.
    pub async fn verify_app_lock(&self, secret: &str) -> CoreResult<LockVerdict> {
        let existing = self.existing_lock().await?;
        Ok(self.check_secret(&existing, secret).await)
    }

    /// Whether the platform's biometric prompt may stand in for the
    /// secret. Recorded here so both apps read one setting; the prompt
    /// itself is the platform's.
    ///
    /// Guarded by the secret in place: whoever has their own finger
    /// enrolled on this phone must not be able to turn their own
    /// fingerprint into a key to this vault.
    pub async fn set_biometric_unlock(&self, enabled: bool, current: &str) -> CoreResult<()> {
        let existing = self.existing_lock().await?;
        self.require_current(&existing, Some(current)).await?;
        self.state.lock().await.commit(|payload| {
            if let Some(lock) = &mut payload.settings.app_lock {
                lock.biometric = enabled;
            }
            Ok(())
        })
    }

    async fn existing_lock(&self) -> CoreResult<AppLock> {
        self.state
            .lock()
            .await
            .payload
            .settings
            .app_lock
            .clone()
            .ok_or_else(|| CoreError::InvalidInput {
                kind: "lock",
                detail: "no lock is set".to_owned(),
            })
    }

    /// The current secret must be given and must verify, delays
    /// included: changing the lock is an unlock attempt like any other.
    async fn require_current(&self, existing: &AppLock, current: Option<&str>) -> CoreResult<()> {
        let Some(current) = current else {
            return Err(CoreError::InvalidInput {
                kind: "lock",
                detail: "the current PIN or password is required".to_owned(),
            });
        };
        let verdict = self.check_secret(existing, current).await;
        if verdict.unlocked {
            return Ok(());
        }
        Err(CoreError::InvalidInput {
            kind: "lock",
            detail: if verdict.retry_after_secs > 0 {
                format!(
                    "too many attempts: try again in {} s",
                    verdict.retry_after_secs
                )
            } else {
                "wrong PIN or password".to_owned()
            },
        })
    }

    /// Hashes and compares under the attempts lock, so guesses are
    /// serialized and the delay cannot be raced. The vault lock is not
    /// held meanwhile: an unlock never waits on a sync. A delay runs
    /// from the verdict, not from the guess: Argon2 takes its time, and
    /// more on a busy device, and that time came off the delay.
    async fn check_secret(&self, existing: &AppLock, secret: &str) -> LockVerdict {
        let mut attempts = self.attempts.lock().await;
        let wait = attempts.retry_after(Instant::now());
        if wait > 0 {
            return LockVerdict {
                unlocked: false,
                failures: attempts.failures(),
                retry_after_secs: wait,
            };
        }
        match &existing.secret {
            Some(stored) if lock::verify_secret(secret, stored) => attempts.succeed(),
            _ => attempts.fail(Instant::now()),
        }
    }
}

#[cfg(test)]
mod tests;
