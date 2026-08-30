//! The application lock: a PIN or password asked before the interface
//! shows, on top of the vault encryption.
//!
//! The vault is already encrypted with a key the platform keeps; the
//! lock is the curtain in front of it, what stops the person holding
//! an unlocked phone rather than the one who extracted the file. The
//! secret itself is never stored: only an Argon2id hash under its own
//! salt, compared in constant time, and guesses slow down after a few
//! failures so that a short PIN cannot be tried a thousand times.

use std::time::{Duration, Instant};

use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{CoreError, CoreResult};

/// What kind of secret unlocks the app. Kept next to the hash so the
/// unlock screen knows which keyboard to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockKind {
    /// Digits only, 4 to 12 of them.
    Pin,
    /// Anything, 8 characters or more.
    Password,
}

/// The stored form of the secret: hex salt and hex Argon2id output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSecret {
    pub salt: String,
    pub hash: String,
}

/// The lock as the vault keeps it. The apps get a copy with `secret`
/// blanked: they need the kind, never the hash.
///
/// When the lock comes back is not a setting: the secret is asked when
/// the app opens, and again once it has been away — the desktop ends
/// its session by closing, the phone by going to the background. A
/// delay to choose between only ever asked the user to guess how long
/// their own screen is safe for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppLock {
    pub kind: LockKind,
    /// Whether the platform's biometric prompt may stand in for the
    /// secret. The core never sees a biometric: the app asks the OS,
    /// and only skips the secret when the OS says yes.
    #[serde(default)]
    pub biometric: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<LockSecret>,
}

/// Outcome of an unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockVerdict {
    pub unlocked: bool,
    /// Consecutive failures so far; zero once unlocked.
    pub failures: u32,
    /// Seconds before the next attempt is even evaluated; zero when it
    /// can be tried now.
    pub retry_after_secs: u32,
}

/// Failures before the delays start.
const FREE_ATTEMPTS: u32 = 3;
/// First delay, doubled at every further failure.
const FIRST_DELAY_SECS: u64 = 5;
/// Longest delay between two attempts.
const MAX_DELAY_SECS: u64 = 300;

/// How long to wait after `failures` consecutive failures: nothing for
/// the first three, then 5 s doubling up to 5 min.
pub fn delay_after(failures: u32) -> Duration {
    if failures < FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let doublings = (failures - FREE_ATTEMPTS).min(16);
    Duration::from_secs((FIRST_DELAY_SECS << doublings).min(MAX_DELAY_SECS))
}

/// In-memory record of recent failures. Lives with the manager, never
/// in the vault: a restart resets it, which is fine because a restart
/// costs the attacker more than the delay did.
#[derive(Debug, Default)]
pub struct LockAttempts {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl LockAttempts {
    /// Seconds still to wait, zero when an attempt may be made.
    pub fn retry_after(&self, now: Instant) -> u32 {
        match self.blocked_until {
            Some(until) if until > now => until.duration_since(now).as_secs().max(1) as u32,
            _ => 0,
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Records a failed attempt and starts the matching delay.
    pub fn fail(&mut self, now: Instant) -> LockVerdict {
        self.failures += 1;
        let delay = delay_after(self.failures);
        self.blocked_until = (delay > Duration::ZERO).then(|| now + delay);
        LockVerdict {
            unlocked: false,
            failures: self.failures,
            retry_after_secs: delay.as_secs() as u32,
        }
    }

    pub fn succeed(&mut self) -> LockVerdict {
        self.failures = 0;
        self.blocked_until = None;
        LockVerdict {
            unlocked: true,
            failures: 0,
            retry_after_secs: 0,
        }
    }
}

/// Checks that a secret is acceptable for its kind, before it is ever
/// hashed. Rules are deliberately few: the delays are the defence, not
/// a composition policy.
pub fn validate_secret(kind: LockKind, secret: &str) -> CoreResult<()> {
    match kind {
        LockKind::Pin => {
            let digits = secret.chars().count();
            if !(4..=12).contains(&digits) || !secret.chars().all(|c| c.is_ascii_digit()) {
                return Err(CoreError::InvalidInput {
                    kind: "pin",
                    detail: "a PIN is 4 to 12 digits".to_owned(),
                });
            }
        }
        LockKind::Password => {
            let length = secret.chars().count();
            if length < 8 {
                return Err(CoreError::InvalidInput {
                    kind: "password",
                    detail: "a password is at least 8 characters".to_owned(),
                });
            }
            if length > 256 {
                return Err(CoreError::InvalidInput {
                    kind: "password",
                    detail: "a password is at most 256 characters".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Hashes a secret under a fresh salt. Argon2id with the vault's own
/// pinned parameters (m=19456 KiB, t=2, p=1): a dependency bump must
/// never change what an existing lock expects.
pub fn hash_secret(secret: &str) -> CoreResult<LockSecret> {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut hash = derive(secret, &salt)?;
    let stored = LockSecret {
        salt: hex(&salt),
        hash: hex(&hash),
    };
    hash.zeroize();
    Ok(stored)
}

/// Whether `secret` is the one behind `stored`, in constant time over
/// the hash. Malformed stored material counts as a mismatch, never as
/// a match.
pub fn verify_secret(secret: &str, stored: &LockSecret) -> bool {
    let (Some(salt), Some(expected)) = (unhex(&stored.salt), unhex(&stored.hash)) else {
        return false;
    };
    let Ok(mut derived) = derive(secret, &salt) else {
        return false;
    };
    let matches = derived.len() == expected.len() && bool::from(derived.ct_eq(&expected));
    derived.zeroize();
    matches
}

fn derive(secret: &str, salt: &[u8]) -> CoreResult<[u8; 32]> {
    let params = argon2::Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| CoreError::Internal(format!("argon2 parameters: {e}")))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(secret.as_bytes(), salt, &mut out)
        .map_err(|e| CoreError::Internal(format!("argon2: {e}")))?;
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let stored = hash_secret("123456").unwrap();
        assert!(verify_secret("123456", &stored));
        assert!(!verify_secret("123457", &stored));
        assert!(!verify_secret("", &stored));
    }

    #[test]
    fn same_secret_different_salts() {
        let a = hash_secret("correct horse").unwrap();
        let b = hash_secret("correct horse").unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.hash, b.hash);
        assert!(!a.hash.contains("correct"));
    }

    #[test]
    fn malformed_stored_material_never_matches() {
        let stored = LockSecret {
            salt: "zz".to_owned(),
            hash: "00".to_owned(),
        };
        assert!(!verify_secret("anything", &stored));
    }

    #[test]
    fn pin_rules() {
        assert!(validate_secret(LockKind::Pin, "1234").is_ok());
        assert!(validate_secret(LockKind::Pin, "123456789012").is_ok());
        assert!(validate_secret(LockKind::Pin, "123").is_err());
        assert!(validate_secret(LockKind::Pin, "1234567890123").is_err());
        assert!(validate_secret(LockKind::Pin, "12a4").is_err());
        assert!(validate_secret(LockKind::Pin, "").is_err());
    }

    #[test]
    fn password_rules() {
        assert!(validate_secret(LockKind::Password, "12345678").is_ok());
        assert!(validate_secret(LockKind::Password, "1234567").is_err());
        assert!(validate_secret(LockKind::Password, &"a".repeat(257)).is_err());
        // Unicode counts in characters, not bytes.
        assert!(validate_secret(LockKind::Password, "ééééééé").is_err());
        assert!(validate_secret(LockKind::Password, "éééééééé").is_ok());
    }

    #[test]
    fn delays_start_after_three_failures_and_cap() {
        assert_eq!(delay_after(0), Duration::ZERO);
        assert_eq!(delay_after(2), Duration::ZERO);
        assert_eq!(delay_after(3), Duration::from_secs(5));
        assert_eq!(delay_after(4), Duration::from_secs(10));
        assert_eq!(delay_after(5), Duration::from_secs(20));
        assert_eq!(delay_after(9), Duration::from_secs(300));
        assert_eq!(delay_after(40), Duration::from_secs(300));
    }

    #[test]
    fn attempts_block_then_reset() {
        let now = Instant::now();
        let mut attempts = LockAttempts::default();
        assert_eq!(attempts.retry_after(now), 0);
        attempts.fail(now);
        attempts.fail(now);
        assert_eq!(attempts.retry_after(now), 0);
        let verdict = attempts.fail(now);
        assert_eq!(verdict.failures, 3);
        assert_eq!(verdict.retry_after_secs, 5);
        assert_eq!(attempts.retry_after(now), 5);
        assert_eq!(attempts.retry_after(now + Duration::from_secs(6)), 0);
        let verdict = attempts.succeed();
        assert!(verdict.unlocked);
        assert_eq!(attempts.failures(), 0);
        assert_eq!(attempts.retry_after(now), 0);
    }

    #[test]
    fn app_lock_serde_keeps_the_secret_only_when_present() {
        let lock = AppLock {
            kind: LockKind::Pin,
            biometric: true,
            secret: Some(hash_secret("1234").unwrap()),
        };
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains("\"secret\""));
        let back: AppLock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lock);

        // A redacted copy serializes without the field.
        let redacted = AppLock {
            secret: None,
            ..lock
        };
        assert!(!serde_json::to_string(&redacted).unwrap().contains("secret"));
        // A record written before the delay was dropped still reads:
        // the field it carries is simply no longer anyone's business.
        let old: AppLock =
            serde_json::from_str(r#"{"kind":"password","auto_lock_secs":900}"#).unwrap();
        assert_eq!(old.kind, LockKind::Password);
        assert!(!old.biometric);
        assert!(old.secret.is_none());
    }
}
