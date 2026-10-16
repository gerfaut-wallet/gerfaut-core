//! The update check, seen from the apps: they say when a session is
//! open, when the user closes a notice or turns the check off, and when
//! the button is pressed, and they show what comes back. When a check
//! is due, what to announce and what was closed are decided in
//! [`crate::updates`], over the record the vault keeps.
//!
//! The request takes the route the syncs take (see `settings.rs`):
//! through Tor when a backend is an onion address, and not at all when
//! Tor cannot be had. The check a session makes never starts Tor for
//! itself: it waits for a Tor that already runs. Whether a session is
//! open is the app's word: it never says so behind its lock, nor while
//! it is disguised.

use crate::error::{CoreError, CoreResult};
use crate::now_secs;
use crate::updates::{self, GITHUB_API, UpdateRecord, UpdateStatus, Version};

use super::WalletManager;

impl WalletManager {
    /// What to tell someone running `current_version` about releases,
    /// from what the vault holds. Reads only.
    pub async fn update_status(&self, current_version: &str) -> UpdateStatus {
        self.state
            .lock()
            .await
            .payload
            .updates
            .status(current_version)
    }

    /// A session is open: the app is on screen and unlocked, and says so
    /// as the session opens and from time to time while it lasts. The
    /// release of `owner/repo` is asked for when a check is due, at most
    /// once a day and never within a day of the first session, and the
    /// status that follows comes back.
    ///
    /// It never fails. A check that goes wrong is a day with nothing
    /// new to say, and it counts: "once a day" holds whatever the
    /// network does. When Tor is needed, the check goes through a Tor
    /// that already runs, the system's or the built-in client once a
    /// sync or the live watch started it, and never starts one: an app
    /// says a session is open at every return to the screen, and a
    /// bootstrap for each would take up to a minute and a half, then
    /// keep the client running. Without that Tor nothing is sent and
    /// the day does not count: the next session asks again, and the
    /// status says why nothing was asked.
    pub async fn update_session(&self, repo: &str, current_version: &str) -> UpdateStatus {
        self.update_session_at(GITHUB_API, repo, current_version, now_secs())
            .await
    }

    pub(crate) async fn update_session_at(
        &self,
        api: &str,
        repo: &str,
        current_version: &str,
        now: u64,
    ) -> UpdateStatus {
        let due = {
            let state = self.state.lock().await;
            state.payload.updates.due(now)
        };
        // The first session is the start of the day that asks nothing,
        // whatever the setting says now: turned on later, the check
        // does not wait a day more.
        self.note_update(|record| record.session_at(now)).await;
        if due {
            self.check_on_its_own(api, repo, now).await;
        }
        self.update_status(current_version).await
    }

    /// The check a session found due.
    async fn check_on_its_own(&self, api: &str, repo: &str, now: u64) {
        // Tor first, before the day is spent: the proxy is only ever
        // needed for Tor, and when none runs nothing goes out.
        let Ok(proxy) = self.running_beside_syncs_proxy().await else {
            self.note_update(|record| record.tor_unavailable = true)
                .await;
            return;
        };
        // Stamped before the request, under the lock: two sessions that
        // found it due at once send one, and a check turned off while
        // Tor was being reached sends none. A stamp that cannot be
        // written sends nothing either, since it is what holds the day.
        {
            let mut state = self.state.lock().await;
            if !state.payload.updates.due(now) {
                return;
            }
            let stamped = state.commit(|payload| {
                payload.updates.checked_at = Some(now);
                payload.updates.tor_unavailable = false;
                Ok(())
            });
            if let Err(error) = stamped {
                log::warn!("the update check was not stamped, and not sent: {error}");
                return;
            }
        }
        if let Ok(tag) = updates::latest_tag(api, repo, proxy.as_deref()).await {
            self.note_update(|record| record.answered(&tag)).await;
        }
    }

    /// Asks GitHub for the latest release of `owner/repo` now, due or
    /// not: the button in Settings › About. When [`Self::uses_tor`] says
    /// so it goes through the Tor proxy a sync would resolve, and when
    /// that proxy cannot be had it fails with [`CoreError::Tor`] before
    /// any request exists: never a request in the clear. Anything else
    /// that goes wrong is "could not check".
    ///
    /// The answer is on screen as soon as it comes, so the notice has
    /// nothing left to say about the release it names: that release
    /// counts as closed. The daily check keeps its own schedule.
    pub async fn check_update(
        &self,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<UpdateStatus> {
        self.check_update_at(GITHUB_API, repo, current_version)
            .await
    }

    pub(crate) async fn check_update_at(
        &self,
        api: &str,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<UpdateStatus> {
        let proxy = match self.beside_syncs_proxy().await {
            Ok(proxy) => proxy,
            Err(error) => {
                self.note_update(|record| record.tor_unavailable = true)
                    .await;
                return Err(error);
            }
        };
        let answer = updates::latest_tag(api, repo, proxy.as_deref()).await;
        self.note_update(|record| {
            record.tor_unavailable = false;
            if let Ok(tag) = &answer {
                record.answered(tag);
                if let Some(latest) = record.latest.as_deref().and_then(Version::parse) {
                    record.dismiss(&latest);
                }
            }
        })
        .await;
        answer?;
        Ok(self.update_status(current_version).await)
    }

    /// Closes the notice on `version`, the release it announced: neither
    /// it nor any release before it is announced again. A version that
    /// does not read as one is refused.
    pub async fn dismiss_update(&self, version: &str) -> CoreResult<()> {
        let version = Version::parse(version).ok_or_else(|| CoreError::InvalidInput {
            kind: "version",
            detail: "expected a version such as 1.2.3".to_owned(),
        })?;
        self.state.lock().await.commit(|payload| {
            payload.updates.dismiss(&version);
            Ok(())
        })
    }

    /// Turns the check the app makes on its own on or off. The button
    /// asks either way.
    pub async fn set_update_automatic(&self, automatic: bool) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            payload.updates.automatic = automatic;
            Ok(())
        })
    }

    /// Applies `change` to the update record, and saves it when it
    /// changed anything. A save that fails is logged and left to the
    /// next one: this is what the core noticed, not what the user
    /// decided, and the worst it costs is a check asked again.
    async fn note_update(&self, change: impl FnOnce(&mut UpdateRecord)) {
        let mut state = self.state.lock().await;
        let mut record = state.payload.updates.clone();
        change(&mut record);
        if record == state.payload.updates {
            return;
        }
        if let Err(error) = state.commit(|payload| {
            payload.updates = record;
            Ok(())
        }) {
            log::warn!("the update check could not keep what it found: {error}");
        }
    }
}

#[cfg(test)]
mod tests;
