//! This device's connection to the premium account, and the account's
//! other devices.
//!
//! The key connects a device once; the token the server hands back is
//! what every later request carries. A function here that changes the
//! connection holds `premium_changes` across its network call, and
//! writes the vault once the server has answered, in one write with
//! everything that answer settles: a key and the token it earned go in
//! together or not at all. The apps call these and compose nothing
//! themselves.
//!
//! An answer can be lost on the way: a phone in a tunnel, a slow Tor
//! circuit, a timeout. A connection or a key change the server made and
//! this device never heard of would cost a device nobody holds, or the
//! only copy of the new key. So this side draws the secret itself, the
//! device token or the new key, writes it to the vault before the
//! request leaves, and sends that very request again until an answer
//! settles it: the server takes the same request twice as the one it
//! already carried out.

use std::time::{Duration, Instant};

use crate::error::{CoreError, CoreResult, PremiumError};
use crate::premium::device::{self, PendingConnect, Secret};
use crate::premium::licence;
use crate::premium::{Device, DevicePlatform, Licence};

use super::{WalletManager, same_key};

/// How long a connection waits after a rate limit that named no wait.
const CONNECT_WAIT_UNNAMED: Duration = Duration::from_secs(300);

impl WalletManager {
    /// Connects this device with `key`, which replaces the old
    /// activation. The key's shape is checked first. This device then
    /// draws its token, and stores it with the key as a connection
    /// under way before the request leaves; the key and the token are
    /// the account's in the vault only once the server has answered. A
    /// connection whose answer was lost is sent again as it was, same
    /// token, rather than drawn anew: the server answers it with the
    /// device it already made. The certificate is fetched after that,
    /// which a waiting device may do: when it cannot be had, for a key
    /// never paid for or a server gone quiet, the device stays connected
    /// and [`Self::premium_refresh_licence`] says why.
    ///
    /// The device that comes back has full access when it is the
    /// account's first, and waits otherwise. A key entered again on a
    /// device it already connected connects nothing new, since a new
    /// device would wait where this one may not: the device it already
    /// is comes back, and a connection to another account still under
    /// way is over, its token queued for the server to drop. Another
    /// key moves this device to that account:
    /// the removals the old account has yet to hear of go first, with
    /// the old token, and what cannot go is dropped; then what the vault
    /// knew of the old account goes, its certificate and its checklist,
    /// and the server is told the old connection is over, now or later.
    /// A key change of the old account that did not finish refuses the
    /// move while this device holds its token,
    /// [`PremiumError::KeyChangePending`]: moving on would lose the only
    /// copy of its new key. Without the token, the change was never
    /// applied, and connecting ends it.
    ///
    /// With the stored key, any refusal the server would give again
    /// leaves this device disconnected, with the server's words when it
    /// gave some: a key it no longer knows, a key with every device it
    /// takes, a server with no route for devices. A rate limit and a
    /// failure of the server's own are not that.
    pub async fn premium_connect(
        &self,
        base_url: &str,
        key: &str,
        platform: DevicePlatform,
    ) -> CoreResult<Device> {
        if !licence::is_well_formed_key(key) {
            return Err(CoreError::InvalidInput {
                kind: "premium key",
                detail: "a key is sixteen symbols, shown as xxxx-xxxx-xxxx-xxxx".to_owned(),
            });
        }
        let key = licence::normalize_key(key);
        let _change = self.premium_changes.lock().await;
        self.connect(base_url, key, platform).await
    }

    /// Connects this device when the vault says it should be and is not:
    /// a connection sent and not answered is sent again as it was, and a
    /// stored key with no token, a vault written before devices existed,
    /// is connected. The apps call it before any premium call; it
    /// returns the device it connected, or `None` when there was
    /// nothing to do.
    ///
    /// It never sends the key behind the user's back once the server
    /// has said no. A device the server disowned, a key it no longer
    /// knows, a key with every device it takes, any other refusal it
    /// would give again: each leaves the device disconnected until the
    /// user connects it again, with [`Self::premium_connect`]. A rate
    /// limit is waited out: until the wait the server named is over, a
    /// connection of the key it met answers
    /// [`PremiumError::RateLimited`] with what is left of it, without a
    /// request. Nothing owed is `None`, whatever wait runs.
    pub async fn premium_ensure_device(
        &self,
        base_url: &str,
        platform: DevicePlatform,
    ) -> CoreResult<Option<Device>> {
        let _change = self.premium_changes.lock().await;
        let (key, platform) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            match (&premium.pending_connect, &premium.key) {
                (Some(pending), _) => (pending.key().to_owned(), pending.platform),
                (None, Some(key)) if !premium.has_device() && !premium.disconnected => {
                    (licence::normalize_key(key), platform)
                }
                _ => return Ok(None),
            }
        };
        if let Some(wait) = self.connect_wait(&key) {
            return Err(PremiumError::RateLimited {
                retry_after: Some(wait.as_secs().max(1)),
            }
            .into());
        }
        self.connect(base_url, key, platform).await.map(Some)
    }

    /// This device, as the server sees it: whether it has full access,
    /// and until when it waits otherwise.
    pub async fn premium_device(&self, base_url: &str) -> CoreResult<Device> {
        self.premium_client(base_url).await?.device_me().await
    }

    /// Every device of the account, oldest first. A device that waits
    /// is refused with [`PremiumError::DevicePending`].
    pub async fn premium_devices(&self, base_url: &str) -> CoreResult<Vec<Device>> {
        self.premium_client(base_url).await?.devices().await
    }

    /// Gives a waiting device full access now.
    pub async fn premium_approve_device(&self, base_url: &str, id: &str) -> CoreResult<Device> {
        self.premium_client(base_url)
            .await?
            .approve_device(id)
            .await
    }

    /// Refuses a waiting device, or disconnects one with full access.
    /// When `id` is this device's own, its token is dropped once the
    /// server confirmed, the key stays, and the device reads as
    /// disowned: connecting again is the user's call. Removing this
    /// device while a key change did not finish is refused, as logging
    /// out is, [`PremiumError::KeyChangePending`]: the new key may
    /// already be the account's, and this device the only one left to
    /// finish the change.
    pub async fn premium_remove_device(&self, base_url: &str, id: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
        {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            if premium.key_change_pending() && premium.device.as_ref().is_some_and(|d| d.id == id) {
                return Err(PremiumError::KeyChangePending.into());
            }
        }
        self.premium_client(base_url)
            .await?
            .remove_device(id)
            .await?;
        let mut state = self.state.lock().await;
        let premium = &state.payload.settings.premium;
        let this_device = premium.device.as_ref().is_some_and(|d| d.id == id);
        if !this_device && !premium.announced_devices.iter().any(|a| a == id) {
            return Ok(());
        }
        state.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if this_device {
                premium.device = None;
                premium.disconnected = true;
            }
            premium.announced_devices.retain(|a| a != id);
            Ok(())
        })
    }

    /// Logs this device out of the account: the server is told, and
    /// whatever it answers, the key, the token and the certificate leave
    /// the vault, with what the screens remembered about the account.
    /// The consents stay, so the same key entered again asks nothing
    /// twice. A server that could not be told keeps the token live: it
    /// waits, never shown, for [`Self::premium_flush_logouts`]. What
    /// "Forget this key" did, and the server now hears of it.
    ///
    /// A key change that did not finish is refused,
    /// [`PremiumError::KeyChangePending`], while this device could still
    /// finish it: the new key may already be the account's, and this
    /// vault would be the last place that holds it.
    pub async fn premium_log_out(&self, base_url: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
        let token = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            if premium.key_change_pending() && premium.has_device() {
                return Err(PremiumError::KeyChangePending.into());
            }
            premium.device.as_ref().map(|d| d.token().to_owned())
        };
        let told = match &token {
            Some(token) => self.revoke(base_url, token).await.is_ok(),
            None => true,
        };
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium.forget_account();
            if let Some(token) = token.as_deref().filter(|_| !told) {
                premium.queue_logout(token);
            }
            Ok(())
        })
    }

    /// Tells the server about the connections this device dropped while
    /// it could not be reached, one `DELETE /v1/devices/me` each with
    /// the token that connection held. A token the server no longer
    /// knows counts as told. A refusal keeps its token and the round
    /// goes on; a server that cannot be reached, or a rate limit, ends
    /// the round, and the first error is returned. Nothing to tell
    /// costs no connection. The apps call it on start and with the
    /// heartbeat. Returns how many are still to tell.
    pub async fn premium_flush_logouts(&self, base_url: &str) -> CoreResult<usize> {
        let tokens: Vec<String> = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            premium
                .pending_logouts
                .iter()
                .map(|t| t.expose().to_owned())
                .collect()
        };
        if tokens.is_empty() {
            return Ok(0);
        }
        let mut told = Vec::new();
        let mut failure = None;
        for token in &tokens {
            match self.revoke(base_url, token).await {
                Ok(()) => told.push(token.clone()),
                Err(error @ CoreError::Premium(PremiumError::Rejected(_))) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error);
                    break;
                }
            }
        }
        let left = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium
                .pending_logouts
                .retain(|t| !told.iter().any(|done| done == t.expose()));
            Ok(premium.pending_logouts.len())
        })?;
        match failure {
            Some(error) => Err(error),
            None => Ok(left),
        }
    }

    /// Replaces the account key. The old one stops working everywhere at
    /// once, every other device is disconnected, and this one stays
    /// connected with its token. Returns the new key, formatted to be
    /// shown: it is shown nowhere else, ever.
    ///
    /// The new key is drawn here and stored as a change under way before
    /// the request leaves. While it is, the apps say the change did not
    /// finish, and trying again sends that same key: the server answers
    /// it with the key the account already has. Once the server has
    /// answered, the key is the account's in the vault, not saved yet,
    /// and the certificate, whose subject changes with the key, is
    /// fetched again; one that cannot be had leaves the last one, whose
    /// dates still hold. A refusal that settles it drops the change; an
    /// answer lost on the way keeps it. The key the server applied is
    /// returned even when the vault cannot record it: the vault still
    /// holds it as the change under way, and the next try completes it.
    ///
    /// A device without its token sends nothing,
    /// [`PremiumError::NoDevice`], and a change under way ends there:
    /// the server applies a change only for a device it keeps, and keeps
    /// that device after, so this one's was never applied.
    pub async fn premium_change_key(&self, base_url: &str) -> CoreResult<String> {
        let _change = self.premium_changes.lock().await;
        let (pending, connected) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            (premium.pending_key.clone(), premium.has_device())
        };
        if !connected {
            if pending.is_some() {
                self.state.lock().await.commit(|payload| {
                    payload.settings.premium.pending_key = None;
                    Ok(())
                })?;
            }
            return Err(PremiumError::NoDevice.into());
        }
        let key = match pending {
            Some(key) => key.expose().to_owned(),
            None => {
                let key = licence::draw_account_key()?;
                self.state.lock().await.commit(|payload| {
                    payload.settings.premium.pending_key = Some(Secret::new(key.clone()));
                    Ok(())
                })?;
                key
            }
        };
        let answer = match self.premium_client(base_url).await {
            Ok(client) => client.change_key(&key).await,
            Err(error) => Err(error),
        };
        let applied = match answer {
            Ok(applied) => applied,
            Err(error) => {
                if settles_key_change(&error) {
                    self.state.lock().await.commit(|payload| {
                        let premium = &mut payload.settings.premium;
                        if premium.pending_key.as_ref().map(Secret::expose) == Some(key.as_str()) {
                            premium.pending_key = None;
                        }
                        Ok(())
                    })?;
                }
                return Err(error);
            }
        };
        let recorded = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium.key = Some(applied.clone());
            premium.pending_key = None;
            premium.key_saved = false;
            // Every other device is gone, and with them what was
            // announced of them.
            premium.announced_devices.clear();
            Ok(())
        });
        if let Err(error) = recorded {
            log::warn!(
                "the new premium key could not be recorded, and is kept as a change under way: {error}"
            );
        }
        let _ = self.premium_refresh_licence(base_url).await;
        Ok(licence::format_key(&applied))
    }

    /// Fetches the certificate again, for the paid time a renewal added
    /// or the key that changed, and keeps it: only while the connection
    /// it was asked with is still the stored one, since a device that
    /// logged out or moved to another account meanwhile has no use for
    /// it.
    pub async fn premium_refresh_licence(&self, base_url: &str) -> CoreResult<Licence> {
        let client = self.premium_client(base_url).await?;
        let licence = client.licence().await?;
        let asked_with = client.device_token().unwrap_or_default();
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if premium.holds_token(asked_with) {
                premium.certificate = Some(licence.certificate.clone());
            }
            Ok(())
        })?;
        Ok(licence)
    }

    /// Records whether the user saved the key somewhere safe.
    pub async fn premium_set_key_saved(&self, saved: bool) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            payload.settings.premium.key_saved = saved;
            Ok(())
        })
    }

    /// Hides the "Protect your Premium account" card.
    pub async fn premium_hide_checklist(&self) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            payload.settings.premium.checklist_hidden = true;
            Ok(())
        })
    }

    /// Records the waiting devices announced by a local notification,
    /// and returns the ones to announce now. `pending` is the id of
    /// every device that waits, as the latest list shows them: the
    /// record becomes that, so a device that no longer waits leaves it.
    /// The ids it did not hold before come back, each handed out once,
    /// however many callers ask at the same time.
    pub async fn premium_mark_announced(&self, pending: &[String]) -> CoreResult<Vec<String>> {
        let mut state = self.state.lock().await;
        if state.payload.settings.premium.announced_devices == pending {
            return Ok(Vec::new());
        }
        state.commit(|payload| Ok(payload.settings.premium.mark_announced(pending)))
    }

    /// The connection itself, under `premium_changes`.
    async fn connect(
        &self,
        base_url: &str,
        key: String,
        platform: DevicePlatform,
    ) -> CoreResult<Device> {
        let mut stored = self.state.lock().await.payload.settings.premium.clone();
        let same_account = same_key(stored.key.as_deref(), Some(&key));
        // Moving on while a key change of this account is unanswered
        // would lose the new key, whoever asks: the user, or a
        // connection to another account sent again. Moving on stays
        // open, as logging out does, when this device can no longer
        // finish the change: without its token, the change was never
        // applied.
        if !same_account
            && stored.key.is_some()
            && stored.key_change_pending()
            && stored.has_device()
        {
            return Err(PremiumError::KeyChangePending.into());
        }
        if same_account && stored.has_device() {
            // The key this device is connected with: a connection under
            // way is over, whatever the server says next, or sent again
            // later it would move this device behind the user's back.
            // Its token, which the server may have made a device of,
            // joins the ones to tell it about.
            let abandoned = stored.pending_connect.take();
            if let Some(abandoned) = &abandoned {
                self.state.lock().await.commit(|payload| {
                    let premium = &mut payload.settings.premium;
                    premium.pending_connect = None;
                    premium.queue_logout(abandoned.token());
                    Ok(())
                })?;
            }
            match self.premium_client(base_url).await?.device_me().await {
                Ok(device) => {
                    if abandoned.is_some() {
                        let _ = self.premium_flush_logouts(base_url).await;
                    }
                    let _ = self.premium_refresh_licence(base_url).await;
                    return Ok(device);
                }
                // The token was disowned and is dropped: connecting again
                // is what the user asked.
                Err(CoreError::Premium(PremiumError::DeviceDisconnected)) => {}
                Err(error) => return Err(error),
            }
        }

        // The connection under way for this key, sent again as it was, or
        // a new one, stored before it leaves. One under way for another
        // key is over: its token, which the server may have made a device
        // of, joins the ones to tell it about.
        let request = match stored.pending_connect.clone() {
            Some(pending) if same_key(Some(pending.key()), Some(&key)) => pending,
            abandoned => {
                let fresh =
                    PendingConnect::new(key.clone(), device::draw_device_token()?, platform);
                self.state.lock().await.commit(|payload| {
                    let premium = &mut payload.settings.premium;
                    if let Some(abandoned) = &abandoned {
                        premium.queue_logout(abandoned.token());
                    }
                    premium.pending_connect = Some(fresh.clone());
                    Ok(())
                })?;
                fresh
            }
        };

        // Moving to another account: the old one hears of its removals
        // with its own token before that token goes.
        let switching = stored.key.is_some() && !same_account;
        if switching
            && stored.has_device()
            && !stored.pending_unwatch.is_empty()
            && let Err(error) = self.premium_flush_unwatch(base_url).await
        {
            log::warn!(
                "the previous premium account could not be told about every removed wallet: {error}"
            );
        }

        let answer = match self
            .premium_client_with_key(base_url, Some(request.key().to_owned()))
            .await
        {
            Ok(client) => {
                client
                    .connect_device(request.platform, request.token())
                    .await
            }
            Err(error) => Err(error),
        };
        let connected = match answer {
            Ok(connected) => connected,
            Err(error) => {
                self.after_refused_connect(&request, same_account, &error)
                    .await?;
                return Err(error);
            }
        };
        *self.premium_connect_after.lock().unwrap() = None;

        let credential = connected.credential();
        let committed = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            let mut dropped = 0;
            if !same_key(premium.key.as_deref(), Some(&key)) {
                // Another account: nothing this device knew of the last
                // one holds for this one.
                dropped = std::mem::take(&mut premium.pending_unwatch).len();
                premium.certificate = None;
                premium.key_saved = false;
                premium.checklist_hidden = false;
                premium.announced_devices.clear();
            }
            // No key change is left to finish: this device either had no
            // token, and its change was never applied, or it moves to
            // another account, which it may not while one could finish.
            premium.pending_key = None;
            if let Some(previous) = premium.device.replace(credential.clone())
                && previous.token() != credential.token()
            {
                premium.queue_logout(previous.token());
            }
            if premium
                .pending_connect
                .as_ref()
                .is_some_and(|p| p.token() == request.token())
            {
                premium.pending_connect = None;
            }
            premium.key = Some(key.clone());
            premium.disconnected = false;
            premium.disconnected_reason = None;
            premium.acknowledged_offline_until = None;
            Ok(dropped)
        });
        match committed {
            Ok(0) => {}
            Ok(dropped) => log::warn!(
                "{dropped} wallet removals the previous premium account never heard of were dropped"
            ),
            Err(error) => {
                // The server holds a device nobody will: it goes.
                let _ = self.revoke(base_url, connected.token()).await;
                return Err(error);
            }
        }
        if switching {
            let _ = self.premium_flush_logouts(base_url).await;
        }
        let _ = self.premium_refresh_licence(base_url).await;
        Ok(connected.device)
    }

    /// What a failed connection leaves in the vault. A refusal that
    /// settles it drops the connection under way, and one the server
    /// would give the stored key again disconnects this device; an
    /// answer lost on the way keeps it, to be sent again as it was; a
    /// rate limit also holds back the next automatic try of that key
    /// for the wait it named.
    async fn after_refused_connect(
        &self,
        request: &PendingConnect,
        stored_key: bool,
        error: &CoreError,
    ) -> CoreResult<()> {
        if let CoreError::Premium(PremiumError::RateLimited { retry_after }) = error {
            let wait = retry_after.map_or(CONNECT_WAIT_UNNAMED, Duration::from_secs);
            *self.premium_connect_after.lock().unwrap() =
                Some((Instant::now() + wait, request.key().to_owned()));
        }
        if !settles_connect(error) {
            return Ok(());
        }
        // The stored key, refused for good: sent again on its own, it
        // would meet the same answer, with a new token each time.
        let disconnect = stored_key && refused_for_good(error);
        let reason = match error {
            CoreError::Premium(
                PremiumError::TooManyDevices(words) | PremiumError::Rejected(words),
            ) => Some(words.clone()),
            _ => None,
        };
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if premium
                .pending_connect
                .as_ref()
                .is_some_and(|p| p.token() == request.token())
            {
                premium.pending_connect = None;
            }
            if disconnect && !premium.has_device() {
                premium.disconnected = true;
                premium.disconnected_reason = reason;
            }
            Ok(())
        })
    }

    /// How long a connection of `key` still waits on the rate limit it
    /// met. A connection of another key waits on nothing: the server
    /// counts connections by key.
    fn connect_wait(&self, key: &str) -> Option<Duration> {
        let mut after = self.premium_connect_after.lock().unwrap();
        let (until, limited) = after.as_ref()?;
        match until.checked_duration_since(Instant::now()) {
            Some(wait) => same_key(Some(limited), Some(key)).then_some(wait),
            None => {
                *after = None;
                None
            }
        }
    }

    /// Tells the server that the connection holding `token` is over.
    /// Done when it says so, or that it no longer knows the token.
    async fn revoke(&self, base_url: &str, token: &str) -> CoreResult<()> {
        let client = self
            .premium_client_with_key(base_url, None)
            .await?
            .with_device_token(Some(token.to_owned()));
        match client.log_out_device().await {
            Ok(())
            | Err(CoreError::Premium(PremiumError::DeviceDisconnected | PremiumError::NotFound)) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

/// Whether a failed connection was settled, so that the same request
/// would get the same answer: refused here before it left, or by the
/// server for good. Anything else, a server that could not be reached
/// or answered something unreadable, may have made the device, and the
/// request is sent again.
fn settles_connect(error: &CoreError) -> bool {
    refused_for_good(error)
        || matches!(
            error,
            CoreError::InvalidInput { .. } | CoreError::Premium(PremiumError::NoKey)
        )
}

/// Whether the server refused a connection with an answer of its own
/// that the same request would meet again: every refusal but a rate
/// limit, which a wait lifts, and a failure of the server's own, which
/// reads as [`PremiumError::Unreachable`].
fn refused_for_good(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Premium(
            PremiumError::UnknownKey
                | PremiumError::TooManyDevices(_)
                | PremiumError::Rejected(_)
                | PremiumError::DeviceRequired
                | PremiumError::DevicePending { .. }
                | PremiumError::DeviceDisconnected
                | PremiumError::NoPaidTime
                | PremiumError::NotFound
        )
    )
}

/// Whether a failed key change was settled by the server without the
/// new key: refused in its own words, asked by a device that may not
/// ask, or asked with a token the server no longer knows, or with none.
/// The server applies a change only for a device it still has, and
/// keeps that device after as the account's only one, which nothing
/// but this device can then remove: it does not while the change is
/// under way, see [`WalletManager::premium_log_out`] and
/// [`WalletManager::premium_remove_device`], and an account deleted
/// has no key left to lose. So a token gone means no try of this
/// change was applied. A server that could not be reached, or answered
/// something unreadable, may hide a change an earlier try made: the
/// new key is kept.
fn settles_key_change(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::InvalidInput { .. }
            | CoreError::Premium(
                PremiumError::Rejected(_)
                    | PremiumError::DevicePending { .. }
                    | PremiumError::DeviceDisconnected
                    | PremiumError::DeviceRequired
                    | PremiumError::NoDevice
                    | PremiumError::NotFound
            )
    )
}

#[cfg(test)]
mod tests;
