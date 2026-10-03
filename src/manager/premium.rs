//! The premium account as the vault keeps it, the client that speaks
//! to the server for it, and the wallets the server stops watching.
//! This device's connection to the account, and the account's other
//! devices, are in `devices.rs`.

use crate::chain::{self, tor};
use crate::error::{CoreError, CoreResult, PremiumError};
use crate::premium::{Channel, PremiumClient, PremiumState};

use super::WalletManager;

impl WalletManager {
    /// The premium account as the vault keeps it, the device token
    /// blanked: it never leaves the core. The rest is as stored, and
    /// [`PremiumState::device`] still says whether this device is
    /// connected.
    pub async fn premium_state(&self) -> PremiumState {
        let mut premium = self.state.lock().await.payload.settings.premium.clone();
        premium.redact();
        premium
    }

    /// Replaces what the apps keep in the premium account state: they
    /// read it, change what they need, and hand it back. Two things are
    /// theirs to write: the consents and the dismissed banner. A yes for
    /// a wallet also drops its removal still queued for the server, as
    /// [`PremiumState::consent`] does. Whatever the copy says of the
    /// rest is ignored, the queued removals included:
    /// [`Self::remove_wallet`] queues them, and a copy read before this
    /// device moved to another account would otherwise bring back the
    /// old account's, to go out with the new account's token. The key,
    /// the certificate, this device's connection, whether the server
    /// disowned it, and what was sent and not answered move only with
    /// the server's answer, through
    /// [`Self::premium_connect`], [`Self::premium_ensure_device`],
    /// [`Self::premium_refresh_licence`], [`Self::premium_change_key`],
    /// [`Self::premium_remove_device`], [`Self::premium_log_out`],
    /// [`Self::premium_flush_logouts`] and
    /// [`Self::premium_delete_account`], or when a call hears that the
    /// token is disowned. A copy read before one of those and handed
    /// back after it can then neither bring back a key that was logged
    /// out or replaced, nor drop the one that replaced it. What the
    /// account's safety card remembers has setters of its own, for the
    /// same reason: a stale copy must not mark a key just changed as
    /// saved. See [`Self::premium_set_key_saved`],
    /// [`Self::premium_hide_checklist`] and
    /// [`Self::premium_mark_announced`].
    ///
    /// A new yes for a wallet no longer on this device is dropped: a
    /// copy read before [`Self::remove_wallet`] would otherwise bring
    /// back the consent the removal took, and cancel the removal queued
    /// for the server.
    pub async fn set_premium_state(&self, mut premium: PremiumState) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            let stored = &payload.settings.premium;
            premium.watched.retain(|consent| {
                stored.is_consented(&consent.wallet_id)
                    || payload
                        .wallets
                        .iter()
                        .any(|record| record.meta.id == consent.wallet_id)
            });
            payload.settings.premium = payload.settings.premium.with_app_part_of(premium);
            Ok(())
        })
    }

    /// A client for the premium server at `base_url`, carrying the
    /// stored key and this device's token. A token the server disowns
    /// through it, whoever makes the call, is dropped from the vault
    /// before the error comes back, and the key stays: see
    /// [`PremiumError::DeviceDisconnected`].
    ///
    /// The client goes through Tor when the base URL is an onion, and
    /// when the backend of the active network is one: a person who
    /// reaches their own node through Tor chose not to show their
    /// address, and the premium server is not where to show it after
    /// all. The route is resolved before the client exists, and a Tor
    /// that cannot be reached is a client that is not built: nothing
    /// falls back to the clear. A clearnet backend with a clearnet base
    /// URL never probes for Tor.
    pub async fn premium_client(&self, base_url: &str) -> CoreResult<PremiumClient> {
        let (key, token) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            (
                premium.key.clone(),
                premium.device.as_ref().map(|d| d.token().to_owned()),
            )
        };
        self.premium_client_for(base_url, key, token).await
    }

    /// [`Self::premium_client`] carrying the key and the token a caller
    /// read beside what they go with.
    async fn premium_client_for(
        &self,
        base_url: &str,
        key: Option<String>,
        token: Option<String>,
    ) -> CoreResult<PremiumClient> {
        Ok(self
            .premium_client_with_key(base_url, key)
            .await?
            .with_device_token(token)
            .on_disowned(self.premium_disowned_hook()))
    }

    /// [`Self::premium_client`] carrying `key` instead of the stored
    /// one, and no device token: for connecting a key just typed,
    /// before anything is stored. The route is decided the same way.
    pub async fn premium_client_with_key(
        &self,
        base_url: &str,
        key: Option<String>,
    ) -> CoreResult<PremiumClient> {
        // Tor as soon as any backend is an onion, on any network, as for
        // the update check: the requests carry the device token, and
        // switching to a network whose backend is in the clear must
        // not show this device's address to the server beside it.
        let proxy = if chain::is_onion(base_url) || self.uses_tor().await {
            let (settings, data_dir) = self.tor_setup().await;
            Some(tor::resolve(&settings, &data_dir).await?.proxy())
        } else {
            None
        };
        let client = PremiumClient::new(base_url, key, proxy.as_deref())?;
        #[cfg(test)]
        let client = match self.premium_public_key.lock().unwrap().clone() {
            Some(public_key) => client.with_public_key(&public_key),
            None => client,
        };
        Ok(client)
    }

    /// What drops a token the server disowned: the stored one, if it is
    /// still that token. The manager is held weakly, so a client kept
    /// past it keeps nothing alive. A vault that cannot be written keeps
    /// the token, and the next call hears the same answer and tries
    /// again.
    fn premium_disowned_hook(&self) -> crate::premium::client::DisownedHook {
        let shared = std::sync::Arc::downgrade(&self.shared);
        std::sync::Arc::new(move |token: String| {
            let shared = shared.clone();
            Box::pin(async move {
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                let mut state = shared.state.lock().await;
                if state.payload.settings.premium.holds_token(&token) {
                    let _ = state.commit(|payload| {
                        payload.settings.premium.disown(&token);
                        Ok(())
                    });
                }
            })
        })
    }

    /// Confirms a channel with the code the server sent to it, through
    /// the client [`Self::premium_client`] builds: the same token, the
    /// same route.
    pub async fn premium_confirm_channel(
        &self,
        base_url: &str,
        id: &str,
        code: &str,
    ) -> CoreResult<Channel> {
        self.premium_client(base_url)
            .await?
            .confirm_channel(id, code)
            .await
    }

    /// Deletes the account on the server, then forgets it here: the
    /// key, the token, the certificate, the consents, the dismissed
    /// banner. A key with nothing behind it is not worth keeping, and
    /// the next key entered starts from nothing. Nothing is forgotten
    /// unless the server confirmed. A token the server disowns is not
    /// that: an account deleted from another device disowns it, and so
    /// does a device disconnected from one that is still there, which
    /// this device can no longer tell apart. The token goes, the key
    /// stays, and [`Self::premium_log_out`] is what forgets the rest.
    /// The tokens of past connections still to be dropped by the server,
    /// another account's among them, stay queued.
    pub async fn premium_delete_account(&self, base_url: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
        self.premium_client(base_url)
            .await?
            .delete_account()
            .await?;
        self.state.lock().await.commit(|payload| {
            let gone = std::mem::take(&mut payload.settings.premium);
            // Tokens of past connections, other accounts' among them,
            // are still to be dropped by the server.
            let premium = &mut payload.settings.premium;
            premium.pending_logouts = gone.pending_logouts;
            if let Some(pending) = &gone.pending_connect {
                premium.queue_logout(pending.token());
            }
            Ok(())
        })
    }

    /// Tells the server to stop watching a wallet that stays on this
    /// device: the switch in the settings turned off. The yes goes with
    /// it once the server has nothing under that id: told, or answered
    /// that there is nothing there ([`PremiumError::NotFound`]). A
    /// wallet the server does not watch needs no consent on file; one
    /// left behind would have a later removal queue a message the
    /// server has already heard, and the screens say the server is told
    /// when it has nothing to hear. Switching the wallet back on asks
    /// the question again, as it should: the descriptor leaves the
    /// device only on a yes said for that sending. Any other answer
    /// leaves everything as it was: a server that cannot be reached,
    /// one that refuses for lack of paid time, a device that waits or
    /// was disowned, a rate limit or any refusal of its own says
    /// nothing about what it still holds, and the wallet is still
    /// watched there, the yes still standing here, until it is told
    /// again.
    pub async fn premium_unwatch_wallet(&self, base_url: &str, id: &str) -> CoreResult<()> {
        match self.premium_client(base_url).await?.delete_wallet(id).await {
            Ok(()) | Err(CoreError::Premium(PremiumError::NotFound)) => {}
            Err(e) => return Err(e),
        }
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium.withdraw(id);
            premium.unwatched(id);
            Ok(())
        })
    }

    /// Tells the server about the wallets removed from this device
    /// since it last heard, one `DELETE` each in the order they went,
    /// through the client [`Self::premium_client`] builds. A wallet the
    /// server has nothing under counts as told. A wallet the server
    /// refuses stays queued and the round
    /// goes on to the next: a refusal is about that one id, and one
    /// the server never accepts must not hold every wallet behind it.
    /// Any other answer ends the round where it stands: a server that
    /// cannot be reached, and a rate limit, which is about this client
    /// and would turn away every request behind it as well. Either way what was told is
    /// forgotten, the rest waits for the next call, and the first
    /// error is returned. Nothing to tell, or no connected device to
    /// tell it with, costs no connection. Returns how many removals
    /// still wait.
    ///
    /// The removals and the token they go with are read together, and
    /// what the server answered settles them only while this device
    /// still holds that token: once it has moved to another account,
    /// the queue is that account's, and the old one's answers told it
    /// nothing.
    pub async fn premium_flush_unwatch(&self, base_url: &str) -> CoreResult<usize> {
        let (pending, key, token) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            let token = match &premium.device {
                Some(device) if premium.has_key() => device.token().to_owned(),
                _ => return Ok(premium.pending_unwatch.len()),
            };
            (premium.pending_unwatch.clone(), premium.key.clone(), token)
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let client = self
            .premium_client_for(base_url, key, Some(token.clone()))
            .await?;
        let mut told = Vec::new();
        let mut failure = None;
        for id in &pending {
            match client.delete_wallet(id).await {
                Ok(()) => told.push(id.clone()),
                // Nothing under that id: the state we wanted.
                Err(CoreError::Premium(PremiumError::NotFound)) => {
                    told.push(id.clone());
                }
                // A refusal says nothing about what the server holds,
                // and the message waits. It is about this id, though,
                // and the next may fare better:
                // one the server refuses for good would otherwise hold
                // the rest for good too.
                Err(e @ CoreError::Premium(PremiumError::Rejected(_))) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                }
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                    break;
                }
            }
        }
        let left = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if premium.holds_token(&token) {
                for id in &told {
                    premium.unwatched(id);
                }
            }
            Ok(premium.pending_unwatch.len())
        })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(left),
        }
    }
}

#[cfg(test)]
mod tests;
