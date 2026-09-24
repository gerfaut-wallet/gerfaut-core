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

use crate::error::{CoreError, CoreResult, PremiumError};
use crate::premium::licence;
use crate::premium::{Device, DevicePlatform, Licence};

use super::{WalletManager, same_key};

impl WalletManager {
    /// Connects this device with `key`, which replaces the old
    /// activation. The key's shape is checked first; then it goes to
    /// the server, the one request it ever goes with, and the key and
    /// the token that came back are stored in one write, only once the
    /// server has answered. The certificate is fetched after that, which
    /// a waiting device may do: when it cannot be had, for a key never
    /// paid for or a server gone quiet, the device stays connected and
    /// [`Self::premium_refresh_licence`] says why.
    ///
    /// The device that comes back has full access when it is the
    /// account's first, and waits otherwise. A key entered again on a
    /// device it already connected connects nothing new, since a new
    /// device would wait where this one may not: the device it already
    /// is comes back. Another key moves this device to that account;
    /// what the vault knew of the last one goes, its certificate and
    /// its checklist, and the server is told, as far as it can be
    /// reached, that the old connection is over.
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
        let _change = self.premium_changes.lock().await;
        self.connect(base_url, licence::normalize_key(key), platform)
            .await
    }

    /// Connects this device with the stored key when it holds one and
    /// no token: a vault written before devices existed. The apps call
    /// it before any premium call; it connects once, and returns the
    /// device it connected, or `None` when there was nothing to do. A
    /// device the server disowned is not connected again behind the
    /// user's back: that is theirs to ask, with [`Self::premium_connect`].
    ///
    /// A stored key the server no longer knows, changed on another
    /// device or its account gone, is recorded as disowned, and the
    /// error comes back: asking again at every call would not change
    /// the answer.
    pub async fn premium_ensure_device(
        &self,
        base_url: &str,
        platform: DevicePlatform,
    ) -> CoreResult<Option<Device>> {
        let _change = self.premium_changes.lock().await;
        let key = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            match &premium.key {
                Some(key) if !premium.has_device() && !premium.disconnected => {
                    licence::normalize_key(key)
                }
                _ => return Ok(None),
            }
        };
        match self.connect(base_url, key.clone(), platform).await {
            Ok(device) => Ok(Some(device)),
            Err(error @ CoreError::Premium(PremiumError::UnknownKey)) => {
                self.state.lock().await.commit(|payload| {
                    let premium = &mut payload.settings.premium;
                    if !premium.has_device() && same_key(premium.key.as_deref(), Some(&key)) {
                        premium.disconnected = true;
                    }
                    Ok(())
                })?;
                Err(error)
            }
            Err(error) => Err(error),
        }
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
    /// disowned: connecting again is the user's call.
    pub async fn premium_remove_device(&self, base_url: &str, id: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
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

    /// Logs this device out of the account: the server is told, as far
    /// as it can be reached, and whatever it answers, the key, the token
    /// and the certificate leave the vault, with what the screens
    /// remembered about the account. The consents stay, so the same key
    /// entered again asks nothing twice. What "Forget this key" did,
    /// and the server now hears of it.
    pub async fn premium_log_out(&self, base_url: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
        let token = self
            .state
            .lock()
            .await
            .payload
            .settings
            .premium
            .device
            .as_ref()
            .map(|d| d.token().to_owned());
        if let Some(token) = token {
            self.log_out_token(base_url, &token).await;
        }
        self.state.lock().await.commit(|payload| {
            payload.settings.premium.forget_account();
            Ok(())
        })
    }

    /// Replaces the account key. The old one stops working everywhere at
    /// once, every other device is disconnected, and this one stays
    /// connected with its token. The new key is stored as soon as the
    /// server gave it, marked as not saved yet, and the certificate,
    /// whose subject changes with the key, is fetched again; one that
    /// cannot be had leaves the last one, whose dates still hold.
    /// Returns the new key, formatted to be shown: it is shown nowhere
    /// else, ever.
    pub async fn premium_change_key(&self, base_url: &str) -> CoreResult<String> {
        let _change = self.premium_changes.lock().await;
        let key = self.premium_client(base_url).await?.change_key().await?;
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium.key = Some(key.clone());
            premium.key_saved = false;
            // Every other device is gone, and with them what was
            // announced of them.
            premium.announced_devices.clear();
            Ok(())
        })?;
        let _ = self.premium_refresh_licence(base_url).await;
        Ok(licence::format_key(&key))
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
        let connected_already = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            premium.has_device() && same_key(premium.key.as_deref(), Some(&key))
        };
        if connected_already {
            match self.premium_client(base_url).await?.device_me().await {
                Ok(device) => {
                    let _ = self.premium_refresh_licence(base_url).await;
                    return Ok(device);
                }
                // The token was disowned and is dropped: connecting again
                // is what the user asked.
                Err(CoreError::Premium(PremiumError::DeviceDisconnected)) => {}
                Err(error) => return Err(error),
            }
        }
        let connected = self
            .premium_client_with_key(base_url, Some(key.clone()))
            .await?
            .connect_device(platform)
            .await?;
        let credential = connected.credential();
        let committed = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if !same_key(premium.key.as_deref(), Some(&key)) {
                // Another account: nothing this device knew of the last
                // one holds for this one.
                premium.certificate = None;
                premium.key_saved = false;
                premium.checklist_hidden = false;
                premium.announced_devices.clear();
            }
            let previous = premium.device.replace(credential);
            premium.key = Some(key.clone());
            premium.disconnected = false;
            premium.acknowledged_offline_until = None;
            Ok(previous)
        });
        match committed {
            Ok(Some(previous)) => self.log_out_token(base_url, previous.token()).await,
            Ok(None) => {}
            Err(error) => {
                // The server holds a device nobody will: it goes.
                self.log_out_token(base_url, connected.token()).await;
                return Err(error);
            }
        }
        let _ = self.premium_refresh_licence(base_url).await;
        Ok(connected.device)
    }

    /// Tells the server, as far as it can be reached, that the device
    /// holding `token` leaves. Nothing waits on the answer: whatever it
    /// is, what the caller does next is the same.
    async fn log_out_token(&self, base_url: &str, token: &str) {
        if let Ok(client) = self.premium_client_with_key(base_url, None).await {
            let _ = client
                .with_device_token(Some(token.to_owned()))
                .log_out_device()
                .await;
        }
    }
}

#[cfg(test)]
mod tests;
