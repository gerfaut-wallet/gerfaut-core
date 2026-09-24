//! What an app keeps about its premium account, in the encrypted vault.
//!
//! The key is the account: losing it is losing the paid time, so it
//! lives in the vault with the wallets, never in a plain preference
//! store. Beside it, the last certificate the server issued, so the
//! screen says "premium until" without a network; which wallets the
//! user agreed to send to the server, and when, because a descriptor
//! leaves the device only on an explicit yes; which watched wallets
//! were removed from the device before the server could be told,
//! because removing a wallet here must remove it there and cannot wait
//! for the network; and how long the "watch is offline" banner was told
//! to keep quiet.
//!
//! Since a key only connects a device, the device's own credential sits
//! beside the key: the token the server handed this device, which every
//! request but the connection carries. Then what the screens remember
//! about the account's safety: whether the server disowned this device,
//! whether the user saved the key, whether the checklist was put away,
//! and which waiting devices a notification already announced.

use serde::{Deserialize, Serialize};

use super::device::DeviceCredential;

/// A wallet the user agreed to have watched by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedWallet {
    /// The app's own wallet id, the one the server is told.
    pub wallet_id: String,
    /// Unix seconds: when the user said yes.
    pub consented_at: i64,
}

/// The premium account as the vault keeps it. Empty by default, which
/// is what a vault written before premium existed reads as.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PremiumState {
    /// The account key, normalized. `None` until the user enters one.
    #[serde(default)]
    pub key: Option<String>,
    /// The last certificate the server issued, verified before it was
    /// stored; read back with `licence::verify_certificate`.
    #[serde(default)]
    pub certificate: Option<String>,
    /// The wallets the user agreed to send to the server.
    #[serde(default)]
    pub watched: Vec<WatchedWallet>,
    /// Unix seconds until which the "watch is offline" banner stays
    /// hidden, because the user dismissed it.
    #[serde(default)]
    pub acknowledged_offline_until: Option<i64>,
    /// Wallets removed from this device while the server still watched
    /// them, in the order they went, until the server has been told.
    #[serde(default)]
    pub pending_unwatch: Vec<String>,
    /// This device's connection to the account: its id, its token, when
    /// it connected. `None` until the key connects it, and again once
    /// the server disowned it. The core alone writes it.
    #[serde(default)]
    pub device: Option<DeviceCredential>,
    /// The server disowned this device: another device disconnected it,
    /// the key was changed elsewhere, or the key no longer opens the
    /// account. The key stays, and connecting again waits for the user
    /// to ask. The core alone writes it.
    #[serde(default)]
    pub disconnected: bool,
    /// The user said the key is saved somewhere safe.
    #[serde(default)]
    pub key_saved: bool,
    /// The "Protect your Premium account" card was hidden.
    #[serde(default)]
    pub checklist_hidden: bool,
    /// Waiting devices a local notification already announced, so each
    /// is announced once.
    #[serde(default)]
    pub announced_devices: Vec<String>,
}

impl PremiumState {
    /// Whether an account key is set.
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// When the user agreed to have this wallet watched, if they did.
    pub fn consented_at(&self, wallet_id: &str) -> Option<i64> {
        self.watched
            .iter()
            .find(|w| w.wallet_id == wallet_id)
            .map(|w| w.consented_at)
    }

    /// Records the user's yes for a wallet. Asking twice keeps the first
    /// answer's date.
    pub fn consent(&mut self, wallet_id: &str, now_unix: i64) {
        // A yes said now outranks a removal the server never heard of.
        self.unwatched(wallet_id);
        if self.consented_at(wallet_id).is_none() {
            self.watched.push(WatchedWallet {
                wallet_id: wallet_id.to_owned(),
                consented_at: now_unix,
            });
        }
    }

    /// Forgets the yes for a wallet: the next time it comes up, the
    /// user is asked again.
    pub fn withdraw(&mut self, wallet_id: &str) {
        self.watched.retain(|w| w.wallet_id != wallet_id);
    }

    /// Whether the user agreed to have this wallet watched.
    pub fn is_consented(&self, wallet_id: &str) -> bool {
        self.consented_at(wallet_id).is_some()
    }

    /// Records that the server must stop watching a wallet that is gone
    /// from this device, and forgets the yes with it. Queued once,
    /// however many times it is asked.
    pub fn queue_unwatch(&mut self, wallet_id: &str) {
        self.withdraw(wallet_id);
        if !self.pending_unwatch.iter().any(|w| w == wallet_id) {
            self.pending_unwatch.push(wallet_id.to_owned());
        }
    }

    /// The server no longer watches this wallet: nothing left to tell it.
    pub fn unwatched(&mut self, wallet_id: &str) {
        self.pending_unwatch.retain(|w| w != wallet_id);
    }

    /// Whether this device holds a connection to the account.
    pub fn has_device(&self) -> bool {
        self.device.is_some()
    }

    /// Whether `token` is the one this device holds.
    pub(crate) fn holds_token(&self, token: &str) -> bool {
        self.device.as_ref().is_some_and(|d| d.token() == token)
    }

    /// The server no longer knows `token`: the connection it belonged
    /// to is gone, the key stays. Only that token is dropped: one stored
    /// since, by a connection made meanwhile, is not touched. Returns
    /// whether anything changed.
    pub(crate) fn disown(&mut self, token: &str) -> bool {
        if !self.holds_token(token) {
            return false;
        }
        self.device = None;
        self.disconnected = true;
        true
    }

    /// This device leaves the account: the key, its connection, its
    /// certificate and what the screens remembered about it go. The
    /// consents stay, so the same key entered again asks nothing twice,
    /// and so do the removals the server has yet to hear of.
    pub(crate) fn forget_account(&mut self) {
        self.key = None;
        self.certificate = None;
        self.acknowledged_offline_until = None;
        self.device = None;
        self.disconnected = false;
        self.key_saved = false;
        self.checklist_hidden = false;
        self.announced_devices.clear();
    }

    /// Records the waiting devices a notification has announced.
    /// `pending` is every device that waits, as the latest list shows
    /// them: the record becomes that, so a device that no longer waits
    /// leaves it. Returns the ones it did not hold before, in the order
    /// given: the devices to announce now, each handed out once.
    pub(crate) fn mark_announced(&mut self, pending: &[String]) -> Vec<String> {
        let mut record: Vec<String> = Vec::with_capacity(pending.len());
        for id in pending {
            if !record.contains(id) {
                record.push(id.clone());
            }
        }
        let fresh = record
            .iter()
            .filter(|id| !self.announced_devices.contains(id))
            .cloned()
            .collect();
        self.announced_devices = record;
        fresh
    }

    /// Blanks the device token: the state as an app is handed it.
    pub(crate) fn redact(&mut self) {
        self.device = self.device.as_ref().map(DeviceCredential::redacted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA";
    const OTHER_TOKEN: &str = "gdt1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn connected() -> PremiumState {
        PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            device: Some(DeviceCredential::new("d1".to_owned(), TOKEN.to_owned(), 5)),
            ..PremiumState::default()
        }
    }

    /// A vault written before devices existed holds a key and no token.
    /// It reads unchanged, as a device never connected, not as one the
    /// server disowned.
    #[test]
    fn a_vault_from_before_devices_reads_as_never_connected() {
        let state: PremiumState = serde_json::from_str(
            r#"{"key":"abcdefghijkmnpqr","certificate":"eyJ2IjoxfQ.c2ln","watched":[{"wallet_id":"w1","consented_at":100}],"acknowledged_offline_until":null,"pending_unwatch":["w2"]}"#,
        )
        .unwrap();
        assert!(state.has_key());
        assert!(!state.has_device());
        assert!(!state.disconnected);
        assert!(!state.key_saved);
        assert!(!state.checklist_hidden);
        assert!(state.announced_devices.is_empty());
        assert_eq!(state.pending_unwatch, vec!["w2".to_owned()]);
        assert!(state.is_consented("w1"));
    }

    #[test]
    fn a_disowned_token_goes_and_a_newer_one_stays() {
        let mut state = connected();
        assert!(
            !state.disown(OTHER_TOKEN),
            "not the token this device holds"
        );
        assert!(state.has_device());
        assert!(!state.disconnected);
        assert!(state.disown(TOKEN));
        assert!(!state.has_device());
        assert!(state.disconnected);
        assert!(state.has_key(), "the key stays");
        assert!(!state.disown(TOKEN), "nothing left to drop");
    }

    #[test]
    fn leaving_the_account_keeps_the_consents_and_the_removals() {
        let mut state = PremiumState {
            certificate: Some("eyJ2IjoxfQ.c2ln".to_owned()),
            acknowledged_offline_until: Some(500),
            disconnected: true,
            key_saved: true,
            checklist_hidden: true,
            announced_devices: vec!["d2".to_owned()],
            ..connected()
        };
        state.consent("w1", 100);
        state.queue_unwatch("w2");
        state.forget_account();
        let mut expected = PremiumState::default();
        expected.consent("w1", 100);
        expected.queue_unwatch("w2");
        assert_eq!(state, expected);
    }

    #[test]
    fn each_waiting_device_is_announced_once_and_forgotten_once_it_stops_waiting() {
        let ids = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let mut state = PremiumState::default();
        assert_eq!(
            state.mark_announced(&ids(&["d1", "d2"])),
            ids(&["d1", "d2"])
        );
        assert_eq!(state.mark_announced(&ids(&["d1", "d2"])), ids(&[]));
        // d1 was approved or refused: it leaves the record. d3 is new,
        // and named twice is announced once.
        assert_eq!(
            state.mark_announced(&ids(&["d2", "d3", "d3"])),
            ids(&["d3"])
        );
        assert_eq!(state.announced_devices, ids(&["d2", "d3"]));
        assert_eq!(state.mark_announced(&[]), ids(&[]));
        assert!(state.announced_devices.is_empty());
    }

    #[test]
    fn the_state_an_app_is_handed_has_no_token() {
        let mut state = connected();
        let shown = format!("{state:?}");
        assert!(!shown.contains(TOKEN), "{shown}");
        state.redact();
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains(TOKEN), "{json}");
        assert!(!state.holds_token(TOKEN));
        assert_eq!(state.device.as_ref().unwrap().id, "d1");
        assert!(state.has_device());
    }

    #[test]
    fn a_removal_waits_once_and_leaves_when_told() {
        let mut state = PremiumState::default();
        state.consent("w1", 100);
        state.queue_unwatch("w1");
        state.queue_unwatch("w1");
        assert_eq!(state.pending_unwatch, vec!["w1".to_owned()]);
        assert!(!state.is_consented("w1"), "the yes went with the wallet");
        state.unwatched("w1");
        assert!(state.pending_unwatch.is_empty());
    }

    #[test]
    fn a_new_yes_cancels_a_pending_removal() {
        let mut state = PremiumState::default();
        state.queue_unwatch("w1");
        state.consent("w1", 200);
        assert!(state.pending_unwatch.is_empty());
        assert_eq!(state.consented_at("w1"), Some(200));
    }

    #[test]
    fn a_vault_from_before_reads_with_nothing_pending() {
        let state: PremiumState =
            serde_json::from_str(r#"{"key":"abcdefghijkmnpqr","watched":[]}"#).unwrap();
        assert!(state.pending_unwatch.is_empty());
    }

    #[test]
    fn an_empty_state_reads_from_nothing() {
        let state: PremiumState = serde_json::from_str("{}").unwrap();
        assert_eq!(state, PremiumState::default());
        assert!(!state.has_key());
        assert_eq!(state.consented_at("w1"), None);
    }

    #[test]
    fn consent_is_recorded_once_and_withdrawn() {
        let mut state = PremiumState::default();
        state.consent("w1", 100);
        state.consent("w1", 200);
        state.consent("w2", 300);
        assert_eq!(state.consented_at("w1"), Some(100));
        assert_eq!(state.consented_at("w2"), Some(300));
        state.withdraw("w1");
        assert_eq!(state.consented_at("w1"), None);
        assert_eq!(state.watched.len(), 1);
    }

    #[test]
    fn the_state_round_trips_through_json() {
        let state = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            certificate: Some("eyJ2IjoxfQ.c2ln".to_owned()),
            watched: vec![WatchedWallet {
                wallet_id: "w1".to_owned(),
                consented_at: 100,
            }],
            acknowledged_offline_until: Some(500),
            pending_unwatch: Vec::new(),
            device: Some(DeviceCredential::new("d1".to_owned(), TOKEN.to_owned(), 7)),
            disconnected: false,
            key_saved: true,
            checklist_hidden: false,
            announced_devices: vec!["d2".to_owned()],
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"key":"abcdefghijkmnpqr","certificate":"eyJ2IjoxfQ.c2ln","watched":[{{"wallet_id":"w1","consented_at":100}}],"acknowledged_offline_until":500,"pending_unwatch":[],"device":{{"id":"d1","token":"{TOKEN}","connected_at":7}},"disconnected":false,"key_saved":true,"checklist_hidden":false,"announced_devices":["d2"]}}"#
            )
        );
        assert_eq!(serde_json::from_str::<PremiumState>(&json).unwrap(), state);
    }
}
