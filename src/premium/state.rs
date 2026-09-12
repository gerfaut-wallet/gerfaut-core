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

use serde::{Deserialize, Serialize};

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            r#"{"key":"abcdefghijkmnpqr","certificate":"eyJ2IjoxfQ.c2ln","watched":[{"wallet_id":"w1","consented_at":100}],"acknowledged_offline_until":500,"pending_unwatch":[]}"#
        );
        assert_eq!(serde_json::from_str::<PremiumState>(&json).unwrap(), state);
    }
}
