//! What an app keeps about its premium account, in the encrypted vault.
//!
//! The key is the account: losing it is losing the paid time, so it
//! lives in the vault with the wallets, never in a plain preference
//! store. Beside it, the last certificate the server issued, so the
//! screen says "premium until" without a network; which wallets the
//! user agreed to send to the server, and when, because a descriptor
//! leaves the device only on an explicit yes; and how long the "watch
//! is offline" banner was told to keep quiet.

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            r#"{"key":"abcdefghijkmnpqr","certificate":"eyJ2IjoxfQ.c2ln","watched":[{"wallet_id":"w1","consented_at":100}],"acknowledged_offline_until":500}"#
        );
        assert_eq!(serde_json::from_str::<PremiumState>(&json).unwrap(), state);
    }
}
