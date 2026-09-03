//! Wallet identity and metadata, persisted in the vault.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::input::{RecognizedKind, ScriptKind};
use crate::network::Network;
use crate::wallet::snapshot::BalanceSnapshot;

/// Default stop gap for full scans: number of consecutive unused
/// addresses after which scanning stops.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// What a wallet is made of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletKind {
    /// A descriptor wallet, driven by the BDK engine.
    Descriptors {
        /// Canonical external (receive) descriptor, checksummed.
        external: String,
        /// Canonical internal (change) descriptor, when known.
        internal: Option<String>,
        script: ScriptKind,
    },
    /// A single watched address, tracked without derivation.
    SingleAddress { address: String },
}

/// When and against what a wallet was last synchronized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStamp {
    /// Unix timestamp, seconds.
    pub at: u64,
    /// Chain tip height observed during that sync.
    pub tip_height: u32,
    /// Human-readable backend identifier (URL host).
    pub backend: String,
}

/// Totals cached in the vault so list views render without loading
/// the full wallet state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedTotals {
    pub balance: BalanceSnapshot,
    pub tx_count: u32,
}

/// The glyph a wallet shows next to its name, chosen by the user. The
/// names are Lucide's, the set is fixed so both apps draw the same
/// icon for the same value. A vault written before icons existed reads
/// as the generic wallet, and so does a name this build does not know:
/// a backup from a newer build must still open here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletIcon {
    /// A single signing key.
    Key,
    /// Several keys guarding the coins: multisig, a vault policy.
    Shield,
    /// A watched address.
    MapPin,
    /// Cold storage.
    Snowflake,
    /// A treasury, a company's coins.
    Landmark,
    /// Savings.
    PiggyBank,
    /// The generic wallet: the default, and what any unknown name
    /// becomes (serde wants that catch-all declared last).
    #[default]
    #[serde(other)]
    Wallet,
}

/// A wallet's stored identity. Everything here is metadata: chain state
/// lives in the wallet record next to it.
///
/// The `labels` map is shaped for BIP-329 interoperability: keys are
/// `"<type>:<ref>"` with the BIP-329 types (`tx`, `addr`, `output`, ...),
/// so future label sync and export map one-to-one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletMeta {
    /// Stable unique id (UUID v4).
    pub id: String,
    pub name: String,
    /// The glyph shown next to the name; the generic wallet unless the
    /// user picked another.
    #[serde(default)]
    pub icon: WalletIcon,
    pub network: Network,
    pub kind: WalletKind,
    /// What the import classifier recognized, kept for display.
    pub recognized_as: RecognizedKind,
    /// Unix timestamp, seconds.
    pub created_at: u64,
    pub gap_limit: u32,
    /// Gap limit the last full scan actually used. When the setting is
    /// raised above it, the next sync is a full scan again: incremental
    /// syncs only watch revealed addresses and would never find funds
    /// past the old limit.
    #[serde(default = "default_scan_gap")]
    pub scan_gap: u32,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub last_sync: Option<SyncStamp>,
    #[serde(default)]
    pub cached: CachedTotals,
}

/// Wallets stored before scan tracking existed were scanned with the
/// default gap: only a setting above it needs a new full scan.
fn default_scan_gap() -> u32 {
    DEFAULT_GAP_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_reads_snake_case_and_forgives_the_unknown() {
        assert_eq!(
            serde_json::to_string(&WalletIcon::PiggyBank).unwrap(),
            "\"piggy_bank\""
        );
        assert_eq!(
            serde_json::from_str::<WalletIcon>("\"map_pin\"").unwrap(),
            WalletIcon::MapPin
        );
        // A name a newer build invented, or a vault from before icons
        // existed, both read as the plain wallet rather than refusing
        // the whole vault.
        assert_eq!(
            serde_json::from_str::<WalletIcon>("\"dragon\"").unwrap(),
            WalletIcon::Wallet
        );
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default)]
            icon: WalletIcon,
        }
        assert_eq!(
            serde_json::from_str::<Holder>("{}").unwrap().icon,
            WalletIcon::Wallet
        );
    }
}
