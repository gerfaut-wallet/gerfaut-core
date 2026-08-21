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
    pub network: Network,
    pub kind: WalletKind,
    /// What the import classifier recognized, kept for display.
    pub recognized_as: RecognizedKind,
    /// Unix timestamp, seconds.
    pub created_at: u64,
    pub gap_limit: u32,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub last_sync: Option<SyncStamp>,
    #[serde(default)]
    pub cached: CachedTotals,
}
