//! Serializable views of wallet state, shared by every UI.
//!
//! These types are the contract between the core and the apps: the
//! desktop reads them over Tauri commands, the mobile app over the FFI
//! bridge. They carry plain data only — amounts in satoshis, ids as
//! strings — so both sides render exactly the same thing.

use serde::{Deserialize, Serialize};

use crate::wallet::meta::WalletMeta;
use crate::wallet::tx_extras::{OpReturnData, TxExtras};

/// A transaction a sync brought in for the first time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTx {
    pub txid: String,
    /// Net effect on the wallet, in satoshis, signed like a summary.
    pub net_sats: i64,
    pub confirmed: bool,
}

/// Balance breakdown, in satoshis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceSnapshot {
    /// Confirmed and spendable.
    pub confirmed: u64,
    /// Unconfirmed change returning to the wallet.
    pub trusted_pending: u64,
    /// Unconfirmed external receives.
    pub untrusted_pending: u64,
    /// Coinbase outputs still maturing.
    pub immature: u64,
    /// Sum of everything above.
    pub total: u64,
    /// Signed sum of the transactions not yet in a block: the part of
    /// `total` still arriving (positive), or what has left it without
    /// the chain having taken it yet (negative). `None` once everything
    /// is settled. Read from the transactions, not from the two pending
    /// buckets above: a spend that returns no change leaves both at
    /// zero while the total has already dropped.
    #[serde(default)]
    pub pending_net_sats: Option<i64>,
}

/// Confirmation status of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TxStatus {
    Confirmed {
        height: u32,
        /// Block time, unix seconds, when known.
        timestamp: Option<u64>,
    },
    Pending,
}

/// One row of a transaction list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxSummary {
    pub txid: String,
    /// Net effect on the wallet, in satoshis: positive for an incoming
    /// transaction, negative for an outgoing one.
    pub net_sats: i64,
    /// Fee paid, when computable from known inputs.
    pub fee_sats: Option<u64>,
    pub status: TxStatus,
    /// Confirmations at snapshot time; 0 while pending.
    pub confirmations: u32,
}

/// One side entry (input or output) of a transaction detail view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIo {
    /// Address, when the script has one.
    pub address: Option<String>,
    /// Value in satoshis; unknown for inputs whose previous output the
    /// wallet does not know.
    pub value_sats: Option<u64>,
    /// Whether this side belongs to the wallet.
    pub is_mine: bool,
    /// Output on the wallet's change keychain (descriptor wallets only).
    #[serde(default)]
    pub change: bool,
    /// Decoded OP_RETURN payload, for data-carrying outputs.
    #[serde(default)]
    pub op_return: Option<OpReturnData>,
    /// For an input, the transaction of the output it spends. The
    /// outpoint is what names an input on the chain: the diagram shows
    /// it truncated, and an address alone cannot stand for it because
    /// the same address may be spent from twice.
    #[serde(default)]
    pub prev_txid: Option<String>,
    /// For an input, the index of the output it spends.
    #[serde(default)]
    pub prev_vout: Option<u32>,
}

/// Full transaction detail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxDetail {
    pub summary: TxSummary,
    pub inputs: Vec<TxIo>,
    pub outputs: Vec<TxIo>,
    /// Virtual size in vbytes.
    pub vsize: u64,
    /// Fee rate in sat/vB, when the fee is known.
    pub fee_rate_sat_vb: Option<f64>,
    /// Deep transaction facts; absent only for watched-address entries
    /// synced by older versions.
    #[serde(default)]
    pub extras: Option<TxExtras>,
}

/// Which derivation chain an address or UTXO belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Keychain {
    External,
    Internal,
}

/// One unspent output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub value_sats: u64,
    pub status: TxStatus,
    /// Derivation info; absent for single-address wallets.
    pub keychain: Option<Keychain>,
    pub derivation_index: Option<u32>,
}

/// One row of the address audit list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRow {
    pub index: u32,
    pub address: String,
    /// Whether the chain has seen this address used.
    pub used: bool,
    /// Sum of the unspent outputs currently on this address.
    pub balance_sats: u64,
}

/// Revealed addresses of a wallet, by keychain, capped in size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressList {
    pub external: Vec<AddressRow>,
    /// Change addresses; empty when none were revealed (or for wallets
    /// without a change descriptor).
    pub internal: Vec<AddressRow>,
    /// True when a keychain had more rows than the cap.
    pub truncated: bool,
}

/// One receive address row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressEntry {
    pub index: u32,
    pub address: String,
    /// Whether the chain has seen this address used.
    pub used: bool,
    /// Derivation path for descriptor wallets: absolute
    /// (`m/84'/1'/0'/0/5`) when the origin is unambiguous, else
    /// keychain-relative (`0/5`). None for watched single addresses.
    #[serde(default)]
    pub derivation: Option<String>,
}

/// Home view of a wallet: metadata, balance, transaction list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub meta: WalletMeta,
    pub balance: BalanceSnapshot,
    /// Sorted for display: pending first, then by descending
    /// confirmation height.
    pub txs: Vec<TxSummary>,
    /// Chain tip height at the last sync; 0 before the first sync.
    pub tip_height: u32,
    /// True when older transactions remain to be fetched (a watched
    /// address with more history than one sync round covers). The
    /// balance stays exact; the UI offers to load the rest, which calls
    /// [`crate::manager::WalletManager::load_more_history`].
    #[serde(default)]
    pub truncated: bool,
}

/// Outcome of one sync run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub wallet_id: String,
    /// Transactions that appeared since the previous sync.
    pub new_tx_count: u32,
    /// The same transactions, one line each, so the apps can say what
    /// happened (a notification, a banner) without reloading the wallet.
    #[serde(default)]
    pub new_txs: Vec<NewTx>,
    pub balance: BalanceSnapshot,
    pub tip_height: u32,
    pub took_ms: u64,
    /// Human-readable backend identifier (URL host).
    pub backend: String,
}
