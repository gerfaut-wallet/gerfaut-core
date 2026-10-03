//! What an Esplora server answers besides a history, as far as the core
//! reads it: the counters of a script or of an address, where a
//! transaction stands, the coins of an address, and whether an output
//! is spent. What it does not read is skipped as it is parsed.

use bdk_wallet::bitcoin::{BlockHash, Txid};
use serde::Deserialize;

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub block_hash: Option<BlockHash>,
    /// Unix seconds, as the miner set them.
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// The counters of a script: its confirmed transactions, and those in
/// the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct ScriptHashStats {
    pub chain_stats: ScriptHashTxsSummary,
    pub mempool_stats: ScriptHashTxsSummary,
}

/// The counters of an address, the same as a script's.
pub(crate) type AddressStats = ScriptHashStats;

/// One side of [`ScriptHashStats`]: the coins paid and spent, and the
/// transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct ScriptHashTxsSummary {
    pub funded_txo_count: u32,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u32,
    pub spent_txo_sum: u64,
    pub tx_count: u32,
}

/// A coin of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub status: TxStatus,
    /// In satoshis.
    pub value: u64,
}

/// Whether an output is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) struct OutputStatus {
    pub spent: bool,
}
