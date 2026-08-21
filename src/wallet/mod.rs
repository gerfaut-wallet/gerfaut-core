//! Wallet model: metadata, serializable snapshots, and the lightweight
//! state of single-address wallets.

pub mod meta;
pub mod snapshot;
pub mod views;

use serde::{Deserialize, Serialize};

use crate::wallet::snapshot::TxIo;

/// Chain state of a single watched address, tracked without the BDK
/// engine (a lone address has no descriptor to derive from). Rebuilt
/// from the backend at each sync.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AddressWatchState {
    /// Transactions touching the address, newest first.
    pub txs: Vec<AddressTx>,
    /// Unspent outputs of the address, as reported by the backend.
    #[serde(default)]
    pub utxos: Vec<AddressUtxo>,
    /// Chain tip height at the last sync.
    pub tip_height: u32,
    /// Sum of outputs funding the address, in satoshis (confirmed and
    /// mempool combined).
    pub funded_sats: u64,
    /// Sum of inputs spending from the address, in satoshis (confirmed
    /// and mempool combined).
    pub spent_sats: u64,
    /// True when the address has more history than the sync fetched;
    /// the totals above remain exact (they come from backend stats).
    #[serde(default)]
    pub truncated: bool,
}

/// One transaction as seen from a watched address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddressTx {
    pub txid: String,
    /// Net effect on the address, in satoshis.
    pub net_sats: i64,
    pub fee_sats: Option<u64>,
    pub height: Option<u32>,
    /// Block time, unix seconds, when confirmed.
    pub timestamp: Option<u64>,
    pub vsize: u64,
    pub inputs: Vec<TxIo>,
    pub outputs: Vec<TxIo>,
}

/// One unspent output of a watched address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub height: Option<u32>,
    pub timestamp: Option<u64>,
}
