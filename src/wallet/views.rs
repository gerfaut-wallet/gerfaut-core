//! Builders turning engine state into the serializable snapshots of
//! [`crate::wallet::snapshot`]. Pure functions, no I/O.

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::bitcoin::{Script, Txid};
use bdk_wallet::chain::ChainPosition;

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::wallet::snapshot::{
    AddressEntry, AddressList, AddressRow, BalanceSnapshot, Keychain, NewTx, TxDetail, TxIo,
    TxStatus, TxSummary, UtxoInfo,
};
use crate::wallet::{AddressTx, AddressWatchState, tx_extras};

/// Confirmations of a block at `height` when the tip is `tip`.
fn confirmations(height: u32, tip: u32) -> u32 {
    tip.saturating_sub(height).saturating_add(1)
}

fn address_of(script: &Script, network: Network) -> Option<String> {
    Address::from_script(script, network.to_bitcoin())
        .ok()
        .map(|a| a.to_string())
}

// --- descriptor wallets (BDK engine) -----------------------------------

pub(crate) fn balance(wallet: &bdk_wallet::Wallet) -> BalanceSnapshot {
    let balance = wallet.balance();
    BalanceSnapshot {
        confirmed: balance.confirmed.to_sat(),
        trusted_pending: balance.trusted_pending.to_sat(),
        untrusted_pending: balance.untrusted_pending.to_sat(),
        immature: balance.immature.to_sat(),
        total: balance.total().to_sat(),
    }
}

pub(crate) fn tip_height(wallet: &bdk_wallet::Wallet) -> u32 {
    wallet.latest_checkpoint().height()
}

fn status_of(position: &ChainPosition<bdk_wallet::chain::ConfirmationBlockTime>) -> TxStatus {
    match position {
        ChainPosition::Confirmed { anchor, .. } => TxStatus::Confirmed {
            height: anchor.block_id.height,
            timestamp: Some(anchor.confirmation_time),
        },
        ChainPosition::Unconfirmed { .. } => TxStatus::Pending,
    }
}

/// Transaction list, pending first, then newest confirmed first.
pub(crate) fn tx_summaries(wallet: &bdk_wallet::Wallet) -> Vec<TxSummary> {
    let tip = tip_height(wallet);
    let mut txs: Vec<TxSummary> = wallet
        .transactions()
        .map(|wtx| {
            let (sent, received) = wallet.sent_and_received(&wtx.tx_node.tx);
            let status = status_of(&wtx.chain_position);
            TxSummary {
                txid: wtx.tx_node.txid.to_string(),
                net_sats: received.to_sat() as i64 - sent.to_sat() as i64,
                fee_sats: wallet
                    .calculate_fee(&wtx.tx_node.tx)
                    .ok()
                    .map(|f| f.to_sat()),
                confirmations: match status {
                    TxStatus::Confirmed { height, .. } => confirmations(height, tip),
                    TxStatus::Pending => 0,
                },
                status,
            }
        })
        .collect();
    sort_summaries(&mut txs);
    txs
}

/// Pending first, then by descending height, txid as a stable tiebreak.
/// The transactions the engine holds that `known` does not: what a
/// sync just brought in.
pub(crate) fn new_txs(
    wallet: &bdk_wallet::Wallet,
    known: &std::collections::HashSet<bdk_wallet::bitcoin::Txid>,
) -> Vec<NewTx> {
    wallet
        .transactions()
        .filter(|wtx| !known.contains(&wtx.tx_node.txid))
        .map(|wtx| {
            let (sent, received) = wallet.sent_and_received(&wtx.tx_node.tx);
            NewTx {
                txid: wtx.tx_node.txid.to_string(),
                net_sats: received.to_sat() as i64 - sent.to_sat() as i64,
                confirmed: wtx.chain_position.is_confirmed(),
            }
        })
        .collect()
}

pub(crate) fn sort_summaries(txs: &mut [TxSummary]) {
    txs.sort_by(|a, b| {
        let key = |t: &TxSummary| match t.status {
            TxStatus::Pending => (0u8, 0i64),
            TxStatus::Confirmed { height, .. } => (1, -(height as i64)),
        };
        key(a).cmp(&key(b)).then_with(|| a.txid.cmp(&b.txid))
    });
}

pub(crate) fn tx_detail(
    wallet: &bdk_wallet::Wallet,
    network: Network,
    txid: &str,
) -> CoreResult<TxDetail> {
    let txid: Txid = txid.parse().map_err(|_| CoreError::InvalidInput {
        kind: "txid",
        detail: format!("not a transaction id: {txid}"),
    })?;
    let wtx = wallet
        .get_tx(txid)
        .ok_or_else(|| CoreError::WalletNotFound(format!("transaction {txid} not in wallet")))?;
    let tx = wtx.tx_node.tx.clone();
    let status = status_of(&wtx.chain_position);
    let tip = tip_height(wallet);

    let inputs: Vec<TxIo> = tx
        .input
        .iter()
        .map(|txin| {
            let previous = wallet.tx_graph().get_txout(txin.previous_output);
            TxIo {
                address: previous.and_then(|p| address_of(&p.script_pubkey, network)),
                value_sats: previous.map(|p| p.value.to_sat()),
                is_mine: previous.is_some_and(|p| wallet.is_mine(p.script_pubkey.clone())),
                ..TxIo::default()
            }
        })
        .collect();
    let outputs: Vec<TxIo> = tx
        .output
        .iter()
        .map(|txout| TxIo {
            address: address_of(&txout.script_pubkey, network),
            value_sats: Some(txout.value.to_sat()),
            is_mine: wallet.is_mine(txout.script_pubkey.clone()),
            change: matches!(
                wallet.derivation_of_spk(txout.script_pubkey.clone()),
                Some((KeychainKind::Internal, _))
            ),
            op_return: tx_extras::op_return_of(&txout.script_pubkey),
        })
        .collect();

    let (sent, received) = wallet.sent_and_received(&tx);
    let fee_sats = wallet.calculate_fee(&tx).ok().map(|f| f.to_sat());
    let vsize = tx.vsize() as u64;
    let extras = tx_extras::analyze(&tx, |outpoint| {
        wallet.tx_graph().get_txout(*outpoint).cloned()
    });
    Ok(TxDetail {
        summary: TxSummary {
            txid: txid.to_string(),
            net_sats: received.to_sat() as i64 - sent.to_sat() as i64,
            fee_sats,
            confirmations: match status {
                TxStatus::Confirmed { height, .. } => confirmations(height, tip),
                TxStatus::Pending => 0,
            },
            status,
        },
        inputs,
        outputs,
        vsize,
        fee_rate_sat_vb: fee_sats.map(|fee| fee as f64 / vsize as f64),
        extras: Some(extras),
    })
}

pub(crate) fn utxos(wallet: &bdk_wallet::Wallet, network: Network) -> Vec<UtxoInfo> {
    let tip = tip_height(wallet);
    let mut utxos: Vec<UtxoInfo> = wallet
        .list_unspent()
        .map(|output| UtxoInfo {
            txid: output.outpoint.txid.to_string(),
            vout: output.outpoint.vout,
            address: address_of(&output.txout.script_pubkey, network),
            value_sats: output.txout.value.to_sat(),
            status: status_of(&output.chain_position),
            keychain: Some(match output.keychain {
                KeychainKind::External => Keychain::External,
                KeychainKind::Internal => Keychain::Internal,
            }),
            derivation_index: Some(output.derivation_index),
        })
        .collect();
    let _ = tip; // confirmations live in `status`; tip kept for future use
    utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value_sats));
    utxos
}

/// Rows shown per keychain on the address page before truncation: an
/// audit view, not an infinite scroll.
pub(crate) const ADDRESS_LIST_CAP: usize = 200;

/// Revealed addresses of both keychains, ascending, with usage and the
/// balance currently sitting on each. Reveals the first external
/// address if nothing is revealed yet: the caller must persist the
/// staged change set afterwards.
pub(crate) fn address_list(wallet: &mut bdk_wallet::Wallet) -> AddressList {
    // Balance per (keychain, index) from the unspent set.
    let mut balances: std::collections::HashMap<(KeychainKind, u32), u64> =
        std::collections::HashMap::new();
    for output in wallet.list_unspent() {
        *balances
            .entry((output.keychain, output.derivation_index))
            .or_default() += output.txout.value.to_sat();
    }

    // Guarantee at least one visible external address.
    let _ = wallet.next_unused_address(KeychainKind::External);

    let mut truncated = false;
    let mut rows = |keychain: KeychainKind| -> Vec<AddressRow> {
        let Some(last) = wallet.derivation_index(keychain) else {
            return Vec::new();
        };
        let count = last as usize + 1;
        if count > ADDRESS_LIST_CAP {
            truncated = true;
        }
        (0..count.min(ADDRESS_LIST_CAP) as u32)
            .map(|index| AddressRow {
                index,
                address: wallet.peek_address(keychain, index).address.to_string(),
                used: wallet.spk_index().is_used(keychain, index),
                balance_sats: balances.get(&(keychain, index)).copied().unwrap_or(0),
            })
            .collect()
    };
    let external = rows(KeychainKind::External);
    let internal = rows(KeychainKind::Internal);
    AddressList {
        external,
        internal,
        truncated,
    }
}

/// The next unused receive address plus `lookahead` upcoming ones.
///
/// Reveals the next unused address if needed: the caller must persist
/// the staged change set afterwards.
pub(crate) fn receive_addresses(
    wallet: &mut bdk_wallet::Wallet,
    lookahead: u32,
) -> Vec<AddressEntry> {
    let next = wallet.next_unused_address(KeychainKind::External);
    let mut entries = vec![AddressEntry {
        index: next.index,
        address: next.address.to_string(),
        used: false,
        derivation: derivation_path(wallet, next.index),
    }];
    for offset in 1..=lookahead {
        let peeked = wallet.peek_address(KeychainKind::External, next.index + offset);
        entries.push(AddressEntry {
            index: peeked.index,
            address: peeked.address.to_string(),
            used: false,
            derivation: derivation_path(wallet, peeked.index),
        });
    }
    entries
}

/// Absolute derivation path of one external address, when the
/// descriptor carries a single unambiguous origin (`m/84'/1'/0'/0/5`).
/// Multi-key descriptors with diverging origins fall back to the
/// keychain-relative path (`0/5`).
fn derivation_path(wallet: &bdk_wallet::Wallet, index: u32) -> Option<String> {
    use bdk_wallet::miniscript::ForEachKey;
    let descriptor = wallet.public_descriptor(KeychainKind::External);
    let definite = descriptor.at_derivation_index(index).ok()?;
    let mut paths: Vec<String> = Vec::new();
    definite.for_each_key(|key| {
        if let Some(path) = key.full_derivation_path() {
            let text = path.to_string();
            paths.push(text.strip_prefix("m/").unwrap_or(&text).to_owned());
        }
        true
    });
    paths.sort();
    paths.dedup();
    match paths.as_slice() {
        [only] => Some(format!("m/{only}")),
        _ => Some(format!("0/{index}")),
    }
}

// --- single-address wallets --------------------------------------------

pub(crate) fn address_balance(state: &AddressWatchState) -> BalanceSnapshot {
    let confirmed_funded: u64 = state
        .utxos
        .iter()
        .filter(|u| u.height.is_some())
        .map(|u| u.value_sats)
        .sum();
    let pending_funded: u64 = state
        .utxos
        .iter()
        .filter(|u| u.height.is_none())
        .map(|u| u.value_sats)
        .sum();
    BalanceSnapshot {
        confirmed: confirmed_funded,
        trusted_pending: 0,
        untrusted_pending: pending_funded,
        immature: 0,
        total: confirmed_funded + pending_funded,
    }
}

fn address_tx_status(tx: &AddressTx) -> TxStatus {
    match tx.height {
        Some(height) => TxStatus::Confirmed {
            height,
            timestamp: tx.timestamp,
        },
        None => TxStatus::Pending,
    }
}

pub(crate) fn address_tx_summaries(state: &AddressWatchState) -> Vec<TxSummary> {
    let mut txs: Vec<TxSummary> = state
        .txs
        .iter()
        .map(|tx| {
            let status = address_tx_status(tx);
            TxSummary {
                txid: tx.txid.clone(),
                net_sats: tx.net_sats,
                fee_sats: tx.fee_sats,
                confirmations: match status {
                    TxStatus::Confirmed { height, .. } => confirmations(height, state.tip_height),
                    TxStatus::Pending => 0,
                },
                status,
            }
        })
        .collect();
    sort_summaries(&mut txs);
    txs
}

pub(crate) fn address_tx_detail(state: &AddressWatchState, txid: &str) -> CoreResult<TxDetail> {
    let tx =
        state.txs.iter().find(|t| t.txid == txid).ok_or_else(|| {
            CoreError::WalletNotFound(format!("transaction {txid} not in wallet"))
        })?;
    let status = address_tx_status(tx);
    Ok(TxDetail {
        summary: TxSummary {
            txid: tx.txid.clone(),
            net_sats: tx.net_sats,
            fee_sats: tx.fee_sats,
            confirmations: match status {
                TxStatus::Confirmed { height, .. } => confirmations(height, state.tip_height),
                TxStatus::Pending => 0,
            },
            status,
        },
        inputs: tx.inputs.clone(),
        outputs: tx.outputs.clone(),
        vsize: tx.vsize,
        fee_rate_sat_vb: tx
            .fee_sats
            .filter(|_| tx.vsize > 0)
            .map(|fee| fee as f64 / tx.vsize as f64),
        extras: tx.extras.clone(),
    })
}

pub(crate) fn address_utxos(state: &AddressWatchState, address: &str) -> Vec<UtxoInfo> {
    let mut utxos: Vec<UtxoInfo> = state
        .utxos
        .iter()
        .map(|utxo| UtxoInfo {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            address: Some(address.to_owned()),
            value_sats: utxo.value_sats,
            status: match utxo.height {
                Some(height) => TxStatus::Confirmed {
                    height,
                    timestamp: utxo.timestamp,
                },
                None => TxStatus::Pending,
            },
            keychain: None,
            derivation_index: None,
        })
        .collect();
    utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value_sats));
    utxos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(txid: &str, status: TxStatus) -> TxSummary {
        TxSummary {
            txid: txid.to_owned(),
            net_sats: 0,
            fee_sats: None,
            confirmations: 0,
            status,
        }
    }

    #[test]
    fn pending_sorts_before_confirmed_newest_first() {
        let mut txs = vec![
            summary(
                "aa",
                TxStatus::Confirmed {
                    height: 100,
                    timestamp: None,
                },
            ),
            summary(
                "bb",
                TxStatus::Confirmed {
                    height: 200,
                    timestamp: None,
                },
            ),
            summary("cc", TxStatus::Pending),
        ];
        sort_summaries(&mut txs);
        let order: Vec<&str> = txs.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(order, vec!["cc", "bb", "aa"]);
    }

    #[test]
    fn confirmation_math() {
        assert_eq!(confirmations(100, 100), 1);
        assert_eq!(confirmations(90, 100), 11);
        assert_eq!(confirmations(101, 100), 1, "tip behind anchor saturates");
    }

    #[test]
    fn address_balance_splits_confirmed_and_pending() {
        let state = AddressWatchState {
            utxos: vec![
                crate::wallet::AddressUtxo {
                    txid: "aa".into(),
                    vout: 0,
                    value_sats: 1000,
                    height: Some(10),
                    timestamp: None,
                },
                crate::wallet::AddressUtxo {
                    txid: "bb".into(),
                    vout: 1,
                    value_sats: 500,
                    height: None,
                    timestamp: None,
                },
            ],
            ..Default::default()
        };
        let balance = address_balance(&state);
        assert_eq!(balance.confirmed, 1000);
        assert_eq!(balance.untrusted_pending, 500);
        assert_eq!(balance.total, 1500);
    }
}
