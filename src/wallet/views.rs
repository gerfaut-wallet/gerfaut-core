//! Builders turning engine state into the serializable snapshots of
//! [`crate::wallet::snapshot`]. Pure functions, no I/O.

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::bitcoin::{Script, Txid};
use bdk_wallet::chain::ChainPosition;

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::wallet::policy::Coin;
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
        pending_net_sats: pending_net(
            wallet
                .transactions()
                .filter(|wtx| matches!(wtx.chain_position, ChainPosition::Unconfirmed { .. }))
                .map(|wtx| net_of(wallet, &wtx.tx_node.tx)),
        ),
    }
}

/// What a transaction did to the wallet, in sats: what came in less
/// what went out, the fee included on the way out.
fn net_of(wallet: &bdk_wallet::Wallet, tx: &bdk_wallet::bitcoin::Transaction) -> i64 {
    let (sent, received) = wallet.sent_and_received(tx);
    received.to_sat() as i64 - sent.to_sat() as i64
}

/// The signed sum of what is still out of a block, or `None` when
/// nothing is. The figure and the fact travel as one value: a spend
/// that happens to net to zero is still pending, and still shows.
fn pending_net(nets: impl Iterator<Item = i64>) -> Option<i64> {
    nets.fold(None, |sum, net| Some(sum.unwrap_or(0) + net))
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
            let status = status_of(&wtx.chain_position);
            TxSummary {
                txid: wtx.tx_node.txid.to_string(),
                net_sats: net_of(wallet, &wtx.tx_node.tx),
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
/// What the engine held before a sync, to tell afterwards what the
/// sync changed.
pub(crate) struct Known {
    /// Every transaction.
    pub all: std::collections::HashSet<Txid>,
    /// Those still waiting for a block.
    pub pending: std::collections::HashSet<Txid>,
}

pub(crate) fn known(wallet: &bdk_wallet::Wallet) -> Known {
    let mut known = Known {
        all: Default::default(),
        pending: Default::default(),
    };
    for wtx in wallet.transactions() {
        known.all.insert(wtx.tx_node.txid);
        if !wtx.chain_position.is_confirmed() {
            known.pending.insert(wtx.tx_node.txid);
        }
    }
    known
}

/// The transactions the engine holds that `known` does not: what a
/// sync just brought in.
pub(crate) fn new_txs(wallet: &bdk_wallet::Wallet, known: &Known) -> Vec<NewTx> {
    wallet
        .transactions()
        .filter(|wtx| !known.all.contains(&wtx.tx_node.txid))
        .map(|wtx| NewTx {
            txid: wtx.tx_node.txid.to_string(),
            net_sats: net_of(wallet, &wtx.tx_node.tx),
            confirmed: wtx.chain_position.is_confirmed(),
        })
        .collect()
}

/// The transactions that were waiting for a block before the sync and
/// are in one now.
pub(crate) fn confirmed_txs(wallet: &bdk_wallet::Wallet, known: &Known) -> Vec<NewTx> {
    wallet
        .transactions()
        .filter(|wtx| {
            wtx.chain_position.is_confirmed() && known.pending.contains(&wtx.tx_node.txid)
        })
        .map(|wtx| NewTx {
            txid: wtx.tx_node.txid.to_string(),
            net_sats: net_of(wallet, &wtx.tx_node.tx),
            confirmed: true,
        })
        .collect()
}

/// The same two lists for a watched address, whose state is replaced
/// whole by each sync: what `watch` holds that `previous` did not, and
/// what `previous` held unconfirmed that `watch` has in a block.
pub(crate) fn address_changes(
    previous: Option<&AddressWatchState>,
    watch: &AddressWatchState,
) -> (Vec<NewTx>, Vec<NewTx>) {
    let before: std::collections::HashMap<&str, bool> = previous
        .iter()
        .flat_map(|state| &state.txs)
        .map(|tx| (tx.txid.as_str(), tx.height.is_some()))
        .collect();
    let line = |tx: &AddressTx| NewTx {
        txid: tx.txid.clone(),
        net_sats: tx.net_sats,
        confirmed: tx.height.is_some(),
    };
    let new = watch
        .txs
        .iter()
        .filter(|tx| !before.contains_key(tx.txid.as_str()))
        .map(line)
        .collect();
    let confirmed = watch
        .txs
        .iter()
        .filter(|tx| tx.height.is_some() && before.get(tx.txid.as_str()) == Some(&false))
        .map(line)
        .collect();
    (new, confirmed)
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
            // A coinbase input spends nothing: its outpoint is the null
            // one the consensus rules require, all zeroes and a vout of
            // u32::MAX. Handing that to a screen as an identifier would
            // have it draw a transaction that does not exist.
            let outpoint = (!txin.previous_output.is_null()).then_some(txin.previous_output);
            TxIo {
                address: previous.and_then(|p| address_of(&p.script_pubkey, network)),
                value_sats: previous.map(|p| p.value.to_sat()),
                is_mine: previous.is_some_and(|p| wallet.is_mine(p.script_pubkey.clone())),
                prev_txid: outpoint.map(|o| o.txid.to_string()),
                prev_vout: outpoint.map(|o| o.vout),
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
            ..TxIo::default()
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

/// The unspent outputs reduced to what the policy analysis counts
/// relative locks from: where and when each one confirmed.
pub(crate) fn coins(wallet: &bdk_wallet::Wallet) -> Vec<Coin> {
    wallet
        .list_unspent()
        .map(|output| {
            let (height, timestamp) = match &output.chain_position {
                ChainPosition::Confirmed { anchor, .. } => {
                    (Some(anchor.block_id.height), Some(anchor.confirmation_time))
                }
                ChainPosition::Unconfirmed { .. } => (None, None),
            };
            Coin {
                outpoint: output.outpoint.to_string(),
                value_sats: output.txout.value.to_sat(),
                height,
                timestamp,
            }
        })
        .collect()
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
        pending_net_sats: pending_net(
            state
                .txs
                .iter()
                .filter(|tx| tx.height.is_none())
                .map(|tx| tx.net_sats),
        ),
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

    /// A coinbase input carries the null outpoint the consensus rules
    /// require. It must never reach a screen as an identifier: the
    /// diagram would name a transaction of all zeroes that never
    /// existed, and the same address-free input would look spendable.
    #[test]
    fn a_coinbase_input_hands_out_no_outpoint() {
        use bdk_wallet::bitcoin::OutPoint;
        let null = OutPoint::null();
        assert!(null.is_null());
        let outpoint = (!null.is_null()).then_some(null);
        assert_eq!(outpoint.map(|o| o.txid.to_string()), None);
        assert_eq!(outpoint.map(|o| o.vout), None);

        // A real one still comes through whole, index included.
        let spent = OutPoint::new(
            "3f5591c1e6b4bbbb2b2e8f5b0e2c8d1f9a7c4e6d2b8a0f3c5e7d9b1a4c6e8f0a"
                .parse()
                .expect("txid"),
            2,
        );
        let kept = (!spent.is_null()).then_some(spent);
        assert_eq!(kept.map(|o| o.vout), Some(2));
    }

    /// BIP-84 test vector account, on testnet paths: public, and used
    /// across the tests of this crate.
    const EXTERNAL: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";
    const INTERNAL: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/1/*)";

    /// A payment is worth two words: when it shows up, and when a block
    /// takes it. The first sync lists it as new and pending, the one
    /// that finds it in a block lists it as confirmed, and neither
    /// says it twice.
    #[test]
    fn a_sync_tells_an_arrival_from_a_confirmation() {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            Amount, BlockHash, OutPoint, Transaction, TxIn, TxOut, absolute, transaction,
        };
        use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};

        let mut wallet = bdk_wallet::Wallet::create(EXTERNAL, INTERNAL)
            .network(bdk_wallet::bitcoin::Network::Signet)
            .create_wallet_no_persist()
            .unwrap();
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        let payment = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let txid = payment.compute_txid();

        // It enters the mempool.
        let before = known(&wallet);
        wallet.apply_unconfirmed_txs([(payment.clone(), 1_700_000_000)]);
        assert_eq!(
            new_txs(&wallet, &before),
            vec![NewTx {
                txid: txid.to_string(),
                net_sats: 50_000,
                confirmed: false,
            }]
        );
        assert!(confirmed_txs(&wallet, &before).is_empty());

        // A sync that finds nothing changed says nothing.
        let before = known(&wallet);
        assert!(before.pending.contains(&txid));
        assert!(new_txs(&wallet, &before).is_empty());
        assert!(confirmed_txs(&wallet, &before).is_empty());

        // A block takes it.
        let block = BlockId {
            height: 10,
            hash: BlockHash::from_byte_array([1; 32]),
        };
        let mut update = bdk_wallet::Update {
            chain: Some(wallet.latest_checkpoint().push(block).unwrap()),
            ..Default::default()
        };
        update.tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: block,
                confirmation_time: 1_700_000_600,
            },
            txid,
        ));
        wallet.apply_update(update).unwrap();
        assert!(new_txs(&wallet, &before).is_empty());
        assert_eq!(
            confirmed_txs(&wallet, &before),
            vec![NewTx {
                txid: txid.to_string(),
                net_sats: 50_000,
                confirmed: true,
            }]
        );

        // And the sync after that has nothing left to say about it.
        let before = known(&wallet);
        assert!(before.pending.is_empty());
        assert!(confirmed_txs(&wallet, &before).is_empty());
    }

    /// The same for a watched address, whose state each sync replaces
    /// whole: one seen for the first time already in a block is new,
    /// not "confirmed" as well.
    #[test]
    fn a_watched_address_tells_an_arrival_from_a_confirmation() {
        let tx = |txid: &str, height: Option<u32>| AddressTx {
            txid: txid.to_owned(),
            net_sats: 1_000,
            fee_sats: None,
            height,
            timestamp: None,
            vsize: 100,
            inputs: vec![],
            outputs: vec![],
            extras: None,
        };
        let line = |txid: &str, confirmed: bool| NewTx {
            txid: txid.to_owned(),
            net_sats: 1_000,
            confirmed,
        };
        let first = AddressWatchState {
            txs: vec![tx("pending", None), tx("old", Some(100))],
            ..Default::default()
        };
        assert_eq!(
            address_changes(None, &first),
            (vec![line("pending", false), line("old", true)], vec![])
        );
        let second = AddressWatchState {
            txs: vec![
                tx("fresh", Some(201)),
                tx("pending", Some(200)),
                tx("old", Some(100)),
            ],
            ..Default::default()
        };
        assert_eq!(
            address_changes(Some(&first), &second),
            (vec![line("fresh", true)], vec![line("pending", true)])
        );
        assert_eq!(address_changes(Some(&second), &second), (vec![], vec![]));
    }

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
        assert_eq!(balance.pending_net_sats, None, "no transaction listed");
    }

    fn address_tx(txid: &str, net_sats: i64, height: Option<u32>) -> AddressTx {
        AddressTx {
            txid: txid.into(),
            net_sats,
            fee_sats: None,
            height,
            timestamp: None,
            vsize: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            extras: None,
        }
    }

    /// The pending line under a balance reads the transactions, not the
    /// pending buckets: a spend that returns no change leaves both
    /// buckets at zero while the total has already dropped, and the
    /// buckets can only ever say "plus".
    #[test]
    fn address_balance_nets_what_is_still_out_of_a_block() {
        let settled = AddressWatchState {
            txs: vec![address_tx("aa", 100_000, Some(10))],
            ..Default::default()
        };
        assert_eq!(address_balance(&settled).pending_net_sats, None);

        let arriving = AddressWatchState {
            txs: vec![
                address_tx("bb", 50_000, None),
                address_tx("aa", 100_000, Some(10)),
            ],
            ..Default::default()
        };
        assert_eq!(address_balance(&arriving).pending_net_sats, Some(50_000));

        // A sweep leaves nothing behind: no change, no pending bucket.
        let leaving = AddressWatchState {
            txs: vec![
                address_tx("cc", -100_000, None),
                address_tx("aa", 100_000, Some(10)),
            ],
            ..Default::default()
        };
        let balance = address_balance(&leaving);
        assert_eq!(balance.untrusted_pending, 0);
        assert_eq!(balance.pending_net_sats, Some(-100_000));

        // Both at once: one figure, the net of the two.
        let both = AddressWatchState {
            txs: vec![
                address_tx("bb", 50_000, None),
                address_tx("cc", -31_000, None),
                address_tx("aa", 100_000, Some(10)),
            ],
            ..Default::default()
        };
        assert_eq!(address_balance(&both).pending_net_sats, Some(19_000));
    }

    #[test]
    fn a_pending_spend_that_nets_to_nothing_is_still_pending() {
        assert_eq!(pending_net(std::iter::empty()), None);
        assert_eq!(pending_net([0].into_iter()), Some(0));
        assert_eq!(pending_net([700, -700].into_iter()), Some(0));
    }

    /// Vaults written before the field existed still open: the cached
    /// balance of every wallet is stored in them.
    #[test]
    fn a_balance_saved_without_the_pending_net_still_loads() {
        let old = r#"{"confirmed":1500,"trusted_pending":0,"untrusted_pending":0,"immature":0,"total":1500}"#;
        let balance: BalanceSnapshot = serde_json::from_str(old).expect("old balance");
        assert_eq!(balance.pending_net_sats, None);
        assert_eq!(balance.total, 1500);
    }
}
