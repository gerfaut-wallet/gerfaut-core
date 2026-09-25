//! Builders turning engine state into the serializable snapshots of
//! [`crate::wallet::snapshot`]. Pure functions, no I/O.

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::bitcoin::{Script, Txid};
use bdk_wallet::chain::ChainPosition;

use crate::error::{CoreError, CoreResult};
use crate::live::news::{Moves, Seen};
use crate::network::Network;
use crate::wallet::policy::Coin;
use crate::wallet::snapshot::{
    AddressEntry, AddressList, AddressRow, BalanceSnapshot, Keychain, TxDetail, TxIo, TxStatus,
    TxSummary, UtxoInfo,
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
    nets.fold(None, |sum, net| Some(sum.unwrap_or(0).saturating_add(net)))
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

/// What the engine held before a sync, to tell afterwards what the
/// sync changed.
pub(crate) struct Known {
    /// Every transaction.
    pub all: std::collections::HashSet<Txid>,
    /// Those still waiting for a block, as they were then.
    pub pending: std::collections::HashMap<Txid, Seen>,
}

/// A transaction of the engine as a sync sees it.
fn seen_of(
    wallet: &bdk_wallet::Wallet,
    tx: &bdk_wallet::bitcoin::Transaction,
    confirmed: bool,
) -> Seen {
    Seen {
        txid: tx.compute_txid().to_string(),
        net_sats: net_of(wallet, tx),
        confirmed,
        spends: tx
            .input
            .iter()
            .map(|input| {
                (
                    input.previous_output.txid.to_string(),
                    input.previous_output.vout,
                )
            })
            .collect(),
    }
}

pub(crate) fn known(wallet: &bdk_wallet::Wallet) -> Known {
    let mut known = Known {
        all: Default::default(),
        pending: Default::default(),
    };
    for wtx in wallet.transactions() {
        known.all.insert(wtx.tx_node.txid);
        if !wtx.chain_position.is_confirmed() {
            known
                .pending
                .insert(wtx.tx_node.txid, seen_of(wallet, &wtx.tx_node.tx, false));
        }
    }
    known
}

/// The scripts worth watching live for a descriptor wallet, the ones
/// most likely to move first, since a transport may only cover the
/// head of the list: the unused receive addresses, the scripts holding
/// coins (a spend shows there first), the receive addresses within the
/// gap limit past the last revealed one, the change addresses the same
/// way, and then the used, empty ones, newest first. A script past the
/// revealed range is marked as such. Each comes with the Electrum
/// status of the history the wallet holds for it, as
/// [`electrum_statuses`] computes it.
///
/// The list stops at [`crate::watch::MAX_SCRIPTS_PER_WALLET`], all a
/// watch takes of one wallet, and nothing past it is derived: this runs
/// under the lock of the vault after every sync, and a wallet a server
/// had reveal a hundred thousand addresses would otherwise hold it for
/// as many derivations each time.
pub(crate) fn watch_scripts(
    wallet: &bdk_wallet::Wallet,
    gap_limit: u32,
    orders: &HistoryOrders,
) -> Vec<crate::watch::WatchedScript> {
    let mut seen = std::collections::HashSet::new();
    let mut listed: Vec<(bdk_wallet::bitcoin::ScriptBuf, bool)> = Vec::new();
    // True once the list is full.
    let mut push = |script: bdk_wallet::bitcoin::ScriptBuf, lookahead: bool| {
        if seen.insert(script.clone()) {
            listed.push((script, lookahead));
        }
        listed.len() >= crate::watch::MAX_SCRIPTS_PER_WALLET
    };
    let keychains: Vec<KeychainKind> = wallet.keychains().map(|(keychain, _)| keychain).collect();
    let ahead = |keychain: KeychainKind| {
        let next = wallet
            .derivation_index(keychain)
            .map_or(0, |last| last.saturating_add(1));
        (next..next.saturating_add(gap_limit))
            .map(move |index| wallet.peek_address(keychain, index).script_pubkey())
    };
    'full: {
        for info in wallet.list_unused_addresses(KeychainKind::External) {
            if push(info.script_pubkey(), false) {
                break 'full;
            }
        }
        for coin in wallet.list_unspent() {
            if push(coin.txout.script_pubkey, false) {
                break 'full;
            }
        }
        for script in ahead(KeychainKind::External) {
            if push(script, true) {
                break 'full;
            }
        }
        if keychains.contains(&KeychainKind::Internal) {
            for info in wallet.list_unused_addresses(KeychainKind::Internal) {
                if push(info.script_pubkey(), false) {
                    break 'full;
                }
            }
            for script in ahead(KeychainKind::Internal) {
                if push(script, true) {
                    break 'full;
                }
            }
        }
        for keychain in keychains {
            let Some(last) = wallet.derivation_index(keychain) else {
                continue;
            };
            for index in (0..=last).rev() {
                if push(wallet.peek_address(keychain, index).script_pubkey(), false) {
                    break 'full;
                }
            }
        }
    }
    let scripts: Vec<bdk_wallet::bitcoin::ScriptBuf> =
        listed.iter().map(|(script, _)| script.clone()).collect();
    let statuses = electrum_statuses(wallet, &scripts, orders);
    listed
        .into_iter()
        .zip(statuses)
        .map(
            |((script, lookahead), status)| crate::watch::WatchedScript {
                script: script.to_hex_string(),
                lookahead,
                status,
            },
        )
        .collect()
}

/// The order an Electrum server listed the history of each script in,
/// the last time a sync read it there: txids and heights, 0 or -1 for
/// the mempool.
pub(crate) type HistoryOrders =
    std::collections::HashMap<bdk_wallet::bitcoin::ScriptBuf, Vec<(Txid, i32)>>;

/// The Electrum status of the history a watched address holds, the
/// same way: its transactions by height and txid, then the mempool.
pub(crate) fn address_status(state: &AddressWatchState) -> Option<String> {
    let mut history: Vec<(&str, i64)> = state
        .txs
        .iter()
        .map(|tx| (tx.txid.as_str(), tx.height.map_or(0, i64::from)))
        .collect();
    if history.is_empty() {
        return None;
    }
    history.sort_by_key(|(txid, height)| (*height <= 0, *height, *txid));
    Some(electrum_status(
        history
            .iter()
            .map(|(txid, height)| format!("{txid}:{height}:")),
    ))
}

/// The SHA-256 of the parts of a status, in hex.
fn electrum_status(parts: impl Iterator<Item = String>) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, HashEngine, sha256};
    let mut engine = sha256::Hash::engine();
    for part in parts {
        engine.input(part.as_bytes());
    }
    let digest = sha256::Hash::from_engine(engine).to_byte_array();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The Electrum status of the history the wallet holds for each script,
/// `None` for one it holds nothing for: the SHA-256 of `txid:height:`
/// for each transaction, in the order the server lists them.
///
/// That order is the server's: confirmed transactions by height, then
/// by their place in the block, which the wallet does not know, then
/// the mempool. When a sync read the script from an Electrum server and
/// the wallet holds the same transactions it listed, its order is used;
/// otherwise the transactions of one block are taken by txid, and a
/// script with two in one block may get a status no server gives. That
/// costs a sync of the script when a watch starts, and nothing else.
pub(crate) fn electrum_statuses(
    wallet: &bdk_wallet::Wallet,
    scripts: &[bdk_wallet::bitcoin::ScriptBuf],
    orders: &HistoryOrders,
) -> Vec<Option<String>> {
    let graph = wallet.tx_graph();
    let position: std::collections::HashMap<&Script, usize> = scripts
        .iter()
        .enumerate()
        .map(|(index, script)| (script.as_script(), index))
        .collect();
    let unconfirmed: std::collections::HashSet<Txid> = wallet
        .transactions()
        .filter(|wtx| !wtx.chain_position.is_confirmed())
        .map(|wtx| wtx.tx_node.txid)
        .collect();
    let mut histories: Vec<Vec<(Txid, i32)>> = vec![Vec::new(); scripts.len()];
    for wtx in wallet.transactions() {
        let tx = &wtx.tx_node.tx;
        let height = match wtx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                i32::try_from(anchor.block_id.height).unwrap_or(i32::MAX)
            }
            ChainPosition::Unconfirmed { .. } => {
                // -1 when it spends an output still in the mempool.
                if tx
                    .input
                    .iter()
                    .any(|input| unconfirmed.contains(&input.previous_output.txid))
                {
                    -1
                } else {
                    0
                }
            }
        };
        let mut touched = std::collections::BTreeSet::new();
        for output in &tx.output {
            if let Some(&index) = position.get(output.script_pubkey.as_script()) {
                touched.insert(index);
            }
        }
        for input in &tx.input {
            if let Some(previous) = graph.get_txout(input.previous_output)
                && let Some(&index) = position.get(previous.script_pubkey.as_script())
            {
                touched.insert(index);
            }
        }
        for index in touched {
            histories[index].push((wtx.tx_node.txid, height));
        }
    }
    // What a history holds, the order and the mempool heights aside.
    let content = |history: &[(Txid, i32)]| {
        let mut content: Vec<(Txid, i32)> = history
            .iter()
            .map(|(txid, height)| (*txid, (*height).max(0)))
            .collect();
        content.sort_unstable();
        content
    };
    scripts
        .iter()
        .zip(histories)
        .map(|(script, mut history)| {
            if history.is_empty() {
                return None;
            }
            let history = match orders.get(script) {
                Some(order) if content(order) == content(&history) => order.clone(),
                _ => {
                    history.sort_by_key(|(txid, height)| {
                        (*height <= 0, (*height).max(0), txid.to_string())
                    });
                    history
                }
            };
            Some(electrum_status(
                history
                    .iter()
                    .map(|(txid, height)| format!("{txid}:{height}:")),
            ))
        })
        .collect()
}

/// What the wallet already holds, handed to a sync so that it asks the
/// server only for what is missing, and what it holds for each of
/// `scripts`: the transactions touching it, which of them confirmed, and
/// the counters an Esplora server keeps for it.
pub(crate) fn held(
    wallet: &bdk_wallet::Wallet,
    scripts: &[bdk_wallet::bitcoin::ScriptBuf],
) -> crate::chain::Held {
    use crate::chain::{Held, ScriptFacts};
    let graph = wallet.tx_graph();
    let mut held = Held {
        txs: graph
            .full_txs()
            .map(|node| (node.txid, node.tx.clone()))
            .collect(),
        txouts: graph
            .floating_txouts()
            .map(|(outpoint, _)| outpoint)
            .collect(),
        ..Held::default()
    };
    let position: std::collections::HashMap<&Script, usize> = scripts
        .iter()
        .enumerate()
        .map(|(index, script)| (script.as_script(), index))
        .collect();
    let mut facts = vec![ScriptFacts::default(); scripts.len()];
    for wtx in wallet.transactions() {
        let txid = wtx.tx_node.txid;
        let confirmed = match wtx.chain_position {
            ChainPosition::Confirmed {
                anchor,
                transitively: None,
            } => {
                held.anchors.insert(txid, anchor);
                true
            }
            ChainPosition::Confirmed { .. } => true,
            ChainPosition::Unconfirmed { .. } => false,
        };
        // What the transaction does to each script it touches: coins
        // paid to it, and coins of it spent.
        let mut touched: std::collections::BTreeMap<usize, crate::chain::esplora::Tally> =
            Default::default();
        for output in &wtx.tx_node.tx.output {
            if let Some(&index) = position.get(output.script_pubkey.as_script()) {
                let tally = touched.entry(index).or_default();
                tally.funded += 1;
                tally.funded_sats = tally.funded_sats.saturating_add(output.value.to_sat());
            }
        }
        for input in &wtx.tx_node.tx.input {
            if let Some(previous) = graph.get_txout(input.previous_output)
                && let Some(&index) = position.get(previous.script_pubkey.as_script())
            {
                let tally = touched.entry(index).or_default();
                tally.spent += 1;
                tally.spent_sats = tally.spent_sats.saturating_add(previous.value.to_sat());
            }
        }
        for (index, tally) in touched {
            let facts = &mut facts[index];
            facts.expected.insert(txid);
            let side = if confirmed {
                facts.confirmed.insert(txid);
                &mut facts.counts.chain
            } else {
                &mut facts.counts.mempool
            };
            side.txs += 1;
            side.funded += tally.funded;
            side.funded_sats = side.funded_sats.saturating_add(tally.funded_sats);
            side.spent += tally.spent;
            side.spent_sats = side.spent_sats.saturating_add(tally.spent_sats);
        }
    }
    held.scripts = scripts.iter().cloned().zip(facts).collect();
    held
}

/// Whether the wallet holds a transaction still waiting for a block.
pub(crate) fn has_pending(wallet: &bdk_wallet::Wallet) -> bool {
    wallet
        .transactions()
        .any(|wtx| !wtx.chain_position.is_confirmed())
}

/// What a sync of a descriptor wallet moved, against what the engine
/// held before it: the transactions it brought in, the ones it saw
/// confirm, and the pending ones the wallet no longer holds, replaced
/// by a conflicting transaction or evicted from the mempool.
pub(crate) fn moves(wallet: &bdk_wallet::Wallet, known: &Known) -> Moves {
    let mut moves = Moves {
        pending_before: known.pending.values().cloned().collect(),
        ..Moves::default()
    };
    let mut held = std::collections::HashSet::new();
    for wtx in wallet.transactions() {
        let txid = wtx.tx_node.txid;
        held.insert(txid);
        let confirmed = wtx.chain_position.is_confirmed();
        if !known.all.contains(&txid) {
            moves.new.push(seen_of(wallet, &wtx.tx_node.tx, confirmed));
        } else if confirmed && known.pending.contains_key(&txid) {
            moves.confirmed.push(seen_of(wallet, &wtx.tx_node.tx, true));
        }
    }
    moves.gone = known
        .pending
        .iter()
        .filter(|(txid, _)| !held.contains(*txid))
        .map(|(_, seen)| seen.clone())
        .collect();
    moves
}

/// A transaction of a watched address as a sync sees it.
fn address_seen(tx: &AddressTx) -> Seen {
    Seen {
        txid: tx.txid.clone(),
        net_sats: tx.net_sats,
        confirmed: tx.height.is_some(),
        spends: tx
            .inputs
            .iter()
            .filter_map(|input| Some((input.prev_txid.clone()?, input.prev_vout?)))
            .collect(),
    }
}

/// The same for a watched address, whose state is replaced whole by
/// each sync: what `watch` holds that `previous` did not, what
/// `previous` held unconfirmed that `watch` has in a block, and what
/// `previous` held unconfirmed that `watch` does not hold at all.
pub(crate) fn address_moves(
    previous: Option<&AddressWatchState>,
    watch: &AddressWatchState,
) -> Moves {
    let before: std::collections::HashMap<&str, bool> = previous
        .iter()
        .flat_map(|state| &state.txs)
        .map(|tx| (tx.txid.as_str(), tx.height.is_some()))
        .collect();
    let now: std::collections::HashSet<&str> =
        watch.txs.iter().map(|tx| tx.txid.as_str()).collect();
    let pending_before: Vec<&AddressTx> = previous
        .iter()
        .flat_map(|state| &state.txs)
        .filter(|tx| tx.height.is_none())
        .collect();
    // A sync reads at most a page of unconfirmed transactions. When it
    // came back full, one missing from it may only have been pushed
    // off the page, by anyone who sends the address enough dust: that
    // is no sign it left the mempool, and nothing is said gone.
    let page_full = watch.txs.iter().filter(|tx| tx.height.is_none()).count()
        >= crate::chain::electrum::address::MEMPOOL_PER_ROUND;
    Moves {
        new: watch
            .txs
            .iter()
            .filter(|tx| !before.contains_key(tx.txid.as_str()))
            .map(address_seen)
            .collect(),
        confirmed: watch
            .txs
            .iter()
            .filter(|tx| tx.height.is_some() && before.get(tx.txid.as_str()) == Some(&false))
            .map(address_seen)
            .collect(),
        gone: pending_before
            .iter()
            .filter(|tx| !page_full && !now.contains(tx.txid.as_str()))
            .map(|tx| address_seen(tx))
            .collect(),
        pending_before: pending_before.into_iter().map(address_seen).collect(),
    }
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

/// Most upcoming addresses handed out at once, past the next unused
/// one: the count comes from the app, and derivation is not free.
const MAX_LOOKAHEAD: u32 = 200;

/// Highest index a non-hardened derivation step can take.
const MAX_INDEX: u32 = (1 << 31) - 1;

/// The next unused receive address plus up to `lookahead` upcoming
/// unused ones, 200 at most.
///
/// An upcoming address that already received a payment, one a sync
/// found past addresses nobody paid, is skipped rather than offered
/// again. A descriptor with no wildcard has one address, given once.
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
    if !wallet
        .public_descriptor(KeychainKind::External)
        .has_wildcard()
    {
        return entries;
    }
    let wanted = lookahead.min(MAX_LOOKAHEAD) as usize + 1;
    let mut index = next.index;
    while entries.len() < wanted && index < MAX_INDEX {
        index += 1;
        // Only a script the index holds can have been paid; one past it
        // reads as "used" to the index, and is not.
        let index_holds = wallet
            .spk_index()
            .spk_at_index(KeychainKind::External, index)
            .is_some();
        if index_holds && wallet.spk_index().is_used(KeychainKind::External, index) {
            continue;
        }
        let peeked = wallet.peek_address(KeychainKind::External, index);
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
    // The coins are the server's word. Summed with a plain `+`, values
    // no coin can hold panicked a debug build and wrapped around to a
    // small balance in a release one.
    let funded = |confirmed: bool| {
        state
            .utxos
            .iter()
            .filter(|u| u.height.is_some() == confirmed)
            .fold(0u64, |sum, u| sum.saturating_add(u.value_sats))
    };
    let confirmed_funded = funded(true);
    let pending_funded = funded(false);
    BalanceSnapshot {
        confirmed: confirmed_funded,
        trusted_pending: 0,
        untrusted_pending: pending_funded,
        immature: 0,
        total: confirmed_funded.saturating_add(pending_funded),
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
    use crate::wallet::snapshot::NewTx;

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

    /// Upcoming addresses skip one a payment already reached, stop at
    /// the cap whatever the app asks, and a descriptor without a
    /// wildcard hands out its one address once.
    #[test]
    fn upcoming_receive_addresses_are_unused_bounded_and_distinct() {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            Amount, OutPoint, Transaction, TxIn, TxOut, absolute, transaction,
        };

        let mut wallet = bdk_wallet::Wallet::create(EXTERNAL, INTERNAL)
            .network(bdk_wallet::bitcoin::Network::Signet)
            .create_wallet_no_persist()
            .unwrap();
        // Index 2 is paid while 0 and 1 stay empty: another app handed
        // it out.
        let paid = wallet.peek_address(KeychainKind::External, 2).address;
        let payment = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: paid.script_pubkey(),
            }],
        };
        wallet.apply_unconfirmed_txs([(payment, 1_700_000_000)]);

        let entries = receive_addresses(&mut wallet, 3);
        let indexes: Vec<u32> = entries.iter().map(|e| e.index).collect();
        assert_eq!(indexes, [0, 1, 3, 4]);
        assert!(entries.iter().all(|e| e.address != paid.to_string()));

        assert_eq!(
            receive_addresses(&mut wallet, u32::MAX).len(),
            MAX_LOOKAHEAD as usize + 1
        );

        let mut single = bdk_wallet::Wallet::create_single(
            "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/0)",
        )
        .network(bdk_wallet::bitcoin::Network::Signet)
        .create_wallet_no_persist()
        .unwrap();
        assert_eq!(receive_addresses(&mut single, 5).len(), 1);
    }

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
            moves(&wallet, &before).lines(),
            (
                vec![NewTx {
                    txid: txid.to_string(),
                    net_sats: 50_000,
                    confirmed: false,
                }],
                vec![]
            )
        );

        // A sync that finds nothing changed says nothing.
        let before = known(&wallet);
        assert!(before.pending.contains_key(&txid));
        assert_eq!(moves(&wallet, &before).lines(), (vec![], vec![]));

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
        assert_eq!(
            moves(&wallet, &before).lines(),
            (
                vec![],
                vec![NewTx {
                    txid: txid.to_string(),
                    net_sats: 50_000,
                    confirmed: true,
                }]
            )
        );
        assert!(moves(&wallet, &before).gone.is_empty());

        // And the sync after that has nothing left to say about it.
        let before = known(&wallet);
        assert!(before.pending.is_empty());
        assert_eq!(moves(&wallet, &before).lines(), (vec![], vec![]));
    }

    /// A wallet that revealed far more addresses than a watch takes of
    /// one wallet lists what the watch takes, the head first, and stops
    /// there.
    #[test]
    fn a_long_wallet_lists_what_a_watch_takes_and_no_more() {
        let mut wallet = bdk_wallet::Wallet::create(EXTERNAL, INTERNAL)
            .network(bdk_wallet::bitcoin::Network::Signet)
            .create_wallet_no_persist()
            .unwrap();
        let _ = wallet
            .reveal_addresses_to(KeychainKind::External, 1_000)
            .count();
        let scripts = watch_scripts(&wallet, 20, &HistoryOrders::new());
        assert_eq!(scripts.len(), crate::watch::MAX_SCRIPTS_PER_WALLET);
        assert_eq!(
            scripts[0].script,
            wallet
                .peek_address(KeychainKind::External, 0)
                .script_pubkey()
                .to_hex_string()
        );
        assert!(scripts.iter().all(|script| !script.lookahead));
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
            address_moves(None, &first).lines(),
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
            address_moves(Some(&first), &second).lines(),
            (vec![line("fresh", true)], vec![line("pending", true)])
        );
        assert!(address_moves(Some(&first), &second).gone.is_empty());
        assert_eq!(
            address_moves(Some(&second), &second).lines(),
            (vec![], vec![])
        );
        // A pending one the next state does not hold is gone.
        let third = AddressWatchState {
            txs: vec![tx("old", Some(100))],
            ..Default::default()
        };
        let moves = address_moves(Some(&first), &third);
        assert_eq!(moves.gone.len(), 1);
        assert_eq!(moves.gone[0].txid, "pending");
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

    /// Coins no one can hold, as a hostile server may list them, stop
    /// at the largest balance there is instead of panicking or wrapping
    /// around to a small one.
    #[test]
    fn address_balance_never_overflows() {
        let coin = |txid: &str, height: Option<u32>| crate::wallet::AddressUtxo {
            txid: txid.into(),
            vout: 0,
            value_sats: u64::MAX,
            height,
            timestamp: None,
        };
        let state = AddressWatchState {
            utxos: vec![coin("aa", Some(1)), coin("bb", Some(2)), coin("cc", None)],
            txs: vec![
                address_tx("dd", i64::MAX, None),
                address_tx("ee", i64::MAX, None),
            ],
            ..Default::default()
        };
        let balance = address_balance(&state);
        assert_eq!(balance.confirmed, u64::MAX);
        assert_eq!(balance.total, u64::MAX);
        assert_eq!(balance.pending_net_sats, Some(i64::MAX));
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

    /// A payment pushed off a full page of unconfirmed transactions,
    /// by dust anyone can send, is not said gone: only one missing from
    /// a page with room left is.
    #[test]
    fn a_full_page_of_pending_transactions_says_nothing_gone() {
        let first = AddressWatchState {
            txs: vec![address_tx("paid", 50_000, None)],
            ..Default::default()
        };
        let dust = |count: usize| AddressWatchState {
            txs: (0..count)
                .map(|n| address_tx(&format!("dust{n}"), 546, None))
                .collect(),
            ..Default::default()
        };
        let full = crate::chain::electrum::address::MEMPOOL_PER_ROUND;
        assert!(address_moves(Some(&first), &dust(full)).gone.is_empty());
        let room = address_moves(Some(&first), &dust(full - 1));
        assert_eq!(room.gone.len(), 1);
        assert_eq!(room.gone[0].txid, "paid");
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
