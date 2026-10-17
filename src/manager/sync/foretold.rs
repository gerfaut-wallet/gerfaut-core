//! Confirmations the live watch foretold from a status and proved in
//! their block ([`crate::watch::Proven`]), taken without a sync.
//!
//! The watch has checked each merkle branch against the header the
//! server pushed. What is left to check needs the wallet: that the
//! header carries its chain on, from the block it holds at that height
//! or right after its tip, each with the work its network asks for, and
//! that it still holds what the confirmation was foretold from, the
//! history whose status, its waiting transactions at that height, is
//! the status the server pushed. Anything else, and the scripts are
//! synced instead: nothing is shown confirmed on a guess alone.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::time::Instant;

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::{Address, ScriptBuf, Txid};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};

use super::{Reach, SyncSlot, WalletManager, apply_address_state, apply_synced};
use crate::chain::{self, Endpoint, has_proof_of_work};
use crate::error::CoreResult;
use crate::manager::{ManagerState, ensure_engine, find_record};
use crate::network::Network;
use crate::wallet::meta::{WalletKind, WalletMeta};
use crate::wallet::snapshot::SyncReport;
use crate::wallet::views;
use crate::watch::{Headers, Proven, confirmed_at, history_status};

impl WalletManager {
    /// Takes the confirmations the live watch proved for a wallet, as a
    /// sync would have found them, under the wallet's turn to sync:
    /// what they confirm is recorded for whoever announces, and the
    /// watch is handed the wallet as it now stands. `None` when they
    /// cannot be taken as they are, and their scripts are to be synced.
    pub(crate) async fn take_confirmations(
        &self,
        id: &str,
        proven: &[Proven],
    ) -> CoreResult<Option<SyncReport>> {
        let slot = match self.syncing.lock() {
            Ok(mut slots) => slots.entry(id.to_owned()).or_default().clone(),
            Err(_) => SyncSlot::default(),
        };
        let turn = slot.lock().await;
        let started = Instant::now();
        let report = take(&mut *self.state.lock().await, id, proven, started)?;
        drop(turn);
        if report.is_some() {
            self.live_refresh().await;
        }
        Ok(report)
    }
}

/// What a sync would have recorded of `proven`, recorded: `None` when
/// the wallet cannot take them as they are.
fn take(
    state: &mut ManagerState,
    id: &str,
    proven: &[Proven],
    started: Instant,
) -> CoreResult<Option<SyncReport>> {
    let meta = find_record(&state.payload, id)?.meta.clone();
    let Some(server) = server_of(state, &meta, proven) else {
        return Ok(None);
    };
    let Some(top) = top_chain(meta.network, proven) else {
        return Ok(None);
    };
    match &meta.kind {
        WalletKind::Descriptors { .. } => {
            take_descriptor(state, &meta, proven, top, &server, started)
        }
        WalletKind::SingleAddress { address } => {
            take_address(state, &meta, address, proven, top, &server, started)
        }
    }
}

/// The server that proved them all, when a sync of the wallet may be
/// sent there: one its backend names on its network.
fn server_of(state: &ManagerState, meta: &WalletMeta, proven: &[Proven]) -> Option<Endpoint> {
    let server = &proven.first()?.server;
    if proven.iter().any(|proven| proven.server != *server) {
        return None;
    }
    let (config, certs) = state.chain_setup(meta.network);
    crate::watch::servers_for(&config, meta.network, &certs)
        .is_ok_and(|allowed| allowed.contains(server))
        .then(|| server.clone())
}

/// The headers that reach highest of all `proven`, when they follow one
/// another, each with the work `network` asks for, and hold the block of
/// every other one.
fn top_chain(network: Network, proven: &[Proven]) -> Option<&Headers> {
    let top = proven
        .iter()
        .map(|proven| proven.headers.as_ref())
        .max_by_key(|headers| headers.last_height())?;
    let chained = top
        .chain
        .windows(2)
        .all(|pair| pair[1].prev_blockhash == pair[0].block_hash());
    let worked = top
        .chain
        .iter()
        .all(|header| has_proof_of_work(network, header));
    let holds_all = proven.iter().all(|proven| {
        block_of(proven).is_some_and(|(height, header)| {
            top.at(height)
                .is_some_and(|held| held.block_hash() == header.block_hash())
        })
    });
    (chained && worked && holds_all && !top.chain.is_empty()).then_some(top)
}

/// The block a confirmation was proven in: its height and header.
fn block_of(proven: &Proven) -> Option<(u32, &Header)> {
    Some((proven.headers.last_height(), proven.headers.chain.last()?))
}

/// The txids of a history still waiting for a block.
fn waiting(history: &[(Txid, i32)]) -> BTreeSet<Txid> {
    history
        .iter()
        .filter(|(_, height)| *height <= 0)
        .map(|(txid, _)| *txid)
        .collect()
}

/// Whether `held` is what `proven` was foretold from: its waiting
/// transactions at the height of the block are the status the server
/// pushed, and they are the ones proven. The history it comes to.
fn foretells(held: &[(Txid, i32)], proven: &Proven) -> Option<Vec<(Txid, i32)>> {
    let (height, _) = block_of(proven)?;
    let guessed = confirmed_at(held, height)?;
    let proven_txids: BTreeSet<Txid> = proven.txids.iter().copied().collect();
    (history_status(&guessed) == proven.status && waiting(held) == proven_txids).then_some(guessed)
}

/// The wallet's chain, `tip`, carried on up to the last of `headers`:
/// from the block it holds at their height, or right after it. `None`
/// when they do not meet it there, or end below it.
fn carried(tip: &CheckPoint, headers: &Headers) -> Option<CheckPoint> {
    let top = headers.last_height();
    if tip.height() > top {
        return None;
    }
    let from = match headers.at(tip.height()) {
        Some(held) if held.block_hash() == tip.hash() => tip.height().checked_add(1)?,
        Some(_) => return None,
        None if headers.first == tip.height().checked_add(1)? => {
            if headers.chain.first()?.prev_blockhash != tip.hash() {
                return None;
            }
            headers.first
        }
        None => return None,
    };
    let above = (from..=top).filter_map(|height| {
        headers.at(height).map(|header| BlockId {
            height,
            hash: header.block_hash(),
        })
    });
    tip.clone().extend(above).ok()
}

/// A report of a wallet that took nothing: it held them already.
fn nothing_new(
    id: &str,
    balance: crate::wallet::snapshot::BalanceSnapshot,
    tip_height: u32,
    server: &Endpoint,
    started: Instant,
) -> SyncReport {
    SyncReport {
        wallet_id: id.to_owned(),
        new_tx_count: 0,
        new_txs: Vec::new(),
        confirmed_txs: Vec::new(),
        balance,
        tip_height,
        took_ms: started.elapsed().as_millis() as u64,
        backend: server.label(),
    }
}

fn take_descriptor(
    state: &mut ManagerState,
    meta: &WalletMeta,
    proven: &[Proven],
    top: &Headers,
    server: &Endpoint,
    started: Instant,
) -> CoreResult<Option<SyncReport>> {
    let orders = std::mem::take(&mut state.orders);
    let taken = ensure_engine(state, &meta.id).map(|engine| {
        let wanted = descriptor_update(engine, proven, top, &orders);
        (
            wanted,
            views::known(engine),
            views::balance(engine),
            views::tip_height(engine),
        )
    });
    state.orders = orders;
    let (wanted, known, balance, tip_height) = taken?;
    match wanted {
        None => Ok(None),
        Some(None) => Ok(Some(nothing_new(
            &meta.id, balance, tip_height, server, started,
        ))),
        Some(Some((synced, reach))) => {
            apply_synced(state, meta, synced, server, &reach, &known, started).map(Some)
        }
    }
}

/// The update `proven` makes of a descriptor wallet, and the scripts it
/// reads: `None` when the wallet cannot take them, `Some(None)` when it
/// holds them already.
#[allow(clippy::type_complexity)]
fn descriptor_update(
    engine: &bdk_wallet::Wallet,
    proven: &[Proven],
    top: &Headers,
    orders: &views::HistoryOrders,
) -> Option<Option<(chain::Synced, Reach)>> {
    let mut anchors = BTreeSet::new();
    let mut listed = Vec::new();
    let mut scripts = Vec::new();
    for proven in proven {
        let script = ScriptBuf::from_hex(&proven.script).ok()?;
        engine.spk_index().index_of_spk(script.clone())?;
        let held = views::electrum_histories(engine, std::slice::from_ref(&script), orders)
            .pop()
            .unwrap_or_default();
        if !held.is_empty() && history_status(&held) == proven.status {
            continue;
        }
        let guessed = foretells(&held, proven)?;
        let (height, header) = block_of(proven)?;
        let confirmation = ConfirmationBlockTime {
            block_id: BlockId {
                height,
                hash: header.block_hash(),
            },
            confirmation_time: u64::from(header.time),
        };
        anchors.extend(waiting(&held).into_iter().map(|txid| (confirmation, txid)));
        listed.push((script.clone(), guessed));
        scripts.push(script);
    }
    if scripts.is_empty() {
        return Some(None);
    }
    let mut chain = carried(&engine.latest_checkpoint(), top)?;
    for (anchor, _) in &anchors {
        let block = anchor.block_id;
        chain = match chain.get(block.height) {
            Some(held) if held.hash() == block.hash => chain,
            Some(_) => return None,
            None => chain.insert(block),
        };
    }
    let mut tx_update = TxUpdate::default();
    tx_update.anchors = anchors;
    let update = bdk_wallet::Update {
        last_active_indices: BTreeMap::new(),
        tx_update,
        chain: Some(chain),
    };
    let synced = chain::Synced {
        update,
        drop_above: None,
        orders: listed,
    };
    Some(Some((synced, Reach::Scripts(scripts))))
}

fn take_address(
    state: &mut ManagerState,
    meta: &WalletMeta,
    address: &str,
    proven: &[Proven],
    top: &Headers,
    server: &Endpoint,
    started: Instant,
) -> CoreResult<Option<SyncReport>> {
    let ours = Address::from_str(address)
        .ok()
        .and_then(|address| address.require_network(meta.network.to_bitcoin()).ok())
        .map(|address| address.script_pubkey().to_hex_string());
    let Some(watch) = find_record(&state.payload, &meta.id)?.address_state.clone() else {
        return Ok(None);
    };
    // One script, foretold once: two in a burst said the status moved
    // twice, and only a sync knows where it stands.
    let [proven] = proven else {
        return Ok(None);
    };
    if ours.as_deref() != Some(proven.script.as_str()) {
        return Ok(None);
    }
    if views::address_status(&watch).as_deref() == Some(proven.status.as_str()) {
        return Ok(Some(nothing_new(
            &meta.id,
            views::address_balance(&watch),
            watch.tip_height,
            server,
            started,
        )));
    }
    let held = views::address_history(&watch);
    let (Some(_), Some((height, header))) = (foretells(&held, proven), block_of(proven)) else {
        return Ok(None);
    };
    if height < watch.tip_height {
        return Ok(None);
    }
    let confirmed = waiting(&held);
    let taken_now = |txid: &str| {
        txid.parse::<Txid>()
            .is_ok_and(|txid| confirmed.contains(&txid))
    };
    let time = u64::from(header.time);
    let mut taken = watch;
    for tx in taken.txs.iter_mut().filter(|tx| taken_now(&tx.txid)) {
        tx.height = Some(height);
        tx.timestamp = Some(time);
    }
    for coin in taken
        .utxos
        .iter_mut()
        .filter(|coin| coin.height.is_none() && taken_now(&coin.txid))
    {
        coin.height = Some(height);
        coin.timestamp = Some(time);
    }
    taken.tip_height = taken.tip_height.max(top.last_height());
    apply_address_state(state, meta, taken, server, started, false).map(Some)
}
