//! Syncs: a wallet read against the backend of its network, one sync
//! of a wallet at a time, as far as the caller needs; every wallet of a
//! network in turn; and the older history of a watched address.

use std::collections::HashSet;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::chain::{self, Endpoint};
use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::now_secs;
use crate::wallet::meta::{CachedTotals, SyncStamp, WalletKind, WalletMeta};
use crate::wallet::snapshot::SyncReport;
use crate::wallet::views;
use crate::wallet::{AddressTx, AddressWatchState};

use super::{
    ManagerState, SyncSlot, WalletManager, drop_blocks_above, ensure_engine, find_record,
    find_record_mut, merge_changeset,
};

/// Outcome of syncing every wallet of a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAllReport {
    pub reports: Vec<SyncReport>,
    pub failures: Vec<SyncFailure>,
}

/// One wallet that failed to sync; the others are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFailure {
    pub wallet_id: String,
    pub message: String,
}

/// How long routine syncs may go on reading only the counters of the
/// scripts that did not move before one lists their unconfirmed
/// transactions again: a day. What the counters cannot tell is a
/// replacement paying the same amount to the same address.
const COMPLETE_EVERY_SECS: u64 = 24 * 60 * 60;

/// Whether a sync read every script of the wallet less than a day ago.
pub(crate) fn complete_lately(meta: &WalletMeta, now: u64) -> bool {
    meta.complete_at
        .is_some_and(|at| now.saturating_sub(at) < COMPLETE_EVERY_SECS)
}

/// How much of a descriptor wallet a sync reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reach {
    /// These scripts only: the ones the live watch saw move.
    Scripts(Vec<bdk_wallet::bitcoin::ScriptBuf>),
    /// The scripts of the transactions waiting for a block.
    Pending,
    /// Every revealed script, and the receive addresses past them; an
    /// Esplora server is asked for the history only of the scripts
    /// whose counters moved.
    Checked,
    /// The same, and the unconfirmed transactions of each script that
    /// has some listed whatever its counters say.
    Complete,
    /// Every script from the first one of each keychain, with the gap
    /// limit: a first sync, or a rescan.
    Full,
}

impl Reach {
    fn rank(&self) -> u8 {
        match self {
            Reach::Scripts(_) | Reach::Pending => 0,
            Reach::Checked => 1,
            Reach::Complete => 2,
            Reach::Full => 3,
        }
    }

    /// Whether a sync that read this far read everything `asked` would
    /// have.
    fn covers(&self, asked: &Reach) -> bool {
        match (self, asked) {
            (Reach::Scripts(read), Reach::Scripts(wanted)) => {
                wanted.iter().all(|script| read.contains(script))
            }
            (Reach::Scripts(_) | Reach::Pending, _) => false,
            (_, Reach::Scripts(_) | Reach::Pending) => true,
            _ => self.rank() >= asked.rank(),
        }
    }
}

/// The plan of a sync that reads `reach` of a wallet, and the reach it
/// comes to: scripts the wallet does not know, past what its index looks
/// ahead, are only found by a full scan, and a wallet waiting on no
/// block has nothing pending to read.
fn plan_for(engine: &bdk_wallet::Wallet, reach: &Reach, gap_limit: u32) -> (chain::Plan, Reach) {
    use bdk_wallet::KeychainKind;
    use bdk_wallet::chain::SpkIterator;
    let reach = match reach {
        Reach::Scripts(scripts)
            if scripts
                .iter()
                .any(|script| engine.spk_index().index_of_spk(script.clone()).is_none()) =>
        {
            Reach::Full
        }
        Reach::Pending => match views::pending_scripts(engine) {
            scripts if scripts.is_empty() => Reach::Checked,
            scripts => Reach::Scripts(scripts),
        },
        other => other.clone(),
    };
    let revealed = || -> Vec<bdk_wallet::bitcoin::ScriptBuf> {
        engine
            .spk_index()
            .revealed_spks(..)
            .map(|(_, script)| script)
            .collect()
    };
    let (scripts, scans, reading) = match &reach {
        Reach::Full => {
            let scans = engine
                .keychains()
                .map(|(keychain, descriptor)| chain::Scan {
                    keychain,
                    spks: Box::new(SpkIterator::new(descriptor.clone())),
                })
                .collect();
            (Vec::new(), scans, chain::Reading::Complete)
        }
        Reach::Scripts(scripts) => (scripts.clone(), Vec::new(), chain::Reading::Complete),
        Reach::Checked | Reach::Complete | Reach::Pending => {
            // The receive addresses past the last revealed one: where a
            // payment to an address the wallet never showed lands, one
            // another app or the signing device handed out.
            let next = engine
                .derivation_index(KeychainKind::External)
                .map_or(0, |last| last.saturating_add(1));
            let tail = chain::Scan {
                keychain: KeychainKind::External,
                spks: Box::new(SpkIterator::new_with_range(
                    engine.public_descriptor(KeychainKind::External).clone(),
                    next..,
                )),
            };
            let reading = if reach == Reach::Checked {
                chain::Reading::Checked
            } else {
                chain::Reading::Complete
            };
            (revealed(), vec![tail], reading)
        }
    };
    // What the wallet holds for every script it revealed, and for those
    // of the plan: a rescan reads the revealed ones the way a sync does,
    // down to what the wallet holds, and any sync reads a script outside
    // its plan whose confirmation a reorganisation moved.
    let held = {
        let mut all = revealed();
        let known: HashSet<&bdk_wallet::bitcoin::ScriptBuf> = all.iter().collect();
        let extra: Vec<bdk_wallet::bitcoin::ScriptBuf> = scripts
            .iter()
            .filter(|script| !known.contains(script))
            .cloned()
            .collect();
        all.extend(extra);
        views::held(engine, &all)
    };
    let plan = chain::Plan {
        network: Network::from_bitcoin(engine.network()),
        tip: engine.latest_checkpoint(),
        start_time: now_secs(),
        scripts,
        scans,
        stop_gap: gap_limit,
        reading,
        held,
    };
    (plan, reach)
}

impl WalletManager {
    /// Syncs one wallet against its network's backend. Public backends
    /// are tried in order until one answers.
    ///
    /// Every revealed script is looked at, and nothing the wallet holds
    /// is fetched again. An Electrum server is asked for the history of
    /// each script, a list of txids cheaper than any check. An Esplora
    /// server is asked for the counters of each script first, and for
    /// its history only when they moved; the first sync of a wallet
    /// since the vault was opened, and one a day after that, also lists
    /// the unconfirmed transactions of each script that has some, since
    /// a replacement paying the same amount leaves the counters as they
    /// were.
    pub async fn sync_wallet(&self, id: &str) -> CoreResult<SyncReport> {
        let reach = self.routine_reach(id).await;
        let (report, _) = self.sync_wallet_read(id, reach, None).await?;
        self.live_offer(&report);
        Ok(report)
    }

    /// Scans a wallet again from its first address with the current gap
    /// limit, whatever it already knows: an incremental sync only
    /// watches the addresses it revealed, so funds that landed past
    /// them, or a descriptor also used elsewhere, are only found by
    /// starting over. A watched address has no gap: this is a sync.
    pub async fn rescan_wallet(&self, id: &str) -> CoreResult<SyncReport> {
        let (report, _) = self.sync_wallet_read(id, Reach::Full, None).await?;
        self.live_offer(&report);
        Ok(report)
    }

    /// How far a sync the app asks for reads: see [`Self::sync_wallet`].
    async fn routine_reach(&self, id: &str) -> Reach {
        let done_here = self
            .complete_here
            .lock()
            .map(|done| done.contains(id))
            .unwrap_or(false);
        let state = self.state.lock().await;
        let recent = find_record(&state.payload, id)
            .is_ok_and(|record| complete_lately(&record.meta, now_secs()));
        if done_here && recent {
            Reach::Checked
        } else {
            Reach::Complete
        }
    }

    /// One sync of a wallet at a time, whoever asks: the app, a
    /// background job, the live watch. A caller that arrives while one
    /// runs waits for it, then runs its own: that sync may have read the
    /// wallet before what the caller came for happened, a payment the
    /// watch just heard of. Callers that wait together share the one
    /// sync that follows: each takes the result of a sync that started
    /// after it arrived and read at least as much as it would have, with
    /// nothing listed as new, the lists having gone to the caller that
    /// ran it. What that sync found worth announcing is in the vault for
    /// whoever claims it ([`Self::claim_announcements`]), so no caller
    /// can lose it.
    ///
    /// `prefer` is a server to try first: the one the live watch listens
    /// to, for a sync it asked for. Returns the report and the server
    /// that answered; none when the report is another caller's.
    pub(crate) async fn sync_wallet_read(
        &self,
        id: &str,
        reach: Reach,
        prefer: Option<(Network, Endpoint)>,
    ) -> CoreResult<(SyncReport, Option<Endpoint>)> {
        let arrived = Instant::now();
        let slot = match self.syncing.lock() {
            Ok(mut slots) => slots.entry(id.to_owned()).or_default().clone(),
            Err(_) => SyncSlot::default(),
        };
        let mut last = slot.lock().await;
        if let Some((started, report, read)) = last.as_ref()
            && *started > arrived
            && read.covers(&reach)
        {
            let report = SyncReport {
                new_tx_count: 0,
                new_txs: Vec::new(),
                confirmed_txs: Vec::new(),
                ..report.clone()
            };
            return Ok((report, None));
        }
        let started = Instant::now();
        let (report, read, answered) = self.sync_wallet_alone(id, reach, prefer).await?;
        *last = Some((started, report.clone(), read));
        drop(last);
        // The scripts this sync revealed, and whether something is
        // still waiting for a block.
        self.live_refresh().await;
        Ok((report, Some(answered)))
    }

    async fn sync_wallet_alone(
        &self,
        id: &str,
        reach: Reach,
        prefer: Option<(Network, Endpoint)>,
    ) -> CoreResult<(SyncReport, Reach, Endpoint)> {
        let started = Instant::now();

        // Snapshot what the sync needs; do not hold the lock during I/O.
        let (meta, config, certs) = {
            let state = self.state.lock().await;
            let record = find_record(&state.payload, id)?;
            let mut meta = record.meta.clone();
            // The effective gap limit is the global setting.
            meta.gap_limit = state.payload.settings.gap_limit;
            let (config, certs) = state.chain_setup(record.meta.network);
            (meta, config, certs)
        };
        let mut endpoints = chain::endpoints(&config, meta.network, &certs)?;
        // Try the backend that answered last time first: on networks
        // where one public instance is blocked, this skips a dead
        // 20-second timeout on every sync.
        if let Some(stamp) = &meta.last_sync
            && let Some(position) = endpoints
                .iter()
                .position(|endpoint| endpoint.label() == stamp.backend)
            && position > 0
        {
            let preferred = endpoints.remove(position);
            endpoints.insert(0, preferred);
        }
        // And before it, the server of the watch that asked for this
        // sync: it told of the change, so it holds what changed. Only a
        // server a watch of the wallet's own network may talk to under
        // its backend: the watch may have moved to another network, or
        // another backend, since the sync was asked for, and a wallet's
        // addresses never go to a server its backend does not name.
        if let Some((network, prefer)) = prefer
            && network == meta.network
            && crate::watch::servers_for(&config, meta.network, &certs)
                .is_ok_and(|allowed| allowed.contains(&prefer))
        {
            endpoints.retain(|endpoint| *endpoint != prefer);
            endpoints.insert(0, prefer);
        }
        let proxy = self.tor_proxy_for(&endpoints).await?;

        match &meta.kind {
            WalletKind::Descriptors { .. } => {
                self.sync_descriptor_wallet(&meta, &endpoints, proxy.as_deref(), started, reach)
                    .await
            }
            WalletKind::SingleAddress { address } => self
                .sync_address_wallet(&meta, address, &endpoints, proxy.as_deref(), started)
                .await
                .map(|(report, answered)| (report, Reach::Full, answered)),
        }
    }

    async fn sync_descriptor_wallet(
        &self,
        meta: &WalletMeta,
        endpoints: &[Endpoint],
        proxy: Option<&str>,
        started: Instant,
        reach: Reach,
    ) -> CoreResult<(SyncReport, Reach, Endpoint)> {
        // First sync, a gap limit raised since the last full scan, or a
        // rescan asked for: only a full scan looks past the addresses
        // already revealed.
        // And a day at most since a sync read every script: the syncs
        // the live watch asks for read only what moved, whoever asks.
        let reach = if meta.last_sync.is_none() || meta.scan_gap < meta.gap_limit {
            Reach::Full
        } else if reach.rank() < Reach::Complete.rank() && !complete_lately(meta, now_secs()) {
            Reach::Complete
        } else {
            reach
        };
        let mut attempts: Vec<String> = Vec::new();

        for endpoint in endpoints {
            // Build a fresh plan under the lock (a plan is consumed by
            // each attempt).
            let (plan, known, reach) = {
                let mut state = self.state.lock().await;
                let engine = ensure_engine(&mut state, &meta.id)?;
                let (plan, reach) = plan_for(engine, &reach, meta.gap_limit);
                (plan, views::known(engine), reach)
            };

            let response = chain::sync_engine(endpoint, plan, proxy).await;
            match response {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(synced) => {
                    let mut state = self.state.lock().await;
                    state.orders.extend(synced.orders);
                    let vanishing = crate::live::news::vanishing(&state.payload, &meta.id);
                    if let Some(height) = synced.drop_above {
                        drop_blocks_above(&mut state, &meta.id, height)?;
                    }
                    let engine = ensure_engine(&mut state, &meta.id)?;
                    engine
                        .apply_update(synced.update)
                        .map_err(|e| CoreError::Sync {
                            backend: endpoint.label(),
                            detail: e.to_string(),
                        })?;

                    let balance = views::balance(engine);
                    let tip_height = views::tip_height(engine);
                    let tx_count_after = engine.transactions().count() as u32;
                    let moves = views::moves(engine, &known);
                    let read = match &reach {
                        Reach::Scripts(scripts) => Some(scripts.iter().cloned().collect()),
                        _ => None,
                    };
                    let recheck = views::recheck(engine, &vanishing, read.as_ref());
                    let (new_txs, confirmed_txs) = moves.lines();
                    let staged = engine.take_staged();

                    if let Some(staged) = staged {
                        merge_changeset(&mut state, &meta.id, staged)?;
                    }
                    let now = now_secs();
                    crate::live::news::record(
                        &mut state.payload,
                        &meta.id,
                        meta.last_sync.is_none(),
                        &moves,
                        now,
                    );
                    crate::live::news::settle(&mut state.payload, &meta.id, &recheck, now);
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
                        confirmed_txs,
                        balance,
                        tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    let scanned = (reach == Reach::Full).then_some(meta.gap_limit);
                    let complete = matches!(reach, Reach::Full | Reach::Complete);
                    finish_sync(
                        &mut state,
                        &meta.id,
                        &report,
                        tx_count_after,
                        scanned,
                        complete,
                    )?;
                    drop(state);
                    if complete && let Ok(mut done) = self.complete_here.lock() {
                        done.insert(meta.id.clone());
                    }
                    return Ok((report, reach, endpoint.clone()));
                }
            }
        }

        Err(sync_failure(endpoints, attempts))
    }

    async fn sync_address_wallet(
        &self,
        meta: &WalletMeta,
        address: &str,
        endpoints: &[Endpoint],
        proxy: Option<&str>,
        started: Instant,
    ) -> CoreResult<(SyncReport, Endpoint)> {
        let mut attempts: Vec<String> = Vec::new();
        // What the wallet holds: what the server lists as it was is not
        // read again.
        let held: Vec<AddressTx> = {
            let state = self.state.lock().await;
            find_record(&state.payload, &meta.id)?
                .address_state
                .as_ref()
                .map(|watch| watch.txs.clone())
                .unwrap_or_default()
        };
        for endpoint in endpoints {
            match chain::fetch_address_state(endpoint, address, meta.network, proxy, &held).await {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(mut watch) => {
                    let mut state = self.state.lock().await;
                    // Against the state as stored, before the older
                    // rounds are carried over into the fresh one.
                    let moves = views::address_moves(
                        find_record(&state.payload, &meta.id)?
                            .address_state
                            .as_ref(),
                        &watch,
                    );
                    let recheck = views::address_recheck(
                        &crate::live::news::vanishing(&state.payload, &meta.id),
                        &watch,
                    );
                    let (new_txs, confirmed_txs) = moves.lines();
                    // A sync fetches the newest round only. Keep the older
                    // rounds the user already loaded, otherwise every sync
                    // would silently undo "load older transactions".
                    if let Some(previous) = find_record(&state.payload, &meta.id)?
                        .address_state
                        .as_ref()
                    {
                        keep_older_history(&mut watch, previous);
                    }
                    let tx_count_after = watch.txs.len() as u32;
                    let now = now_secs();
                    crate::live::news::record(
                        &mut state.payload,
                        &meta.id,
                        meta.last_sync.is_none(),
                        &moves,
                        now,
                    );
                    crate::live::news::settle(&mut state.payload, &meta.id, &recheck, now);
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
                        confirmed_txs,
                        balance: views::address_balance(&watch),
                        tip_height: watch.tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    find_record_mut(&mut state.payload, &meta.id)?.address_state = Some(watch);
                    finish_sync(&mut state, &meta.id, &report, tx_count_after, None, true)?;
                    return Ok((report, endpoint.clone()));
                }
            }
        }
        Err(sync_failure(endpoints, attempts))
    }

    /// Fetches an older round of history for a watched address and
    /// appends it to the stored list. The balance and the UTXO set
    /// already cover the whole chain, so only the list grows.
    ///
    /// Returns how many transactions were added. Zero means the history
    /// is exhausted.
    pub async fn load_more_history(&self, id: &str) -> CoreResult<u32> {
        let (meta, config, certs, cursor) = {
            let state = self.state.lock().await;
            let record = find_record(&state.payload, id)?;
            let cursor = record
                .address_state
                .as_ref()
                .and_then(|watch| watch.history_cursor.clone());
            let (config, certs) = state.chain_setup(record.meta.network);
            (record.meta.clone(), config, certs, cursor)
        };
        let WalletKind::SingleAddress { address } = &meta.kind else {
            return Err(CoreError::InvalidInput {
                kind: "wallet_kind",
                detail: "descriptor wallets already carry their full history".to_owned(),
            });
        };
        let Some(cursor) = cursor else {
            return Ok(0);
        };
        let endpoints = chain::endpoints(&config, meta.network, &certs)?;
        let proxy = self.tor_proxy_for(&endpoints).await?;

        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::fetch_address_history(
                endpoint,
                address,
                meta.network,
                &cursor,
                proxy.as_deref(),
            )
            .await
            {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(round) => {
                    let mut state = self.state.lock().await;
                    let record = find_record_mut(&mut state.payload, id)?;
                    let Some(watch) = record.address_state.as_mut() else {
                        return Ok(0);
                    };
                    let known: std::collections::HashSet<String> =
                        watch.txs.iter().map(|tx| tx.txid.clone()).collect();
                    let fresh: Vec<_> = round
                        .txs
                        .into_iter()
                        .filter(|tx| !known.contains(&tx.txid))
                        .collect();
                    let added = fresh.len() as u32;
                    watch.txs.extend(fresh);
                    watch.history_cursor = round.cursor;
                    watch.truncated = watch.history_cursor.is_some();
                    let tx_count = watch.txs.len() as u32;
                    record.meta.cached.tx_count = tx_count;
                    state.vault.save(&state.payload)?;
                    return Ok(added);
                }
            }
        }
        Err(sync_failure(&endpoints, attempts))
    }

    /// Syncs every wallet of a network (or all of them), sequentially:
    /// public backends are shared infrastructure, not something to
    /// hammer in parallel. One failure does not stop the others.
    pub async fn sync_all(&self, network: Option<Network>) -> SyncAllReport {
        let metas = self.list_wallets(network).await;
        let mut report = SyncAllReport {
            reports: Vec::new(),
            failures: Vec::new(),
        };
        for meta in metas {
            match self.sync_wallet(&meta.id).await {
                Ok(sync) => report.reports.push(sync),
                Err(error) => report.failures.push(SyncFailure {
                    wallet_id: meta.id,
                    message: error.to_string(),
                }),
            }
        }
        report
    }
}

/// One error covering every endpoint tried, so the user sees each
/// backend's outcome instead of only the last one.
pub(super) fn sync_failure(endpoints: &[Endpoint], attempts: Vec<String>) -> CoreError {
    CoreError::Sync {
        backend: config_label(endpoints),
        detail: if attempts.is_empty() {
            "no backend available".to_owned()
        } else {
            attempts.join("; ")
        },
    }
}

fn config_label(endpoints: &[Endpoint]) -> String {
    endpoints
        .first()
        .map(|e| e.label())
        .unwrap_or_else(|| "backend".to_owned())
}

/// Carries the deep history of `previous` over to a freshly synced
/// `watch`, which only holds the newest round.
///
/// Only transactions confirmed strictly below the fresh round's oldest
/// block are kept: that part of the chain is settled, while anything
/// inside the fresh window is authoritative in `watch` (a replacement or
/// a reorg must not be resurrected).
fn keep_older_history(watch: &mut AddressWatchState, previous: &AddressWatchState) {
    let Some(oldest_fresh) = watch.txs.iter().filter_map(|tx| tx.height).min() else {
        return;
    };
    let known: std::collections::HashSet<&str> =
        watch.txs.iter().map(|tx| tx.txid.as_str()).collect();
    let older: Vec<AddressTx> = previous
        .txs
        .iter()
        .filter(|tx| tx.height.is_some_and(|height| height < oldest_fresh))
        .filter(|tx| !known.contains(tx.txid.as_str()))
        .cloned()
        .collect();
    if older.is_empty() {
        return;
    }
    watch.txs.extend(older);
    // The deeper cursor wins: the list now reaches at least that far.
    watch.history_cursor = previous.history_cursor.clone();
    watch.truncated = watch.history_cursor.is_some();
}

/// Updates cached totals and the sync stamp, then persists the vault.
///
/// `tx_count` is the absolute engine count after the sync, never an
/// accumulated delta: replacements, evictions, and interleaved syncs
/// must not make the cached figure drift. `scanned_gap` is the gap limit
/// a full scan just covered, `None` after an incremental sync.
/// `complete` says the sync read every script it could have.
fn finish_sync(
    state: &mut ManagerState,
    id: &str,
    report: &SyncReport,
    tx_count: u32,
    scanned_gap: Option<u32>,
    complete: bool,
) -> CoreResult<()> {
    {
        let record = find_record_mut(&mut state.payload, id)?;
        record.meta.cached = CachedTotals {
            balance: report.balance,
            tx_count,
        };
        if let Some(gap) = scanned_gap {
            record.meta.scan_gap = gap;
        }
        if complete {
            record.meta.complete_at = Some(now_secs());
        }
        record.meta.last_sync = Some(SyncStamp {
            at: now_secs(),
            tip_height: report.tip_height,
            backend: report.backend.clone(),
        });
    }
    state.vault.save(&state.payload)?;
    Ok(())
}

#[cfg(test)]
mod tests;
