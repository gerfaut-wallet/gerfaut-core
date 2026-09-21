//! Live alerts: the watcher of [`crate::watch`] wired to the vault.
//!
//! [`crate::watch::LiveWatch`] says "this wallet moved" and knows
//! nothing of the vault. Here the manager, which owns the vault,
//! answers: it syncs the wallet that was named, with the sync every
//! other caller uses, and turns what that sync found into events. One
//! process holds one manager, so the watch, the syncs it triggers and
//! the record of what was announced all have a single owner, however
//! many isolates or tasks call in.
//!
//! # For the apps
//!
//! - [`WalletManager::live_start`] returns the single receiver of the
//!   events. Consume it from one task, in Rust: a desktop window that
//!   is minimised throttles its timers, a Tauri task does not care.
//! - [`LiveEvent::Transaction`] is what to announce: a transaction
//!   seen for the first time, in the mempool or already in a block,
//!   and later its first confirmation. Each is handed out once, and
//!   the record of that lives in the vault: a restart, a second
//!   isolate or a background job syncing on its own never makes it
//!   twice. A caller that announces from a sync report of its own
//!   takes it through [`WalletManager::claim_announcements`] first.
//! - Settings and wallets change under a running watch without any
//!   call from the app: the backend, the network, Tor, an accepted
//!   certificate, a wallet added or removed, the scripts a sync
//!   revealed.
//! - [`WalletManager::live_tick`] is for a host whose timers stop
//!   while it sleeps: call it from an alarm every few minutes, and
//!   when the network comes back.
//! - Stop the watch before the vault locks.
//!
//! # At exit
//!
//! [`WalletManager::live_stop`] returns at once, whatever the
//! connection is doing: the watcher is dropped where it waits, the
//! syncs it started are abandoned with their connections, and the
//! receiver of the events ends right after what it already holds.
//! Nothing of the core runs on the blocking pool of the runtime (a name
//! lookup aside, which the system resolver bounds), so a host can then
//! exit the process, or drop its runtime with
//! [`tokio::runtime::Runtime::shutdown_timeout`], without waiting on a
//! server. A sync the host started itself is abandoned the same way
//! when its future is dropped.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::error::CoreResult;
use crate::manager::{ManagerState, WalletManager};
use crate::network::Network;
use crate::store::{Announced, TxStage};
use crate::wallet::snapshot::SyncReport;
use crate::watch::{
    ChangeReason, LiveWatch, WatchConfig, WatchEvent, WatchEvents, WatchStatus, WatchedWallet,
};

/// Announcements remembered. Past this the oldest are forgotten, which
/// costs nothing: a sync reports a transaction once, and the record
/// only has to outlive the callers racing for that one report.
pub(crate) const ANNOUNCED_MAX: usize = 2_000;
/// Events held for a consumer that lags.
const EVENT_QUEUE: usize = 256;
/// When a change was pushed and the sync found nothing, the sync is
/// run again after these delays: with the automatic backend the push
/// comes from one server and the sync reads another, which may hear of
/// the transaction a moment later.
const RETRIES: [Duration; 2] = [Duration::from_secs(3), Duration::from_secs(10)];
/// Syncs the watch runs at once. A wallet that takes long to sync holds
/// one of them and never the others; a backend, often a public one, is
/// never asked for every wallet at the same moment.
const SYNCS_AT_ONCE: usize = 2;

/// One transaction to announce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTx {
    pub wallet_id: String,
    pub txid: String,
    /// Net effect on the wallet, in satoshis.
    pub net_sats: i64,
    pub stage: TxStage,
}

/// What a running live watch says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// Announce this. Handed out once per transaction and stage.
    Transaction(LiveTx),
    /// A wallet was synced because it moved: refresh what shows it.
    WalletSynced {
        report: SyncReport,
    },
    /// The sync a change asked for failed; the next change, or the
    /// next regular sync, tries again.
    SyncFailed {
        wallet_id: String,
        message: String,
    },
    NewBlock {
        height: u32,
    },
    Status(WatchStatus),
}

/// The single receiver of the live events.
#[derive(Debug)]
pub struct LiveEvents {
    events: mpsc::Receiver<LiveEvent>,
}

impl LiveEvents {
    /// The next event; `None` once the watch has stopped.
    pub async fn next(&mut self) -> Option<LiveEvent> {
        self.events.recv().await
    }
}

/// A running watch, kept by the manager.
pub(crate) struct Running {
    watch: LiveWatch,
    config: WatchConfig,
    wallets: Vec<WatchedWallet>,
    /// The reading of the settings and wallets last handed to the watch.
    applied: u64,
    /// Stops the task that turns what the watch says into events.
    halt: watch::Sender<bool>,
}

impl Running {
    fn stop(&self) {
        self.watch.stop();
        let _ = self.halt.send(true);
    }
}

/// What the watch asked of a wallet: the strongest reason, and a full
/// scan when any change asked for one.
#[derive(Debug, Clone, Copy)]
struct Asked {
    reason: ChangeReason,
    rescan: bool,
}

impl Asked {
    fn and(self, other: Asked) -> Asked {
        Asked {
            reason: self.reason.max(other.reason),
            rescan: self.rescan || other.rescan,
        }
    }
}

/// What a sync the watch ran came to: its report, and whether it was
/// the wallet's first, or why it failed.
type Synced = Result<(SyncReport, bool), String>;

/// Resolves once the watch is asked to stop, or its handle is gone.
async fn stopped(halted: &mut watch::Receiver<bool>) {
    loop {
        if *halted.borrow_and_update() {
            return;
        }
        if halted.changed().await.is_err() {
            return;
        }
    }
}

/// Hands an event over, unless the watch stops first. False when the
/// watch stopped or nobody is left to take it.
async fn deliver(
    events: &mpsc::Sender<LiveEvent>,
    event: LiveEvent,
    halted: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        sent = events.send(event) => sent.is_ok(),
        () = stopped(halted) => false,
    }
}

/// What the watcher needs to reach the backend of the active network.
fn config_of(state: &ManagerState) -> WatchConfig {
    let settings = &state.payload.settings;
    WatchConfig {
        network: settings.active_network,
        backend: settings.backend_for(settings.active_network),
        electrum_certs: settings.electrum_certs.clone(),
        tor: settings.tor.clone(),
        data_dir: state.data_dir.clone(),
        keepalive_secs: None,
    }
}

/// The wallets of a network as the watcher takes them.
fn list_of(state: &mut ManagerState, network: Network) -> Vec<WatchedWallet> {
    let gap_limit = state.payload.settings.gap_limit;
    let ids: Vec<String> = state
        .payload
        .wallets
        .iter()
        .filter(|record| record.meta.network == network)
        .map(|record| record.meta.id.clone())
        .collect();
    ids.into_iter()
        .filter_map(|id| crate::manager::watched_wallet(state, &id, gap_limit))
        .collect()
}

impl WalletManager {
    /// Starts the live watch of the active network, or starts it over:
    /// a watch already running is stopped and its receiver closes.
    /// Must be called inside a tokio runtime.
    pub async fn live_start(&self) -> CoreResult<LiveEvents> {
        self.live_start_with(None).await
    }

    pub(crate) async fn live_start_with(
        &self,
        timings: Option<crate::watch::Timings>,
    ) -> CoreResult<LiveEvents> {
        let (config, wallets, applied) = self.watch_setup().await;
        let (watch, changes) = LiveWatch::start_with(config.clone(), wallets.clone(), timings);
        let (halt, halted) = watch::channel(false);
        let (events, receiver) = mpsc::channel(EVENT_QUEUE);
        let previous = self.live_slot().replace(Running {
            watch,
            config,
            wallets,
            applied,
            halt,
        });
        if let Some(previous) = previous {
            previous.stop();
        }
        tokio::spawn(self.clone().relay(changes, events, halted));
        // Whatever changed between the reading above and now.
        self.live_refresh().await;
        Ok(LiveEvents { events: receiver })
    }

    /// Stops the live watch and closes its connection. Returns at once,
    /// whatever the connection is doing, and abandons the syncs the
    /// watch started; the receiver of the events ends right after what
    /// it already holds. Idempotent.
    pub async fn live_stop(&self) {
        let running = self.live_slot().take();
        if let Some(running) = running {
            running.stop();
        }
    }

    /// Checks the connection now; see [`LiveWatch::tick`]. Nothing
    /// when no watch runs.
    pub async fn live_tick(&self) {
        if let Some(running) = self.live_slot().as_ref() {
            running.watch.tick();
        }
    }

    /// Where the watch stands; off when none runs.
    pub async fn live_status(&self) -> WatchStatus {
        match self.live_slot().as_ref() {
            Some(running) => running.watch.status(),
            None => WatchStatus::default(),
        }
    }

    fn live_slot(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hands a running watch the settings and the wallets as they are
    /// now. Every change that matters calls this; with no watch running
    /// it costs a lock. Of two calls that race, the later reading wins.
    pub(crate) async fn live_refresh(&self) {
        if self.live_slot().is_none() {
            return;
        }
        let (config, wallets, reading) = self.watch_setup().await;
        let mut slot = self.live_slot();
        let Some(running) = slot.as_mut() else {
            return;
        };
        if reading <= running.applied {
            return;
        }
        running.applied = reading;
        if config != running.config {
            running.config = config.clone();
            running.wallets = wallets.clone();
            running.watch.reconfigure(config, wallets);
        } else if wallets != running.wallets {
            running.wallets = wallets.clone();
            running.watch.set_wallets(wallets);
        }
    }

    /// What the watcher needs to reach the backend of the active
    /// network: a copy of four settings, and nothing of the wallets.
    pub async fn watch_config(&self) -> WatchConfig {
        config_of(&*self.state.lock().await)
    }

    /// The scripts of every wallet of a network, in the order a
    /// transport should cover them; see
    /// [`crate::wallet::views::watch_scripts`]. A wallet whose engine
    /// cannot be loaded is left out.
    pub async fn watch_list(&self, network: Network) -> Vec<WatchedWallet> {
        list_of(&mut *self.state.lock().await, network)
    }

    /// The configuration and the list together, read under one lock,
    /// with the rank of that reading.
    async fn watch_setup(&self) -> (WatchConfig, Vec<WatchedWallet>, u64) {
        let mut state = self.state.lock().await;
        let reading = self.watch_setups.fetch_add(1, Ordering::SeqCst) + 1;
        let config = config_of(&state);
        let wallets = list_of(&mut state, config.network);
        (config, wallets, reading)
    }

    /// Of what a sync report lists, what nobody has announced yet, now
    /// recorded as announced. The record is in the vault, so the answer
    /// holds across restarts and across every caller of this process: a
    /// transaction is handed out once when it shows up and once when it
    /// confirms, whoever asks first.
    pub async fn claim_announcements(&self, report: &SyncReport) -> CoreResult<Vec<LiveTx>> {
        let stage_of = |confirmed: bool| {
            if confirmed {
                TxStage::Confirmed
            } else {
                TxStage::Mempool
            }
        };
        let listed = report
            .new_txs
            .iter()
            .map(|tx| (tx, stage_of(tx.confirmed)))
            .chain(
                report
                    .confirmed_txs
                    .iter()
                    .map(|tx| (tx, TxStage::Confirmed)),
            );
        let mut state = self.state.lock().await;
        let mut claimed: Vec<LiveTx> = Vec::new();
        for (tx, stage) in listed {
            let told = |entry: &Announced| {
                entry.txid == tx.txid && (entry.stage == stage || entry.stage == TxStage::Confirmed)
            };
            if state.payload.announced.iter().any(told)
                || claimed
                    .iter()
                    .any(|c| c.txid == tx.txid && c.stage == stage)
            {
                continue;
            }
            claimed.push(LiveTx {
                wallet_id: report.wallet_id.clone(),
                txid: tx.txid.clone(),
                net_sats: tx.net_sats,
                stage,
            });
        }
        if claimed.is_empty() {
            return Ok(claimed);
        }
        state.commit(|payload| {
            payload.announced.extend(claimed.iter().map(|tx| Announced {
                txid: tx.txid.clone(),
                stage: tx.stage,
            }));
            let excess = payload.announced.len().saturating_sub(ANNOUNCED_MAX);
            payload.announced.drain(..excess);
            Ok(())
        })?;
        Ok(claimed)
    }

    /// Turns what the watch says into events: syncs the wallets it
    /// names, a few at a time and one at a time per wallet, and hands
    /// out what they found. Ends when the watch stops, and abandons the
    /// syncs still running then.
    async fn relay(
        self,
        mut changes: WatchEvents,
        events: mpsc::Sender<LiveEvent>,
        mut halted: watch::Receiver<bool>,
    ) {
        let permits = Arc::new(Semaphore::new(SYNCS_AT_ONCE));
        let mut syncs: JoinSet<Synced> = JoinSet::new();
        let mut wallet_of: HashMap<tokio::task::Id, String> = HashMap::new();
        // A wallet with a sync under way, and what was asked of it since.
        let mut again: HashMap<String, Option<Asked>> = HashMap::new();
        // The loop waits on its own copy: the ones below hand theirs to
        // what they call.
        let mut stop = halted.clone();
        loop {
            tokio::select! {
                () = stopped(&mut stop) => break,
                change = changes.next() => {
                    let Some(change) = change else {
                        break;
                    };
                    let event = match change {
                        WatchEvent::WalletChanged {
                            wallet_id,
                            reason,
                            rescan,
                        } => {
                            let asked = Asked { reason, rescan };
                            match again.get_mut(&wallet_id) {
                                Some(next) => *next = Some(next.map_or(asked, |n| n.and(asked))),
                                None => {
                                    again.insert(wallet_id.clone(), None);
                                    let task = syncs.spawn(self.clone().live_sync(
                                        wallet_id.clone(),
                                        asked,
                                        permits.clone(),
                                    ));
                                    wallet_of.insert(task.id(), wallet_id);
                                }
                            }
                            continue;
                        }
                        WatchEvent::NewBlock { height } => LiveEvent::NewBlock { height },
                        WatchEvent::Status(status) => LiveEvent::Status(status),
                    };
                    if !deliver(&events, event, &mut halted).await {
                        break;
                    }
                }
                Some(done) = syncs.join_next_with_id() => {
                    let (task, outcome) = match done {
                        Ok((task, outcome)) => (task, outcome),
                        Err(error) => (error.id(), Err("the sync stopped unexpectedly".to_owned())),
                    };
                    let Some(wallet_id) = wallet_of.remove(&task) else {
                        continue;
                    };
                    if !self.announce(&wallet_id, outcome, &events, &mut halted).await {
                        break;
                    }
                    if let Some(Some(next)) = again.remove(&wallet_id) {
                        again.insert(wallet_id.clone(), None);
                        let task = syncs.spawn(self.clone().live_sync(
                            wallet_id.clone(),
                            next,
                            permits.clone(),
                        ));
                        wallet_of.insert(task.id(), wallet_id);
                    }
                }
            }
        }
        syncs.abort_all();
        let _ = events.try_send(LiveEvent::Status(WatchStatus::default()));
    }

    /// Hands out what one sync of a wallet came to. False when the
    /// watch stopped or nobody takes the events any more.
    async fn announce(
        &self,
        wallet_id: &str,
        outcome: Synced,
        events: &mpsc::Sender<LiveEvent>,
        halted: &mut watch::Receiver<bool>,
    ) -> bool {
        match outcome {
            Ok((report, first_sync)) => {
                // A wallet that was never synced holds its whole
                // history as "new": that is an import, not news.
                if let Ok(claimed) = self.claim_announcements(&report).await
                    && !first_sync
                {
                    for tx in claimed {
                        // What was claimed is owed: handed over even
                        // when the watch stops meanwhile.
                        if events.send(LiveEvent::Transaction(tx)).await.is_err() {
                            return false;
                        }
                    }
                }
                deliver(events, LiveEvent::WalletSynced { report }, halted).await
            }
            Err(message) => {
                deliver(
                    events,
                    LiveEvent::SyncFailed {
                        wallet_id: wallet_id.to_owned(),
                        message,
                    },
                    halted,
                )
                .await
            }
        }
    }

    /// The sync a change asked for, run under one of the permits.
    async fn live_sync(self, wallet_id: String, asked: Asked, permits: Arc<Semaphore>) -> Synced {
        let first_sync = self
            .list_wallets(None)
            .await
            .iter()
            .find(|meta| meta.id == wallet_id)
            .is_none_or(|meta| meta.last_sync.is_none());
        let sync = async || {
            let _permit = permits.acquire().await;
            if asked.rescan {
                self.rescan_wallet(&wallet_id).await
            } else {
                self.sync_wallet(&wallet_id).await
            }
        };
        let mut outcome = sync().await;
        for delay in RETRIES {
            let found_nothing = matches!(
                &outcome,
                Ok(report) if report.new_txs.is_empty() && report.confirmed_txs.is_empty()
            );
            if asked.reason != ChangeReason::Activity || !found_nothing {
                break;
            }
            tokio::time::sleep(delay).await;
            outcome = sync().await;
        }
        outcome
            .map(|report| (report, first_sync))
            .map_err(|error| error.to_string())
    }
}
