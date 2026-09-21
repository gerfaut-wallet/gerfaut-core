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
//!   twice.
//! - Every sync, whoever runs it, records what it found in the vault
//!   ([`news`]), and nothing of it goes out until someone claims it.
//!   The watch claims after each sync it runs. A host that runs a sync
//!   of its own claims after it with
//!   [`WalletManager::claim_announcements`] and announces what it gets:
//!   the contract is written there.
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
use crate::store::TxStage;
use crate::wallet::snapshot::SyncReport;
use crate::watch::{
    ChangeReason, LiveWatch, WatchConfig, WatchEvent, WatchEvents, WatchStatus, WatchedWallet,
};

pub(crate) mod news;
#[cfg(test)]
mod tests;

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
/// Transactions claimed, and handed out, at a time.
const CLAIM_BATCH: usize = 32;
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

/// What a sync the watch ran came to: its report, or why it failed.
type Synced = Result<SyncReport, String>;

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

    /// What the syncs of `report.wallet_id` found worth announcing and
    /// nobody has claimed yet, now recorded as announced. Only the
    /// wallet of `report` is read: every sync, whoever ran it, recorded
    /// its findings in the vault, and they are handed out here to the
    /// first caller that asks. The record is in the vault, so this
    /// holds across restarts and across every caller of the process.
    ///
    /// What comes out, once per transaction and stage:
    ///
    /// - [`TxStage::Mempool`]: a transaction seen for the first time,
    ///   not yet in a block.
    /// - [`TxStage::Confirmed`]: its first confirmation, or a
    ///   transaction first seen already in a block. One seen and
    ///   confirmed before anyone claimed it comes out once, confirmed.
    ///
    /// A wallet's first sync records nothing: its whole history is an
    /// import, not news. What was pending then is news when it
    /// confirms.
    ///
    /// # Contract for a host
    ///
    /// - Claim after every sync you run, [`WalletManager::sync_wallet`],
    ///   [`WalletManager::rescan_wallet`] and each report of
    ///   [`WalletManager::sync_all`], whatever the report lists. A
    ///   report with nothing listed may come from a sync that ran for
    ///   another caller, and what it found waits here.
    /// - Announce everything returned, or drop it on purpose (alerts
    ///   off, a disguised app): nothing returned is ever returned
    ///   again. Whoever claims announces.
    /// - Do not leave out the wallets you saw synced for the first
    ///   time: the core already did, and what you would leave out may
    ///   be news another sync of that wallet found meanwhile.
    /// - Claims race safely. The live watch claims after each of its
    ///   own syncs; a host sync and a watch sync of the same wallet,
    ///   at the same moment, announce each transaction exactly once
    ///   between them.
    /// - What nobody claims is kept twelve hours, then forgotten: a host
    ///   that syncs with its alerts off claims all the same, and drops
    ///   what it gets, or all of it is said the day they are turned on.
    pub async fn claim_announcements(&self, report: &SyncReport) -> CoreResult<Vec<LiveTx>> {
        self.claim_news(&report.wallet_id, usize::MAX).await
    }

    /// Takes up to `max` pieces of the news waiting for a wallet.
    async fn claim_news(&self, wallet_id: &str, max: usize) -> CoreResult<Vec<LiveTx>> {
        let now = crate::manager::now_secs();
        let mut state = self.state.lock().await;
        if max == 0 || news::waiting(&state.payload, wallet_id, now) == 0 {
            return Ok(Vec::new());
        }
        state.commit(|payload| Ok(news::claim(payload, wallet_id, max, now)))
    }

    /// How much news waits for a wallet.
    async fn news_waiting(&self, wallet_id: &str) -> usize {
        let now = crate::manager::now_secs();
        news::waiting(&self.state.lock().await.payload, wallet_id, now)
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
            Ok(report) => {
                // Room is made in the queue before anything is claimed,
                // and what is claimed goes into that room at once: a
                // watch that stops, or a host that stops reading,
                // leaves the news in the vault, never claimed and lost.
                loop {
                    let waiting = self.news_waiting(wallet_id).await.min(CLAIM_BATCH);
                    if waiting == 0 {
                        break;
                    }
                    let room = tokio::select! {
                        room = events.reserve_many(waiting) => room,
                        () = stopped(halted) => return false,
                    };
                    let Ok(mut room) = room else {
                        return false;
                    };
                    let Ok(claimed) = self.claim_news(wallet_id, waiting).await else {
                        break;
                    };
                    let all = claimed.len() < waiting;
                    for tx in claimed {
                        if let Some(slot) = room.next() {
                            slot.send(LiveEvent::Transaction(tx));
                        }
                    }
                    if all {
                        break;
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
            if asked.reason != ChangeReason::Activity
                || !found_nothing
                || self.news_waiting(&wallet_id).await > 0
            {
                break;
            }
            tokio::time::sleep(delay).await;
            outcome = sync().await;
        }
        outcome.map_err(|error| error.to_string())
    }
}
