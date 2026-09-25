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
//!   is minimised throttles its timers, a Tauri task does not care. A
//!   watch that starts catches up on what happened while nothing ran:
//!   the contract is written there.
//! - [`LiveEvent::Transaction`] is what to announce: a transaction
//!   seen for the first time, in the mempool or already in a block,
//!   and later its first confirmation; a fee bump is not a new
//!   transaction, and a payment that vanished from the mempool is said
//!   so ([`TxStage::Dropped`]). Each is handed out once, and the record
//!   of that lives in the vault: a restart, a second isolate or a
//!   background job syncing on its own never makes it twice.
//! - Every sync, whoever runs it, records what it found in the vault,
//!   and nothing of it goes out until someone claims it.
//!   The watch claims after each sync it runs, and, while it runs,
//!   whatever a host sync left unclaimed. A host that runs a sync
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

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use bdk_wallet::bitcoin::ScriptBuf;

use crate::chain::Endpoint;
use crate::error::CoreResult;
use crate::manager::{ManagerState, Reach, WalletManager};
use crate::network::Network;
use crate::store::TxStage;
use crate::wallet::snapshot::SyncReport;
use crate::watch::{
    ChangeReason, LiveWatch, Timings, WatchConfig, WatchEvent, WatchEvents, WatchStatus,
    WatchedWallet,
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
/// Pushed changes of a wallet the syncs may find nothing behind, in a
/// row, before the next one is made to wait: see [`Futile`].
const FREE_FUTILE: u32 = 2;
/// Transactions claimed, and handed out, at a time.
const CLAIM_BATCH: usize = 32;
/// Syncs the watch runs at once. A wallet that takes long to sync holds
/// one of them and never the others; a backend, often a public one, is
/// never asked for every wallet at the same moment.
const SYNCS_AT_ONCE: usize = 2;
/// How long a wallet whose complete sync the watch ran, and failed, is
/// left before the watch tries again.
const DUE_RETRY: Duration = Duration::from_secs(60 * 60);

/// One transaction to announce.
///
/// # Contract for a host
///
/// Use `replaces.unwrap_or(txid)` as the notification id. A fee bump
/// confirms under a txid of its own, and `replaces` names the one the
/// payment was first announced under, so the confirmation takes the
/// place of the pending notice instead of showing beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTx {
    pub wallet_id: String,
    pub txid: String,
    /// Net effect on the wallet, in satoshis.
    pub net_sats: i64,
    pub stage: TxStage,
    /// The txid this payment was first announced under, for this wallet,
    /// when `txid` is a fee bump the core recognised of it, however many
    /// bumps lie between: the first one announced, never an intermediate
    /// one. `None` for a transaction announced under its own txid. A
    /// [`TxStage::Dropped`] carries the txid the payment was announced
    /// under as its `txid`, and no `replaces`.
    #[serde(default)]
    pub replaces: Option<String>,
}

/// What a running live watch says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// Announce this. Handed out once per transaction and stage: see
    /// [`WalletManager::claim_announcements`] for what each stage means.
    /// With [`TxStage::Dropped`], warn that a payment said to be coming
    /// has vanished.
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
    /// The syncs someone else ran while the watch runs, for their news.
    offers: mpsc::UnboundedSender<SyncReport>,
    /// Counts the configurations handed to the watch after its first.
    reconfigured: watch::Sender<u64>,
}

impl Running {
    fn stop(&self) {
        self.watch.stop();
        let _ = self.halt.send(true);
    }
}

/// What the watch asked of a wallet: the strongest reason, and the
/// scripts that moved, `None` for the whole wallet.
#[derive(Debug, Clone)]
struct Asked {
    reason: ChangeReason,
    scripts: Option<BTreeSet<String>>,
}

impl Asked {
    fn of(reason: ChangeReason, scripts: Vec<String>) -> Asked {
        Asked {
            reason,
            scripts: (!scripts.is_empty()).then(|| scripts.into_iter().collect()),
        }
    }

    fn and(self, other: Asked) -> Asked {
        Asked {
            reason: self.reason.max(other.reason),
            scripts: match (self.scripts, other.scripts) {
                (Some(mut these), Some(those)) => {
                    these.extend(those);
                    Some(these)
                }
                _ => None,
            },
        }
    }

    /// How much of the wallet the sync reads: the scripts that moved; the
    /// ones waiting for a block, for a block; every script, counters
    /// first, when the transport cannot say which moved. A script past
    /// what the wallet's index looks ahead turns it into a full scan
    /// (see [`crate::manager::Reach`]).
    fn reach(&self) -> Reach {
        match &self.scripts {
            Some(scripts) => Reach::Scripts(
                scripts
                    .iter()
                    .filter_map(|hex| ScriptBuf::from_hex(hex).ok())
                    .collect(),
            ),
            None => match self.reason {
                ChangeReason::NewBlock => Reach::Pending,
                ChangeReason::Started | ChangeReason::Reconnected => Reach::Complete,
                ChangeReason::Activity => Reach::Checked,
            },
        }
    }
}

/// What a sync the watch ran came to: its report, or why it failed.
type Synced = Result<SyncReport, String>;

/// Pushed changes the syncs found nothing behind, in a row, by wallet.
///
/// A sync costs the backend's answers, a vault written to disk and a
/// radio kept awake. A server that keeps saying a wallet moved when
/// nothing did, a status forged anew every few seconds, would have the
/// app pay that for as long as the watch runs. So past [`FREE_FUTILE`]
/// such changes in a row, the sync the next one asks for waits, twice
/// as long each time, up to a cap. A sync that finds something,
/// whatever asked for it, ends the wait. A block, a reconnection and
/// the catch-up of a start never wait: only what the server claims
/// about a script does.
#[derive(Debug, Default)]
struct Futile(HashMap<String, u32>);

impl Futile {
    /// How long the sync `asked` for this wallet waits before it runs.
    fn hold(&self, wallet_id: &str, asked: &Asked, timings: &Timings) -> Duration {
        if asked.reason != ChangeReason::Activity {
            return Duration::ZERO;
        }
        let futile = self.0.get(wallet_id).copied().unwrap_or(0);
        let Some(doublings) = futile.checked_sub(FREE_FUTILE) else {
            return Duration::ZERO;
        };
        timings
            .hold
            .saturating_mul(2u32.saturating_pow(doublings))
            .min(timings.hold_cap)
    }

    /// Takes what a sync `asked` for this wallet came to: whether it
    /// found anything, a failure counting as nothing found.
    fn settle(&mut self, wallet_id: &str, asked: &Asked, found: bool) {
        if found {
            self.0.remove(wallet_id);
        } else if asked.reason == ChangeReason::Activity {
            let futile = self.0.entry(wallet_id.to_owned()).or_default();
            *futile = futile.saturating_add(1);
        }
    }
}

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
    ///
    /// # Contract for a host
    ///
    /// - Start it as soon as the vault is open, before or alongside the
    ///   app's own opening sync; there is nothing to wait for.
    /// - Once its connection is up and has read every script once, the
    ///   watch syncs, two at a time, the wallets whose scripts moved
    ///   while nothing listened, and hands out through
    ///   [`LiveEvent::Transaction`] what happened then: a payment that
    ///   arrived while the app was closed, the phone off, the service
    ///   killed. An Electrum server says which scripts moved; over any
    ///   other backend every wallet of the network is synced. The same
    ///   after a new configuration, and after a lost connection.
    /// - The opening sync of the app may race that catch-up. Each
    ///   transaction still comes out exactly once, through the watch or
    ///   through the app, provided the app claims after its own syncs
    ///   ([`Self::claim_announcements`]) and announces what it claims.
    /// - The events of one wallet come as its transactions, then its
    ///   [`LiveEvent::WalletSynced`]: a host may hold the first until
    ///   the second, to say them together.
    /// - At exit, see the module documentation: [`Self::live_stop`]
    ///   returns at once, and nothing of the core holds the runtime.
    pub async fn live_start(&self) -> CoreResult<LiveEvents> {
        self.live_start_with(None).await
    }

    pub(crate) async fn live_start_with(&self, timings: Option<Timings>) -> CoreResult<LiveEvents> {
        let (config, wallets, applied) = self.watch_setup().await;
        let pace = timings.unwrap_or_else(|| Timings::of(&config));
        let (watch, changes) = LiveWatch::start_with(config.clone(), wallets.clone(), timings);
        let (halt, halted) = watch::channel(false);
        let (events, receiver) = mpsc::channel(EVENT_QUEUE);
        let (offers, offered) = mpsc::unbounded_channel();
        let (reconfigured, configs) = watch::channel(0);
        let previous = self.live_slot().replace(Running {
            watch,
            config,
            wallets,
            applied,
            halt,
            offers,
            reconfigured,
        });
        if let Some(previous) = previous {
            previous.stop();
        }
        tokio::spawn(
            self.clone()
                .relay(changes, offered, configs, events, halted, pace),
        );
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

    /// Hands a running watch a sync someone else ran. What that sync
    /// found and nobody claimed is announced by the watch: a watch that
    /// starts no longer syncs a wallet whose scripts did not move, and
    /// its news would otherwise wait for the next one that does.
    pub(crate) fn live_offer(&self, report: &SyncReport) {
        if let Some(running) = self.live_slot().as_ref() {
            let _ = running.offers.send(report.clone());
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
            running.reconfigured.send_modify(|count| *count += 1);
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
    /// - [`TxStage::Dropped`]: an incoming payment that came out at the
    ///   mempool stage left the mempool, and nothing the wallet holds
    ///   pays it instead. Warn that the money is not coming.
    ///
    /// A fee bump comes out as nothing. A new unconfirmed transaction
    /// that spends an output a pending one of the wallet spent, one
    /// that came out at the mempool stage, and that moves the wallet the
    /// same way, in or out, and by nearly as much, is recorded as said.
    /// Whichever of them confirms comes out once, confirmed. A
    /// replacement that pays the wallet much less, or sends much more
    /// out, comes out as a transaction of its own, and an incoming
    /// payment it cut down, or stopped paying, comes out as dropped.
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
    ///   own syncs, and after a host's when the host did not; a host sync and a watch sync of the same wallet,
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

    /// The wallets of the watched network with news nobody claimed, each
    /// with a report of its last sync, as the vault keeps it.
    async fn unclaimed_reports(&self) -> Vec<SyncReport> {
        let now = crate::manager::now_secs();
        let state = self.state.lock().await;
        let network = state.payload.settings.active_network;
        state
            .payload
            .wallets
            .iter()
            .filter(|record| record.meta.network == network)
            .filter(|record| news::waiting(&state.payload, &record.meta.id, now) > 0)
            .map(|record| SyncReport {
                wallet_id: record.meta.id.clone(),
                new_tx_count: 0,
                new_txs: Vec::new(),
                confirmed_txs: Vec::new(),
                balance: record.meta.cached.balance,
                tip_height: record
                    .meta
                    .last_sync
                    .as_ref()
                    .map_or(0, |stamp| stamp.tip_height),
                took_ms: 0,
                backend: record
                    .meta
                    .last_sync
                    .as_ref()
                    .map(|stamp| stamp.backend.clone())
                    .unwrap_or_default(),
            })
            .collect()
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
        mut offered: mpsc::UnboundedReceiver<SyncReport>,
        mut configs: watch::Receiver<u64>,
        events: mpsc::Sender<LiveEvent>,
        mut halted: watch::Receiver<bool>,
        pace: Timings,
    ) {
        let permits = Arc::new(Semaphore::new(SYNCS_AT_ONCE));
        let mut syncs: JoinSet<Synced> = JoinSet::new();
        // The wallet of each sync, and what that sync was asked for.
        let mut wallet_of: HashMap<tokio::task::Id, (String, Asked)> = HashMap::new();
        // A wallet with a sync under way, and what was asked of it since.
        let mut again: HashMap<String, Option<Asked>> = HashMap::new();
        let mut futile = Futile::default();
        // What a sync that failed was asked, run again at the next look.
        let mut owed: HashMap<String, Asked> = HashMap::new();
        // When the watch last ran the complete sync of a wallet it found
        // due: one that failed is not tried again at every look.
        let mut tried: HashMap<String, tokio::time::Instant> = HashMap::new();
        // How often the watch looks for both, besides at each block.
        let mut looks = tokio::time::interval_at(tokio::time::Instant::now() + pace.due, pace.due);
        looks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // What a sync found before the watch started, and nobody claimed:
        // a start no longer syncs a wallet whose scripts did not move.
        for report in self.unclaimed_reports().await {
            let wallet_id = report.wallet_id.clone();
            if !self
                .announce(&wallet_id, Ok(report), &events, &mut halted)
                .await
            {
                return;
            }
        }
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
                            scripts,
                            ..
                        } => {
                            let asked = Asked::of(reason, scripts);
                            self.ask(&mut syncs, &mut wallet_of, &mut again, &futile, &permits, &pace, wallet_id, asked);
                            continue;
                        }
                        WatchEvent::NewBlock { height } => {
                            self.look(&mut syncs, &mut wallet_of, &mut again, &futile, &permits, &pace, &mut owed, &mut tried).await;
                            LiveEvent::NewBlock { height }
                        }
                        WatchEvent::Status(status) => LiveEvent::Status(status),
                    };
                    if !deliver(&events, event, &mut halted).await {
                        break;
                    }
                }
                Ok(()) = configs.changed() => {
                    // Another network, another backend: what was asked
                    // under the old one is dropped, the syncs running or
                    // waiting for a permit with it. The watch catches up
                    // under the new one, as a start does.
                    syncs.abort_all();
                    wallet_of.clear();
                    again.clear();
                    owed.clear();
                    tried.clear();
                }
                Some(report) = offered.recv() => {
                    // A sync of the watch's own under way claims it.
                    if again.contains_key(&report.wallet_id)
                        || self.news_waiting(&report.wallet_id).await == 0
                    {
                        continue;
                    }
                    let wallet_id = report.wallet_id.clone();
                    let report = SyncReport {
                        new_tx_count: 0,
                        new_txs: Vec::new(),
                        confirmed_txs: Vec::new(),
                        ..report
                    };
                    if !self.announce(&wallet_id, Ok(report), &events, &mut halted).await {
                        break;
                    }
                }
                _ = looks.tick() => {
                    self.look(&mut syncs, &mut wallet_of, &mut again, &futile, &permits, &pace, &mut owed, &mut tried).await;
                }
                Some(done) = syncs.join_next_with_id() => {
                    let (task, outcome) = match done {
                        Ok((task, outcome)) => (task, outcome),
                        Err(error) => (error.id(), Err("the sync stopped unexpectedly".to_owned())),
                    };
                    let Some((wallet_id, asked)) = wallet_of.remove(&task) else {
                        continue;
                    };
                    // Before the news is claimed and handed out below.
                    let found = match &outcome {
                        Ok(report) => {
                            !report.new_txs.is_empty()
                                || !report.confirmed_txs.is_empty()
                                || self.news_waiting(&wallet_id).await > 0
                        }
                        Err(_) => false,
                    };
                    futile.settle(&wallet_id, &asked, found);
                    if outcome.is_err() {
                        let asked = match owed.remove(&wallet_id) {
                            Some(earlier) => earlier.and(asked),
                            None => asked,
                        };
                        owed.insert(wallet_id.clone(), asked);
                    }
                    if !self.announce(&wallet_id, outcome, &events, &mut halted).await {
                        break;
                    }
                    if let Some(Some(next)) = again.remove(&wallet_id) {
                        again.insert(wallet_id.clone(), None);
                        let hold = futile.hold(&wallet_id, &next, &pace);
                        let task = syncs.spawn(self.clone().live_sync(
                            wallet_id.clone(),
                            next.clone(),
                            permits.clone(),
                            hold,
                            pace.retries,
                        ));
                        wallet_of.insert(task.id(), (wallet_id, next));
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

    /// Runs the sync `asked` of a wallet, or, with one under way, keeps
    /// it for when that one ends.
    #[allow(clippy::too_many_arguments)]
    fn ask(
        &self,
        syncs: &mut JoinSet<Synced>,
        wallet_of: &mut HashMap<tokio::task::Id, (String, Asked)>,
        again: &mut HashMap<String, Option<Asked>>,
        futile: &Futile,
        permits: &Arc<Semaphore>,
        pace: &Timings,
        wallet_id: String,
        asked: Asked,
    ) {
        match again.get_mut(&wallet_id) {
            Some(next) => {
                *next = Some(match next.take() {
                    Some(earlier) => earlier.and(asked),
                    None => asked,
                });
            }
            None => {
                again.insert(wallet_id.clone(), None);
                let hold = futile.hold(&wallet_id, &asked, pace);
                let task = syncs.spawn(self.clone().live_sync(
                    wallet_id.clone(),
                    asked.clone(),
                    permits.clone(),
                    hold,
                    pace.retries,
                ));
                wallet_of.insert(task.id(), (wallet_id, asked));
            }
        }
    }

    /// What the watch runs of its own accord, at each block and every
    /// [`Timings::due`], while it has a session: the syncs that failed,
    /// again, and a complete sync of each wallet that has had none for a
    /// day. The syncs the watch asks for read only what moved, and a
    /// phone can keep a watch for days with no other sync: this is what
    /// reads, once a day, whatever the watch cannot hear, such as a
    /// script past what it follows of a wallet.
    #[allow(clippy::too_many_arguments)]
    async fn look(
        &self,
        syncs: &mut JoinSet<Synced>,
        wallet_of: &mut HashMap<tokio::task::Id, (String, Asked)>,
        again: &mut HashMap<String, Option<Asked>>,
        futile: &Futile,
        permits: &Arc<Semaphore>,
        pace: &Timings,
        owed: &mut HashMap<String, Asked>,
        tried: &mut HashMap<String, tokio::time::Instant>,
    ) {
        if self.watch_serving().is_none() {
            return;
        }
        let now = tokio::time::Instant::now();
        tried.retain(|_, at| now.duration_since(*at) < DUE_RETRY);
        let mut asks: Vec<(String, Asked)> = owed.drain().collect();
        for wallet_id in self.due_complete().await {
            if tried.contains_key(&wallet_id) {
                continue;
            }
            tried.insert(wallet_id.clone(), now);
            asks.push((wallet_id, Asked::of(ChangeReason::Started, Vec::new())));
        }
        for (wallet_id, asked) in asks {
            self.ask(
                syncs, wallet_of, again, futile, permits, pace, wallet_id, asked,
            );
        }
    }

    /// The wallets of the watched network whose last complete sync is a
    /// day old, or that never had one.
    async fn due_complete(&self) -> Vec<String> {
        let now = crate::manager::now_secs();
        let state = self.state.lock().await;
        let network = state.payload.settings.active_network;
        state
            .payload
            .wallets
            .iter()
            .filter(|record| record.meta.network == network)
            .filter(|record| !crate::manager::complete_lately(&record.meta, now))
            .map(|record| record.meta.id.clone())
            .collect()
    }

    /// The server the live watch has a session with, if any.
    fn watch_serving(&self) -> Option<(Network, Endpoint)> {
        self.live_slot()
            .as_ref()
            .and_then(|running| running.watch.serving())
    }

    /// The sync a change asked for, run under one of the permits once
    /// `hold` has passed: of the scripts that moved when the watch named
    /// them, on the server the watch listens to first, which holds what
    /// it said moved. A sync that found nothing behind a pushed change,
    /// read from another server, is run again after each of `retries`:
    /// that server may hear of the transaction a moment later. Read from
    /// the watch's own server, it found all there was.
    async fn live_sync(
        self,
        wallet_id: String,
        asked: Asked,
        permits: Arc<Semaphore>,
        hold: Duration,
        retries: [Duration; 2],
    ) -> Synced {
        if !hold.is_zero() {
            tokio::time::sleep(hold).await;
        }
        let reach = asked.reach();
        let sync = async || {
            let _permit = permits.acquire().await;
            let serving = self.watch_serving();
            let outcome = self
                .sync_wallet_read(&wallet_id, reach.clone(), serving.clone())
                .await;
            (outcome, serving)
        };
        let (mut outcome, mut serving) = sync().await;
        for delay in retries {
            let found_nothing = matches!(
                &outcome,
                Ok((report, _)) if report.new_txs.is_empty() && report.confirmed_txs.is_empty()
            );
            let read_where_told = matches!(
                (&outcome, &serving),
                (Ok((_, Some(read))), Some((_, told))) if read == told
            );
            if asked.reason != ChangeReason::Activity
                || !found_nothing
                || read_where_told
                || self.news_waiting(&wallet_id).await > 0
            {
                break;
            }
            tokio::time::sleep(delay).await;
            (outcome, serving) = sync().await;
        }
        outcome
            .map(|(report, _)| report)
            .map_err(|error| error.to_string())
    }
}
