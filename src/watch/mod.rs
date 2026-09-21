//! The live watcher: one long-lived connection to the configured
//! backend, turned into "something changed for wallet X".
//!
//! A sync asks the backend a question and hangs up. Between two syncs
//! nothing listens, so a payment is noticed at the next one. The
//! watcher is what listens: it keeps one connection open for the
//! active network and says when a watched script moved and when a
//! block arrived. It is a trigger and nothing more. It fetches no
//! transaction, holds no balance and never opens the vault: whoever
//! owns the vault runs the usual sync of the wallet that was named,
//! and the usual diff of that sync says what happened. In the apps
//! that owner is [`crate::WalletManager`], whose `live_start` wires
//! the two together; this module can be driven on its own as well.
//!
//! # Transports
//!
//! In the order they are preferred:
//!
//! 1. **Electrum subscriptions.** `blockchain.scripthash.subscribe`
//!    for every watched script and `blockchain.headers.subscribe`, on
//!    one connection. The server pushes a new status the moment a
//!    script gains a mempool transaction, and again when it confirms.
//! 2. **The WebSocket of a mempool instance** (`/api/v1/ws`), for an
//!    Esplora backend that is one. It pushes every block, and
//!    transactions for as many scripts as the server allows on one
//!    connection: ten on the public instances, one by default. The
//!    scripts past that number are covered by polling.
//! 3. **Short polling** of any other Esplora: once a minute, the tip
//!    hash and at most three script lookups, the head of the list every
//!    round and the rest in rotation. About 240 requests an hour.
//!
//! With the automatic public backend, an Electrum server of the
//! catalogue run by an operator that mode already rotates through is
//! tried first, so that push works without a setting. No host is ever
//! contacted that the configured backend does not already name.
//!
//! # What the server learns
//!
//! The scripts of the wallets, which every sync already hands it, and
//! one thing a sync does not: for how long the app stays connected,
//! and from which address. Onion hosts are reached through the same
//! Tor proxy a sync resolves and are refused without one; TLS is
//! checked as a sync checks it, accepted fingerprints included.
//!
//! # Contract
//!
//! - [`LiveWatch::start`] is called inside a tokio runtime and returns
//!   a handle and the single receiver of its events.
//! - The caller owns the list of what is watched and hands it over
//!   again after each sync ([`LiveWatch::set_wallets`]): newly revealed
//!   scripts are subscribed on the open connection, nothing else is
//!   sent again.
//! - [`WatchEvent::WalletChanged`] means "sync this wallet now". With
//!   `rescan` set, the change was seen past the addresses the wallet
//!   has revealed: a sync reads receive addresses that far, and only a
//!   full scan reads change addresses there.
//! - Once the first connection is up and every script it covers has
//!   been read once, every wallet is reported
//!   ([`ChangeReason::Started`]): the sync that follows catches up on
//!   whatever happened while nothing listened. The same after a new
//!   configuration.
//! - A lost connection is reopened with a capped, jittered backoff. An
//!   Electrum server is asked for every status again and only the
//!   scripts whose status moved meanwhile are reported, along with any
//!   it had no status for before; the other transports cannot tell,
//!   and report every wallet once.
//! - Timers stop while a phone sleeps. [`LiveWatch::tick`] is the
//!   entry point a host alarm calls: it measures the pause on the wall
//!   clock, pings at once, and cuts a backoff short.
//! - Start the watcher before the opening sync, so nothing falls
//!   between the two. Stop it when the vault locks.

mod electrum;
mod mempool;
pub(crate) mod net;
mod poll;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use bdk_wallet::bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::chain::tor::TorSettings;
use crate::chain::{self, BackendConfig, Endpoint, TrustedCerts};
use crate::network::Network;

/// Scripts watched for one wallet, past which the tail of its list is
/// left to the regular syncs.
pub const MAX_SCRIPTS_PER_WALLET: usize = 200;
/// Scripts watched in all.
pub const MAX_SCRIPTS: usize = 2_000;
/// The longest script read from a list, in bytes: the consensus limit.
const MAX_SCRIPT_BYTES: usize = 10_000;
/// Events held for a consumer that lags. They coalesce, so a full
/// queue delays an event and never loses a wallet.
const EVENT_QUEUE: usize = 64;

/// Everything the watcher needs to reach the backend, and nothing of
/// the vault: a copy of four settings and the data directory, where
/// the embedded Tor client keeps its state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchConfig {
    pub network: Network,
    pub backend: BackendConfig,
    pub electrum_certs: TrustedCerts,
    pub tor: TorSettings,
    pub data_dir: PathBuf,
    /// Seconds between two keepalive pings; `None` is 240. Electrum
    /// servers drop a session idle for about ten minutes. Held between
    /// 30 and 540.
    #[serde(default)]
    pub keepalive_secs: Option<u32>,
}

/// One script of a watched wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedScript {
    /// The script pubkey, in hex.
    pub script: String,
    /// Past the addresses the wallet has revealed: a change seen here
    /// asks for a full scan, the only sync that reads change addresses
    /// this far.
    pub lookahead: bool,
}

/// One wallet to watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedWallet {
    pub wallet_id: String,
    /// Most likely to move first: a transport that cannot cover them
    /// all covers the head of the list.
    pub scripts: Vec<WatchedScript>,
    /// The wallet holds an unconfirmed transaction, so a new block is
    /// worth a sync on a transport that does not push confirmations.
    pub has_pending: bool,
}

/// Why a wallet is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeReason {
    /// The watch started, or started over under a new configuration:
    /// what happened before it listened is unknown.
    Started,
    /// The connection was lost and reopened, and the transport cannot
    /// say what happened meanwhile.
    Reconnected,
    /// A block arrived while the wallet held an unconfirmed
    /// transaction.
    NewBlock,
    /// The backend reported a change on one of the wallet's scripts.
    Activity,
}

/// What the watcher says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchEvent {
    /// Sync this wallet now; a full scan when `rescan` is set.
    WalletChanged {
        wallet_id: String,
        reason: ChangeReason,
        rescan: bool,
    },
    /// The chain has a new tip.
    NewBlock { height: u32 },
    /// The status changed; also readable at any time from
    /// [`LiveWatch::status`].
    Status(WatchStatus),
}

/// Where the watcher stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchState {
    /// Stopped, or nothing to watch.
    #[default]
    Off,
    /// Opening the first connection.
    Connecting,
    /// A push connection is open.
    Connected,
    /// The connection was lost; the next attempt is scheduled.
    Reconnecting,
    /// No push is available from this backend: it is polled.
    Polling,
}

/// How changes reach the watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchTransport {
    Electrum,
    MempoolWebsocket,
    EsploraPolling,
}

/// What a screen, or a persistent notification, shows about the watch.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WatchStatus {
    pub state: WatchState,
    pub transport: Option<WatchTransport>,
    /// The host in use or being tried, never a full address.
    pub server: Option<String>,
    /// Why the last connection failed, while reconnecting.
    pub detail: Option<String>,
    /// Scripts in the list.
    pub watched_scripts: u32,
    /// Scripts the server pushes changes for; the rest are polled.
    pub pushed_scripts: u32,
}

/// Durations of the watcher, in one place so tests can shorten them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timings {
    /// Quiet time after the last change of a burst before the wallet
    /// is reported.
    pub quiet: Duration,
    /// The longest a burst may hold a report back.
    pub burst: Duration,
    /// The shortest time between two reports of the same wallet: what
    /// a server that floods notifications can cost, at most.
    pub gap: Duration,
    pub keepalive: Duration,
    /// How long a ping may go unanswered.
    pub pong: Duration,
    pub backoff_first: Duration,
    pub backoff_cap: Duration,
    /// A connection that lasted this long resets the backoff.
    pub stable: Duration,
    pub connect: Duration,
    pub tor_connect: Duration,
    pub poll: Duration,
    /// While polling, how often push is tried again.
    pub reprobe: Duration,
    /// For the live alerts ([`crate::live`]): the delays after which a
    /// sync that found nothing behind a pushed change is run again. The
    /// push may come from one server and the sync read another, which
    /// hears of the transaction a moment later.
    pub retries: [Duration; 2],
    /// For the live alerts too: the first wait put before the sync of a
    /// wallet whose pushed changes the syncs keep finding nothing
    /// behind, doubled each time after, up to `hold_cap`.
    pub hold: Duration,
    pub hold_cap: Duration,
}

impl Timings {
    pub(crate) fn of(config: &WatchConfig) -> Self {
        let keepalive = config.keepalive_secs.unwrap_or(240).clamp(30, 540);
        Timings {
            quiet: Duration::from_millis(600),
            burst: Duration::from_secs(2),
            gap: Duration::from_secs(5),
            keepalive: Duration::from_secs(u64::from(keepalive)),
            pong: Duration::from_secs(20),
            backoff_first: Duration::from_secs(2),
            backoff_cap: Duration::from_secs(120),
            stable: Duration::from_secs(60),
            connect: Duration::from_secs(20),
            tor_connect: Duration::from_secs(60),
            poll: Duration::from_secs(60),
            reprobe: Duration::from_secs(30 * 60),
            retries: [Duration::from_secs(3), Duration::from_secs(10)],
            hold: Duration::from_secs(30),
            hold_cap: Duration::from_secs(10 * 60),
        }
    }
}

enum Command {
    Wallets(Vec<WatchedWallet>),
    Reconfigure(Box<WatchConfig>, Vec<WatchedWallet>),
    Tick,
    Stop,
}

/// The handle on a running watcher. Dropping it stops the watcher.
#[derive(Debug)]
pub struct LiveWatch {
    commands: mpsc::UnboundedSender<Command>,
    status: watch::Receiver<WatchStatus>,
    /// Set once to stop the watcher, whatever it is waiting on.
    halt: watch::Sender<bool>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Command::Wallets(_) => "Wallets",
            Command::Reconfigure(..) => "Reconfigure",
            Command::Tick => "Tick",
            Command::Stop => "Stop",
        })
    }
}

/// The single receiver of a watcher's events.
#[derive(Debug)]
pub struct WatchEvents {
    events: mpsc::Receiver<WatchEvent>,
}

impl WatchEvents {
    /// The next event; `None` once the watcher has stopped.
    pub async fn next(&mut self) -> Option<WatchEvent> {
        self.events.recv().await
    }
}

impl LiveWatch {
    /// Starts watching. Must be called inside a tokio runtime, which
    /// the watcher's task then lives on.
    pub fn start(config: WatchConfig, wallets: Vec<WatchedWallet>) -> (LiveWatch, WatchEvents) {
        Self::start_with(config, wallets, None)
    }

    pub(crate) fn start_with(
        config: WatchConfig,
        wallets: Vec<WatchedWallet>,
        timings: Option<Timings>,
    ) -> (LiveWatch, WatchEvents) {
        let fixed_timings = timings.is_some();
        let timings = timings.unwrap_or_else(|| Timings::of(&config));
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (event_tx, events) = mpsc::channel(EVENT_QUEUE);
        let (status_tx, status) = watch::channel(WatchStatus::default());
        let mut hub = Hub {
            config,
            timings,
            watched: Watched::default(),
            commands: command_rx,
            events: event_tx,
            status: status_tx,
            debounce: Debouncer::default(),
            tip: None,
            caught_up: false,
            interrupted: false,
            statuses: HashMap::new(),
            fingerprints: HashMap::new(),
            track_limit: None,
            last_alive: SystemTime::now(),
            fixed_timings,
        };
        hub.watched = Watched::new(wallets);
        let (halt, halted) = watch::channel(false);
        tokio::spawn(watcher(hub, halted));
        (
            LiveWatch {
                commands,
                status,
                halt,
            },
            WatchEvents { events },
        )
    }

    /// Replaces the list of what is watched: after a sync, a wallet
    /// added or removed. Scripts already subscribed stay as they are.
    pub fn set_wallets(&self, wallets: Vec<WatchedWallet>) {
        let _ = self.commands.send(Command::Wallets(wallets));
    }

    /// Another network, another backend, other Tor settings, a newly
    /// accepted certificate: the connection is reopened under them.
    pub fn reconfigure(&self, config: WatchConfig, wallets: Vec<WatchedWallet>) {
        let _ = self
            .commands
            .send(Command::Reconfigure(Box::new(config), wallets));
    }

    /// Checks the connection now. For a host whose timers stop while
    /// it sleeps: called from an alarm, and when the network changes.
    /// Pings at once and gives the answer a short budget, cuts a
    /// backoff short, and runs a poll round that is due. Cheap, and
    /// safe to call at any rate.
    pub fn tick(&self) {
        let _ = self.commands.send(Command::Tick);
    }

    pub fn status(&self) -> WatchStatus {
        if *self.halt.borrow() {
            return WatchStatus::default();
        }
        self.status.borrow().clone()
    }

    /// Stops the watcher and closes its connection, at once: the task
    /// is dropped wherever it waits, a connection being opened, a
    /// server that stopped answering, a Tor circuit being built.
    /// Idempotent.
    pub fn stop(&self) {
        let _ = self.halt.send(true);
        let _ = self.commands.send(Command::Stop);
    }
}

impl Drop for LiveWatch {
    fn drop(&mut self) {
        self.stop();
    }
}

// --- what is watched ------------------------------------------------------

/// One script as the transports need it.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub script: ScriptBuf,
    /// Hex of the script: its key here and on a mempool WebSocket.
    pub hex: String,
    /// The Electrum script hash: SHA-256 of the script, reversed.
    pub scripthash: String,
    pub lookahead: bool,
    /// Indexes into [`Watched::wallets`].
    pub owners: Vec<usize>,
}

/// The list in the order transports cover it: the first script of
/// every wallet, then the second of each, and so on, so that a
/// transport that covers ten scripts covers the head of every wallet.
#[derive(Debug, Default)]
pub(crate) struct Watched {
    pub wallets: Vec<(String, bool)>,
    pub entries: Vec<Entry>,
    by_hex: HashMap<String, usize>,
    by_scripthash: HashMap<String, usize>,
}

impl Watched {
    fn new(wallets: Vec<WatchedWallet>) -> Self {
        use bdk_wallet::bitcoin::hashes::{Hash, sha256};
        let mut watched = Watched {
            wallets: wallets
                .iter()
                .map(|wallet| (wallet.wallet_id.clone(), wallet.has_pending))
                .collect(),
            ..Watched::default()
        };
        let longest = wallets
            .iter()
            .map(|wallet| wallet.scripts.len().min(MAX_SCRIPTS_PER_WALLET))
            .max()
            .unwrap_or(0);
        'ranks: for rank in 0..longest {
            for (owner, wallet) in wallets.iter().enumerate() {
                if rank >= MAX_SCRIPTS_PER_WALLET {
                    break 'ranks;
                }
                let Some(listed) = wallet.scripts.get(rank) else {
                    continue;
                };
                if listed.script.len() > 2 * MAX_SCRIPT_BYTES || listed.script.is_empty() {
                    continue;
                }
                let Ok(script) = ScriptBuf::from_hex(&listed.script) else {
                    continue;
                };
                let hex = listed.script.to_ascii_lowercase();
                if let Some(&index) = watched.by_hex.get(&hex) {
                    let entry = &mut watched.entries[index];
                    if !entry.owners.contains(&owner) {
                        entry.owners.push(owner);
                    }
                    entry.lookahead &= listed.lookahead;
                    continue;
                }
                if watched.entries.len() >= MAX_SCRIPTS {
                    break 'ranks;
                }
                let mut digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
                digest.reverse();
                let scripthash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                watched.by_hex.insert(hex.clone(), watched.entries.len());
                watched
                    .by_scripthash
                    .insert(scripthash.clone(), watched.entries.len());
                watched.entries.push(Entry {
                    script,
                    hex,
                    scripthash,
                    lookahead: listed.lookahead,
                    owners: vec![owner],
                });
            }
        }
        watched
    }

    pub fn by_hex(&self, hex: &str) -> Option<&Entry> {
        self.by_hex.get(hex).map(|&index| &self.entries[index])
    }

    pub fn by_scripthash(&self, scripthash: &str) -> Option<&Entry> {
        self.by_scripthash
            .get(scripthash)
            .map(|&index| &self.entries[index])
    }
}

// --- bursts ---------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Pending {
    first: Instant,
    last: Instant,
    reason: ChangeReason,
    rescan: bool,
}

/// One report per wallet per burst, and never two closer than the gap.
#[derive(Debug, Default)]
struct Debouncer {
    pending: BTreeMap<String, Pending>,
    reported: HashMap<String, Instant>,
}

impl Debouncer {
    fn mark(&mut self, wallet_id: &str, reason: ChangeReason, rescan: bool, now: Instant) {
        self.pending
            .entry(wallet_id.to_owned())
            .and_modify(|pending| {
                pending.last = now;
                pending.reason = pending.reason.max(reason);
                pending.rescan |= rescan;
            })
            .or_insert(Pending {
                first: now,
                last: now,
                reason,
                rescan,
            });
    }

    fn due_at(&self, wallet_id: &str, pending: &Pending, timings: &Timings) -> Instant {
        let settled = (pending.last + timings.quiet).min(pending.first + timings.burst);
        match self.reported.get(wallet_id) {
            Some(reported) => settled.max(*reported + timings.gap),
            None => settled,
        }
    }

    fn next_deadline(&self, timings: &Timings) -> Option<Instant> {
        self.pending
            .iter()
            .map(|(id, pending)| self.due_at(id, pending, timings))
            .min()
    }

    fn take_due(&mut self, now: Instant, timings: &Timings) -> Vec<(String, Pending)> {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(id, pending)| self.due_at(id, pending, timings) <= now)
            .map(|(id, _)| id.clone())
            .collect();
        due.into_iter()
            .filter_map(|id| self.pending.remove(&id).map(|pending| (id, pending)))
            .collect()
    }
}

/// Capped exponential backoff, each delay drawn between half of it and
/// all of it so a fleet of clients does not come back in step.
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Backoff {
    fn delay(&mut self, timings: &Timings) -> Duration {
        let base = self.next.max(timings.backoff_first);
        self.next = (base * 2).min(timings.backoff_cap);
        base.mul_f64(0.5 + rand::random::<f64>() / 2.0)
    }

    fn reset(&mut self) {
        self.next = Duration::ZERO;
    }
}

// --- the hub --------------------------------------------------------------

/// How a session, or a wait, ended.
#[derive(Debug)]
pub(crate) enum Exit {
    Stop,
    Reconfigured,
    /// Try the transports again now: polling gives push another chance.
    Reprobe,
    /// A session was open and ended.
    Lost(String),
    /// No session could be opened with this server.
    Unreachable(String),
    /// The server is there and offers no push (a WebSocket upgrade
    /// answered with an HTTP refusal).
    NoPush(String),
}

/// What a session is woken for, besides its socket.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    Stop,
    Reconfigured,
    /// The list changed.
    Wallets,
    /// The host asks for a liveness check. `idle` is the time since the
    /// last sign of life on the wall clock, which keeps running while a
    /// device sleeps and its timers do not.
    Tick {
        idle: Duration,
    },
    /// Due reports were sent; nothing for the session to do.
    Flushed,
}

/// The state every transport shares and that outlives a connection.
pub(crate) struct Hub {
    pub config: WatchConfig,
    pub timings: Timings,
    pub watched: Watched,
    commands: mpsc::UnboundedReceiver<Command>,
    events: mpsc::Sender<WatchEvent>,
    status: watch::Sender<WatchStatus>,
    debounce: Debouncer,
    tip: Option<u32>,
    /// Every wallet was reported once under this configuration, when
    /// its first session was ready.
    pub caught_up: bool,
    /// A session was lost since the last one was ready.
    pub interrupted: bool,
    /// Electrum statuses by script hash: the baseline a reconnection is
    /// compared against.
    pub statuses: HashMap<String, Option<String>>,
    /// Esplora counters by script hex: the same for polling.
    pub fingerprints: HashMap<String, poll::Fingerprint>,
    /// Scripts a mempool instance said it tracks per connection.
    pub track_limit: Option<usize>,
    /// Wall clock of the last sign of life, to measure a suspension.
    last_alive: SystemTime,
    /// Timings given by a test, which a new configuration leaves alone.
    fixed_timings: bool,
}

impl Hub {
    pub fn set_status(&mut self, change: impl FnOnce(&mut WatchStatus)) {
        let mut next = self.status.borrow().clone();
        change(&mut next);
        next.watched_scripts = self.watched.entries.len() as u32;
        if *self.status.borrow() == next {
            return;
        }
        let _ = self.status.send(next.clone());
        let _ = self.events.try_send(WatchEvent::Status(next));
    }

    /// A script moved: its wallets are reported once the burst settles.
    pub fn mark_entry(&mut self, entry_hex: &str, reason: ChangeReason) {
        let Some(entry) = self.watched.by_hex(entry_hex) else {
            return;
        };
        let lookahead = entry.lookahead;
        let owners: Vec<String> = entry
            .owners
            .iter()
            .filter_map(|&owner| self.watched.wallets.get(owner))
            .map(|(id, _)| id.clone())
            .collect();
        let now = Instant::now();
        for id in owners {
            self.debounce.mark(&id, reason, lookahead, now);
        }
    }

    pub fn mark_all(&mut self, reason: ChangeReason) {
        let now = Instant::now();
        for (id, _) in &self.watched.wallets {
            self.debounce.mark(id, reason, false, now);
        }
    }

    /// A tip was read. The first one is a baseline; a higher one after
    /// that is a block, and `sync_pending` says whether wallets waiting
    /// for a confirmation are worth a sync on this transport. A lower
    /// one is a server that lags, or one of several behind an address.
    pub fn new_tip(&mut self, height: u32, sync_pending: bool) {
        let Some(previous) = self.tip else {
            self.tip = Some(height);
            return;
        };
        if height <= previous {
            return;
        }
        self.tip = Some(height);
        let _ = self.events.try_send(WatchEvent::NewBlock { height });
        if sync_pending {
            let now = Instant::now();
            for (id, has_pending) in &self.watched.wallets {
                if *has_pending {
                    self.debounce.mark(id, ChangeReason::NewBlock, false, now);
                }
            }
        }
    }

    /// A session is up and has read every script it covers once. The
    /// first one under a configuration reports every wallet, so the
    /// syncs that follow catch up on what happened before anything
    /// listened. One after a lost connection does the same when the
    /// transport cannot say what it missed (`exact` false).
    pub fn ready(&mut self, exact: bool) {
        if !self.caught_up {
            self.caught_up = true;
            self.mark_all(ChangeReason::Started);
        } else if self.interrupted && !exact {
            self.mark_all(ChangeReason::Reconnected);
        }
        self.interrupted = false;
    }

    /// Notes a sign of life from the server.
    pub fn alive(&mut self) {
        self.last_alive = SystemTime::now();
    }

    fn flush(&mut self) {
        for (wallet_id, pending) in self.debounce.take_due(Instant::now(), &self.timings) {
            let event = WatchEvent::WalletChanged {
                wallet_id: wallet_id.clone(),
                reason: pending.reason,
                rescan: pending.rescan,
            };
            match self.events.try_send(event) {
                Ok(()) => {
                    self.debounce.reported.insert(wallet_id, Instant::now());
                }
                // The consumer lags: the wallet stays marked and goes
                // out with the next flush.
                Err(_) => {
                    let now = Instant::now();
                    self.debounce
                        .mark(&wallet_id, pending.reason, pending.rescan, now);
                }
            }
        }
    }

    /// Waits for whatever concerns a session besides its socket. Cancel
    /// safe: a command is applied in the same poll that receives it.
    pub async fn wake(&mut self) -> Wake {
        let deadline = self.debounce.next_deadline(&self.timings);
        tokio::select! {
            command = self.commands.recv() => match command {
                None | Some(Command::Stop) => Wake::Stop,
                Some(Command::Reconfigure(config, wallets)) => {
                    if !self.fixed_timings {
                        self.timings = Timings::of(&config);
                    }
                    self.config = *config;
                    self.watched = Watched::new(wallets);
                    self.forget_baselines();
                    Wake::Reconfigured
                }
                Some(Command::Wallets(wallets)) => {
                    self.watched = Watched::new(wallets);
                    let kept: HashSet<&String> =
                        self.watched.wallets.iter().map(|(id, _)| id).collect();
                    self.debounce.pending.retain(|id, _| kept.contains(id));
                    self.debounce.reported.retain(|id, _| kept.contains(id));
                    self.set_status(|_| {});
                    Wake::Wallets
                }
                Some(Command::Tick) => {
                    let idle = self.last_alive.elapsed().unwrap_or_default();
                    Wake::Tick { idle }
                }
            },
            () = sleep_until(deadline), if deadline.is_some() => {
                self.flush();
                Wake::Flushed
            }
            () = self.events.closed() => Wake::Stop,
        }
    }

    fn forget_baselines(&mut self) {
        self.tip = None;
        self.caught_up = false;
        self.interrupted = false;
        self.statuses.clear();
        self.fingerprints.clear();
        self.track_limit = None;
        self.debounce = Debouncer::default();
    }

    /// Waits out a delay, or for ever without one, while commands and
    /// due reports are still served. `None` when the delay ran out or
    /// the host ticked; the exit otherwise.
    async fn idle(&mut self, delay: Option<Duration>) -> Option<Exit> {
        let until = delay.map(|delay| Instant::now() + delay);
        loop {
            tokio::select! {
                wake = self.wake() => match wake {
                    Wake::Stop => return Some(Exit::Stop),
                    Wake::Reconfigured => return Some(Exit::Reconfigured),
                    // A list that arrives while nothing is watched is
                    // the end of that wait; a tick ends any wait.
                    Wake::Wallets if until.is_none() => return None,
                    Wake::Tick { .. } => return None,
                    Wake::Wallets | Wake::Flushed => {}
                },
                () = sleep_until(until), if until.is_some() => return None,
            }
        }
    }

    /// Runs `work`, which must not need the hub, while commands are
    /// still served; a stop or a new configuration ends it early.
    pub async fn during<T>(&mut self, work: impl Future<Output = T>) -> Result<T, Exit> {
        tokio::pin!(work);
        loop {
            tokio::select! {
                output = &mut work => return Ok(output),
                wake = self.wake() => match wake {
                    Wake::Stop => return Err(Exit::Stop),
                    Wake::Reconfigured => return Err(Exit::Reconfigured),
                    Wake::Wallets | Wake::Tick { .. } | Wake::Flushed => {}
                },
            }
        }
    }

    /// The Tor proxy for this endpoint: resolved when it is an onion,
    /// `None` otherwise. A failure is a lost connection like any other,
    /// and never a reason to go around Tor.
    pub async fn proxy_for(&mut self, endpoint: &Endpoint) -> Result<Option<String>, Exit> {
        if !endpoint.is_onion() {
            return Ok(None);
        }
        let settings = self.config.tor.clone();
        let data_dir = self.config.data_dir.clone();
        let route = self
            .during(async move { chain::tor::resolve(&settings, &data_dir).await })
            .await?;
        match route {
            Ok(route) => Ok(Some(route.proxy())),
            Err(error) => Err(Exit::Lost(error.to_string())),
        }
    }

    /// How long a ping may go unanswered: three times as long through
    /// Tor, where a circuit can stall and recover.
    pub fn pong_budget(&self, endpoint: &Endpoint) -> Duration {
        if endpoint.is_onion() {
            self.timings.pong * 3
        } else {
            self.timings.pong
        }
    }

    pub fn connect_budget(&self, endpoint: &Endpoint) -> Duration {
        if endpoint.is_onion() {
            self.timings.tor_connect
        } else {
            self.timings.connect
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

// --- the supervisor ---------------------------------------------------------

/// The servers to try, in order. An automatic public backend names no
/// server: an Electrum server of the catalogue comes first when its
/// operator is one the rotation already goes through, because it can
/// push every script, and the rotation itself follows.
fn candidates(config: &WatchConfig) -> Result<Vec<Endpoint>, String> {
    let mut endpoints = chain::endpoints(&config.backend, config.network, &config.electrum_certs)
        .map_err(|e| e.to_string())?;
    if config.backend == (BackendConfig::Public { server: None }) {
        let operators: Vec<String> = endpoints.iter().map(Endpoint::label).collect();
        let pushing: Vec<Endpoint> = chain::public::public_servers(config.network)
            .into_iter()
            .filter(|server| {
                server.protocol == chain::public::ServerProtocol::Electrum && !server.self_signed
            })
            .filter(|server| {
                chain::host_of(&server.url).is_some_and(|host| {
                    operators.iter().any(|operator| {
                        host == *operator || host.ends_with(&format!(".{operator}"))
                    })
                })
            })
            .filter_map(|server| {
                let chosen = BackendConfig::Public {
                    server: Some(server.id),
                };
                chain::endpoints(&chosen, config.network, &config.electrum_certs)
                    .ok()?
                    .into_iter()
                    .next()
            })
            .take(1)
            .collect();
        endpoints.splice(0..0, pushing);
    }
    Ok(endpoints)
}

/// The task of a watcher: the supervisor, cut short the moment the
/// handle asks it to stop, wherever it waits. Whatever it held, sockets
/// included, is dropped there and then.
async fn watcher(mut hub: Hub, mut halted: watch::Receiver<bool>) {
    tokio::select! {
        () = supervise(&mut hub) => {}
        // A dropped handle stops the watcher too.
        _ = halted.wait_for(|halt| *halt) => {}
    }
    hub.watched = Watched::default();
    hub.set_status(|status| *status = WatchStatus::default());
}

async fn supervise(hub: &mut Hub) {
    let mut backoff = Backoff {
        next: Duration::ZERO,
    };
    // When push was last found missing on every Esplora endpoint.
    let mut no_push: Option<Instant> = None;
    loop {
        if hub.watched.entries.is_empty() {
            hub.set_status(|status| *status = WatchStatus::default());
            match hub.idle(None).await {
                Some(Exit::Stop) => break,
                _ => continue,
            }
        }
        let started = Instant::now();
        let exit = match candidates(&hub.config) {
            Ok(endpoints) => run_once(hub, &endpoints, &mut no_push).await,
            Err(detail) => Exit::Lost(detail),
        };
        match exit {
            Exit::Stop => break,
            Exit::Reconfigured => {
                backoff.reset();
                no_push = None;
            }
            Exit::Reprobe => no_push = None,
            exit @ (Exit::Lost(_) | Exit::Unreachable(_) | Exit::NoPush(_)) => {
                if started.elapsed() >= hub.timings.stable {
                    backoff.reset();
                }
                let delay = backoff.delay(&hub.timings);
                // Without a session, the transport last tried is not one
                // in use.
                let established = matches!(exit, Exit::Lost(_));
                hub.interrupted |= established;
                let (Exit::Lost(detail) | Exit::Unreachable(detail) | Exit::NoPush(detail)) = exit
                else {
                    continue;
                };
                hub.set_status(|status| {
                    if !established {
                        status.transport = None;
                    }
                    status.state = WatchState::Reconnecting;
                    status.detail = Some(detail);
                    status.pushed_scripts = 0;
                });
                match hub.idle(Some(delay)).await {
                    Some(Exit::Stop) => break,
                    Some(Exit::Reconfigured) => {
                        backoff.reset();
                        no_push = None;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// One pass over the candidates: the first that holds a session keeps
/// it until it ends.
async fn run_once(hub: &mut Hub, endpoints: &[Endpoint], no_push: &mut Option<Instant>) -> Exit {
    let mut last = Exit::Lost("no backend to watch".to_owned());
    let mut esplora: Vec<&Endpoint> = Vec::new();
    for endpoint in endpoints {
        match endpoint {
            Endpoint::Electrum(target) => {
                let target = target.clone();
                match electrum::run(hub, endpoint, &target).await {
                    // The next candidate may do.
                    Exit::Unreachable(detail) => last = Exit::Unreachable(detail),
                    exit => return exit,
                }
            }
            Endpoint::Esplora(_) => esplora.push(endpoint),
        }
    }
    let push_worth_trying = no_push.is_none_or(|at| at.elapsed() >= hub.timings.reprobe);
    if push_worth_trying {
        for endpoint in &esplora {
            let Endpoint::Esplora(url) = endpoint else {
                continue;
            };
            match mempool::run(hub, endpoint, url).await {
                exit @ (Exit::NoPush(_) | Exit::Unreachable(_)) => last = exit,
                exit => return exit,
            }
        }
        *no_push = Some(Instant::now());
    }
    for endpoint in &esplora {
        let Endpoint::Esplora(url) = endpoint else {
            continue;
        };
        match poll::run(hub, endpoint, url).await {
            exit @ Exit::Unreachable(_) => last = exit,
            exit => return exit,
        }
    }
    last
}
