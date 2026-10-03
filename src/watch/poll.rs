//! Short polling of an Esplora server: what is left when nothing can
//! push.
//!
//! A round is the tip hash and at most [`ROUND_BUDGET`] script
//! lookups, one after the other, about once a minute: some 240 requests
//! an hour, whatever the size of the wallets, and the syncs need their
//! share of what a public server allows. The first [`HOT`] scripts of
//! the list, the head of every wallet, are looked up every round; the
//! rest take turns. A lookup reads the counters of
//! `/scripthash/:hash`, which move when a transaction enters the
//! mempool and again when it confirms.
//!
//! No public server says how many requests it allows: mempool.space
//! bans a client that keeps going past its limit, blockstream.info has
//! limited its free access since April 2026. One that limits the rate
//! (HTTP 429) is asked less often ([`Pace`]): each time it does, the
//! wait between rounds doubles, up to ten minutes, never shorter than
//! the wait it named, and comes back to a minute half an hour after the
//! last time. A round it turned away is no failure of the server.

use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::ScriptBuf;
use tokio::time::Instant;

use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport, Watched};
use crate::chain::esplora::{self, Client};
use crate::chain::{ANOTHER_NETWORK, Endpoint};

/// Script lookups in one round.
pub(super) const ROUND_BUDGET: usize = 3;
/// Scripts looked up every round; the rest of the budget rotates.
pub(super) const HOT: usize = 2;
/// Rounds that may fail in a row before the server counts as lost.
const FAILED_ROUNDS: u32 = 3;
/// What a whole round may take.
const ROUND_TIMEOUT: Duration = Duration::from_secs(45);
/// The longest wait between two rounds, however often the server limited
/// the rate of requests.
const SLOWEST: Duration = Duration::from_secs(10 * 60);
/// How long after the last limit the server set the rounds stay slowed.
const SLOWED_FOR: Duration = Duration::from_secs(30 * 60);

/// How often rounds come: see the module documentation.
#[derive(Debug, Default)]
pub(super) struct Pace {
    /// Times the wait doubled.
    slowed: u32,
    /// When the server last limited the rate of requests.
    limited_at: Option<Instant>,
    /// No round before this: the wait the server named.
    not_before: Option<Instant>,
}

impl Pace {
    /// The server limited the rate of requests, and asked for `pause`.
    pub(super) fn limited(&mut self, pause: Duration, now: Instant) {
        self.slowed = self.slowed.saturating_add(1).min(16);
        self.limited_at = Some(now);
        self.not_before = Some(now + pause);
    }

    /// The wait before the next round, `every` being the usual one, a
    /// little more or less so that clients do not fall in step.
    pub(super) fn wait(&mut self, every: Duration, now: Instant) -> Duration {
        if self
            .limited_at
            .is_some_and(|at| now.saturating_duration_since(at) >= SLOWED_FOR)
        {
            self.slowed = 0;
            self.limited_at = None;
        }
        let slowed = every
            .saturating_mul(1 << self.slowed)
            .min(SLOWEST.max(every));
        let wait = slowed.mul_f64(0.85 + 0.3 * rand::random::<f64>());
        let named = self
            .not_before
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now));
        wait.max(named)
    }
}

/// The counters of a script: transactions in the chain and in the
/// mempool, and the coins they moved. Any difference is a change.
pub(crate) type Fingerprint = crate::chain::esplora::Counts;

/// Picks the scripts of each round and looks them up.
pub(super) struct Poller {
    client: Arc<Client>,
    cursor: usize,
}

/// The scripts of one round, owned so the lookups can run while the
/// hub serves commands.
pub(super) struct Plan {
    client: Arc<Client>,
    scripts: Vec<(String, ScriptBuf)>,
}

impl Poller {
    pub(super) fn new(base: &str, proxy: Option<&str>) -> Result<Self, String> {
        Ok(Poller {
            client: Arc::new(esplora::client(base, proxy)?),
            cursor: 0,
        })
    }

    /// The longest wait the server asked for since this was last called,
    /// if it limited the rate of requests meanwhile.
    pub(super) fn take_rate_limit(&self) -> Option<Duration> {
        self.client.take_rate_limit()
    }

    /// The scripts of the next round, among those past the first
    /// `skip`, which a push connection already covers.
    pub(super) fn plan(&mut self, watched: &Watched, skip: usize, hot: usize) -> Plan {
        let pool = watched.entries.get(skip..).unwrap_or_default();
        let hot = hot.min(pool.len()).min(ROUND_BUDGET);
        let mut picked: Vec<&super::Entry> = pool[..hot].iter().collect();
        let rest = &pool[hot..];
        let turns = (ROUND_BUDGET - hot).min(rest.len());
        for turn in 0..turns {
            picked.push(&rest[(self.cursor + turn) % rest.len()]);
        }
        if !rest.is_empty() {
            self.cursor = (self.cursor + turns) % rest.len();
        }
        Plan {
            client: self.client.clone(),
            scripts: picked
                .into_iter()
                .map(|entry| (entry.hex.clone(), entry.script.clone()))
                .collect(),
        }
    }
}

impl Plan {
    /// Looks the scripts up, one after the other.
    pub(super) async fn check(self) -> Result<Vec<(String, Fingerprint)>, String> {
        let lookups = async {
            let mut found = Vec::with_capacity(self.scripts.len());
            for (hex, script) in &self.scripts {
                let stats = self.client.scripthash_stats(script).await?;
                found.push((hex.clone(), Fingerprint::of(&stats)));
            }
            Ok(found)
        };
        tokio::time::timeout(ROUND_TIMEOUT, lookups)
            .await
            .unwrap_or_else(|_| Err("timed out".to_owned()))
    }
}

/// Refuses a server of another network before it hears of any script,
/// from its genesis block: it would report changes that never happened
/// on the wallet's.
pub(super) async fn same_network(hub: &mut Hub, poller: &Poller) -> Result<(), Exit> {
    let client = poller.client.clone();
    let network = hub.config.network;
    match hub
        .during(async move { esplora::check_network(&client, network).await })
        .await?
    {
        Ok(()) => Ok(()),
        Err(detail) if detail == ANOTHER_NETWORK => Err(Exit::Refused(detail)),
        Err(detail) => Err(Exit::Unreachable(detail)),
    }
}

/// Compares what a round found with what was known: a reading that
/// differs from the one before is a change. The first reading of a
/// script is compared with what its wallets hold instead: the list
/// takes turns, a script may be read for the first time an hour into a
/// watch, and what arrived meanwhile must not become its baseline.
pub(super) fn apply(hub: &mut Hub, found: Vec<(String, Fingerprint)>) {
    for (hex, fingerprint) in found {
        let Some(entry) = hub.watched.by_hex(&hex) else {
            continue;
        };
        let lacking = entry
            .counts
            .iter()
            .any(|held| held.is_some_and(|held| held != fingerprint));
        match hub.fingerprints.insert(hex.clone(), fingerprint) {
            Some(known) if known != fingerprint => hub.mark_entry(&hex, ChangeReason::Activity),
            None if lacking => hub.mark_entry(&hex, ChangeReason::Activity),
            _ => {}
        }
    }
    let watched = &hub.watched;
    hub.fingerprints
        .retain(|hex, _| watched.by_hex(hex).is_some());
}

pub(super) async fn run(hub: &mut Hub, endpoint: &Endpoint, base: &str) -> Exit {
    let label = endpoint.label();
    let proxy = match hub.proxy_for(endpoint).await {
        Ok(proxy) => proxy,
        Err(Exit::Lost(detail)) => return Exit::Unreachable(detail),
        Err(exit) => return exit,
    };
    let mut poller = match Poller::new(base, proxy.as_deref()) {
        Ok(poller) => poller,
        Err(detail) => return Exit::Unreachable(detail),
    };
    if let Err(exit) = same_network(hub, &poller).await {
        return exit;
    }
    let mut tip: Option<String> = None;
    let mut failed = 0u32;
    let mut pace = Pace::default();
    let started = Instant::now();
    loop {
        // One round: the tip, then the scripts.
        let client = poller.client.clone();
        let plan = poller.plan(&hub.watched, 0, HOT);
        let known_tip = tip.clone();
        let round = async move {
            let hash = client.tip_hash().await?.to_string();
            let height = if known_tip.as_deref() == Some(hash.as_str()) {
                None
            } else {
                Some(client.height().await?)
            };
            Ok::<_, String>((hash, height, plan.check().await?))
        };
        let outcome = hub.during(round).await;
        let limited = poller.take_rate_limit();
        if let Some(pause) = limited {
            pace.limited(pause, Instant::now());
        }
        match outcome {
            Err(exit) => return exit,
            Ok(Ok((hash, height, found))) => {
                failed = 0;
                hub.alive();
                let first_round = tip.is_none();
                tip = Some(hash);
                if let Some(height) = height {
                    hub.new_tip(height, true);
                }
                apply(hub, found);
                // Polling reads a few scripts a round and cannot say what
                // the others did before: at the start, and after a loss,
                // every wallet is worth one sync.
                if first_round {
                    hub.ready(false);
                }
                hub.serve(Some(endpoint));
                hub.set_status(|status| {
                    status.state = WatchState::Polling;
                    status.transport = Some(WatchTransport::EsploraPolling);
                    status.server = Some(label.clone());
                    status.detail = None;
                    status.pushed_scripts = 0;
                });
            }
            // Turned away for asking too often: the server is there, and
            // the next round comes later.
            Ok(Err(detail)) if limited.is_some() => {
                hub.set_status(|status| status.detail = Some(detail));
            }
            Ok(Err(detail)) => {
                failed += 1;
                if tip.is_none() {
                    return Exit::Unreachable(detail);
                }
                if failed >= FAILED_ROUNDS {
                    return Exit::Lost(detail);
                }
            }
        }
        if started.elapsed() >= hub.timings.reprobe {
            return Exit::Reprobe;
        }
        // The next round; a tick from the host runs it now if it is due.
        let wait = pace.wait(hub.timings.poll, Instant::now());
        let until = Instant::now() + wait;
        let waiting = std::time::SystemTime::now();
        loop {
            tokio::select! {
                wake = hub.wake() => match wake {
                    Wake::Stop => return Exit::Stop,
                    Wake::Reconfigured => return Exit::Reconfigured,
                    // Timers stopped with the device: the round is due
                    // by the wall clock.
                    Wake::Tick { .. } if waiting.elapsed().unwrap_or_default() >= wait => break,
                    Wake::Wallets if hub.watched.entries.is_empty() => return Exit::Reprobe,
                    Wake::Tick { .. } | Wake::Wallets | Wake::Flushed => {}
                },
                () = tokio::time::sleep_until(until) => break,
            }
        }
    }
}
