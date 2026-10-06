//! Short polling of an Esplora server: what is left when nothing can
//! push.
//!
//! A round is the tip hash and at most [`ROUND_BUDGET`] script
//! lookups, one after the other, about once a minute: some 240 requests
//! an hour, whatever the size of the wallets, and the syncs need their
//! share of what a public server allows. The first [`HOT`] scripts of
//! the list are looked up every round, and the rest take turns with
//! what the budget leaves: one a round, so that with N scripts past
//! those two each is read about every N minutes, and every one of them
//! at the next regular sync. Past what a mempool instance pushes, no
//! script is looked up every round, and the three take turns: every
//! N/3 minutes. Every minute for each would be N requests a minute,
//! which no public server would take from every client. A lookup reads
//! the counters of `/scripthash/:hash`, which move when a transaction
//! enters the mempool and again when it confirms. The turns are the
//! list's, not a session's ([`Turns`]): a session that ends, every half
//! hour to try push again, leaves the next one to go on from the script
//! whose turn it was, so the whole list is read and not the same thirty
//! scripts after each start.
//!
//! The user's own node ([`crate::chain::BackendConfig::is_own_node`])
//! answers nobody else, and a round there looks up
//! [`OWN_NODE_ROUND_BUDGET`] scripts, a few at a time: every N/28
//! minutes each, every N/30 past what a mempool instance pushes.
//!
//! No public server says how many requests it allows: mempool.space
//! bans a client that keeps going past its limit, blockstream.info has
//! limited its free access since April 2026. One that limits the rate
//! (HTTP 429) is asked less often ([`Pace`]): each time it does, the
//! wait between rounds doubles, up to ten minutes, never shorter than
//! the wait it named, and comes back to a minute half an hour after the
//! last time. A round it turned away is no failure of the server. The
//! pace is the server's, not a session's: a session that ends, every
//! half hour to try push again, or on a lost connection, leaves it to
//! the next one, which asks nothing of that server before the round
//! the last one had in view.

use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::ScriptBuf;
use tokio::time::Instant;

use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport, Watched};
use crate::chain::esplora::{self, Client};
use crate::chain::{ANOTHER_NETWORK, Endpoint};

/// Script lookups in one round.
pub(super) const ROUND_BUDGET: usize = 3;
/// Script lookups in one round on the user's own node, and how many go
/// out at once there: a round over Tor stays well within its time.
pub(super) const OWN_NODE_ROUND_BUDGET: usize = 30;
const OWN_NODE_AT_ONCE: usize = 4;
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
    /// When the next round is due, as the last wait set it.
    due: Option<Instant>,
}

impl Pace {
    /// The server limited the rate of requests, and asked for `pause`.
    pub(super) fn limited(&mut self, pause: Duration, now: Instant) {
        self.slowed = self.slowed.saturating_add(1).min(16);
        self.limited_at = Some(now);
        self.not_before = Some(now + pause);
    }

    /// How long a session that opens at `now` waits before it asks the
    /// server anything: until the round the last wait set, and the end
    /// of the wait the server named.
    pub(super) fn first_wait(&self, now: Instant) -> Duration {
        self.due
            .max(self.not_before)
            .map_or(Duration::ZERO, |due| due.saturating_duration_since(now))
    }

    /// The wait before the next round, `every` being the usual one, a
    /// little more or less so that clients do not fall in step. The
    /// round is due at its end, for this session or the next.
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
        let wait = wait.max(named);
        self.due = Some(now + wait);
        wait
    }
}

/// The counters of a script: transactions in the chain and in the
/// mempool, and the coins they moved. Any difference is a change.
pub(crate) type Fingerprint = crate::chain::esplora::Counts;

/// Where the scripts that take turns stand: kept by the hub from one
/// session to the next, and from one transport to the other.
#[derive(Debug, Default)]
pub(super) struct Turns {
    /// The script whose turn is next, by its hex.
    next: Option<String>,
    /// Where that script stood among those taking turns: the turns go on
    /// from there when it has left the list.
    at: usize,
}

impl Turns {
    /// Where the next turn falls among `rest`: on the script it was left
    /// on, wherever a change of the list put it. Gone with its wallet,
    /// the turn falls where it stood, or back at the head when the list
    /// no longer reaches that far.
    fn first(&self, rest: &[super::Entry]) -> usize {
        self.next
            .as_deref()
            .and_then(|hex| rest.iter().position(|entry| entry.hex == hex))
            .unwrap_or(if self.at < rest.len() { self.at } else { 0 })
    }
}

/// Picks the scripts of each round and looks them up.
pub(super) struct Poller {
    client: Arc<Client>,
    /// Lookups in a round.
    budget: usize,
    /// Lookups that go out at once.
    at_once: usize,
}

/// The scripts of one round, owned so the lookups can run while the
/// hub serves commands.
pub(super) struct Plan {
    client: Arc<Client>,
    scripts: Vec<(String, ScriptBuf)>,
    at_once: usize,
}

impl Poller {
    /// A poller of the server at `base`, which is the user's own node
    /// when `own_node` is.
    pub(super) fn new(base: &str, proxy: Option<&str>, own_node: bool) -> Result<Self, String> {
        let (budget, at_once) = if own_node {
            (OWN_NODE_ROUND_BUDGET, OWN_NODE_AT_ONCE)
        } else {
            (ROUND_BUDGET, 1)
        };
        Ok(Poller {
            client: Arc::new(esplora::client(base, proxy)?),
            budget,
            at_once,
        })
    }

    /// The longest wait the server asked for since this was last called,
    /// if it limited the rate of requests meanwhile.
    pub(super) fn take_rate_limit(&self) -> Option<Duration> {
        self.client.take_rate_limit()
    }

    /// The scripts of the next round, among those past the first
    /// `skip`, which a push connection already covers: the first `hot`
    /// of them, then the next ones in turn, `turns` moving past them.
    pub(super) fn plan(
        &self,
        watched: &Watched,
        turns: &mut Turns,
        skip: usize,
        hot: usize,
    ) -> Plan {
        let pool = watched.entries.get(skip..).unwrap_or_default();
        let hot = hot.min(pool.len()).min(self.budget);
        let mut picked: Vec<&super::Entry> = pool[..hot].iter().collect();
        let rest = &pool[hot..];
        if !rest.is_empty() {
            let first = turns.first(rest);
            let count = (self.budget - hot).min(rest.len());
            for turn in 0..count {
                picked.push(&rest[(first + turn) % rest.len()]);
            }
            let at = (first + count) % rest.len();
            *turns = Turns {
                next: Some(rest[at].hex.clone()),
                at,
            };
        }
        Plan {
            client: self.client.clone(),
            scripts: picked
                .into_iter()
                .map(|entry| (entry.hex.clone(), entry.script.clone()))
                .collect(),
            at_once: self.at_once,
        }
    }
}

impl Plan {
    /// Looks the scripts up: one after the other on any server, a few at
    /// a time on the user's own node.
    pub(super) async fn check(self) -> Result<Vec<(String, Fingerprint)>, String> {
        use futures_util::{StreamExt, TryStreamExt};
        let Plan {
            client,
            scripts,
            at_once,
        } = self;
        let lookups = futures_util::stream::iter(scripts)
            .map(move |(hex, script)| {
                let client = client.clone();
                async move {
                    let stats = client.scripthash_stats(&script).await?;
                    Ok::<_, String>((hex, Fingerprint::of(&stats)))
                }
            })
            .buffered(at_once)
            .try_collect::<Vec<_>>();
        tokio::time::timeout(ROUND_TIMEOUT, lookups)
            .await
            .unwrap_or_else(|_| Err("timed out".to_owned()))
    }
}

/// Opens a session with the server at `endpoint`: waits for the round
/// its pace has in view, if an earlier session left one, then refuses a
/// server of another network before it hears of any script, from its
/// genesis block: it would report changes that never happened on the
/// wallet's.
pub(super) async fn same_network(
    hub: &mut Hub,
    endpoint: &Endpoint,
    poller: &Poller,
) -> Result<(), Exit> {
    let first = hub.pace(endpoint).first_wait(Instant::now());
    rest(hub, first).await?;
    let client = poller.client.clone();
    let network = hub.config.network;
    let checked = hub
        .during(async move { esplora::check_network(&client, network).await })
        .await?;
    if let Some(pause) = poller.take_rate_limit() {
        hub.pace(endpoint).limited(pause, Instant::now());
    }
    match checked {
        Ok(()) => Ok(()),
        Err(detail) if detail == ANOTHER_NETWORK => Err(Exit::Refused(detail)),
        Err(detail) => Err(Exit::Unreachable(detail)),
    }
}

/// Waits `wait` before the next request; a tick from the host ends the
/// wait as soon as it is over by the wall clock, timers having stopped
/// with the device. An error is the session ending instead.
async fn rest(hub: &mut Hub, wait: Duration) -> Result<(), Exit> {
    if wait.is_zero() {
        return Ok(());
    }
    let until = Instant::now() + wait;
    let waiting = std::time::SystemTime::now();
    loop {
        tokio::select! {
            wake = hub.wake() => match wake {
                Wake::Stop => return Err(Exit::Stop),
                Wake::Reconfigured => return Err(Exit::Reconfigured),
                Wake::Tick { .. } if waiting.elapsed().unwrap_or_default() >= wait => return Ok(()),
                Wake::Wallets if hub.watched.entries.is_empty() => return Err(Exit::Reprobe),
                Wake::Tick { .. } | Wake::Wallets | Wake::Flushed => {}
            },
            () = tokio::time::sleep_until(until) => return Ok(()),
        }
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
    let poller = match Poller::new(base, proxy.as_deref(), hub.config.backend.is_own_node()) {
        Ok(poller) => poller,
        Err(detail) => return Exit::Unreachable(detail),
    };
    if let Err(exit) = same_network(hub, endpoint, &poller).await {
        return exit;
    }
    let mut tip: Option<String> = None;
    let mut failed = 0u32;
    let started = Instant::now();
    loop {
        // One round: the tip, then the scripts.
        let client = poller.client.clone();
        let plan = poller.plan(&hub.watched, &mut hub.turns, 0, HOT);
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
            hub.pace(endpoint).limited(pause, Instant::now());
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
                    status.server_software = None;
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
        // The next round, set before the session may end: the next
        // session keeps to it.
        let every = hub.timings.poll;
        let wait = hub.pace(endpoint).wait(every, Instant::now());
        if started.elapsed() >= hub.timings.reprobe {
            return Exit::Reprobe;
        }
        if let Err(exit) = rest(hub, wait).await {
            return exit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch::{WatchLimits, WatchedScript, WatchedWallet};

    /// A wallet of `count` scripts, numbered from `from` in `tag`.
    fn wallet(id: &str, tag: u8, from: u32, count: u32) -> WatchedWallet {
        WatchedWallet {
            wallet_id: id.to_owned(),
            scripts: (from..from + count)
                .map(|n| WatchedScript {
                    script: format!("0014{tag:02x}{n:038x}"),
                    lookahead: false,
                    status: None,
                    counts: None,
                })
                .collect(),
            has_pending: false,
            pinned: false,
            holds_coins: false,
            unlisted: 0,
        }
    }

    fn poller(own_node: bool) -> Poller {
        Poller::new("http://127.0.0.1:9/api", None, own_node).unwrap()
    }

    /// A round reads three scripts on any server, the head of the list
    /// and one in turn, and thirty on the user's own node, a few at a
    /// time; past the head, every script is read in its turn.
    #[test]
    fn a_round_reads_so_many_scripts() {
        let watched = Watched::new(vec![wallet("w", 0, 0, 100)], WatchLimits::DEFAULT);
        for (own_node, budget) in [(false, ROUND_BUDGET), (true, OWN_NODE_ROUND_BUDGET)] {
            let poller = poller(own_node);
            assert_eq!(poller.at_once, if own_node { OWN_NODE_AT_ONCE } else { 1 });
            let mut turns = Turns::default();
            let mut read = std::collections::HashSet::new();
            for _ in 0..(100 - HOT).div_ceil(budget - HOT) {
                let plan = poller.plan(&watched, &mut turns, 0, HOT);
                assert_eq!(plan.scripts.len(), budget);
                read.extend(plan.scripts.into_iter().map(|(hex, _)| hex));
            }
            assert_eq!(read.len(), 100, "own node: {own_node}");
        }
    }

    /// One session of `rounds` rounds, with a poller of its own: the
    /// scripts it read in turn, in order.
    fn session(watched: &Watched, turns: &mut Turns, rounds: usize) -> Vec<String> {
        let poller = poller(false);
        (0..rounds)
            .flat_map(|_| poller.plan(watched, turns, 0, HOT).scripts)
            .filter(|(hex, _)| !watched.entries[..HOT].iter().any(|e| &e.hex == hex))
            .map(|(hex, _)| hex)
            .collect()
    }

    /// The scripts of a list that take turns, sorted.
    fn in_turn(watched: &Watched) -> Vec<String> {
        let mut hexes: Vec<String> = watched.entries[HOT..]
            .iter()
            .map(|e| e.hex.clone())
            .collect();
        hexes.sort();
        hexes
    }

    fn sorted(mut hexes: Vec<String>) -> Vec<String> {
        hexes.sort();
        hexes
    }

    /// The turns go on from one session to the next, each with a poller
    /// of its own, through a list that changes between them: a wallet
    /// added, then a list that no longer reaches where the turns stood.
    /// Every script of the list is read within a pass of it.
    #[test]
    fn the_turns_outlive_a_session_and_a_change_of_list() {
        // Thirteen sessions of five rounds over 62 scripts in turn: the
        // first 62 lookups are every one of them, once.
        let one = Watched::new(vec![wallet("a", 1, 0, 64)], WatchLimits::DEFAULT);
        let mut turns = Turns::default();
        let read: Vec<String> = (0..13).flat_map(|_| session(&one, &mut turns, 5)).collect();
        assert_eq!(sorted(read[..62].to_vec()), in_turn(&one));
        assert_eq!(read[62..], read[..3]);

        // A wallet added between two sessions takes its place in the
        // list, rank by rank: the turns go on from the script they had
        // reached, and a pass reads every script of the new list.
        let expected = one.entries[HOT + read.len() % 62].hex.clone();
        let two = Watched::new(
            vec![wallet("a", 1, 0, 64), wallet("b", 2, 0, 20)],
            WatchLimits::DEFAULT,
        );
        let pass = session(&two, &mut turns, two.entries.len() - HOT);
        assert_eq!(pass[0], expected);
        assert_eq!(sorted(pass), in_turn(&two));

        // A list that shrank under the place the turns had reached, its
        // script gone with its wallet: the turns start over at its head
        // rather than skip part of it.
        let short = Watched::new(vec![wallet("c", 3, 0, 10)], WatchLimits::DEFAULT);
        let mut turns = Turns {
            next: Some(two.entries[70].hex.clone()),
            at: 68,
        };
        let pass = session(&short, &mut turns, 8);
        let head: Vec<String> = short.entries[HOT..].iter().map(|e| e.hex.clone()).collect();
        assert_eq!(pass, head);
    }
}
