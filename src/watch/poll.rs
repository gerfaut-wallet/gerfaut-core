//! Short polling of an Esplora server: what is left when nothing can
//! push.
//!
//! A round is the tip hash and at most [`ROUND_BUDGET`] script
//! lookups, one after the other, about once a minute: some 240 requests
//! an hour, whatever the size of the wallets. blockstream.info, the
//! public server this is for, allows an address 700 an hour, and the
//! syncs need their share of that. The first [`HOT`] scripts of the
//! list, the head of every wallet, are looked up every round; the
//! rest take turns. A lookup reads the counters of
//! `/scripthash/:hash`, which move when a transaction enters the
//! mempool and again when it confirms.

use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::ScriptBuf;
use tokio::time::Instant;

use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport, Watched};
use crate::chain::Endpoint;
use crate::chain::esplora::{self, Client};

/// Script lookups in one round.
pub(super) const ROUND_BUDGET: usize = 3;
/// Scripts looked up every round; the rest of the budget rotates.
pub(super) const HOT: usize = 2;
/// Rounds that may fail in a row before the server counts as lost.
const FAILED_ROUNDS: u32 = 3;
/// What a whole round may take.
const ROUND_TIMEOUT: Duration = Duration::from_secs(45);

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
                let stats = self
                    .client
                    .get_scripthash_stats(script)
                    .await
                    .map_err(|e| self.client.describe(&e))?;
                found.push((hex.clone(), Fingerprint::of(&stats)));
            }
            Ok(found)
        };
        tokio::time::timeout(ROUND_TIMEOUT, lookups)
            .await
            .unwrap_or_else(|_| Err("timed out".to_owned()))
    }
}

/// Compares what a round found with what was known: the first reading
/// of a script is its baseline, a different one after that is a change.
pub(super) fn apply(hub: &mut Hub, found: Vec<(String, Fingerprint)>) {
    for (hex, fingerprint) in found {
        if hub.watched.by_hex(&hex).is_none() {
            continue;
        }
        match hub.fingerprints.insert(hex.clone(), fingerprint) {
            Some(known) if known != fingerprint => hub.mark_entry(&hex, ChangeReason::Activity),
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
    let mut tip: Option<String> = None;
    let mut failed = 0u32;
    let started = Instant::now();
    loop {
        // One round: the tip, then the scripts.
        let client = poller.client.clone();
        let plan = poller.plan(&hub.watched, 0, HOT);
        let known_tip = tip.clone();
        let round = async move {
            let hash = client
                .get_tip_hash()
                .await
                .map_err(|e| client.describe(&e))?
                .to_string();
            let height = if known_tip.as_deref() == Some(hash.as_str()) {
                None
            } else {
                Some(client.get_height().await.map_err(|e| client.describe(&e))?)
            };
            Ok::<_, String>((hash, height, plan.check().await?))
        };
        match hub.during(round).await {
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
                hub.set_status(|status| {
                    status.state = WatchState::Polling;
                    status.transport = Some(WatchTransport::EsploraPolling);
                    status.server = Some(label.clone());
                    status.detail = None;
                    status.pushed_scripts = 0;
                });
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
        // The next round, a little early or late so that clients do not
        // fall in step; a tick from the host runs it now.
        let wait = hub.timings.poll.mul_f64(0.85 + 0.3 * rand::random::<f64>());
        let until = Instant::now() + wait;
        loop {
            tokio::select! {
                wake = hub.wake() => match wake {
                    Wake::Stop => return Exit::Stop,
                    Wake::Reconfigured => return Exit::Reconfigured,
                    // Timers stopped with the device: the round is due
                    // by the wall clock.
                    Wake::Tick { idle } if idle >= hub.timings.poll => break,
                    Wake::Wallets if hub.watched.entries.is_empty() => return Exit::Reprobe,
                    Wake::Tick { .. } | Wake::Wallets | Wake::Flushed => {}
                },
                () = tokio::time::sleep_until(until) => break,
            }
        }
    }
}
