//! The Electrum transport: script hash and header subscriptions on one
//! connection, newline-delimited JSON-RPC.
//!
//! Subscriptions go out a window at a time, never all at once: a
//! public ElectrumX charges each one to the session and throttles a
//! burst. A script revealed later is subscribed on the open
//! connection; one that left the list is unsubscribed where the
//! protocol allows it and ignored where it does not. Nothing is sent
//! twice while the connection lives.
//!
//! What a server refuses is remembered for the configuration
//! ([`super::Refusals`]): a script it turned down is not asked for
//! again, and past the most it takes on one connection, the next one
//! asks for the head of the list only. Each is reported once, when it
//! is refused, and left to the regular syncs after that: a reconnection
//! does not ask the server, or the syncs, for it again. The most it
//! takes is asked again a day after it was learned, an hour after when
//! it took none: the session ends at the next ping, and the next one
//! asks for the whole list. What is left after a cut for cost is not:
//! the whole list would be cut again.
//!
//! A server can keep its connection and answer every ping while it no
//! longer indexes the chain: it then tells of no block, and of no
//! confirmation, for as long as the session lasts, and the syncs that
//! follow the watch to it read the same stale state. After two hours
//! without a block, which happens about once in 160 000 such windows on
//! mainnet, the server is asked for its tip again, and the tip of
//! another Electrum server of the same operator is read on a connection
//! of its own that asks for nothing else. The one of the two that is two
//! blocks behind or more is left alone for a quarter of an hour: when it
//! is the session's, the watch moves to the other one. A server that
//! does not answer for its tip in time is compared on the last one it
//! gave. A session that opens two blocks below one the watch already
//! heard of, or a server that goes back, is compared at once. No other
//! operator is ever asked, since it would learn from which address the
//! app is used, and an onion server is compared with onion servers only.
//!
//! The headers the server sends as its tip are kept in a row, a day of
//! them, each with the work its network asks for. A status pushed for
//! a script whose wallet waits for a block is compared with what the
//! wallet's history comes to once the latest of them took what waits
//! ([`super::confirmed_at`]). When they match, the proof of each of
//! those transactions in that block is asked for on this connection,
//! and held to what a sync holds a confirmation to
//! ([`crate::chain::proof::check_confirmation`]): the script is reported
//! with the proofs once they all hold ([`super::Proven`]); as any change,
//! for a sync, when one is unsure, leads to another block, or does not
//! come within the time a ping may take; and a false one refuses the
//! server. A block early in the chain, which a header alone does not
//! prove, is never foretold: the sync chains it to its checkpoint.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use bdk_wallet::bitcoin::{BlockHash, Txid};
use electrum_client::GetMerkleRes;
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::Instant;

use super::{
    ChangeReason, Exit, Headers, Hub, Proven, ServerSoftware, Software, Wake, WatchState,
    WatchTransport, confirmed_at,
};
use crate::chain::electrum::status::history_status;
use crate::chain::electrum::{CLIENT_NAME, Target, parse, words};
use crate::chain::net::{self, BoxStream, LineReader};
use crate::chain::proof::{FALSE_PROOF, Proof, check_confirmation, checkpoint_for};
use crate::chain::{ANOTHER_NETWORK, Endpoint, has_proof_of_work, is_genesis_of};
use crate::network::Network;

/// The longest line read. A status is 64 characters and a header 160;
/// a server sending more than this is not speaking the protocol.
const MAX_LINE: usize = 64 * 1024;
/// Subscriptions awaiting their answer at any time. ElectrumX, from 1.18
/// on, holds small answers back until a kilobyte of them waits, or a
/// second has passed since it last wrote: the answer for a script
/// without history is about forty bytes, so a window under twenty-five
/// or so waits that second at every round. Thirty-two fill it.
/// ElectrumX works through ten at a time and queues the rest at no cost
/// to the session, and a server at its limit refuses the few already
/// sent.
pub(super) const WINDOW: usize = 32;
/// The same on the user's own node. electrs, as its author publishes
/// it, looks at every subscription of a connection again each time it
/// has answered all it was sent: twenty thousand subscriptions cost it
/// four minutes of processor ten at a time, close to one thirty-two at
/// a time, and six seconds two hundred and fifty-six at a time. Not on
/// ElectrumX, which works through ten at a time and turns a request that
/// waited thirty seconds into an error that costs the session a hundred:
/// on a session it slows down, two hundred and fifty-six in flight time
/// out, and the session is cut.
pub(super) const OWN_NODE_WINDOW: usize = 256;
/// The window once ElectrumX has let a subscription wait its turn too
/// long: as many as it serves at once on a session it does not slow
/// down, and few enough to be served within its thirty seconds on one it
/// slows down to its last notch.
const NARROW_WINDOW: usize = 10;
/// The refusals of aiorpcx, under ElectrumX, for what a session costs,
/// code and the start of its words: excessive resource usage, before it
/// closes the connection, and a request that waited its turn too long.
const COSTLY: [(i64, &str); 2] = [(-101, "excessive resource usage"), (BUSY, "server busy")];
/// The code of a request that waited its turn too long.
const BUSY: i64 = -102;
/// Subscriptions refused in a row, in words that do not say why, before
/// the server is taken to be at its limit and the rest of the queue is
/// given up: a server at its limit refuses them all, and asking on only
/// costs it more.
const REFUSALS: usize = 5;
/// Subscriptions answered between two counts told in the status, the
/// last one always told. A list on the user's own node runs to twenty
/// thousand answers, and each change of the status is an event a screen
/// redraws for.
const STATUS_STEP: u32 = 100;
/// The protocol range asked for. 1.4 is what a sync speaks; 1.4.2 adds
/// `unsubscribe`, used when the server has it.
const PROTOCOL_MIN: &str = "1.4";
const PROTOCOL_MAX: &str = "1.4.2";
/// Blocks a server must be behind another of its operator to be taken
/// for one that stopped: two indexers read a block a few seconds apart,
/// and one block between them is that.
const BEHIND: u32 = 2;
/// Headers kept of the latest blocks the server sent, a day of them: a
/// confirmation is foretold only for a wallet whose chain they reach.
const HEADERS_KEPT: usize = 144;
/// Transactions proven for one confirmation foretold, at most: past
/// that many, a sync of the script costs less.
const PROOFS_MAX: usize = 10;
/// Proofs remembered on one connection, past which they are forgotten.
const PROOFS_KEPT: usize = 1_000;

enum Request {
    Headers,
    /// The tip asked again, before another server's is read.
    Tip,
    Subscribe(String),
    /// The proof of a transaction in the block at a height.
    Merkle(Txid, u32),
    Other,
}

/// A confirmation foretold, waiting for its proofs: see [`Proven`].
struct Proving {
    /// The script, in hex.
    hex: String,
    status: String,
    txids: Vec<Txid>,
    /// Those whose proof has yet to come.
    waiting: HashSet<Txid>,
    headers: Arc<Headers>,
    /// When the proofs still awaited are given up on, and the script
    /// synced.
    deadline: Instant,
}

/// Where a session stands in comparing its tip with another server's.
enum Look {
    /// Nothing under way: the next look is due [`super::Timings::stale`]
    /// after the last block.
    Idle,
    /// The server was asked for its tip again, by request `id`, and has
    /// until `by` to answer. A deadline that ran out while the device
    /// slept, or a notification still on its way, says nothing of the
    /// server: the tip compared is the one it gives now, after whatever
    /// it sent before. One that does not answer in time, or refuses, is
    /// compared on the tip it last gave.
    Asking { id: u64, by: Instant },
    /// The tip of another server being read.
    Probing(Probe),
}

/// The tip another server of the same operator announced, and which
/// server, read while the session goes on: see [`tip_elsewhere`].
type Probe = Pin<Box<dyn Future<Output = Option<(Endpoint, u32)>> + Send>>;

struct Session {
    /// The server, whose refusals the hub keeps.
    endpoint: Endpoint,
    /// Subscriptions awaiting their answer at most: [`WINDOW`], or
    /// [`OWN_NODE_WINDOW`].
    window: usize,
    writer: WriteHalf<BoxStream>,
    next_id: u64,
    in_flight: HashMap<u64, Request>,
    queue: VecDeque<String>,
    /// Script hashes the server was asked to watch on this connection.
    subscribed: HashSet<String>,
    acknowledged: u32,
    /// Script hashes refused since the last subscription taken.
    refused_run: Vec<String>,
    /// The server takes no more on this connection.
    at_limit: bool,
    /// The id of the first request sent once the window narrowed after a
    /// subscription waited too long ([`Session::narrow`]).
    narrowed_at: Option<u64>,
    /// The server cut the session for what it costs, in these words.
    overloaded: Option<String>,
    /// The server sent a false proof of a confirmation foretold: it is
    /// refused, as a sync refuses it ([`FALSE_PROOF`]).
    false_proof: bool,
    can_unsubscribe: bool,
    /// When the ping in flight, if any, is given up on.
    pong_by: Option<Instant>,
    /// Script hashes of the first pass still waiting for their answer:
    /// the session is ready once none is left.
    opening: HashSet<String>,
    /// The session picks up after another one under the same
    /// configuration: a script it had no status for is reported.
    resumed: bool,
    ready_told: bool,
    /// The latest headers the server sent, in a row: shared with the
    /// confirmations foretold on them, copied only when a header comes
    /// while one holds them.
    headers: Option<Arc<Headers>>,
    /// Proofs to ask for: txid and height.
    proofs_queued: VecDeque<(Txid, u32)>,
    /// Proofs asked for and not answered yet.
    proofs_asked: HashSet<(Txid, u32)>,
    /// Whether the proof the server gave of a transaction leads to the
    /// root of a block, by txid and the block's hash: a block another
    /// replaced at the same height is not that block.
    proofs: HashMap<(Txid, BlockHash), bool>,
    /// Confirmations foretold waiting for their proofs, by script hash.
    provings: HashMap<String, Proving>,
    /// The height of the last block the server announced.
    tip: Option<u32>,
    /// When it last announced one, or when the session opened, or when
    /// the last look began.
    block_at: Instant,
    look: Look,
    /// The Tor proxy the session goes through, when its server is an
    /// onion: the other onion servers of its operator are reached
    /// through it for their tip.
    proxy: Option<String>,
}

pub(super) async fn run(hub: &mut Hub, endpoint: &Endpoint, target: &Target) -> Exit {
    let label = endpoint.label();
    hub.set_status(|status| {
        if status.state != WatchState::Reconnecting {
            status.state = WatchState::Connecting;
        }
        status.transport = Some(WatchTransport::Electrum);
        status.server = Some(label.clone());
    });
    let proxy = match hub.proxy_for(endpoint).await {
        Ok(proxy) => proxy,
        Err(Exit::Lost(detail)) => return Exit::Unreachable(detail),
        Err(exit) => return exit,
    };
    let budget = hub.connect_budget(endpoint);
    let network = hub.config.network;
    let target = target.clone();
    let session_proxy = proxy.clone();
    let opening = async move { open(&target, proxy.as_deref(), network, budget).await };
    let Opened {
        mut reader,
        writer,
        negotiated,
        software,
    } = match hub.during(opening).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(Unopened::Exit(exit))) | Err(exit) => return exit,
        Ok(Err(Unopened::Costly(detail))) => return refused_at_hello(hub, endpoint, detail),
    };

    hub.retry_limit(endpoint);
    let mut session = Session {
        endpoint: endpoint.clone(),
        window: window_for(hub.config.backend.is_own_node(), software.as_deref()),
        writer,
        next_id: 2,
        in_flight: HashMap::new(),
        queue: VecDeque::new(),
        subscribed: HashSet::new(),
        acknowledged: 0,
        refused_run: Vec::new(),
        at_limit: false,
        narrowed_at: None,
        overloaded: None,
        false_proof: false,
        can_unsubscribe: at_least_1_4_2(&negotiated),
        pong_by: None,
        opening: HashSet::new(),
        resumed: hub.caught_up,
        ready_told: false,
        headers: None,
        proofs_queued: VecDeque::new(),
        proofs_asked: HashSet::new(),
        proofs: HashMap::new(),
        provings: HashMap::new(),
        tip: None,
        block_at: Instant::now(),
        look: Look::Idle,
        proxy: session_proxy,
    };
    hub.alive();
    hub.serve(Some(endpoint));
    hub.announced.open(endpoint);
    hub.set_status(|status| {
        status.state = WatchState::Connected;
        status.transport = Some(WatchTransport::Electrum);
        status.server = Some(label.clone());
        status.detail = None;
        status.pushed_scripts = 0;
        status.server_software = software;
    });
    if let Err(detail) = session
        .request(Request::Headers, "blockchain.headers.subscribe", json!([]))
        .await
    {
        return Exit::Lost(detail);
    }
    session.enqueue(hub);
    session.opening = session.queue.iter().cloned().collect();
    if let Err(detail) = session.pump().await {
        return Exit::Lost(detail);
    }

    let mut next_ping = Instant::now() + hub.timings.keepalive_wait();
    loop {
        let pong_by = session.pong_by;
        let proofs_due = session.proofs_due();
        let stale_at = session.block_at + hub.timings.stale;
        let asking_by = match session.look {
            Look::Asking { by, .. } => Some(by),
            Look::Idle | Look::Probing(_) => None,
        };
        let outcome: Result<(), String> = tokio::select! {
            line = reader.next_line() => match line {
                Ok(Some(line)) => {
                    hub.alive();
                    session.pong_by = None;
                    session.handle(hub, &line);
                    if let Some(detail) = session.overloaded.take() {
                        return cost_exit(hub, detail, true);
                    }
                    if session.false_proof {
                        return Exit::Refused(FALSE_PROOF.to_owned());
                    }
                    session.check_ready(hub);
                    session.pump().await
                }
                Ok(None) => Err("the connection was closed".to_owned()),
                Err(error) => Err(error.to_string()),
            },
            wake = hub.wake() => match wake {
                Wake::Stop => return Exit::Stop,
                Wake::Reconfigured => return Exit::Reconfigured,
                // Nothing left to watch: the supervisor waits for a list.
                Wake::Wallets if hub.watched.entries.is_empty() => return Exit::Reprobe,
                Wake::Wallets => {
                    let relisted = session.relist(hub).await;
                    session.check_ready(hub);
                    relisted
                }
                // The limit is checked when the connection is: the
                // next session asks for the whole list.
                Wake::Tick { .. } if hub.limit_ran_out(endpoint) => return Exit::Reprobe,
                Wake::Tick { idle } => {
                    // A deadline set before the device slept says
                    // nothing about the server.
                    // A look under way began before: it starts over,
                    // at once if its time came during the sleep. The
                    // time awake without a block still counts.
                    if idle > hub.timings.keepalive * 2 {
                        session.pong_by = None;
                        session.look = Look::Idle;
                    }
                    session.ping(hub.pong_budget(endpoint)).await
                }
                Wake::Flushed => Ok(()),
            },
            () = tokio::time::sleep_until(next_ping) => {
                if hub.limit_ran_out(endpoint) {
                    return Exit::Reprobe;
                }
                next_ping = Instant::now() + hub.timings.keepalive_wait();
                session.ping(hub.pong_budget(endpoint)).await
            }
            () = super::sleep_until(pong_by), if pong_by.is_some() => {
                Err("the server stopped answering".to_owned())
            }
            () = super::sleep_until(proofs_due), if proofs_due.is_some() => {
                session.expire_proofs(hub);
                session.pump().await
            }
            () = tokio::time::sleep_until(stale_at), if matches!(session.look, Look::Idle) => {
                session.block_at = Instant::now();
                session.ask_tip(hub.pong_budget(endpoint)).await
            }
            () = super::sleep_until(asking_by), if asking_by.is_some() => {
                session.look_now(hub);
                Ok(())
            }
            found = probed(&mut session.look) => {
                session.look = Look::Idle;
                let ours = session.tip;
                match found.zip(ours) {
                    Some(((other, tip), ours)) if tip >= ours.saturating_add(BEHIND) => {
                        // This one is behind: the watch moves on, and
                        // the syncs with it.
                        hub.shun(endpoint);
                        let detail = format!(
                            "{label} is {} blocks behind {}",
                            tip - ours,
                            other.label(),
                        );
                        hub.set_status(|status| status.detail = Some(detail));
                        return Exit::Reprobe;
                    }
                    Some(((other, tip), ours)) if ours >= tip.saturating_add(BEHIND) => {
                        hub.shun(&other);
                    }
                    _ => {}
                }
                Ok(())
            }
        };
        if let Err(detail) = outcome {
            return Exit::Lost(detail);
        }
    }
}

impl Session {
    async fn request(&mut self, kind: Request, method: &str, params: Value) -> Result<(), String> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.in_flight.insert(id, kind);
        send(&mut self.writer, &message).await
    }

    /// Whether a subscription is still to be sent or answered.
    fn subscribing(&self) -> bool {
        !self.queue.is_empty()
            || self
                .in_flight
                .values()
                .any(|request| matches!(request, Request::Subscribe(_)))
    }

    /// Tells the hub once every script of the first pass has its answer.
    fn check_ready(&mut self, hub: &mut Hub) {
        if !self.opening.is_empty() || self.ready_told {
            return;
        }
        self.ready_told = true;
        // Every script of the first pass has its answer: what a limit
        // that ran out had left out is heard now, or was refused again
        // and not reported twice.
        if let Some(refusals) = hub.refusals.get_mut(&self.endpoint) {
            refusals.left_out.clear();
        }
        hub.ready(true);
    }

    /// Queues every script of the list the server is asked for and was
    /// not yet: see [`super::Watched::heard`].
    fn enqueue(&mut self, hub: &Hub) {
        for entry in hub.watched.heard(hub.refusals.get(&self.endpoint)) {
            if self.subscribed.insert(entry.scripthash.clone()) {
                self.queue.push_back(entry.scripthash.clone());
            }
        }
    }

    /// Sends queued proofs, then queued subscriptions, up to the window,
    /// in one write and one flush: a flush each would cost a TLS record,
    /// or a Tor cell, each.
    async fn pump(&mut self) -> Result<(), String> {
        let mut lines = Vec::new();
        while self.in_flight.len() < self.window {
            if let Some((txid, height)) = self.proofs_queued.pop_front() {
                let id = self.next_id;
                self.next_id += 1;
                let message = json!({
                    "jsonrpc": "2.0", "id": id, "method": "blockchain.transaction.get_merkle",
                    "params": [txid.to_string(), height],
                });
                self.in_flight.insert(id, Request::Merkle(txid, height));
                lines.extend(message.to_string().into_bytes());
                lines.push(b'\n');
                continue;
            }
            let Some(scripthash) = self.queue.pop_front() else {
                break;
            };
            let id = self.next_id;
            self.next_id += 1;
            let message = json!({
                "jsonrpc": "2.0", "id": id, "method": "blockchain.scripthash.subscribe",
                "params": [scripthash],
            });
            self.in_flight.insert(id, Request::Subscribe(scripthash));
            lines.extend(message.to_string().into_bytes());
            lines.push(b'\n');
        }
        if lines.is_empty() {
            return Ok(());
        }
        write_lines(&mut self.writer, &lines).await
    }

    /// The list changed: new scripts are subscribed, and the ones that
    /// left are dropped here and, where the server can, there.
    async fn relist(&mut self, hub: &mut Hub) -> Result<(), String> {
        let gone: Vec<String> = self
            .subscribed
            .iter()
            .filter(|scripthash| hub.watched.by_scripthash(scripthash).is_none())
            .cloned()
            .collect();
        for scripthash in gone {
            self.subscribed.remove(&scripthash);
            self.opening.remove(&scripthash);
            if self.provings.remove(&scripthash).is_some() {
                self.drop_unawaited_proofs();
            }
            self.queue.retain(|queued| *queued != scripthash);
            hub.statuses.remove(&scripthash);
            hub.announced.forget(&scripthash);
            if self.can_unsubscribe {
                self.request(
                    Request::Other,
                    "blockchain.scripthash.unsubscribe",
                    json!([scripthash]),
                )
                .await?;
            }
        }
        self.enqueue(hub);
        self.pump().await
    }

    /// Asks the server for its tip again, to be answered within `within`:
    /// see [`Look::Asking`].
    async fn ask_tip(&mut self, within: Duration) -> Result<(), String> {
        self.look = Look::Asking {
            id: self.next_id,
            by: Instant::now() + within,
        };
        self.request(Request::Tip, "blockchain.headers.subscribe", json!([]))
            .await
    }

    /// Reads the tip of another server of the operator now, to compare
    /// with the last one this server gave; nothing to do without one.
    fn look_now(&mut self, hub: &Hub) {
        self.look = self
            .tip
            .and_then(|_| tip_elsewhere(hub, &self.endpoint, self.proxy.as_deref()))
            .map_or(Look::Idle, Look::Probing);
    }

    async fn ping(&mut self, pong: std::time::Duration) -> Result<(), String> {
        if self.pong_by.is_none() {
            self.pong_by = Some(Instant::now() + pong);
        }
        self.request(Request::Other, "server.ping", json!([])).await
    }

    fn handle(&mut self, hub: &mut Hub, line: &[u8]) {
        let Ok(message) = serde_json::from_slice::<Value>(line) else {
            return;
        };
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            let Some(request) = self.in_flight.remove(&id) else {
                return;
            };
            let error = message.get("error").filter(|error| !error.is_null());
            // A proof refused is a guess given up, whatever the words: it
            // is asked for nothing the watch needs.
            if let Some(error) = error
                && costs_too_much(error)
                && !matches!(request, Request::Merkle(..))
            {
                if !self.narrow(id, &request, error) {
                    self.cut(hub, words(error));
                }
                return;
            }
            let refused = error.is_some();
            match request {
                Request::Headers if !refused => {
                    if let Some(height) = height_of(&message["result"]) {
                        self.take_header(hub.config.network, height, &message["result"]);
                        self.tip = Some(height);
                        // Behind a block the watch already heard of,
                        // from the server it left or one before: this
                        // one may be the one that stopped, and is not
                        // given two hours to show it.
                        if hub
                            .tip
                            .is_some_and(|heard| height.saturating_add(BEHIND) <= heard)
                        {
                            self.look_now(hub);
                        }
                        hub.new_tip(height, false);
                    }
                }
                Request::Merkle(txid, height) => {
                    let branch = (!refused).then(|| &message["result"]);
                    self.proved(hub, txid, height, branch);
                }
                Request::Tip => {
                    // The answer to a look since given up, a block or a
                    // wake-up after it, is no answer.
                    if !matches!(self.look, Look::Asking { id: asked, .. } if asked == id) {
                        return;
                    }
                    let height = height_of(&message["result"]).filter(|_| !refused);
                    if let Some(height) = height {
                        self.take_header(hub.config.network, height, &message["result"]);
                    }
                    match height {
                        // A block it did not announce: the server moved.
                        Some(height) if self.tip.is_none_or(|tip| height > tip) => {
                            self.tip = Some(height);
                            self.block_at = Instant::now();
                            self.look = Look::Idle;
                            hub.new_tip(height, false);
                        }
                        // The same tip, or one lower.
                        Some(height) => {
                            self.tip = Some(height);
                            self.look_now(hub);
                        }
                        // No tip: compared on the last one it gave.
                        None => self.look_now(hub),
                    }
                }
                Request::Subscribe(scripthash) if !refused => {
                    self.refused_run.clear();
                    self.acknowledged += 1;
                    if self.at_limit {
                        // Taken after all, answered out of order: the
                        // limit is what the connection holds.
                        let refusals = hub.refusals.entry(self.endpoint.clone()).or_default();
                        let held = self.acknowledged as usize;
                        refusals.learn(refusals.limit.map_or(held, |limit| limit.max(held)));
                    }
                    if self.acknowledged.is_multiple_of(STATUS_STEP) || !self.subscribing() {
                        let acknowledged = self.acknowledged;
                        hub.set_status(|status| status.pushed_scripts = acknowledged);
                    }
                    self.status(hub, &scripthash, &message["result"], true);
                    self.opening.remove(&scripthash);
                }
                Request::Subscribe(scripthash) => {
                    let refusal = words(&message["error"]);
                    self.refused(hub, &scripthash, &refusal);
                    let acknowledged = self.acknowledged;
                    hub.set_status(|status| {
                        status.detail = Some(refusal);
                        status.pushed_scripts = acknowledged;
                    });
                }
                _ => {}
            }
            return;
        }
        let params = &message["params"];
        match message.get("method").and_then(Value::as_str) {
            Some("blockchain.scripthash.subscribe") => {
                if let Some(scripthash) = params[0].as_str() {
                    let scripthash = scripthash.to_owned();
                    self.status(hub, &scripthash, &params[1], false);
                }
            }
            Some("blockchain.headers.subscribe") => {
                if let Some(height) = height_of(&params[0]) {
                    self.take_header(hub.config.network, height, &params[0]);
                    let back = self.tip.is_some_and(|tip| height < tip);
                    self.tip = Some(height);
                    hub.new_tip(height, false);
                    if back {
                        // A server that goes back is the most suspect
                        // of all: it is compared at once.
                        if !matches!(self.look, Look::Probing(_)) {
                            self.look_now(hub);
                        }
                    } else {
                        // A block: the server indexes, and no other one
                        // is asked about it.
                        self.block_at = Instant::now();
                        self.look = Look::Idle;
                    }
                }
            }
            _ => {}
        }
    }

    /// The server refused to watch a script. One script refused, a
    /// history too long for the server to hash in time for instance, is
    /// not asked of that server again, and is left to the regular syncs
    /// after one of its own now: what it did while nothing listened is
    /// unknown, whatever a session before this one heard of it. A
    /// refusal that names a limit, or several in a row, is a server at
    /// the most it takes on one connection: what it took is watched, and
    /// the rest is not asked for, on this connection or the next. Each
    /// script given up is as unknown as the one refused, and has a sync
    /// of its own too.
    fn refused(&mut self, hub: &mut Hub, scripthash: &str, refusal: &str) {
        let mut given_up = vec![scripthash.to_owned()];
        if !self.at_limit {
            let refusals = hub.refusals.entry(self.endpoint.clone()).or_default();
            self.refused_run.push(scripthash.to_owned());
            if names_a_limit(refusal) || self.refused_run.len() >= REFUSALS {
                self.at_limit = true;
                // Past the limit, not refused for themselves.
                for past in self.refused_run.drain(..) {
                    refusals.scripts.remove(&past);
                }
                // What this connection took, rather than a number the
                // server's words may give: a limit per address counts
                // the other connections from it too.
                refusals.learn(self.acknowledged as usize);
                given_up.extend(self.queue.drain(..));
            } else {
                refusals.scripts.insert(scripthash.to_owned());
            }
        }
        let reason = self.opening_reason();
        for scripthash in &given_up {
            self.opening.remove(scripthash);
        }
        let left_out = hub.refusals.get(&self.endpoint).map(|r| &r.left_out);
        let report: Vec<String> = given_up
            .iter()
            .filter(|scripthash| left_out.is_none_or(|left_out| !left_out.contains(*scripthash)))
            .filter_map(|scripthash| hub.watched.by_scripthash(scripthash))
            .map(|entry| entry.hex.clone())
            .collect();
        for hex in &report {
            hub.mark_entry(hex, reason);
        }
    }

    /// ElectrumX let a subscription wait its turn too long and refused it,
    /// on a session it slows down for what it costs: each such refusal
    /// costs the session more, and enough of them cut it. The first time,
    /// the window narrows to [`NARROW_WINDOW`], and every subscription
    /// already sent and refused the same way is sent again later; one
    /// sent after, refused the same way, is a session the server is about
    /// to cut, and it is cut ([`Session::cut`]).
    fn narrow(&mut self, id: u64, request: &Request, error: &Value) -> bool {
        let Request::Subscribe(scripthash) = request else {
            return false;
        };
        if error.get("code").and_then(Value::as_i64) != Some(BUSY) {
            return false;
        }
        let narrowed_at = *self.narrowed_at.get_or_insert(self.next_id);
        if id >= narrowed_at {
            return false;
        }
        self.window = self.window.min(NARROW_WINDOW);
        self.queue.push_front(scripthash.clone());
        true
    }

    /// The server refused a request for what the session costs it,
    /// ElectrumX past its budget, and is closing the connection. It
    /// keeps that cost against the address for a while, and coming back
    /// at once with the same burst would only be cut again: the session
    /// ends ([`cost_exit`]), and the next session there asks for half as
    /// many scripts as this one took ([`ask_less`]).
    fn cut(&mut self, hub: &mut Hub, detail: String) {
        let half = self.acknowledged as usize / 2;
        ask_less(hub, &self.endpoint, half, self.opening_reason());
        self.overloaded = Some(detail);
    }

    /// A status arrived for a script, as the answer to a subscription
    /// (`answer`) or as a notification. It is news when it differs from
    /// the status of what the wallet holds for the script; a
    /// notification must also differ from the last status the server
    /// gave, so that one sent again is not heard twice.
    fn status(&mut self, hub: &mut Hub, scripthash: &str, status: &Value, answer: bool) {
        let Some(entry) = hub.watched.by_scripthash(scripthash) else {
            return;
        };
        let hex = entry.hex.clone();
        let status = status
            .as_str()
            .map(|s| s.chars().take(64).collect::<String>());
        let lacking = entry.statuses.iter().any(|held| *held != status);
        let previous = hub.statuses.insert(scripthash.to_owned(), status.clone());
        hub.announced.set(scripthash, status.clone());
        if !answer
            && previous.as_ref() != Some(&status)
            && self.provings.remove(scripthash).is_some()
        {
            // What was being proven of the status before is moot.
            self.drop_unawaited_proofs();
        }
        if !lacking || (!answer && previous.as_ref() == Some(&status)) {
            return;
        }
        if !answer && self.foretold(hub, scripthash, status.as_deref()) {
            return;
        }
        let reason = if answer {
            self.opening_reason()
        } else {
            ChangeReason::Activity
        };
        hub.mark_entry(&hex, reason);
    }

    /// Takes a header the server sent as its tip at `height`: kept
    /// after the ones before it when it follows the last of them below
    /// its height, alone otherwise, and dropped with them when it lacks
    /// the work its network asks for.
    fn take_header(&mut self, network: Network, height: u32, sent: &Value) {
        let header = sent
            .get("hex")
            .and_then(Value::as_str)
            .and_then(|hex| deserialize_hex::<Header>(hex).ok())
            .filter(|header| has_proof_of_work(network, height, header));
        let Some(header) = header else {
            self.headers = None;
            return;
        };
        let alone = || {
            Arc::new(Headers {
                first: height,
                chain: vec![header],
            })
        };
        let mut kept = match self.headers.take() {
            Some(mut headers)
                if height > headers.first && height <= headers.last_height().saturating_add(1) =>
            {
                let row = Arc::make_mut(&mut headers);
                row.chain
                    .truncate(usize::try_from(height - row.first).unwrap_or(usize::MAX));
                let follows = row
                    .chain
                    .last()
                    .is_some_and(|parent| header.prev_blockhash == parent.block_hash());
                if follows {
                    row.chain.push(header);
                    headers
                } else {
                    alone()
                }
            }
            _ => alone(),
        };
        if kept.chain.len() > HEADERS_KEPT {
            let row = Arc::make_mut(&mut kept);
            let over = row.chain.len() - HEADERS_KEPT;
            row.chain.drain(..over);
            row.first = row
                .first
                .saturating_add(u32::try_from(over).unwrap_or(u32::MAX));
        }
        self.headers = Some(kept);
    }

    /// Whether a status pushed for a script is what the history each of
    /// its wallets holds comes to once the latest block the server sent
    /// takes what waits in it ([`confirmed_at`]). The proof of each of
    /// those transactions in that block is asked for, and the script is
    /// reported with them once they all hold ([`Self::proved`]), or for
    /// a sync when one fails or comes late.
    fn foretold(&mut self, hub: &mut Hub, scripthash: &str, status: Option<&str>) -> bool {
        let (Some(status), Some(headers)) = (status, self.headers.as_ref()) else {
            return false;
        };
        let Some(entry) = hub.watched.by_scripthash(scripthash) else {
            return false;
        };
        let height = headers.last_height();
        let Some(block) = headers.at(height).map(Header::block_hash) else {
            return false;
        };
        // A block in a period whose forged header costs little proves
        // nothing alone: its chain to the checkpoint is read by the sync
        // of the script, not foretold here.
        if checkpoint_for(hub.config.network, height).is_some() {
            return false;
        }
        let mut txids = BTreeSet::new();
        for held in &entry.histories {
            match confirmed_at(held, height) {
                Some(guessed) if history_status(&guessed) == status => {
                    txids.extend(
                        held.iter()
                            .filter(|(_, height)| *height <= 0)
                            .map(|(txid, _)| *txid),
                    );
                }
                _ => return false,
            }
        }
        if entry.lookahead || txids.is_empty() || txids.len() > PROOFS_MAX {
            return false;
        }
        let proof = |txid: &Txid| self.proofs.get(&(*txid, block)).copied();
        if txids.iter().any(|txid| proof(txid) == Some(false)) {
            return false;
        }
        let waiting: HashSet<Txid> = txids
            .iter()
            .filter(|txid| proof(txid) != Some(true))
            .copied()
            .collect();
        for txid in &waiting {
            if self.proofs_asked.insert((*txid, height)) {
                self.proofs_queued.push_back((*txid, height));
            }
        }
        let proving = Proving {
            hex: entry.hex.clone(),
            status: status.to_owned(),
            txids: txids.into_iter().collect(),
            waiting,
            headers: Arc::clone(headers),
            deadline: Instant::now() + hub.pong_budget(&self.endpoint),
        };
        if proving.waiting.is_empty() {
            hub.mark_proven(&self.proven(proving));
        } else {
            self.provings.insert(scripthash.to_owned(), proving);
        }
        true
    }

    /// The server answered for the proof of `txid` in the block at
    /// `height`, with `branch`, or refused. Each confirmation waiting
    /// on it is reported once all its proofs hold, and its script is
    /// reported for a sync as soon as one fails.
    fn proved(&mut self, hub: &mut Hub, txid: Txid, height: u32, branch: Option<&Value>) {
        self.proofs_asked.remove(&(txid, height));
        if self.proofs.len() > PROOFS_KEPT {
            self.proofs.clear();
        }
        let branch =
            branch.and_then(|branch| serde_json::from_value::<GetMerkleRes>(branch.clone()).ok());
        let network = hub.config.network;
        let waiting: Vec<String> = self
            .provings
            .iter()
            .filter(|(_, proving)| {
                proving.headers.last_height() == height && proving.waiting.contains(&txid)
            })
            .map(|(scripthash, _)| scripthash.clone())
            .collect();
        for scripthash in waiting {
            let Some(mut proving) = self.provings.remove(&scripthash) else {
                continue;
            };
            let Some(header) = proving.headers.at(height) else {
                hub.mark_entry(&proving.hex, ChangeReason::Activity);
                continue;
            };
            // Held to what a sync holds a confirmation to. One that
            // leads elsewhere, a block replaced since the header came, or
            // one unsure, is left to the sync of the script; a false one
            // refuses the server, as a sync refuses it.
            let proof = branch.as_ref().map_or(Proof::Unsure, |branch| {
                check_confirmation(network, height, header, txid, branch)
            });
            match proof {
                Proof::Holds => {
                    self.proofs.insert((txid, header.block_hash()), true);
                }
                Proof::False => {
                    self.proofs.insert((txid, header.block_hash()), false);
                    self.false_proof = true;
                    hub.mark_entry(&proving.hex, ChangeReason::Activity);
                    continue;
                }
                Proof::Unsure | Proof::Elsewhere => {
                    hub.mark_entry(&proving.hex, ChangeReason::Activity);
                    continue;
                }
            }
            proving.waiting.remove(&txid);
            if proving.waiting.is_empty() {
                hub.mark_proven(&self.proven(proving));
            } else {
                self.provings.insert(scripthash, proving);
            }
        }
    }

    /// When the first proof still awaited is given up on.
    fn proofs_due(&self) -> Option<Instant> {
        self.provings.values().map(|proving| proving.deadline).min()
    }

    /// Gives up on the proofs the server is late with: their scripts are
    /// reported for a sync.
    fn expire_proofs(&mut self, hub: &mut Hub) {
        let now = Instant::now();
        let late: Vec<String> = self
            .provings
            .iter()
            .filter(|(_, proving)| proving.deadline <= now)
            .map(|(scripthash, _)| scripthash.clone())
            .collect();
        for scripthash in late {
            if let Some(proving) = self.provings.remove(&scripthash) {
                hub.mark_entry(&proving.hex, ChangeReason::Activity);
            }
        }
        self.drop_unawaited_proofs();
    }

    /// Forgets the proofs no confirmation foretold waits on any more:
    /// asked and never answered, they would hold their place in the
    /// window of requests in flight for as long as the session lasts,
    /// and an answer that comes after is not read.
    fn drop_unawaited_proofs(&mut self) {
        let awaited: HashSet<(Txid, u32)> = self
            .provings
            .values()
            .flat_map(|proving| {
                let height = proving.headers.last_height();
                proving.waiting.iter().map(move |txid| (*txid, height))
            })
            .collect();
        self.in_flight.retain(|_, request| match request {
            Request::Merkle(txid, height) => awaited.contains(&(*txid, *height)),
            _ => true,
        });
        self.proofs_asked.retain(|asked| awaited.contains(asked));
        self.proofs_queued.retain(|queued| awaited.contains(queued));
    }

    /// A confirmation whose proofs all hold, as the wallet takes it.
    fn proven(&self, proving: Proving) -> Proven {
        Proven {
            script: proving.hex,
            status: proving.status,
            txids: proving.txids,
            headers: proving.headers,
            server: self.endpoint.clone(),
        }
    }

    /// Why a script read on subscribing is reported: the watch starts,
    /// or picks up after a lost connection.
    fn opening_reason(&self) -> ChangeReason {
        if self.resumed {
            ChangeReason::Reconnected
        } else {
            ChangeReason::Started
        }
    }
}

/// Why the opening of a session came to nothing.
enum Unopened {
    Exit(Exit),
    /// The server refused the handshake for what the watch costs it,
    /// in these words: ElectrumX still holding the cost of an earlier
    /// session against the address.
    Costly(String),
}

impl Unopened {
    fn unreachable(detail: String) -> Unopened {
        Unopened::Exit(Exit::Unreachable(detail))
    }

    /// What went wrong, in words, for a caller that only tells it.
    fn into_words(self) -> String {
        match self {
            Unopened::Exit(Exit::Unreachable(detail)) | Unopened::Costly(detail) => detail,
            Unopened::Exit(exit) => format!("{exit:?}"),
        }
    }
}

/// The result of the request numbered `id`, past whatever the server
/// says before it, within `budget`.
async fn answer(
    reader: &mut LineReader<ReadHalf<BoxStream>>,
    id: u64,
    budget: Duration,
) -> Result<Value, Unopened> {
    let read = async {
        loop {
            let line = reader
                .next_line()
                .await
                .map_err(|e| Unopened::unreachable(e.to_string()))?
                .ok_or_else(|| Unopened::unreachable("the connection was closed".to_owned()))?;
            let Ok(mut message) = serde_json::from_slice::<Value>(&line) else {
                return Err(Unopened::unreachable("unexpected response".to_owned()));
            };
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error").filter(|e| !e.is_null()) {
                if costs_too_much(error) {
                    return Err(Unopened::Costly(words(error)));
                }
                return Err(Unopened::unreachable(format!(
                    "the server refused the request: {}",
                    words(error)
                )));
            }
            return Ok(message["result"].take());
        }
    };
    tokio::time::timeout(budget, read)
        .await
        .map_err(|_| Unopened::unreachable(format!("timed out after {} s", budget.as_secs())))?
}

/// The next session on `endpoint` asks for `kept` scripts at most, the
/// limit a cut for cost leaves, which holds for the configuration. The
/// scripts that leaves out are not asked for again, so each is reported
/// once, for a sync of its own, as a script given up on a refusal is:
/// what it does from now on, nothing will tell. None kept is no cut: a
/// watch that asks for nothing would never learn more.
fn ask_less(hub: &mut Hub, endpoint: &Endpoint, kept: usize, reason: ChangeReason) {
    if kept == 0 {
        return;
    }
    let refusals = hub.refusals.get(endpoint);
    let kept = refusals
        .and_then(|refusals| refusals.limit)
        .map_or(kept, |limit| limit.min(kept));
    let past: Vec<String> = hub
        .watched
        .heard(refusals)
        .skip(kept)
        .filter(|entry| refusals.is_none_or(|r| !r.left_out.contains(&entry.scripthash)))
        .map(|entry| entry.hex.clone())
        .collect();
    hub.refusals
        .entry(endpoint.clone())
        .or_default()
        .learn_cut(kept);
    for hex in &past {
        hub.mark_entry(hex, reason);
    }
}

/// The server refused the handshake for what the watch costs it, before
/// it heard of a script: ElectrumX still holds the cost of an earlier
/// session against the address. Asked for the same list once that wears
/// off, it would cut the watch again: the next session asks for half of
/// what this one was to ask, unless a cut already halved it, since the
/// list is not what a refusal at the handshake measures.
fn refused_at_hello(hub: &mut Hub, endpoint: &Endpoint, detail: String) -> Exit {
    let refusals = hub.refusals.get(endpoint);
    if !refusals.is_some_and(|refusals| refusals.cut) {
        let asked = hub.watched.heard(refusals).count();
        let reason = if hub.caught_up {
            ChangeReason::Reconnected
        } else {
            ChangeReason::Started
        };
        ask_less(hub, endpoint, asked / 2, reason);
    }
    cost_exit(hub, detail, false)
}

/// How the watch leaves a server that refused it for what it costs,
/// before a session (`opened` false) or during one. Someone else's is
/// left alone as after a cut ([`Exit::Refused`]), not tried again at
/// every backoff, each try adding to what it holds against the address.
/// The user's own node is tried again at the ordinary pace: its limits
/// are theirs to raise, and a node that restarts must not keep Live off
/// a quarter of an hour after it is back.
fn cost_exit(hub: &Hub, detail: String, opened: bool) -> Exit {
    if !hub.config.backend.is_own_node() {
        Exit::Refused(detail)
    } else if opened {
        Exit::Lost(detail)
    } else {
        Exit::Unreachable(detail)
    }
}

/// A connection open, and what the server said opening it.
struct Opened {
    reader: LineReader<ReadHalf<BoxStream>>,
    writer: WriteHalf<BoxStream>,
    /// The protocol version agreed on.
    negotiated: String,
    /// What the server says it runs.
    software: Option<String>,
}

/// Opens a connection and asks what comes before anything else:
/// `server.version`, the first call a server expects and the one that
/// fixes the protocol version, then its genesis block, before it hears
/// of any script. A server of another network, a signet port typed for
/// testnet4, would report changes that never happened on the wallet's.
async fn open(
    target: &Target,
    proxy: Option<&str>,
    network: Network,
    budget: Duration,
) -> Result<Opened, Unopened> {
    let (tls, host, port) = parse(&target.url).map_err(Unopened::unreachable)?;
    let stream = net::open(&host, port, target.security(tls), proxy, budget)
        .await
        .map_err(|fault| Unopened::unreachable(fault.to_string()))?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = LineReader::new(reader, MAX_LINE);
    let hello = json!({
        "jsonrpc": "2.0", "id": 0, "method": "server.version",
        "params": [CLIENT_NAME, [PROTOCOL_MIN, PROTOCOL_MAX]],
    });
    send(&mut writer, &hello)
        .await
        .map_err(Unopened::unreachable)?;
    let version = answer(&mut reader, 0, budget).await?;
    let negotiated = version[1].as_str().unwrap_or_default().to_owned();
    let software = version[0]
        .as_str()
        .map(crate::chain::server_words)
        .filter(|software| !software.is_empty());
    let genesis = json!({
        "jsonrpc": "2.0", "id": 1, "method": "blockchain.block.header", "params": [0],
    });
    send(&mut writer, &genesis)
        .await
        .map_err(Unopened::unreachable)?;
    let genesis = answer(&mut reader, 1, budget).await?;
    let genesis = genesis
        .as_str()
        .and_then(|hex| deserialize_hex::<Header>(hex).ok());
    if !genesis.is_some_and(|header| is_genesis_of(network, header.block_hash())) {
        return Err(Unopened::Exit(Exit::Refused(ANOTHER_NETWORK.to_owned())));
    }
    Ok(Opened {
        reader,
        writer,
        negotiated,
        software,
    })
}

/// The Electrum servers of `candidates` other than `endpoint` that its
/// operator runs, in their order: through Tor when it is, in the clear
/// when it is not. One runs the other when its host is the other's, or
/// one under it ([`crate::chain::same_operator`]), as the watch picks the Electrum
/// servers of an operator of the rotation.
pub(super) fn siblings(candidates: Vec<Endpoint>, endpoint: &Endpoint) -> Vec<(Endpoint, Target)> {
    let ours = endpoint.label();
    candidates
        .into_iter()
        .filter(|other| other != endpoint && other.is_onion() == endpoint.is_onion())
        .filter(|other| {
            let theirs = other.label();
            crate::chain::same_operator(&theirs, &ours)
                || crate::chain::same_operator(&ours, &theirs)
        })
        .filter_map(|other| match &other {
            Endpoint::Electrum(target) => {
                let target = target.clone();
                Some((other, target))
            }
            Endpoint::Esplora(_) => None,
        })
        .collect()
}

/// Reads the tip of the other Electrum servers the watch may talk to
/// that the operator of `endpoint` runs, one after the other until one
/// answers, each on a connection of its own that asks for nothing but
/// the tip; `None` when there is no such server, which leaves the
/// session as it is. A server being left alone is not asked. `proxy` is
/// the Tor proxy of the session: the others are onions when its server
/// is one ([`siblings`]), and go through the same.
fn tip_elsewhere(hub: &Hub, endpoint: &Endpoint, proxy: Option<&str>) -> Option<Probe> {
    let candidates = super::candidates(&hub.config).unwrap_or_default();
    let others: Vec<(Endpoint, Target, Duration)> = siblings(candidates, endpoint)
        .into_iter()
        .filter(|(other, _)| hub.shunned_until(other).is_none())
        .map(|(other, target)| {
            let budget = hub.connect_budget(&other);
            (other, target, budget)
        })
        .collect();
    if others.is_empty() {
        return None;
    }
    let network = hub.config.network;
    let proxy = proxy.map(str::to_owned);
    Some(Box::pin(async move {
        for (other, target, budget) in others {
            if let Ok(tip) = tip_of(&target, proxy.as_deref(), network, budget).await {
                return Some((other, tip));
            }
        }
        None
    }))
}

/// The tip a server announces, on a connection that asks for nothing
/// else and is closed as soon as it answers. A height no chain of the
/// network can have reached by now is no answer.
async fn tip_of(
    target: &Target,
    proxy: Option<&str>,
    network: Network,
    budget: Duration,
) -> Result<u32, String> {
    let Opened {
        mut reader,
        mut writer,
        ..
    } = open(target, proxy, network, budget)
        .await
        .map_err(|unopened| match unopened {
            Unopened::Exit(exit) => format!("{exit:?}"),
            Unopened::Costly(detail) => detail,
        })?;
    let tip = json!({
        "jsonrpc": "2.0", "id": 2, "method": "blockchain.headers.subscribe", "params": [],
    });
    send(&mut writer, &tip).await?;
    let header = answer(&mut reader, 2, budget)
        .await
        .map_err(Unopened::into_words)?;
    height_of(&header)
        .filter(|height| *height <= crate::chain::height_limit(network, crate::now_secs()))
        .ok_or_else(|| "unexpected response".to_owned())
}

/// What a probe found, once it ends; never, without one.
async fn probed(look: &mut Look) -> Option<(Endpoint, u32)> {
    match look {
        Look::Probing(probe) => probe.await,
        Look::Idle | Look::Asking { .. } => std::future::pending().await,
    }
}

async fn send(writer: &mut WriteHalf<BoxStream>, message: &Value) -> Result<(), String> {
    let mut line = message.to_string().into_bytes();
    line.push(b'\n');
    write_lines(writer, &line).await
}

/// Writes whole lines, then flushes once.
async fn write_lines(writer: &mut WriteHalf<BoxStream>, lines: &[u8]) -> Result<(), String> {
    let write = async {
        writer.write_all(lines).await?;
        writer.flush().await
    };
    match tokio::time::timeout(std::time::Duration::from_secs(20), write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("the connection was closed: {error}")),
        Err(_) => Err("the server stopped reading".to_owned()),
    }
}

fn height_of(header: &Value) -> Option<u32> {
    header
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
}

/// Whether an error is ElectrumX refusing a request for what the session
/// costs it, in its own code and words: see [`COSTLY`]. Busy words from
/// another server, a node that starts or indexes, are not: the watch
/// would leave it alone a quarter of an hour for nothing.
fn costs_too_much(error: &Value) -> bool {
    let code = error.get("code").and_then(Value::as_i64);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    COSTLY
        .iter()
        .any(|(costly, words)| code == Some(*costly) && message.starts_with(words))
}

/// Whether a refusal says the server takes no more subscriptions on the
/// connection: "Too many subscriptions on this connection (limit: N)"
/// from electrs, "subscription limit reached (N max per client)" from
/// the electrs of mempool, "Subscription limit reached" from Fulcrum.
fn names_a_limit(refusal: &str) -> bool {
    let refusal = refusal.to_lowercase();
    refusal.contains("subscription") && (refusal.contains("limit") || refusal.contains("too many"))
}

/// The window of a session: [`OWN_NODE_WINDOW`] on the user's own node,
/// unless it runs ElectrumX, and [`WINDOW`] everywhere else.
pub(super) fn window_for(own_node: bool, software: Option<&str>) -> usize {
    let electrumx = Software::of(software) == Software::Named(ServerSoftware::ElectrumX);
    if own_node && !electrumx {
        OWN_NODE_WINDOW
    } else {
        WINDOW
    }
}

fn at_least_1_4_2(version: &str) -> bool {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let version = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    version >= (1, 4, 2)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    /// A stream that keeps what is written and counts the flushes, and
    /// never has anything to read.
    #[derive(Clone, Default)]
    struct Counting {
        written: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<Mutex<usize>>,
    }

    impl AsyncRead for Counting {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Counting {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            *self.flushes.lock().unwrap() += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A window of subscriptions goes out in one write and one flush.
    #[tokio::test]
    async fn a_window_of_subscriptions_is_flushed_once() {
        let stream = Counting::default();
        let (_reader, writer) = tokio::io::split(Box::new(stream.clone()) as BoxStream);
        let mut session = Session {
            endpoint: Endpoint::Electrum(Target::new("tcp://127.0.0.1:1", None)),
            window: WINDOW,
            writer,
            next_id: 2,
            in_flight: HashMap::new(),
            queue: (0..40).map(|n| format!("{n:064x}")).collect(),
            subscribed: HashSet::new(),
            acknowledged: 0,
            refused_run: Vec::new(),
            at_limit: false,
            narrowed_at: None,
            overloaded: None,
            can_unsubscribe: false,
            pong_by: None,
            opening: HashSet::new(),
            resumed: false,
            ready_told: false,
            false_proof: false,
            headers: None,
            proofs_queued: VecDeque::new(),
            proofs_asked: HashSet::new(),
            proofs: HashMap::new(),
            provings: HashMap::new(),
            tip: None,
            block_at: Instant::now(),
            look: Look::Idle,
            proxy: None,
        };
        session.pump().await.unwrap();
        assert_eq!(*stream.flushes.lock().unwrap(), 1);
        let written = stream.written.lock().unwrap().clone();
        let lines: Vec<Value> = written
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(lines.len(), WINDOW);
        assert_eq!(lines[0]["method"], "blockchain.scripthash.subscribe");
        assert_eq!(lines[0]["id"], 2);
        assert_eq!(session.queue.len(), 40 - WINDOW);
        // Nothing more goes out while the window is full.
        session.pump().await.unwrap();
        assert_eq!(*stream.flushes.lock().unwrap(), 1);
    }
}
