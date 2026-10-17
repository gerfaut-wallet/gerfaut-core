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
//! The headers the server sends as its tip are kept in a row, a day of
//! them, each with the work its network asks for. A status pushed for
//! a script whose wallet waits for a block is compared with what the
//! wallet's history comes to once the latest of them took what waits
//! ([`super::confirmed_at`]). When they match, the proof of each of
//! those transactions in that block is asked for on this connection,
//! and the script is reported with the proofs once they all lead to the
//! header's root ([`super::Proven`]); as any change, for a sync, when
//! one does not, or does not come within the time a ping may take.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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
    ChangeReason, Exit, Headers, Hub, Proven, Wake, WatchState, WatchTransport, confirmed_at,
    history_status,
};
use crate::chain::electrum::{CLIENT_NAME, Target, parse, words};
use crate::chain::net::{self, BoxStream, LineReader, Security};
use crate::chain::{ANOTHER_NETWORK, Endpoint, has_proof_of_work, is_genesis_of};
use crate::network::Network;

/// The longest line read. A status is 64 characters and a header 160;
/// a server sending more than this is not speaking the protocol.
const MAX_LINE: usize = 64 * 1024;
/// Subscriptions awaiting their answer at any time: as many as ElectrumX
/// serves at once before it slows a session down. More go no faster, and
/// are already sent when the server starts refusing.
const WINDOW: usize = 10;
/// The codes aiorpcx, under ElectrumX, refuses a request with when the
/// session costs the server too much, before it closes it: excessive
/// resource usage, and server busy.
const COSTLY: [i64; 2] = [-101, -102];
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

struct Session {
    /// The server, whose refusals the hub keeps.
    endpoint: Endpoint,
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
    /// The server cut the session for what it costs, in these words.
    overloaded: Option<String>,
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
    /// The latest headers the server sent, in a row.
    headers: Option<Headers>,
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
}

pub(super) async fn run(hub: &mut Hub, endpoint: &Endpoint, target: &Target) -> Exit {
    let (tls, host, port) = match parse(&target.url) {
        Ok(parts) => parts,
        Err(detail) => return Exit::Unreachable(detail),
    };
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
    let pin = target.pin.clone();
    let network = hub.config.network;
    let opening = async move {
        let security = if tls {
            Security::Electrum {
                pin: pin.as_deref(),
            }
        } else {
            Security::Plain
        };
        let stream = net::open(&host, port, security, proxy.as_deref(), budget)
            .await
            .map_err(Exit::Unreachable)?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = LineReader::new(reader, MAX_LINE);
        // `server.version` is the first call a server expects, and the
        // one that fixes the protocol version.
        let hello = json!({
            "jsonrpc": "2.0", "id": 0, "method": "server.version",
            "params": [CLIENT_NAME, [PROTOCOL_MIN, PROTOCOL_MAX]],
        });
        send(&mut writer, &hello).await.map_err(Exit::Unreachable)?;
        let version = answer(&mut reader, 0, budget)
            .await
            .map_err(Exit::Unreachable)?;
        let negotiated = version[1].as_str().unwrap_or_default().to_owned();
        let software = version[0]
            .as_str()
            .map(crate::chain::server_words)
            .filter(|software| !software.is_empty());
        // Then its genesis block, before it hears of any script: a
        // server of another network, a signet port typed for testnet4,
        // would report changes that never happened on the wallet's.
        let genesis = json!({
            "jsonrpc": "2.0", "id": 1, "method": "blockchain.block.header", "params": [0],
        });
        send(&mut writer, &genesis)
            .await
            .map_err(Exit::Unreachable)?;
        let genesis = answer(&mut reader, 1, budget)
            .await
            .map_err(Exit::Unreachable)?;
        let genesis = genesis
            .as_str()
            .and_then(|hex| deserialize_hex::<Header>(hex).ok());
        if !genesis.is_some_and(|header| is_genesis_of(network, header.block_hash())) {
            return Err(Exit::Refused(ANOTHER_NETWORK.to_owned()));
        }
        Ok((reader, writer, negotiated, software))
    };
    let (mut reader, writer, negotiated, software) = match hub.during(opening).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(exit)) | Err(exit) => return exit,
    };

    hub.retry_limit(endpoint);
    let mut session = Session {
        endpoint: endpoint.clone(),
        writer,
        next_id: 2,
        in_flight: HashMap::new(),
        queue: VecDeque::new(),
        subscribed: HashSet::new(),
        acknowledged: 0,
        refused_run: Vec::new(),
        at_limit: false,
        overloaded: None,
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
    };
    hub.alive();
    hub.serve(Some(endpoint));
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
        let outcome: Result<(), String> = tokio::select! {
            line = reader.next_line() => match line {
                Ok(Some(line)) => {
                    hub.alive();
                    session.pong_by = None;
                    session.handle(hub, &line);
                    if let Some(detail) = session.overloaded.take() {
                        return Exit::Refused(detail);
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
                    if idle > hub.timings.keepalive * 2 {
                        session.pong_by = None;
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

    /// Sends queued proofs, then queued subscriptions, up to the window.
    async fn pump(&mut self) -> Result<(), String> {
        while self.in_flight.len() < WINDOW {
            if let Some((txid, height)) = self.proofs_queued.pop_front() {
                self.request(
                    Request::Merkle(txid, height),
                    "blockchain.transaction.get_merkle",
                    json!([txid.to_string(), height]),
                )
                .await?;
                continue;
            }
            let Some(scripthash) = self.queue.pop_front() else {
                break;
            };
            self.request(
                Request::Subscribe(scripthash.clone()),
                "blockchain.scripthash.subscribe",
                json!([scripthash]),
            )
            .await?;
        }
        Ok(())
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
            self.provings.remove(&scripthash);
            self.queue.retain(|queued| *queued != scripthash);
            hub.statuses.remove(&scripthash);
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
            if let Some(error) = error
                && costs_too_much(error)
            {
                self.cut(hub, words(error));
                return;
            }
            let refused = error.is_some();
            match request {
                Request::Headers if !refused => {
                    if let Some(height) = height_of(&message["result"]) {
                        self.take_header(hub.config.network, height, &message["result"]);
                        hub.new_tip(height, false);
                    }
                }
                Request::Merkle(txid, height) => {
                    let branch = (!refused).then(|| &message["result"]);
                    self.proved(hub, txid, height, branch);
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
                    hub.new_tip(height, false);
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

    /// The server refused a request for what the session costs it,
    /// ElectrumX past its budget, and is closing the connection. It
    /// keeps that cost against the address for a while, and coming back
    /// at once with the same burst would only be cut again: the session
    /// ends, the server is left alone ([`Exit::Refused`]), and the next
    /// session there asks for half as many scripts as this one took.
    /// The scripts that leaves out are not asked for again, so each is
    /// reported once, as a script given up on a refusal is: what it did
    /// from the cut on, nothing will tell.
    fn cut(&mut self, hub: &mut Hub, detail: String) {
        let half = self.acknowledged as usize / 2;
        if half > 0 {
            let refusals = hub.refusals.get(&self.endpoint);
            let kept = refusals
                .and_then(|refusals| refusals.limit)
                .map_or(half, |limit| limit.min(half));
            let past: Vec<String> = hub
                .watched
                .heard(refusals)
                .skip(kept)
                .filter(|entry| refusals.is_none_or(|r| !r.left_out.contains(&entry.scripthash)))
                .map(|entry| entry.hex.clone())
                .collect();
            hub.refusals
                .entry(self.endpoint.clone())
                .or_default()
                .learn_cut(kept);
            let reason = self.opening_reason();
            for hex in &past {
                hub.mark_entry(hex, reason);
            }
        }
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
        if !answer && previous.as_ref() != Some(&status) {
            // What was being proven of the status before is moot.
            self.provings.remove(scripthash);
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
            .filter(|header| has_proof_of_work(network, header));
        let Some(header) = header else {
            self.headers = None;
            return;
        };
        let alone = Headers {
            first: height,
            chain: vec![header],
        };
        let mut kept = match self.headers.take() {
            Some(mut headers)
                if height > headers.first && height <= headers.last_height().saturating_add(1) =>
            {
                headers
                    .chain
                    .truncate(usize::try_from(height - headers.first).unwrap_or(usize::MAX));
                let follows = headers
                    .chain
                    .last()
                    .is_some_and(|parent| header.prev_blockhash == parent.block_hash());
                if follows {
                    headers.chain.push(header);
                    headers
                } else {
                    alone
                }
            }
            _ => alone,
        };
        if kept.chain.len() > HEADERS_KEPT {
            let over = kept.chain.len() - HEADERS_KEPT;
            kept.chain.drain(..over);
            kept.first = kept
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
            headers: Arc::new(headers.clone()),
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
        let branch = branch
            .and_then(|branch| serde_json::from_value::<GetMerkleRes>(branch.clone()).ok())
            .filter(|branch| u32::try_from(branch.block_height) == Ok(height));
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
            let holds = branch.as_ref().is_some_and(|branch| {
                electrum_client::utils::validate_merkle_proof(&txid, &header.merkle_root, branch)
            });
            self.proofs.insert((txid, header.block_hash()), holds);
            if !holds {
                hub.mark_entry(&proving.hex, ChangeReason::Activity);
                continue;
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

/// The result of the request numbered `id`, past whatever the server
/// says before it, within `budget`.
async fn answer(
    reader: &mut LineReader<ReadHalf<BoxStream>>,
    id: u64,
    budget: Duration,
) -> Result<Value, String> {
    let read = async {
        loop {
            let line = reader
                .next_line()
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "the connection was closed".to_owned())?;
            let Ok(mut message) = serde_json::from_slice::<Value>(&line) else {
                return Err("unexpected response".to_owned());
            };
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error").filter(|e| !e.is_null()) {
                return Err(format!("the server refused the request: {}", words(error)));
            }
            return Ok(message["result"].take());
        }
    };
    tokio::time::timeout(budget, read)
        .await
        .map_err(|_| format!("timed out after {} s", budget.as_secs()))?
}

async fn send(writer: &mut WriteHalf<BoxStream>, message: &Value) -> Result<(), String> {
    let mut line = message.to_string().into_bytes();
    line.push(b'\n');
    let write = async {
        writer.write_all(&line).await?;
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

/// Whether an error is a server cutting the session for what it costs:
/// see [`COSTLY`].
fn costs_too_much(error: &Value) -> bool {
    let coded = error
        .get("code")
        .and_then(Value::as_i64)
        .is_some_and(|code| COSTLY.contains(&code));
    let words = words(error).to_lowercase();
    coded || words.contains("excessive resource usage") || words.contains("server busy")
}

/// Whether a refusal says the server takes no more subscriptions on the
/// connection: "Too many subscriptions on this connection (limit: N)"
/// from electrs, "subscription limit reached (N max per client)" from
/// the electrs of mempool, "Subscription limit reached" from Fulcrum.
fn names_a_limit(refusal: &str) -> bool {
    let refusal = refusal.to_lowercase();
    refusal.contains("subscription") && (refusal.contains("limit") || refusal.contains("too many"))
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
