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
//! does not ask the server, or the syncs, for it again.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::Instant;

use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport};
use crate::chain::electrum::{CLIENT_NAME, Target, parse, words};
use crate::chain::net::{self, BoxStream, LineReader, Security};
use crate::chain::{ANOTHER_NETWORK, Endpoint, is_genesis_of};

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

enum Request {
    Headers,
    Subscribe(String),
    Other,
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
                next_ping = Instant::now() + hub.timings.keepalive_wait();
                session.ping(hub.pong_budget(endpoint)).await
            }
            () = super::sleep_until(pong_by), if pong_by.is_some() => {
                Err("the server stopped answering".to_owned())
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

    /// Sends queued subscriptions up to the window.
    async fn pump(&mut self) -> Result<(), String> {
        while self.in_flight.len() < WINDOW {
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
                        hub.new_tip(height, false);
                    }
                }
                Request::Subscribe(scripthash) if !refused => {
                    self.refused_run.clear();
                    self.acknowledged += 1;
                    if self.at_limit {
                        // Taken after all, answered out of order: the
                        // limit is what the connection holds.
                        let limit =
                            &mut hub.refusals.entry(self.endpoint.clone()).or_default().limit;
                        *limit = (*limit).max(Some(self.acknowledged as usize));
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
                refusals.limit = Some(self.acknowledged as usize);
                given_up.extend(self.queue.drain(..));
            } else {
                refusals.scripts.insert(scripthash.to_owned());
            }
        }
        let reason = self.opening_reason();
        for scripthash in given_up {
            self.opening.remove(&scripthash);
            if let Some(entry) = hub.watched.by_scripthash(&scripthash) {
                let hex = entry.hex.clone();
                hub.mark_entry(&hex, reason);
            }
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
            let heard: Vec<String> = hub
                .watched
                .heard(hub.refusals.get(&self.endpoint))
                .map(|entry| entry.hex.clone())
                .collect();
            let limit = &mut hub.refusals.entry(self.endpoint.clone()).or_default().limit;
            let kept = limit.map_or(half, |limit| limit.min(half));
            *limit = Some(kept);
            let reason = self.opening_reason();
            for hex in heard.iter().skip(kept) {
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
        if !lacking || (!answer && previous.as_ref() == Some(&status)) {
            return;
        }
        let reason = if answer {
            self.opening_reason()
        } else {
            ChangeReason::Activity
        };
        hub.mark_entry(&hex, reason);
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
