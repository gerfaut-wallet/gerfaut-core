//! The Electrum transport: script hash and header subscriptions on one
//! connection, newline-delimited JSON-RPC.
//!
//! Subscriptions go out a window at a time, never all at once: a
//! public ElectrumX charges each one to the session and throttles a
//! burst. A script revealed later is subscribed on the open
//! connection; one that left the list is unsubscribed where the
//! protocol allows it and ignored where it does not. Nothing is sent
//! twice while the connection lives.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::time::Instant;

use super::net::{self, BoxStream, LineReader, Security};
use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport};
use crate::chain::Endpoint;
use crate::chain::electrum::{CLIENT_NAME, Target, parse};

/// The longest line read. A status is 64 characters and a header 160;
/// a server sending more than this is not speaking the protocol.
const MAX_LINE: usize = 64 * 1024;
/// Subscriptions awaiting their answer at any time.
const WINDOW: usize = 25;
/// Subscriptions refused in a row before the rest of the queue is given
/// up: a server at its limit refuses them all, and asking on only costs
/// it more.
const REFUSALS: u32 = 5;
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
    writer: WriteHalf<BoxStream>,
    next_id: u64,
    in_flight: HashMap<u64, Request>,
    queue: VecDeque<String>,
    /// Script hashes the server was asked to watch on this connection.
    subscribed: HashSet<String>,
    acknowledged: u32,
    refused: u32,
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
    let opening = async move {
        let security = if tls {
            Security::Electrum {
                pin: pin.as_deref(),
            }
        } else {
            Security::Plain
        };
        let stream = net::open(&host, port, security, proxy.as_deref(), budget).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = LineReader::new(reader, MAX_LINE);
        // `server.version` is the first call a server expects, and the
        // one that fixes the protocol version.
        let hello = json!({
            "jsonrpc": "2.0", "id": 0, "method": "server.version",
            "params": [CLIENT_NAME, [PROTOCOL_MIN, PROTOCOL_MAX]],
        });
        send(&mut writer, &hello).await?;
        let negotiated = tokio::time::timeout(budget, async {
            loop {
                let line = reader
                    .next_line()
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "the connection was closed".to_owned())?;
                let Ok(message) = serde_json::from_slice::<Value>(&line) else {
                    return Err("unexpected response".to_owned());
                };
                if message.get("id").and_then(Value::as_u64) != Some(0) {
                    continue;
                }
                if let Some(error) = message.get("error").filter(|e| !e.is_null()) {
                    return Err(format!("the server refused the request: {}", words(error)));
                }
                return Ok(message["result"][1].as_str().unwrap_or_default().to_owned());
            }
        })
        .await
        .map_err(|_| format!("timed out after {} s", budget.as_secs()))??;
        Ok::<_, String>((reader, writer, negotiated))
    };
    let (mut reader, writer, negotiated) = match hub.during(opening).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(detail)) => return Exit::Unreachable(detail),
        Err(exit) => return exit,
    };

    let mut session = Session {
        writer,
        next_id: 1,
        in_flight: HashMap::new(),
        queue: VecDeque::new(),
        subscribed: HashSet::new(),
        acknowledged: 0,
        refused: 0,
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

    let mut keepalive = tokio::time::interval_at(
        Instant::now() + hub.timings.keepalive,
        hub.timings.keepalive,
    );
    loop {
        let pong_by = session.pong_by;
        let outcome: Result<(), String> = tokio::select! {
            line = reader.next_line() => match line {
                Ok(Some(line)) => {
                    hub.alive();
                    session.pong_by = None;
                    session.handle(hub, &line);
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
            _ = keepalive.tick() => session.ping(hub.pong_budget(endpoint)).await,
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

    /// Tells the hub once every script of the first pass has its answer.
    fn check_ready(&mut self, hub: &mut Hub) {
        if !self.opening.is_empty() || self.ready_told {
            return;
        }
        self.ready_told = true;
        hub.ready(true);
    }

    /// Queues every script of the list not yet asked for.
    fn enqueue(&mut self, hub: &Hub) {
        for entry in &hub.watched.entries {
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
            let refused = message.get("error").is_some_and(|error| !error.is_null());
            match request {
                Request::Headers if !refused => {
                    if let Some(height) = height_of(&message["result"]) {
                        hub.new_tip(height, false);
                    }
                }
                Request::Subscribe(scripthash) if !refused => {
                    self.refused = 0;
                    self.acknowledged += 1;
                    let acknowledged = self.acknowledged;
                    hub.set_status(|status| status.pushed_scripts = acknowledged);
                    self.status(hub, &scripthash, &message["result"], true);
                    self.opening.remove(&scripthash);
                }
                // One script refused, a history too long for the server
                // to hash in time for instance, is left to the regular
                // syncs, after one of its own now: what it did while
                // nothing listened is unknown, whatever a session before
                // this one heard of it. Several in a row is a server at
                // its limit: what it took is watched, and the rest is
                // not asked for.
                Request::Subscribe(scripthash) => {
                    if let Some(entry) = hub.watched.by_scripthash(&scripthash) {
                        let hex = entry.hex.clone();
                        hub.mark_entry(&hex, self.opening_reason());
                    }
                    self.opening.remove(&scripthash);
                    self.refused += 1;
                    let refusal = words(&message["error"]);
                    hub.set_status(|status| status.detail = Some(refusal));
                    if self.refused >= REFUSALS {
                        // Not watched from now on, and what they did
                        // while nothing listened is as unknown as for
                        // the one refused: a sync of their own each.
                        let reason = self.opening_reason();
                        for given_up in self.queue.drain(..) {
                            self.opening.remove(&given_up);
                            if let Some(entry) = hub.watched.by_scripthash(&given_up) {
                                let hex = entry.hex.clone();
                                hub.mark_entry(&hex, reason);
                            }
                        }
                    }
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

/// The message of a JSON-RPC error, kept short: it comes from the
/// server and ends up on a screen.
fn words(error: &Value) -> String {
    let text = error
        .get("message")
        .and_then(Value::as_str)
        .map_or_else(|| error.to_string(), str::to_owned);
    text.chars().take(200).collect()
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
