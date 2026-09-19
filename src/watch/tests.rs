//! The watcher against servers that live in the test: an Electrum
//! server, and a mempool instance with its WebSocket and the REST
//! routes polling reads.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::*;
use crate::chain::tor::{TorMode, TorSettings};

const WAIT: Duration = Duration::from_secs(10);

fn timings() -> Timings {
    Timings {
        quiet: Duration::from_millis(40),
        burst: Duration::from_millis(200),
        gap: Duration::from_millis(150),
        keepalive: Duration::from_millis(150),
        pong: Duration::from_millis(400),
        backoff_first: Duration::from_millis(20),
        backoff_cap: Duration::from_millis(100),
        stable: Duration::from_secs(1),
        connect: Duration::from_secs(5),
        tor_connect: Duration::from_secs(5),
        poll: Duration::from_millis(100),
        reprobe: Duration::from_secs(3600),
    }
}

fn config(backend: BackendConfig) -> WatchConfig {
    WatchConfig {
        network: Network::Signet,
        backend,
        electrum_certs: TrustedCerts::new(),
        tor: TorSettings::default(),
        data_dir: std::env::temp_dir(),
        keepalive_secs: None,
    }
}

/// A P2WPKH script over twenty bytes of `n`: nobody's key.
fn script(n: u8) -> String {
    format!("0014{}", format!("{n:02x}").repeat(20))
}

fn scripthash(script_hex: &str) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, sha256};
    let bytes = data_encoding::HEXLOWER
        .decode(script_hex.as_bytes())
        .unwrap();
    let mut digest = sha256::Hash::hash(&bytes).to_byte_array();
    digest.reverse();
    data_encoding::HEXLOWER.encode(&digest)
}

fn wallet(id: &str, scripts: &[u8], lookahead: &[u8], has_pending: bool) -> WatchedWallet {
    WatchedWallet {
        wallet_id: id.to_owned(),
        scripts: scripts
            .iter()
            .map(|n| WatchedScript {
                script: script(*n),
                lookahead: lookahead.contains(n),
            })
            .collect(),
        has_pending,
    }
}

/// The next event that is not a status, within the wait.
async fn next_event(events: &mut WatchEvents) -> WatchEvent {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(WatchEvent::Status(_))) => {}
            Ok(Some(event)) => return event,
            Ok(None) => panic!("the watcher stopped"),
            Err(_) => panic!("no event within {WAIT:?}"),
        }
    }
}

/// Nothing but statuses for a while.
async fn no_event(events: &mut WatchEvents, during: Duration) {
    let quiet = async {
        loop {
            match events.next().await {
                Some(WatchEvent::Status(_)) => {}
                other => return other,
            }
        }
    };
    if let Ok(event) = tokio::time::timeout(during, quiet).await {
        panic!("expected silence, got {event:?}");
    }
}

async fn until(watch: &LiveWatch, what: &str, holds: impl Fn(&WatchStatus) -> bool) -> WatchStatus {
    let started = std::time::Instant::now();
    loop {
        let status = watch.status();
        if holds(&status) {
            return status;
        }
        assert!(started.elapsed() < WAIT, "never {what}: {status:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn changed(id: &str, reason: ChangeReason, rescan: bool) -> WatchEvent {
    WatchEvent::WalletChanged {
        wallet_id: id.to_owned(),
        reason,
        rescan,
    }
}

// --- a fake Electrum server -------------------------------------------------

#[derive(Default)]
struct ElectrumState {
    statuses: HashMap<String, Option<String>>,
    height: u32,
    /// Every connection so far: what it subscribed, and how to reach it.
    connections: Vec<(Vec<String>, mpsc::UnboundedSender<Option<String>>)>,
    unsubscribed: Vec<String>,
    silent: bool,
    version: &'static str,
}

#[derive(Clone)]
struct FakeElectrum {
    address: SocketAddr,
    state: Arc<Mutex<ElectrumState>>,
}

impl FakeElectrum {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fake = FakeElectrum {
            address: listener.local_addr().unwrap(),
            state: Arc::new(Mutex::new(ElectrumState {
                height: 100,
                version: "1.4",
                ..Default::default()
            })),
        };
        let state = fake.state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(Self::serve(stream, state.clone()));
            }
        });
        fake
    }

    async fn serve(stream: TcpStream, state: Arc<Mutex<ElectrumState>>) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let (push, mut pushed) = mpsc::unbounded_channel();
        let index = {
            let mut state = state.lock().unwrap();
            state.connections.push((Vec::new(), push));
            state.connections.len() - 1
        };
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    let Ok(Some(line)) = line else { return };
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let result = {
                        let mut state = state.lock().unwrap();
                        if state.silent {
                            continue;
                        }
                        match request["method"].as_str().unwrap() {
                            "server.version" => json!(["fake 1.0", state.version]),
                            "blockchain.headers.subscribe" => json!({ "height": state.height, "hex": "00" }),
                            "blockchain.scripthash.subscribe" => {
                                let scripthash = request["params"][0].as_str().unwrap().to_owned();
                                state.connections[index].0.push(scripthash.clone());
                                json!(state.statuses.get(&scripthash).cloned().flatten())
                            }
                            "blockchain.scripthash.unsubscribe" => {
                                let scripthash = request["params"][0].as_str().unwrap().to_owned();
                                state.unsubscribed.push(scripthash);
                                json!(true)
                            }
                            _ => Value::Null,
                        }
                    };
                    let answer = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result });
                    if writer.write_all(format!("{answer}\n").as_bytes()).await.is_err() {
                        return;
                    }
                }
                pushed = pushed.recv() => match pushed {
                    Some(Some(line)) => {
                        if writer.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    // Hang up.
                    _ => return,
                },
            }
        }
    }

    fn backend(&self) -> BackendConfig {
        BackendConfig::CustomElectrum {
            url: format!("tcp://{}", self.address),
        }
    }

    /// Sets a status and tells every connection subscribed to it.
    fn set_status(&self, script_hex: &str, status: &str) {
        let scripthash = scripthash(script_hex);
        let mut state = self.state.lock().unwrap();
        state
            .statuses
            .insert(scripthash.clone(), Some(status.to_owned()));
        let notice = json!({
            "jsonrpc": "2.0", "method": "blockchain.scripthash.subscribe",
            "params": [scripthash, status],
        });
        for (subscribed, push) in &state.connections {
            if subscribed.contains(&scripthash) {
                let _ = push.send(Some(notice.to_string()));
            }
        }
    }

    fn push(&self, line: String) {
        for (_, push) in &self.state.lock().unwrap().connections {
            let _ = push.send(Some(line.clone()));
        }
    }

    fn hang_up(&self) {
        for (_, push) in &self.state.lock().unwrap().connections {
            let _ = push.send(None);
        }
    }

    fn subscriptions(&self) -> Vec<Vec<String>> {
        let state = self.state.lock().unwrap();
        state.connections.iter().map(|c| c.0.clone()).collect()
    }
}

#[tokio::test]
async fn electrum_pushes_a_change_once_per_burst() {
    let server = FakeElectrum::start().await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![
            wallet("a", &[1, 2, 3], &[3], false),
            wallet("b", &[4], &[], false),
        ],
        Some(timings()),
    );
    let status = until(&watch, "subscribed", |s| s.pushed_scripts == 4).await;
    assert_eq!(status.state, WatchState::Connected);
    assert_eq!(status.transport, Some(WatchTransport::Electrum));
    assert_eq!(status.server.as_deref(), Some("127.0.0.1"));
    assert_eq!(status.watched_scripts, 4);
    // The head of every wallet first, then the next rank.
    assert_eq!(
        server.subscriptions(),
        vec![vec![
            scripthash(&script(1)),
            scripthash(&script(4)),
            scripthash(&script(2)),
            scripthash(&script(3)),
        ]]
    );
    // The first statuses were a baseline: nothing to report.
    no_event(&mut events, Duration::from_millis(300)).await;

    // A transaction touching two scripts of one wallet: two notices,
    // one report.
    server.set_status(&script(1), "aa");
    server.set_status(&script(2), "bb");
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::Activity, false)
    );
    no_event(&mut events, Duration::from_millis(300)).await;

    // The same status again is no change, however often it is sent.
    for _ in 0..50 {
        server.set_status(&script(1), "aa");
    }
    no_event(&mut events, Duration::from_millis(300)).await;

    // Past the revealed addresses: only a full scan looks there.
    server.set_status(&script(3), "cc");
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::Activity, true)
    );

    // A block.
    server.push(
        json!({
            "jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
            "params": [{ "height": 101, "hex": "00" }],
        })
        .to_string(),
    );
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 101 }
    );

    // Garbage, an unknown script and an answer nobody asked for are
    // read and dropped.
    server.push("not json".to_owned());
    server.push(json!({ "id": 999_999, "result": "zz" }).to_string());
    server.push(
        json!({ "method": "blockchain.scripthash.subscribe", "params": ["ff", "zz"] }).to_string(),
    );
    no_event(&mut events, Duration::from_millis(300)).await;
    assert_eq!(watch.status().state, WatchState::Connected);

    watch.stop();
    assert!(
        tokio::time::timeout(WAIT, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "a stopped watcher closes its events"
    );
    assert_eq!(watch.status(), WatchStatus::default());
}

#[tokio::test]
async fn electrum_reconnects_and_reports_what_moved_meanwhile() {
    let server = FakeElectrum::start().await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false), wallet("b", &[2], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 2).await;

    // The connection drops, and a payment to "b" lands while it is down.
    server.hang_up();
    server
        .state
        .lock()
        .unwrap()
        .statuses
        .insert(scripthash(&script(2)), Some("dd".to_owned()));
    // Every script is asked for again, and only the one that moved is
    // reported.
    assert_eq!(
        next_event(&mut events).await,
        changed("b", ChangeReason::Activity, false)
    );
    no_event(&mut events, Duration::from_millis(300)).await;
    let subscriptions = server.subscriptions();
    assert_eq!(subscriptions.len(), 2, "one reconnection");
    assert_eq!(subscriptions[1].len(), 2, "both scripts asked for again");
    assert_eq!(watch.status().state, WatchState::Connected);

    // A script revealed by a sync is subscribed on the open connection,
    // and nothing else is sent again.
    watch.set_wallets(vec![
        wallet("a", &[1, 5], &[], false),
        wallet("b", &[2], &[], false),
    ]);
    until(&watch, "the new script is subscribed", |s| {
        s.pushed_scripts == 3
    })
    .await;
    let subscriptions = server.subscriptions();
    assert_eq!(subscriptions.len(), 2);
    assert_eq!(subscriptions[1].last(), Some(&scripthash(&script(5))));
    assert_eq!(subscriptions[1].len(), 3);
    server.set_status(&script(5), "ee");
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::Activity, false)
    );

    // A removed wallet is heard no more.
    watch.set_wallets(vec![wallet("a", &[1, 5], &[], false)]);
    until(&watch, "the list shrinks", |s| s.watched_scripts == 2).await;
    server.set_status(&script(2), "ff");
    no_event(&mut events, Duration::from_millis(300)).await;
    assert_eq!(server.subscriptions().len(), 2, "no reconnection for that");
}

#[tokio::test]
async fn electrum_unsubscribes_where_the_server_can() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().version = "1.4.2";
    let (watch, _events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false), wallet("b", &[2], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 2).await;
    watch.set_wallets(vec![wallet("a", &[1], &[], false)]);
    let started = std::time::Instant::now();
    while server.state.lock().unwrap().unsubscribed.is_empty() {
        assert!(started.elapsed() < WAIT, "never unsubscribed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.state.lock().unwrap().unsubscribed,
        vec![scripthash(&script(2))]
    );
}

/// A socket that stays open and says nothing is found by the ping, and
/// by the tick of a host whose timers were asleep.
#[tokio::test]
async fn electrum_gives_up_on_a_server_that_stops_answering() {
    let server = FakeElectrum::start().await;
    let (watch, _events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(Timings {
            keepalive: Duration::from_secs(3600),
            ..timings()
        }),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 1).await;
    server.state.lock().unwrap().silent = true;
    // No timer will ping for an hour; the host's tick does.
    watch.tick();
    let status = until(&watch, "reconnecting", |s| {
        s.state == WatchState::Reconnecting
    })
    .await;
    assert_eq!(
        status.detail.as_deref(),
        Some("the server stopped answering")
    );
    // And once the server answers again, the watcher is back.
    server.state.lock().unwrap().silent = false;
    watch.tick();
    until(&watch, "connected again", |s| {
        s.state == WatchState::Connected && s.pushed_scripts == 1
    })
    .await;
}

/// An onion backend with no Tor to go through: the watcher says why and
/// keeps trying, and no connection is ever opened around Tor.
#[tokio::test]
async fn an_onion_backend_without_tor_never_connects_in_the_clear() {
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let onion = "gerfautexample000000000000000000000000000000000000000.onion";
    for backend in [
        BackendConfig::CustomElectrum {
            url: format!("tcp://{onion}:50001"),
        },
        BackendConfig::CustomEsplora {
            url: format!("http://{onion}/api"),
        },
    ] {
        let mut config = config(backend);
        config.tor = TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed.clone()),
        };
        let (watch, mut events) =
            LiveWatch::start_with(config, vec![wallet("a", &[1], &[], false)], Some(timings()));
        let status = until(&watch, "reconnecting", |s| {
            s.state == WatchState::Reconnecting
        })
        .await;
        let detail = status.detail.unwrap();
        assert!(detail.starts_with("tor: "), "{detail}");
        assert_eq!(status.pushed_scripts, 0);
        no_event(&mut events, Duration::from_millis(300)).await;
    }
}

// --- a fake mempool instance --------------------------------------------------

#[derive(Default)]
struct MempoolState {
    limit: usize,
    websocket: bool,
    tracked: Vec<Vec<String>>,
    sockets: Vec<mpsc::UnboundedSender<Option<String>>>,
    /// Transactions counted per script hex, for the REST side.
    counts: HashMap<String, u64>,
    looked_up: Vec<String>,
    tip: u32,
    /// The transactions of the one address the REST side knows, as
    /// Esplora spells them, for a sync to read.
    address_txs: Vec<Value>,
}

#[derive(Clone)]
struct FakeMempool {
    address: SocketAddr,
    state: Arc<Mutex<MempoolState>>,
}

impl FakeMempool {
    async fn start(websocket: bool, limit: usize) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fake = FakeMempool {
            address: listener.local_addr().unwrap(),
            state: Arc::new(Mutex::new(MempoolState {
                limit,
                websocket,
                tip: 500,
                ..Default::default()
            })),
        };
        let state = fake.state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(Self::serve(stream, state.clone()));
            }
        });
        fake
    }

    async fn serve(stream: TcpStream, state: Arc<Mutex<MempoolState>>) {
        let mut head = [0u8; 512];
        let Ok(read) = stream.peek(&mut head).await else {
            return;
        };
        let head = String::from_utf8_lossy(&head[..read]).into_owned();
        let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
        if path.ends_with("/v1/ws") && state.lock().unwrap().websocket {
            Self::websocket(stream, state).await;
        } else {
            Self::rest(stream, &path, state).await;
        }
    }

    async fn websocket(stream: TcpStream, state: Arc<Mutex<MempoolState>>) {
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (push, mut pushed) = mpsc::unbounded_channel();
        state.lock().unwrap().sockets.push(push);
        loop {
            tokio::select! {
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { return };
                    let request: Value = serde_json::from_str(text.as_str()).unwrap();
                    let answer = {
                        let mut state = state.lock().unwrap();
                        if let Some(scripts) = request.get("track-scriptpubkeys") {
                            let scripts: Vec<String> = serde_json::from_value(scripts.clone()).unwrap();
                            if scripts.len() > state.limit {
                                Some(json!({ "track-scriptpubkeys-error": format!(
                                    "too many scriptpubkeys requested, this connection supports tracking a maximum of {} scriptpubkeys",
                                    state.limit
                                ) }))
                            } else {
                                state.tracked.push(scripts);
                                None
                            }
                        } else if request["action"] == "want" {
                            Some(json!({ "blocks": [{ "height": state.tip - 1 }, { "height": state.tip }] }))
                        } else if request["action"] == "ping" {
                            Some(json!({ "pong": true }))
                        } else {
                            None
                        }
                    };
                    if let Some(answer) = answer
                        && socket.send(Message::text(answer.to_string())).await.is_err()
                    {
                        return;
                    }
                }
                pushed = pushed.recv() => match pushed {
                    Some(Some(text)) => {
                        if socket.send(Message::text(text)).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                },
            }
        }
    }

    async fn rest(mut stream: TcpStream, path: &str, state: Arc<Mutex<MempoolState>>) {
        let mut request = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
        let (status, body) = {
            let mut state = state.lock().unwrap();
            if path.ends_with("/blocks/tip/hash") {
                ("200 OK", format!("{:064x}", state.tip))
            } else if path.ends_with("/blocks/tip/height") {
                ("200 OK", state.tip.to_string())
            } else if path.ends_with("/utxo") || path.contains("/txs/chain/") {
                ("200 OK", "[]".to_owned())
            } else if path.ends_with("/txs") {
                (
                    "200 OK",
                    Value::Array(state.address_txs.clone()).to_string(),
                )
            } else if let Some(address) = path.rsplit_once("/address/").map(|(_, a)| a) {
                let count = |confirmed: bool| {
                    let txs = state
                        .address_txs
                        .iter()
                        .filter(|tx| tx["status"]["confirmed"] == confirmed)
                        .count();
                    json!({
                        "funded_txo_count": txs, "funded_txo_sum": txs * 50_000,
                        "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": txs,
                    })
                };
                (
                    "200 OK",
                    json!({ "address": address, "chain_stats": count(true), "mempool_stats": count(false) })
                        .to_string(),
                )
            } else if let Some(hash) = path.rsplit_once("/scripthash/").map(|(_, hash)| hash) {
                state.looked_up.push(hash.to_owned());
                let count = state.counts.get(hash).copied().unwrap_or(0);
                let stats = |txs: u64| {
                    json!({
                        "funded_txo_count": txs, "funded_txo_sum": txs * 1000,
                        "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": txs,
                    })
                };
                (
                    "200 OK",
                    json!({ "scripthash": hash, "chain_stats": stats(0), "mempool_stats": stats(count) })
                        .to_string(),
                )
            } else {
                ("404 Not Found", "Not Found".to_owned())
            }
        };
        let answer = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(answer.as_bytes()).await;
    }

    fn backend(&self) -> BackendConfig {
        BackendConfig::CustomEsplora {
            url: format!("http://{}/api", self.address),
        }
    }

    fn push(&self, message: Value) {
        for socket in &self.state.lock().unwrap().sockets {
            let _ = socket.send(Some(message.to_string()));
        }
    }

    /// The key polling looks a script up under: SHA-256, not reversed.
    fn rest_key(script_hex: &str) -> String {
        use bdk_wallet::bitcoin::hashes::{Hash, sha256};
        let bytes = data_encoding::HEXLOWER
            .decode(script_hex.as_bytes())
            .unwrap();
        data_encoding::HEXLOWER.encode(&sha256::Hash::hash(&bytes).to_byte_array())
    }
}

#[tokio::test]
async fn a_mempool_websocket_pushes_what_it_tracks_and_polls_the_rest() {
    let server = FakeMempool::start(true, 2).await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![
            wallet("a", &[1, 2, 3], &[], true),
            wallet("b", &[4], &[], false),
        ],
        Some(timings()),
    );
    // The server names its limit by refusing the list, and the head of
    // every wallet is what it is given then.
    let status = until(&watch, "tracking", |s| s.pushed_scripts == 2).await;
    assert_eq!(status.state, WatchState::Connected);
    assert_eq!(status.transport, Some(WatchTransport::MempoolWebsocket));
    assert_eq!(status.watched_scripts, 4);
    assert_eq!(
        server.state.lock().unwrap().tracked,
        vec![vec![script(1), script(4)]]
    );

    // A pushed transaction.
    server.push(json!({ "multi-scriptpubkey-transactions": {
        script(4): { "mempool": [{ "txid": "00" }], "confirmed": [], "removed": [] }
    } }));
    assert_eq!(
        next_event(&mut events).await,
        changed("b", ChangeReason::Activity, false)
    );

    // A block: the wallet waiting for a confirmation is worth a sync,
    // the other is not.
    server.push(json!({ "block": { "height": 501, "id": "00" } }));
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 501 }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );

    // The scripts the server does not push are polled, and only those.
    let started = std::time::Instant::now();
    while !server
        .state
        .lock()
        .unwrap()
        .looked_up
        .contains(&FakeMempool::rest_key(&script(3)))
    {
        assert!(started.elapsed() < WAIT, "never polled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server
        .state
        .lock()
        .unwrap()
        .counts
        .insert(FakeMempool::rest_key(&script(3)), 1);
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::Activity, false)
    );
    let looked_up = server.state.lock().unwrap().looked_up.clone();
    assert!(!looked_up.contains(&FakeMempool::rest_key(&script(1))));
    assert!(!looked_up.contains(&FakeMempool::rest_key(&script(4))));

    // The connection drops: this transport cannot say what it missed,
    // so every wallet is reported once, and the list is tracked again.
    for socket in &server.state.lock().unwrap().sockets {
        let _ = socket.send(None);
    }
    let mut reported = vec![next_event(&mut events).await, next_event(&mut events).await];
    reported.sort_by_key(|event| format!("{event:?}"));
    assert_eq!(
        reported,
        vec![
            changed("a", ChangeReason::Reconnected, false),
            changed("b", ChangeReason::Reconnected, false),
        ]
    );
    until(&watch, "tracking again", |s| {
        s.state == WatchState::Connected && s.pushed_scripts == 2
    })
    .await;
}

#[tokio::test]
async fn an_esplora_without_a_websocket_is_polled() {
    let server = FakeMempool::start(false, 0).await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1, 2], &[2], true)],
        Some(timings()),
    );
    let status = until(&watch, "polling", |s| s.state == WatchState::Polling).await;
    assert_eq!(status.transport, Some(WatchTransport::EsploraPolling));
    assert_eq!(status.pushed_scripts, 0);
    no_event(&mut events, Duration::from_millis(300)).await;

    server
        .state
        .lock()
        .unwrap()
        .counts
        .insert(FakeMempool::rest_key(&script(2)), 1);
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::Activity, true)
    );

    server.state.lock().unwrap().tip = 501;
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 501 }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );
}

/// Another backend: the old connection is closed, the new one opened,
/// and nothing of the old baseline is compared with the new server.
#[tokio::test]
async fn a_new_configuration_moves_the_watch() {
    let first = FakeElectrum::start().await;
    let second = FakeElectrum::start().await;
    second
        .state
        .lock()
        .unwrap()
        .statuses
        .insert(scripthash(&script(1)), Some("other".to_owned()));
    let (watch, mut events) = LiveWatch::start_with(
        config(first.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 1).await;
    watch.reconfigure(
        config(second.backend()),
        vec![wallet("a", &[1], &[], false)],
    );
    let started = std::time::Instant::now();
    while second.subscriptions().is_empty() {
        assert!(started.elapsed() < WAIT, "never moved");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until(&watch, "subscribed again", |s| s.pushed_scripts == 1).await;
    no_event(&mut events, Duration::from_millis(300)).await;

    // Nothing left to watch: the connection is given up.
    watch.set_wallets(Vec::new());
    until(&watch, "off", |s| s.state == WatchState::Off).await;
}

// --- the parts on their own ---------------------------------------------------

#[test]
fn the_automatic_backend_prefers_a_server_that_pushes() {
    let candidates_of = |network| {
        let mut config = config(BackendConfig::default());
        config.network = network;
        candidates(&config)
            .unwrap()
            .iter()
            .map(Endpoint::label)
            .collect::<Vec<_>>()
    };
    // An Electrum server of an operator the rotation already goes
    // through, then the rotation: no host the mode did not name.
    assert_eq!(
        candidates_of(Network::Mainnet),
        vec![
            "blockstream.info",
            "mempool.space",
            "blockstream.info",
            "mempool.emzy.de"
        ]
    );
    assert_eq!(candidates_of(Network::Signet)[0], "mempool.space");
    assert_eq!(candidates_of(Network::Signet).len(), 4);
    assert!(matches!(
        candidates(&config(BackendConfig::default())).unwrap()[0],
        Endpoint::Electrum(_)
    ));

    // A chosen server is the only one, whatever it speaks.
    let chosen = config(BackendConfig::Public {
        server: Some("blockstream.info".to_owned()),
    });
    assert_eq!(
        candidates(&chosen).unwrap(),
        vec![Endpoint::Esplora(
            "https://blockstream.info/signet/api".to_owned()
        )]
    );
}

#[test]
fn a_list_is_cut_to_what_can_be_watched() {
    let long: Vec<u8> = (0..=255).collect();
    let mut wallets = vec![wallet("a", &long, &[], false)];
    wallets[0].scripts.push(WatchedScript {
        script: "not hex".to_owned(),
        lookahead: false,
    });
    wallets.push(wallet("b", &[1, 1, 250], &[1], false));
    let watched = Watched::new(wallets);
    assert_eq!(watched.entries.len(), MAX_SCRIPTS_PER_WALLET + 1);
    // Shared by two wallets, and revealed in one of them: not lookahead.
    let shared = watched.by_hex(&script(1)).unwrap();
    assert_eq!(shared.owners.len(), 2);
    assert!(!shared.lookahead);
    assert_eq!(
        watched
            .by_scripthash(&scripthash(&script(250)))
            .unwrap()
            .hex,
        script(250)
    );
}

#[tokio::test]
async fn a_burst_is_one_report_and_a_flood_is_held_to_the_gap() {
    let timings = timings();
    let mut debounce = Debouncer::default();
    let start = Instant::now();
    debounce.mark("a", ChangeReason::NewBlock, false, start);
    debounce.mark(
        "a",
        ChangeReason::Activity,
        true,
        start + Duration::from_millis(10),
    );
    debounce.mark(
        "a",
        ChangeReason::Reconnected,
        false,
        start + Duration::from_millis(20),
    );
    assert!(
        debounce
            .take_due(start + Duration::from_millis(30), &timings)
            .is_empty()
    );
    let due = debounce.take_due(start + Duration::from_millis(61), &timings);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].1.reason, ChangeReason::Activity);
    assert!(due[0].1.rescan);

    // Marked without a pause, a wallet still goes out by the end of the
    // burst window.
    for step in 0..20 {
        debounce.mark(
            "b",
            ChangeReason::Activity,
            false,
            start + Duration::from_millis(step * 20),
        );
    }
    assert_eq!(
        debounce.next_deadline(&timings),
        Some(start + timings.burst)
    );

    // Reported a moment ago: the next report waits for the gap.
    debounce.reported.insert("c".to_owned(), start);
    debounce.mark(
        "c",
        ChangeReason::Activity,
        false,
        start + Duration::from_millis(1),
    );
    assert_eq!(
        debounce.due_at("c", &debounce.pending["c"], &timings),
        start + timings.gap
    );
}

#[test]
fn a_backoff_doubles_up_to_its_cap() {
    let timings = timings();
    let mut backoff = Backoff {
        next: Duration::ZERO,
    };
    let mut ceiling = timings.backoff_first;
    for _ in 0..8 {
        let delay = backoff.delay(&timings);
        assert!(
            delay >= ceiling / 2 && delay <= ceiling,
            "{delay:?} {ceiling:?}"
        );
        ceiling = (ceiling * 2).min(timings.backoff_cap);
    }
    assert_eq!(ceiling, timings.backoff_cap);
    backoff.reset();
    assert!(backoff.delay(&timings) <= timings.backoff_first);
}

// --- the manager ---------------------------------------------------------------

/// The BIP-173 test vector address, and its script.
const ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const ADDRESS_SCRIPT: &str = "0014751e76e8199196d454941c45d1b3a323f1433bd6";

fn payment(confirmed: bool) -> Value {
    json!({
        "txid": "11".repeat(32), "version": 2, "locktime": 0, "size": 110, "weight": 440, "fee": 200,
        "vin": [{
            "txid": "22".repeat(32), "vout": 0, "scriptsig": "", "sequence": 4294967293u32,
            "is_coinbase": false,
            "prevout": { "scriptpubkey": script(9), "value": 60_000 },
        }],
        "vout": [{ "scriptpubkey": ADDRESS_SCRIPT, "value": 50_000 }],
        "status": if confirmed {
            json!({ "confirmed": true, "block_height": 501, "block_hash": "33".repeat(32), "block_time": 1_700_000_000 })
        } else {
            json!({ "confirmed": false })
        },
    })
}

async fn next_live(events: &mut crate::live::LiveEvents) -> crate::live::LiveEvent {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(crate::live::LiveEvent::Status(_))) => {}
            Ok(Some(event)) => return event,
            Ok(None) => panic!("the live watch stopped"),
            Err(_) => panic!("no live event within {WAIT:?}"),
        }
    }
}

/// The whole path, against a fake Esplora: the watch sees the script
/// move, the manager syncs the wallet, and the payment is announced
/// when it enters the mempool and again when it confirms, once each,
/// whoever else syncs or asks, and across a restart.
#[tokio::test]
async fn the_manager_announces_a_payment_twice_and_no_more() {
    use crate::live::{LiveEvent, LiveTx};
    use crate::store::TxStage;

    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let key = crate::store::VaultKey::Raw([7; 32]);
    let manager = crate::WalletManager::open(dir.path(), key).unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_backend(Network::Signet, server.backend())
        .await
        .unwrap();
    let parsed = crate::input::parse_input(ADDRESS).unwrap();
    let wallet = manager
        .add_wallet("Watched", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(
        manager.watch_list(Network::Signet).await,
        vec![WatchedWallet {
            wallet_id: wallet.id.clone(),
            scripts: vec![WatchedScript {
                script: ADDRESS_SCRIPT.to_owned(),
                lookahead: false,
            }],
            has_pending: false,
        }]
    );
    manager.sync_wallet(&wallet.id).await.unwrap();

    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    let rest_key = FakeMempool::rest_key(ADDRESS_SCRIPT);
    let started = std::time::Instant::now();
    while !server.state.lock().unwrap().looked_up.contains(&rest_key) {
        assert!(started.elapsed() < WAIT, "never polled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(manager.live_status().await.state, WatchState::Polling);

    // The payment enters the mempool.
    {
        let mut state = server.state.lock().unwrap();
        state.address_txs = vec![payment(false)];
        state.counts.insert(rest_key.clone(), 1);
    }
    let announced = |stage| {
        LiveEvent::Transaction(LiveTx {
            wallet_id: wallet.id.clone(),
            txid: "11".repeat(32),
            net_sats: 50_000,
            stage,
        })
    };
    assert_eq!(next_live(&mut events).await, announced(TxStage::Mempool));
    match next_live(&mut events).await {
        LiveEvent::WalletSynced { report } => assert_eq!(report.new_txs.len(), 1),
        other => panic!("expected the sync, got {other:?}"),
    }

    // A block takes it: the wallet waits for one, so the new tip is
    // worth a sync, and that sync finds the confirmation.
    {
        let mut state = server.state.lock().unwrap();
        state.address_txs = vec![payment(true)];
        state.tip = 501;
    }
    loop {
        match next_live(&mut events).await {
            LiveEvent::NewBlock { height } => assert_eq!(height, 501),
            LiveEvent::WalletSynced { .. } => {}
            event => {
                assert_eq!(event, announced(TxStage::Confirmed));
                break;
            }
        }
    }

    // Anyone else reading the same news is told it was said already,
    // in this process and after a restart.
    let said = crate::wallet::snapshot::SyncReport {
        wallet_id: wallet.id.clone(),
        new_tx_count: 1,
        new_txs: vec![crate::wallet::snapshot::NewTx {
            txid: "11".repeat(32),
            net_sats: 50_000,
            confirmed: false,
        }],
        confirmed_txs: vec![crate::wallet::snapshot::NewTx {
            txid: "11".repeat(32),
            net_sats: 50_000,
            confirmed: true,
        }],
        ..manager.sync_wallet(&wallet.id).await.unwrap()
    };
    assert!(manager.claim_announcements(&said).await.unwrap().is_empty());
    manager.live_stop().await;
    assert!(
        tokio::time::timeout(WAIT, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "a stopped watch closes its events"
    );
    assert_eq!(manager.live_status().await, WatchStatus::default());
    drop(manager);
    let reopened =
        crate::WalletManager::open(dir.path(), crate::store::VaultKey::Raw([7; 32])).unwrap();
    assert!(
        reopened
            .claim_announcements(&said)
            .await
            .unwrap()
            .is_empty()
    );
    // Something never said is handed out, once.
    let mut other = said.clone();
    other.new_txs[0].txid = "44".repeat(32);
    other.confirmed_txs.clear();
    assert_eq!(reopened.claim_announcements(&other).await.unwrap().len(), 1);
    assert!(
        reopened
            .claim_announcements(&other)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A descriptor wallet is watched from the address it shows next, past
/// the ones it has revealed, on both keychains.
#[tokio::test]
async fn a_descriptor_wallet_is_watched_past_what_it_revealed() {
    const EXTERNAL: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";
    let dir = tempfile::tempdir().unwrap();
    let key = crate::store::VaultKey::Raw([7; 32]);
    let manager = crate::WalletManager::open(dir.path(), key).unwrap();
    let parsed = crate::input::parse_input(EXTERNAL).unwrap();
    let wallet = manager
        .add_wallet("Cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let next = manager.receive_addresses(&wallet.id, 0).await.unwrap()[0]
        .address
        .clone();
    let next_script = next
        .parse::<bdk_wallet::bitcoin::Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let list = manager.watch_list(Network::Signet).await;
    assert_eq!(list.len(), 1);
    assert!(!list[0].has_pending);
    let scripts = &list[0].scripts;
    assert_eq!(
        scripts[0].script, next_script,
        "the address shown comes first"
    );
    assert!(!scripts[0].lookahead);
    let gap = manager.settings().await.gap_limit as usize;
    let ahead = scripts.iter().filter(|script| script.lookahead).count();
    assert!(
        ahead >= gap,
        "{ahead} scripts past the revealed ones, gap {gap}"
    );
    let unique: std::collections::HashSet<&String> =
        scripts.iter().map(|script| &script.script).collect();
    assert_eq!(unique.len(), scripts.len());
    // Another network has nothing to watch.
    assert!(manager.watch_list(Network::Mainnet).await.is_empty());
}

// --- live -----------------------------------------------------------------------

const SIGNET_ELECTRUM: &str = "ssl://signet-electrumx.wakiyamap.dev:50002";
const SIGNET_ESPLORA: &str = "https://mempool.emzy.de/signet/api";

/// Scripts that are about to move: the outputs of transactions sitting
/// in the signet mempool, which the next block confirms. A script with
/// a long history is left out, as servers refuse to hash or count it.
async fn scripts_waiting_for_a_block() -> Vec<String> {
    let client = crate::chain::esplora::client(SIGNET_ESPLORA, None).unwrap();
    let mut scripts = Vec::new();
    for recent in client.get_mempool_recent_txs().await.unwrap() {
        let Ok(Some(tx)) = client.get_tx(&recent.txid).await else {
            continue;
        };
        for output in tx.output {
            let Ok(stats) = client.get_scripthash_stats(&output.script_pubkey).await else {
                continue;
            };
            let hex = output.script_pubkey.to_hex_string();
            if stats.chain_stats.tx_count < 500 && !scripts.contains(&hex) {
                scripts.push(hex);
            }
        }
        if scripts.len() >= 8 {
            break;
        }
    }
    scripts.truncate(8);
    scripts
}

/// Live. The three transports watch the same scripts on signet, each
/// against a public server, until the next block confirms what was
/// pending on them. Every event is printed with the time it arrived:
/// run with `--nocapture` to compare the transports. Takes as long as
/// signet takes to find a block, ten minutes on average.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "talks to public signet servers until the next block"]
async fn live_the_three_transports_see_signet_move() {
    let scripts = scripts_waiting_for_a_block().await;
    assert!(
        !scripts.is_empty(),
        "the signet mempool is empty, try later"
    );
    println!("watching {scripts:?}");
    let wallets = vec![WatchedWallet {
        wallet_id: "pending".to_owned(),
        scripts: scripts
            .into_iter()
            .map(|script| WatchedScript {
                script,
                lookahead: false,
            })
            .collect(),
        has_pending: true,
    }];
    // The Electrum server may sign its own certificate: accepted here
    // the way the settings screen does it, by its fingerprint.
    let mut electrum = config(BackendConfig::CustomElectrum {
        url: SIGNET_ELECTRUM.to_owned(),
    });
    let inspected = tokio::task::spawn_blocking(|| {
        crate::chain::electrum::inspect_blocking(&crate::chain::electrum::Target::new(
            SIGNET_ELECTRUM,
            None,
        ))
    })
    .await
    .unwrap()
    .expect("the signet Electrum server answers");
    if let crate::chain::electrum::Inspection::Tls(crate::chain::tls::Verdict::Unknown {
        fingerprint,
        ..
    }) = inspected
    {
        electrum.electrum_certs.insert(
            crate::chain::electrum::certificate_key(SIGNET_ELECTRUM),
            fingerprint,
        );
    }
    let websocket = config(BackendConfig::Public {
        server: Some("mempool.emzy.de".to_owned()),
    });
    let polling = config(BackendConfig::Public {
        server: Some("blockstream.info".to_owned()),
    });

    let started = std::time::Instant::now();
    let (seen, mut all_seen) = mpsc::unbounded_channel();
    let mut watches = Vec::new();
    for (name, config, transport, state) in [
        (
            "electrum",
            electrum,
            WatchTransport::Electrum,
            WatchState::Connected,
        ),
        (
            "websocket",
            websocket,
            WatchTransport::MempoolWebsocket,
            WatchState::Connected,
        ),
        (
            "polling",
            polling,
            WatchTransport::EsploraPolling,
            WatchState::Polling,
        ),
    ] {
        let (watch, mut events) = LiveWatch::start(config, wallets.clone());
        watches.push(watch);
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                let at = started.elapsed().as_secs_f32();
                println!("{at:>8.2} s  {name:<9}  {event:?}");
                match event {
                    WatchEvent::Status(status) if status.state == state => {
                        assert_eq!(status.transport, Some(transport), "{name}");
                    }
                    WatchEvent::WalletChanged { .. } => {
                        let _ = seen.send(name);
                    }
                    _ => {}
                }
            }
        });
    }
    // Polling is printed and not waited for: blockstream.info caps an
    // address at 700 requests an hour, which a machine running these
    // tests may already have spent.
    let mut reported = std::collections::BTreeSet::new();
    while !(reported.contains("electrum") && reported.contains("websocket")) {
        let name = tokio::time::timeout(Duration::from_secs(45 * 60), all_seen.recv())
            .await
            .unwrap_or_else(|_| panic!("only {reported:?} saw the scripts move"))
            .unwrap();
        reported.insert(name);
    }
    // A little longer, for the stragglers of the same block.
    tokio::time::sleep(Duration::from_secs(90)).await;
}
