//! Servers that live in the tests: an Electrum server, and a mempool
//! instance with its WebSocket and the REST routes Esplora clients
//! read. The watcher, the syncs and the live alerts are tested against
//! them, so no test of the suite reaches the network.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::chain::BackendConfig;

/// A P2WPKH script over twenty bytes of `n`: nobody's key.
pub(crate) fn script(n: u8) -> String {
    format!("0014{}", format!("{n:02x}").repeat(20))
}

/// The Electrum script hash of a script in hex: SHA-256, reversed.
pub(crate) fn scripthash(script_hex: &str) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, sha256};
    let bytes = data_encoding::HEXLOWER
        .decode(script_hex.as_bytes())
        .unwrap();
    let mut digest = sha256::Hash::hash(&bytes).to_byte_array();
    digest.reverse();
    data_encoding::HEXLOWER.encode(&digest)
}

// --- a fake Electrum server -------------------------------------------------

#[derive(Default)]
pub(crate) struct ElectrumState {
    pub statuses: HashMap<String, Option<String>>,
    pub height: u32,
    /// Every connection so far: what it subscribed, and how to reach it.
    pub connections: Vec<(Vec<String>, mpsc::UnboundedSender<Option<String>>)>,
    pub unsubscribed: Vec<String>,
    pub silent: bool,
    pub version: &'static str,
}

#[derive(Clone)]
pub(crate) struct FakeElectrum {
    pub address: SocketAddr,
    pub state: Arc<Mutex<ElectrumState>>,
}

impl FakeElectrum {
    pub(crate) async fn start() -> Self {
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

    pub(crate) fn backend(&self) -> BackendConfig {
        BackendConfig::CustomElectrum {
            url: format!("tcp://{}", self.address),
        }
    }

    /// Sets a status and tells every connection subscribed to it.
    pub(crate) fn set_status(&self, script_hex: &str, status: &str) {
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

    pub(crate) fn push(&self, line: String) {
        for (_, push) in &self.state.lock().unwrap().connections {
            let _ = push.send(Some(line.clone()));
        }
    }

    pub(crate) fn hang_up(&self) {
        for (_, push) in &self.state.lock().unwrap().connections {
            let _ = push.send(None);
        }
    }

    pub(crate) fn subscriptions(&self) -> Vec<Vec<String>> {
        let state = self.state.lock().unwrap();
        state.connections.iter().map(|c| c.0.clone()).collect()
    }
}

// --- a fake mempool instance --------------------------------------------------

#[derive(Default)]
pub(crate) struct MempoolState {
    pub limit: usize,
    pub websocket: bool,
    pub tracked: Vec<Vec<String>>,
    pub sockets: Vec<mpsc::UnboundedSender<Option<String>>>,
    /// Transactions counted per script hex, for the REST side.
    pub counts: HashMap<String, u64>,
    pub looked_up: Vec<String>,
    pub tip: u32,
    /// The transactions of the one address the REST side knows, as
    /// Esplora spells them, for a sync to read.
    pub address_txs: Vec<Value>,
}

#[derive(Clone)]
pub(crate) struct FakeMempool {
    pub address: SocketAddr,
    pub state: Arc<Mutex<MempoolState>>,
}

impl FakeMempool {
    pub(crate) async fn start(websocket: bool, limit: usize) -> Self {
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

    pub(crate) fn backend(&self) -> BackendConfig {
        BackendConfig::CustomEsplora {
            url: format!("http://{}/api", self.address),
        }
    }

    pub(crate) fn push(&self, message: Value) {
        for socket in &self.state.lock().unwrap().sockets {
            let _ = socket.send(Some(message.to_string()));
        }
    }

    /// The key polling looks a script up under: SHA-256, not reversed.
    pub(crate) fn rest_key(script_hex: &str) -> String {
        use bdk_wallet::bitcoin::hashes::{Hash, sha256};
        let bytes = data_encoding::HEXLOWER
            .decode(script_hex.as_bytes())
            .unwrap();
        data_encoding::HEXLOWER.encode(&sha256::Hash::hash(&bytes).to_byte_array())
    }
}
