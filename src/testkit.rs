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

use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::{OutPoint, Transaction, Txid};

use crate::chain::BackendConfig;

/// The BIP-173 test vector address, and its script: public material,
/// watched by the tests that need an address.
pub(crate) const ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
pub(crate) const ADDRESS_SCRIPT: &str = "0014751e76e8199196d454941c45d1b3a323f1433bd6";

/// A payment of `sats` to [`ADDRESS`], as Esplora lists it: `txid` and
/// the transaction it spends are that byte repeated, and it spends
/// output 0 of the latter, 60 000 sats of nobody's. Two payments that
/// spend the same byte replace one another.
pub(crate) fn esplora_payment(txid: u8, spends: u8, sats: u64, confirmed: bool) -> Value {
    json!({
        "txid": format!("{txid:02x}").repeat(32), "version": 2, "locktime": 0, "size": 110,
        "weight": 440, "fee": 60_000 - sats,
        "vin": [{
            "txid": format!("{spends:02x}").repeat(32), "vout": 0, "scriptsig": "",
            "sequence": 4294967293u32, "is_coinbase": false,
            "prevout": { "scriptpubkey": script(9), "value": 60_000 },
        }],
        "vout": [{ "scriptpubkey": ADDRESS_SCRIPT, "value": sats }],
        "status": if confirmed {
            json!({
                "confirmed": true, "block_height": 501, "block_hash": "33".repeat(32),
                "block_time": 1_700_000_000,
            })
        } else {
            json!({ "confirmed": false })
        },
    })
}

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

/// How the fake answers one request.
enum Answer {
    Line(Value),
    /// The start of an answer, and nothing more.
    Stall,
    /// Bytes without a line end.
    Flood(usize),
}

/// A block header at `height`, in hex, whose time is 1 700 000 000 plus
/// the height: made up, and enough for what reads a time off it.
pub(crate) fn header_at(height: u32) -> String {
    use bdk_wallet::bitcoin::block::{Header, Version};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    serialize_hex(&Header {
        version: Version::TWO,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1_700_000_000 + height,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    })
}

/// A transaction spending `inputs` to `outputs`, each a script in hex
/// and an amount. Nothing in it comes from a key: no signature, no
/// witness, only what anyone can write.
pub(crate) fn transaction(inputs: &[OutPoint], outputs: &[(&str, u64)]) -> Transaction {
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(script, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: ScriptBuf::from_hex(script).unwrap(),
            })
            .collect(),
    }
}

/// An outpoint of a transaction nobody has: `n` repeated as its txid.
pub(crate) fn nowhere(n: u8, vout: u32) -> OutPoint {
    use bdk_wallet::bitcoin::hashes::Hash;
    OutPoint::new(Txid::from_byte_array([n; 32]), vout)
}

#[derive(Default)]
pub(crate) struct ElectrumState {
    pub statuses: HashMap<String, Option<String>>,
    pub height: u32,
    /// Every connection so far: what it subscribed, and how to reach it.
    pub connections: Vec<(Vec<String>, mpsc::UnboundedSender<Option<String>>)>,
    pub unsubscribed: Vec<String>,
    pub silent: bool,
    pub version: &'static str,
    /// Histories by script hash: txid and height, oldest first, 0 for
    /// the mempool, the way servers list them.
    pub histories: HashMap<String, Vec<(Txid, i64)>>,
    /// Coins by script hash: txid, output, height and value.
    pub unspent: HashMap<String, Vec<(Txid, u32, i64, u64)>>,
    /// Transactions by txid, in hex. A txid may be made to answer with
    /// another transaction's bytes.
    pub txs: HashMap<Txid, String>,
    /// Methods answered with this error message instead.
    pub refuse: HashMap<&'static str, String>,
    /// A method whose answer starts and never ends: the connection
    /// answers nothing more after it.
    pub stall: Option<&'static str>,
    /// A method answered with this many bytes and no line end.
    pub flood: Option<(&'static str, usize)>,
    /// Every method asked for, in order, over every connection.
    pub asked: Vec<String>,
    /// Connections the client closed.
    pub closed: usize,
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
        let mut stalled = false;
        // Whether the client spoke the protocol: the port may be one
        // another test just closed, and a client of that test, still
        // trying it, is neither answered nor counted.
        let mut spoke = false;
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    let Ok(Some(line)) = line else {
                        if spoke {
                            state.lock().unwrap().closed += 1;
                        }
                        return;
                    };
                    let Ok(request) = serde_json::from_str::<Value>(&line) else {
                        return;
                    };
                    let Some(method) = request["method"].as_str().map(str::to_owned) else {
                        return;
                    };
                    spoke = true;
                    let answer = {
                        let mut state = state.lock().unwrap();
                        state.asked.push(method.clone());
                        if state.silent || stalled {
                            continue;
                        }
                        Self::answer(&mut state, index, &request, &method)
                    };
                    let bytes = match answer {
                        Answer::Line(answer) => format!("{answer}\n").into_bytes(),
                        Answer::Stall => {
                            stalled = true;
                            format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":", request["id"]).into_bytes()
                        }
                        Answer::Flood(size) => vec![b'x'; size],
                    };
                    if writer.write_all(&bytes).await.is_err() {
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

    fn answer(state: &mut ElectrumState, index: usize, request: &Value, method: &str) -> Answer {
        if state.stall == Some(method) {
            return Answer::Stall;
        }
        if let Some((flooded, size)) = state.flood
            && flooded == method
        {
            return Answer::Flood(size);
        }
        let id = &request["id"];
        let refusal = |message: &str| {
            Answer::Line(json!({
                "jsonrpc": "2.0", "id": id, "error": { "code": 1, "message": message },
            }))
        };
        if let Some(message) = state.refuse.get(method) {
            return refusal(message);
        }
        let param = request["params"][0].clone();
        let scripthash = param.as_str().unwrap_or_default().to_owned();
        let result = match method {
            "server.version" => json!(["fake 1.0", state.version]),
            "blockchain.headers.subscribe" => json!({ "height": state.height, "hex": "00" }),
            "blockchain.scripthash.subscribe" => {
                state.connections[index].0.push(scripthash.clone());
                json!(state.statuses.get(&scripthash).cloned().flatten())
            }
            "blockchain.scripthash.unsubscribe" => {
                state.unsubscribed.push(scripthash);
                json!(true)
            }
            "blockchain.scripthash.get_history" => Value::Array(
                state
                    .histories
                    .get(&scripthash)
                    .into_iter()
                    .flatten()
                    .map(|(txid, height)| json!({ "tx_hash": txid.to_string(), "height": height }))
                    .collect(),
            ),
            "blockchain.scripthash.listunspent" => Value::Array(
                state
                    .unspent
                    .get(&scripthash)
                    .into_iter()
                    .flatten()
                    .map(|(txid, vout, height, value)| {
                        json!({ "tx_hash": txid.to_string(), "tx_pos": vout, "height": height, "value": value })
                    })
                    .collect(),
            ),
            "blockchain.transaction.get" => {
                let found = param
                    .as_str()
                    .and_then(|txid| txid.parse::<Txid>().ok())
                    .and_then(|txid| state.txs.get(&txid).cloned());
                match found {
                    Some(hex) => json!(hex),
                    None => return refusal("No such mempool or blockchain transaction"),
                }
            }
            "blockchain.block.header" => json!(header_at(param.as_u64().unwrap_or(0) as u32)),
            _ => Value::Null,
        };
        Answer::Line(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    pub(crate) fn add_tx(&self, tx: &Transaction) {
        self.state
            .lock()
            .unwrap()
            .txs
            .insert(tx.compute_txid(), serialize_hex(tx));
    }

    pub(crate) fn set_history(&self, script_hex: &str, history: &[(Txid, i64)]) {
        self.state
            .lock()
            .unwrap()
            .histories
            .insert(scripthash(script_hex), history.to_vec());
    }

    pub(crate) fn set_unspent(&self, script_hex: &str, coins: &[(Txid, u32, i64, u64)]) {
        self.state
            .lock()
            .unwrap()
            .unspent
            .insert(scripthash(script_hex), coins.to_vec());
    }

    /// Connections the client has closed so far.
    pub(crate) fn closed(&self) -> usize {
        self.state.lock().unwrap().closed
    }

    /// Whether a request of this method has arrived.
    pub(crate) fn was_asked(&self, method: &str) -> bool {
        self.state.lock().unwrap().asked.iter().any(|m| m == method)
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
