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

thread_local! {
    /// The txid of the last payment [`esplora_payment`] built under each
    /// label, on this thread: a test runs on a thread of its own.
    static PAYMENTS: std::cell::RefCell<HashMap<u8, String>> = Default::default();
}

/// The txid of a transaction as Esplora lists it: the hash of what it
/// lists, as a server's must be.
pub(crate) fn listed_txid(listed: &Value) -> String {
    let tx: crate::chain::esplora::page::PageTx = serde_json::from_value(listed.clone()).unwrap();
    tx.to_tx().compute_txid().to_string()
}

/// The txid of the payment labelled `label` this test built last with
/// [`esplora_payment`]; the label repeated, a txid of nothing, when it
/// built none under it.
pub(crate) fn esplora_txid(label: u8) -> String {
    PAYMENTS.with(|payments| {
        payments
            .borrow()
            .get(&label)
            .cloned()
            .unwrap_or_else(|| format!("{label:02x}").repeat(32))
    })
}

/// A payment of `sats` to [`ADDRESS`], as Esplora lists it, labelled
/// `label`: its lock time, which tells apart payments alike otherwise,
/// and the name [`esplora_txid`] finds its txid under. The transaction it
/// spends is that byte repeated, and it spends output 0 of the latter,
/// 60 000 sats of nobody's. Two payments that spend the same byte replace
/// one another. Its txid is the hash of what it lists, as a server's is.
pub(crate) fn esplora_payment(label: u8, spends: u8, sats: u64, confirmed: bool) -> Value {
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_consensus(u32::from(label)),
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([spends; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(4_294_967_293),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_hex(ADDRESS_SCRIPT).unwrap(),
        }],
    };
    let txid = tx.compute_txid().to_string();
    PAYMENTS.with(|payments| payments.borrow_mut().insert(label, txid.clone()));
    json!({
        "txid": txid, "version": 2, "locktime": label, "size": 110,
        "weight": 440, "fee": 60_000 - sats,
        "vin": [{
            "txid": format!("{spends:02x}").repeat(32), "vout": 0, "scriptsig": "",
            "sequence": 4294967293u32, "is_coinbase": false,
            "prevout": { "scriptpubkey": script(9), "value": 60_000 },
        }],
        "vout": [{ "scriptpubkey": ADDRESS_SCRIPT, "value": sats }],
        "status": if confirmed {
            json!({
                "confirmed": true, "block_height": 500, "block_hash": "33".repeat(32),
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

/// The Electrum status of a history: SHA-256 of `txid:height:` for each
/// transaction, in the order listed.
pub(crate) fn status_of(history: &[(Txid, i64)]) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, HashEngine, sha256};
    let mut engine = sha256::Hash::engine();
    for (txid, height) in history {
        engine.input(format!("{txid}:{height}:").as_bytes());
    }
    data_encoding::HEXLOWER.encode(&sha256::Hash::from_engine(engine).to_byte_array())
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
    /// The last answer, after which the connection is closed.
    Last(Value),
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
        time: 1_700_000_000_u32.wrapping_add(height),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    })
}

/// The merkle root of a block of `txids`, and the branch of the one at
/// `pos` as a server spells it: each hash reversed, in hex. The last
/// node of an odd row is paired with a copy of itself, as consensus
/// builds the tree. No transaction, no root: all zeroes.
pub(crate) fn merkle_of(txids: &[Txid], pos: usize) -> ([u8; 32], Vec<String>) {
    use bdk_wallet::bitcoin::hashes::{Hash, sha256d};
    let mut row: Vec<[u8; 32]> = txids.iter().map(|txid| txid.to_byte_array()).collect();
    let mut index = pos;
    let mut branch = Vec::new();
    while row.len() > 1 {
        if row.len() % 2 == 1 {
            row.push(*row.last().unwrap());
        }
        let mut sibling = row[index ^ 1];
        sibling.reverse();
        branch.push(data_encoding::HEXLOWER.encode(&sibling));
        row = row
            .chunks(2)
            .map(|pair| {
                let mut inner = [0u8; 64];
                inner[..32].copy_from_slice(&pair[0]);
                inner[32..].copy_from_slice(&pair[1]);
                sha256d::Hash::hash(&inner).to_byte_array()
            })
            .collect();
        index /= 2;
    }
    (row.first().copied().unwrap_or_default(), branch)
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
    /// Methods turned down this many times more, each, the way the
    /// electrs of Blockstream turns a request down when the answers it
    /// holds take all the memory it allows them.
    pub busy: HashMap<&'static str, usize>,
    /// Script hashes whose history is refused, as too long.
    pub refused_histories: std::collections::HashSet<String>,
    /// The most subscriptions one connection holds, and the words that
    /// refuse the next ones.
    pub subscription_limit: Option<(usize, &'static str)>,
    /// Subscriptions past which a connection costs the server too much:
    /// the next one is refused the way ElectrumX does, and the
    /// connection closed.
    pub cost_cut: Option<usize>,
    /// A method whose answer starts and never ends: the connection
    /// answers nothing more after it.
    pub stall: Option<&'static str>,
    /// Methods answered this many times more, each, and then left
    /// unanswered while every other request still is.
    pub answered_only: HashMap<&'static str, usize>,
    /// A method answered with this many bytes and no line end.
    pub flood: Option<(&'static str, usize)>,
    /// A method whose answer, read from the state when the request
    /// arrives, is held back until a permit is added here.
    pub gate: Option<(&'static str, Arc<tokio::sync::Semaphore>)>,
    /// The network whose genesis block the server serves at height 0,
    /// signet when `None`.
    pub genesis: Option<bdk_wallet::bitcoin::Network>,
    /// Every method asked for, in order, over every connection.
    pub asked: Vec<String>,
    /// Connections the client closed.
    pub closed: usize,
    /// What the server says it runs, first in its answer to
    /// `server.version`.
    pub software: &'static str,
    /// Headers served as they are at their height, whatever the chain
    /// below them: real ones, or forged.
    pub served: HashMap<u32, bdk_wallet::bitcoin::block::Header>,
    /// The merkle branch sent for a transaction, as hashes in hex and a
    /// position, in place of the empty one.
    pub branches: HashMap<Txid, (Vec<String>, usize)>,
    /// A header sent once for its height, the first time a header is
    /// asked for there, and the chain's after it: the block a
    /// reorganisation replaced while a client was reading.
    pub stale_once: HashMap<u32, bdk_wallet::bitcoin::block::Header>,
    /// Heights whose header is refused.
    pub refused_headers: std::collections::HashSet<u32>,
}

/// Heights past which the fake Electrum server makes a header up on the
/// spot, its parent all zeroes, instead of chaining it to the genesis
/// block: a height no chain of the tests reaches, which a client is to
/// refuse before it asks for the blocks under it.
const CHAINED_UP_TO: u32 = 100_000;

impl ElectrumState {
    /// The header at `height`, in hex: see [`Self::header_of`].
    fn header(&self, height: u32) -> String {
        serialize_hex(&self.header_of(height))
    }

    /// The headers from `start` up to `end`, excluded, as
    /// [`Self::header_of`] makes them, the chain built once.
    fn headers_between(&self, start: u32, end: u32) -> Vec<bdk_wallet::bitcoin::block::Header> {
        if start > CHAINED_UP_TO || end <= start {
            return (start..end).map(|height| self.header_of(height)).collect();
        }
        let mut headers = Vec::new();
        let mut below = self.header_of(start);
        headers.push(below);
        for height in start + 1..end {
            let header = if height > CHAINED_UP_TO || self.served.contains_key(&height) {
                self.header_of(height)
            } else {
                use bdk_wallet::bitcoin::TxMerkleNode;
                use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
                use bdk_wallet::bitcoin::hashes::Hash;
                let mut next: bdk_wallet::bitcoin::block::Header =
                    deserialize_hex(&header_at(height)).unwrap();
                next.prev_blockhash = below.block_hash();
                let mined = self.mined_at(i64::from(height));
                if !mined.is_empty() {
                    next.merkle_root = TxMerkleNode::from_byte_array(merkle_of(&mined, 0).0);
                }
                next
            };
            headers.push(header);
            below = header;
        }
        headers
    }

    /// The transactions the histories put at `height`, in the order
    /// their block holds them: by txid.
    fn mined_at(&self, height: i64) -> Vec<Txid> {
        let mut mined: Vec<Txid> = self
            .histories
            .values()
            .flatten()
            .filter(|(_, at)| *at == height)
            .map(|(txid, _)| *txid)
            .collect();
        mined.sort();
        mined.dedup();
        mined
    }

    /// The header at `height`: one [`ElectrumState::served`] as it is,
    /// or else the signet genesis block at 0, so a descriptor wallet's
    /// chain meets the server's there, and above it the header of
    /// [`header_at`] with the one below as its parent, whose merkle root
    /// is the root of the transactions the histories put at that height
    /// ([`merkle_of`]), if any.
    pub(crate) fn header_of(&self, height: u32) -> bdk_wallet::bitcoin::block::Header {
        use bdk_wallet::bitcoin::TxMerkleNode;
        use bdk_wallet::bitcoin::block::Header;
        use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
        use bdk_wallet::bitcoin::hashes::Hash;
        if let Some(served) = self.served.get(&height) {
            return *served;
        }
        let mut header = bdk_wallet::bitcoin::constants::genesis_block(
            self.genesis.unwrap_or(bdk_wallet::bitcoin::Network::Signet),
        )
        .header;
        if height > CHAINED_UP_TO {
            return deserialize_hex(&header_at(height)).unwrap();
        }
        let mut mined: HashMap<i64, Vec<Txid>> = HashMap::new();
        for (_, at) in self.histories.values().flatten() {
            mined.entry(*at).or_insert_with(|| self.mined_at(*at));
        }
        for at in 1..=height {
            let mut next: Header = deserialize_hex(&header_at(at)).unwrap();
            next.prev_blockhash = header.block_hash();
            if let Some(txids) = mined.get(&i64::from(at)) {
                let (root, _) = merkle_of(txids, 0);
                next.merkle_root = TxMerkleNode::from_byte_array(root);
            }
            header = next;
        }
        header
    }
}

#[derive(Clone)]
pub(crate) struct FakeElectrum {
    pub address: SocketAddr,
    pub state: Arc<Mutex<ElectrumState>>,
}

impl FakeElectrum {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        crate::chain::proof::forget_proven_coins(&listener.local_addr().unwrap().to_string());
        let fake = FakeElectrum {
            address: listener.local_addr().unwrap(),
            state: Arc::new(Mutex::new(ElectrumState {
                height: 100,
                version: "1.4",
                software: "fake 1.0",
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
                    let (answer, gate) = {
                        let mut state = state.lock().unwrap();
                        state.asked.push(method.clone());
                        if state.silent || stalled {
                            continue;
                        }
                        if let Some(left) = state.answered_only.get_mut(method.as_str()) {
                            if *left == 0 {
                                continue;
                            }
                            *left -= 1;
                        }
                        let gate = state
                            .gate
                            .as_ref()
                            .filter(|(gated, _)| *gated == method)
                            .map(|(_, gate)| gate.clone());
                        (Self::answer(&mut state, index, &request, &method), gate)
                    };
                    if let Some(gate) = gate
                        && let Ok(permit) = gate.acquire().await
                    {
                        permit.forget();
                    }
                    let bytes = match answer {
                        Answer::Line(answer) => format!("{answer}\n").into_bytes(),
                        Answer::Last(answer) => {
                            let _ = writer.write_all(format!("{answer}\n").as_bytes()).await;
                            return;
                        }
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
        if let Some(left) = state.busy.get_mut(method)
            && *left > 0
        {
            *left -= 1;
            return Answer::Line(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": 2, "message": "response budget exhausted, retry later" },
            }));
        }
        if method == "blockchain.scripthash.get_history"
            && request["params"][0]
                .as_str()
                .is_some_and(|hash| state.refused_histories.contains(hash))
        {
            return refusal("history too large");
        }
        if let Some((limit, words)) = state.subscription_limit
            && method == "blockchain.scripthash.subscribe"
            && state.connections[index].0.len() >= limit
        {
            return refusal(words);
        }
        if let Some(cut) = state.cost_cut
            && method == "blockchain.scripthash.subscribe"
            && state.connections[index].0.len() >= cut
        {
            return Answer::Last(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -101, "message": "excessive resource usage" },
            }));
        }
        let param = request["params"][0].clone();
        let scripthash = param.as_str().unwrap_or_default().to_owned();
        let result = match method {
            "server.version" => json!([state.software, state.version]),
            "blockchain.headers.subscribe" => {
                json!({ "height": state.height, "hex": state.header(state.height) })
            }
            "blockchain.block.headers" => {
                let start = param.as_u64().unwrap_or(0) as u32;
                let count = request["params"][1].as_u64().unwrap_or(0) as u32;
                let end = start.saturating_add(count).min(state.height + 1);
                let hex: String = state
                    .headers_between(start, end)
                    .iter()
                    .map(serialize_hex)
                    .collect();
                json!({ "count": end.saturating_sub(start), "hex": hex, "max": 2016 })
            }
            // Its branch in the block the histories make of its height,
            // unless one was set for it.
            "blockchain.transaction.get_merkle" => {
                let height = request["params"][1].as_i64().unwrap_or(0);
                let txid = param.as_str().and_then(|txid| txid.parse::<Txid>().ok());
                let (merkle, pos) = match txid.and_then(|txid| state.branches.get(&txid)) {
                    Some(set) => set.clone(),
                    None => {
                        let mined = state.mined_at(height);
                        let pos = txid
                            .and_then(|txid| mined.iter().position(|at| *at == txid))
                            .unwrap_or(0);
                        (merkle_of(&mined, pos).1, pos)
                    }
                };
                json!({ "block_height": height, "merkle": merkle, "pos": pos })
            }
            "blockchain.scripthash.subscribe" => {
                state.connections[index].0.push(scripthash.clone());
                // A status set by the test, or the one of the history,
                // as a server hashes it.
                let status = match state.statuses.get(&scripthash) {
                    Some(status) => status.clone(),
                    None => state
                        .histories
                        .get(&scripthash)
                        .filter(|history| !history.is_empty())
                        .map(|history| status_of(history)),
                };
                json!(status)
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
            "blockchain.block.header" => {
                let height = param.as_u64().unwrap_or(0) as u32;
                if let Some(stale) = state.stale_once.remove(&height) {
                    json!(serialize_hex(&stale))
                } else if state.refused_headers.contains(&height) {
                    return refusal("header not available");
                } else {
                    json!(state.header(height))
                }
            }
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
            own_node: false,
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
    /// When the REST side was asked for the tip, as each round of
    /// polling opens.
    pub tips_asked: Vec<std::time::Instant>,
    pub tip: u32,
    /// The transactions of the one address the REST side knows, as
    /// Esplora spells them, for a sync to read: the unconfirmed ones,
    /// then the confirmed ones, newest first.
    pub address_txs: Vec<Value>,
    /// Pages of that history read so far.
    pub history_pages: usize,
    /// Every path the REST side was asked for, in order.
    pub paths: Vec<String>,
    /// The REST side closes every connection without an answer, a server
    /// that is down.
    pub down: bool,
    /// The network whose genesis block the REST side names at height 0,
    /// signet when `None`.
    pub genesis: Option<bdk_wallet::bitcoin::Network>,
    /// Histories of scripts, by the key polling reads them under
    /// ([`FakeMempool::rest_key`]), as Esplora spells each transaction,
    /// newest first: what a descriptor wallet's sync reads, its counters
    /// and its pages.
    pub scripts: HashMap<String, Vec<Value>>,
    /// Headers served as they are at their height.
    pub served: HashMap<u32, bdk_wallet::bitcoin::block::Header>,
    /// The branch sent for a txid, as hashes in hex and a position, in
    /// place of the one its block makes.
    pub branches: HashMap<String, (Vec<String>, usize)>,
    /// The coins of the one address, as Esplora lists them.
    pub utxos: Vec<Value>,
    /// Whether the REST side has lost the headers of its blocks, as a
    /// server has those of a block a reorganisation left behind.
    pub headerless: bool,
    /// Blocks a reorganisation replaced, by height: the statuses of the
    /// transactions confirmed there still name them, and their headers
    /// are still served, while the chain and the branches are the new
    /// block's.
    pub stale: HashMap<u32, bdk_wallet::bitcoin::block::Header>,
}

/// The headers of the chain the fake mempool serves, by height: see
/// [`MempoolState::chain`].
type Headers = std::collections::BTreeMap<u32, bdk_wallet::bitcoin::block::Header>;

/// Heights past which the fake mempool makes a header up on the spot,
/// above nothing: the chain it builds again for each request stays
/// short, whatever tip a test makes it claim.
const MEMPOOL_CHAINED_UP_TO: u32 = 10_000;

impl MempoolState {
    /// Every confirmed transaction listed anywhere, its txid and height,
    /// and the time its status gives its block.
    fn confirmed(&self) -> Vec<(Txid, u32, u64)> {
        self.address_txs
            .iter()
            .chain(self.scripts.values().flatten())
            .filter(|tx| tx["status"]["confirmed"] == true)
            .filter_map(|tx| {
                Some((
                    tx["txid"].as_str()?.parse().ok()?,
                    u32::try_from(tx["status"]["block_height"].as_u64()?).ok()?,
                    tx["status"]["block_time"].as_u64().unwrap_or(0),
                ))
            })
            .collect()
    }

    /// The blocks the confirmed transactions make: at each height, their
    /// txids in the order their block holds them, by txid, and the time
    /// their status gives the block.
    fn blocks(&self) -> HashMap<u32, (Vec<Txid>, u64)> {
        let mut blocks: HashMap<u32, (Vec<Txid>, u64)> = HashMap::new();
        for (txid, height, time) in self.confirmed() {
            let block = blocks.entry(height).or_default();
            block.0.push(txid);
            if block.1 == 0 {
                block.1 = time;
            }
        }
        for (txids, _) in blocks.values_mut() {
            txids.sort();
            txids.dedup();
        }
        blocks
    }

    /// The transactions confirmed at `height`, in the order their block
    /// holds them.
    fn mined_at(&self, height: u32) -> Vec<Txid> {
        self.blocks()
            .remove(&height)
            .map(|(txids, _)| txids)
            .unwrap_or_default()
    }

    /// A made-up header at `height` above `parent`: its merkle root the
    /// root of the transactions confirmed there ([`merkle_of`]), its time
    /// the one their status gives, or 1 700 000 000 plus the height.
    fn made_up(
        blocks: &HashMap<u32, (Vec<Txid>, u64)>,
        height: u32,
        parent: bdk_wallet::bitcoin::BlockHash,
    ) -> bdk_wallet::bitcoin::block::Header {
        use bdk_wallet::bitcoin::block::{Header, Version};
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{CompactTarget, TxMerkleNode};
        // The header of `header_at`, built without its hex.
        let mut header = Header {
            version: Version::TWO,
            prev_blockhash: parent,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000_u32.wrapping_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        if let Some((txids, time)) = blocks.get(&height) {
            header.merkle_root = TxMerkleNode::from_byte_array(merkle_of(txids, 0).0);
            if *time > 0 {
                header.time = *time as u32;
            }
        }
        header
    }

    /// The chain the REST side serves, by height: the genesis block of
    /// the network at 0, signet unless set, then made-up headers each
    /// above the one before ([`Self::made_up`]), up to the tip or the
    /// highest confirmation, whichever is higher, and no higher than
    /// [`MEMPOOL_CHAINED_UP_TO`]; a header [`Self::served`] stands in for
    /// the one at its height.
    fn chain(&self) -> Headers {
        let network = self.genesis.unwrap_or(bdk_wallet::bitcoin::Network::Signet);
        let blocks = self.blocks();
        let top = blocks
            .keys()
            .copied()
            .chain([self.tip])
            .max()
            .unwrap_or(0)
            .min(MEMPOOL_CHAINED_UP_TO);
        let mut chain = Headers::new();
        let mut below = bdk_wallet::bitcoin::constants::genesis_block(network).header;
        chain.insert(0, below);
        for height in 1..=top {
            let header = match self.served.get(&height) {
                Some(served) => *served,
                None => Self::made_up(&blocks, height, below.block_hash()),
            };
            chain.insert(height, header);
            below = header;
        }
        for (height, header) in &self.served {
            chain.insert(*height, *header);
        }
        chain
    }

    /// The header at `height`: the chain's, or, past it, a made-up one
    /// above nothing.
    fn header_in(&self, chain: &Headers, height: u32) -> bdk_wallet::bitcoin::block::Header {
        use bdk_wallet::bitcoin::hashes::Hash;
        match chain.get(&height) {
            Some(header) => *header,
            None => Self::made_up(
                &self.blocks(),
                height,
                bdk_wallet::bitcoin::BlockHash::all_zeros(),
            ),
        }
    }

    /// A transaction as the REST side lists it: when confirmed in a block
    /// it names, in the block of the chain at its height, at that block's
    /// time. A status that names no block is listed as it is.
    fn as_listed(&self, chain: &Headers, tx: &Value) -> Value {
        let mut tx = tx.clone();
        if tx["status"]["confirmed"] == true
            && tx["status"].get("block_hash").is_some()
            && let Some(height) = tx["status"]["block_height"].as_u64()
        {
            let header = match self.stale.get(&(height as u32)) {
                Some(stale) => *stale,
                None => self.header_in(chain, height as u32),
            };
            tx["status"]["block_hash"] = json!(header.block_hash().to_string());
            tx["status"]["block_time"] = json!(header.time);
        }
        tx
    }

    /// A page of a history, as Esplora pages it: the unconfirmed
    /// transactions and the first 25 confirmed ones, the 25 confirmed
    /// ones after the txid a path ends with, or the unconfirmed ones
    /// alone.
    fn history_page(&self, chain_headers: &Headers, history: &[Value], path: &str) -> Vec<Value> {
        let confirmed = |tx: &&Value| tx["status"]["confirmed"] == true;
        let chain = history.iter().filter(confirmed);
        let page: Vec<&Value> = if path.ends_with("/txs/mempool") {
            history.iter().filter(|tx| !confirmed(tx)).collect()
        } else {
            match path.rsplit_once("/txs/chain/") {
                Some((_, after)) => chain
                    .skip_while(|tx| tx["txid"] != after)
                    .skip(1)
                    .take(25)
                    .collect(),
                None => history
                    .iter()
                    .filter(|tx| !confirmed(tx))
                    .chain(chain.take(25))
                    .collect(),
            }
        };
        page.into_iter()
            .map(|tx| self.as_listed(chain_headers, tx))
            .collect()
    }

    /// The id of the block at `height` in the chain the REST side
    /// serves ([`Self::chain`]).
    fn block_id(&self, chain: &Headers, height: u32) -> String {
        self.header_in(chain, height).block_hash().to_string()
    }

    /// A transaction listed anywhere, in its raw bytes.
    fn raw_tx(&self, txid: &str) -> Option<Vec<u8>> {
        let listed = self
            .address_txs
            .iter()
            .chain(self.scripts.values().flatten())
            .find(|tx| tx["txid"] == txid)?;
        let tx: crate::chain::esplora::page::PageTx =
            serde_json::from_value(listed.clone()).ok()?;
        Some(bdk_wallet::bitcoin::consensus::encode::serialize(
            &tx.to_tx(),
        ))
    }

    /// The branch of a confirmed transaction in its block, as Esplora
    /// sends it, unless one was set for it.
    fn merkle_proof(&self, txid: &str) -> Option<Value> {
        let (_, height, _) = self
            .confirmed()
            .into_iter()
            .find(|(confirmed, _, _)| confirmed.to_string() == txid)?;
        let (merkle, pos) = match self.branches.get(txid) {
            Some(set) => set.clone(),
            None => {
                let mined = self.mined_at(height);
                let pos = mined.iter().position(|at| at.to_string() == txid)?;
                (merkle_of(&mined, pos).1, pos)
            }
        };
        Some(json!({ "block_height": height, "merkle": merkle, "pos": pos }))
    }
}

#[derive(Clone)]
pub(crate) struct FakeMempool {
    pub address: SocketAddr,
    pub state: Arc<Mutex<MempoolState>>,
}

impl FakeMempool {
    pub(crate) async fn start(websocket: bool, limit: usize) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        crate::chain::proof::forget_proven_coins(&listener.local_addr().unwrap().to_string());
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
        {
            let mut state = state.lock().unwrap();
            if state.down {
                state.paths.push(path);
                return;
            }
        }
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
        let mut raw: Option<Vec<u8>> = None;
        let (status, body) = {
            let mut state = state.lock().unwrap();
            state.paths.push(path.to_owned());
            let chain = state.chain();
            let script = path
                .rsplit_once("/scripthash/")
                .map(|(_, rest)| rest.split('/').next().unwrap_or_default().to_owned())
                .filter(|key| state.scripts.contains_key(key));
            if let Some(hash) = path
                .strip_suffix("/header")
                .and_then(|path| path.rsplit_once("/block/"))
                .map(|(_, hash)| hash)
            {
                let header = chain
                    .values()
                    .chain(state.stale.values())
                    .find(|header| header.block_hash().to_string() == hash)
                    .copied()
                    .or_else(|| {
                        state.confirmed().into_iter().find_map(|(_, height, _)| {
                            let header = state.header_in(&chain, height);
                            (header.block_hash().to_string() == hash).then_some(header)
                        })
                    });
                match header.filter(|_| !state.headerless) {
                    Some(header) => ("200 OK", serialize_hex(&header)),
                    None => ("404 Not Found", "Block not found".to_owned()),
                }
            } else if let Some(txid) = path
                .strip_suffix("/raw")
                .and_then(|path| path.rsplit_once("/tx/"))
                .map(|(_, txid)| txid)
            {
                match state.raw_tx(txid) {
                    Some(bytes) => {
                        raw = Some(bytes);
                        ("200 OK", String::new())
                    }
                    None => ("404 Not Found", "Transaction not found".to_owned()),
                }
            } else if let Some(txid) = path
                .strip_suffix("/merkle-proof")
                .and_then(|path| path.rsplit_once("/tx/"))
                .map(|(_, txid)| txid)
            {
                match state.merkle_proof(txid) {
                    Some(proof) => ("200 OK", proof.to_string()),
                    None => (
                        "404 Not Found",
                        "Transaction not found or is unconfirmed".to_owned(),
                    ),
                }
            } else if path.ends_with("/blocks/tip/hash") {
                state.tips_asked.push(std::time::Instant::now());
                ("200 OK", state.block_id(&chain, state.tip))
            } else if path.ends_with("/blocks/tip/height") {
                ("200 OK", state.tip.to_string())
            } else if path.ends_with("/blocks") {
                let tip = state.tip;
                let blocks: Vec<Value> = (tip.saturating_sub(9)..=tip)
                    .rev()
                    .map(|height| {
                        let header = state.header_in(&chain, height);
                        json!({
                            "id": header.block_hash().to_string(),
                            "height": height,
                            "previousblockhash": (height > 0).then(|| header.prev_blockhash.to_string()),
                        })
                    })
                    .collect();
                ("200 OK", Value::Array(blocks).to_string())
            } else if let Some(height) = path
                .rsplit_once("/block-height/")
                .and_then(|(_, height)| height.parse::<u32>().ok())
            {
                if height <= state.tip {
                    ("200 OK", state.block_id(&chain, height))
                } else {
                    ("404 Not Found", "Block not found".to_owned())
                }
            } else if path.ends_with("/utxo") {
                ("200 OK", Value::Array(state.utxos.clone()).to_string())
            } else if let Some(key) = script.as_ref().filter(|_| path.contains("/txs")) {
                let history = state.scripts[key].clone();
                (
                    "200 OK",
                    Value::Array(state.history_page(&chain, &history, path)).to_string(),
                )
            } else if let Some(key) = script {
                state.looked_up.push(key.clone());
                let side = |confirmed: bool| {
                    let txs: Vec<&Value> = state.scripts[&key]
                        .iter()
                        .filter(|tx| (tx["status"]["confirmed"] == true) == confirmed)
                        .collect();
                    let funded: u64 = txs
                        .iter()
                        .map(|tx| tx["vout"][0]["value"].as_u64().unwrap_or(0))
                        .sum();
                    json!({
                        "funded_txo_count": txs.len(), "funded_txo_sum": funded,
                        "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": txs.len(),
                    })
                };
                (
                    "200 OK",
                    json!({ "scripthash": key, "chain_stats": side(true), "mempool_stats": side(false) })
                        .to_string(),
                )
            } else if path.ends_with("/txs") || path.contains("/txs/chain/") {
                state.history_pages += 1;
                let history = state.address_txs.clone();
                (
                    "200 OK",
                    Value::Array(state.history_page(&chain, &history, path)).to_string(),
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
        let body = raw.unwrap_or_else(|| body.into_bytes());
        let mut answer = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        answer.extend_from_slice(&body);
        let _ = stream.write_all(&answer).await;
    }

    /// The header of the chain the REST side serves at `height`.
    pub(crate) fn header_at_height(
        state: &MempoolState,
        height: u32,
    ) -> bdk_wallet::bitcoin::block::Header {
        state.header_in(&state.chain(), height)
    }

    pub(crate) fn backend(&self) -> BackendConfig {
        BackendConfig::CustomEsplora {
            url: format!("http://{}/api", self.address),
            own_node: false,
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
