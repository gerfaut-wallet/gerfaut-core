//! Syncs against a regtest node and an electrs serving both Electrum and
//! Esplora, both in Docker, with every byte between Gerfaut and the
//! server counted and every request read on the way: what a sync asks
//! for, and what it costs, once the wallet holds its history.
//!
//! The node's own wallet pays the watched one: test coins in a
//! throwaway container, and no key on this side, the watched wallet
//! being the public BIP-84 test vector account.
//!
//! Ignored by default: it needs Docker, and pulls two public images the
//! first time.
//!
//! ```text
//! cargo test --test regtest_sync -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::{Address, Network as BitcoinNetwork};
use gerfaut_core::chain::BackendConfig;
use gerfaut_core::input::parse_input;
use gerfaut_core::live::{LiveEvent, LiveEvents};
use gerfaut_core::manager::WalletManager;
use gerfaut_core::network::Network;
use gerfaut_core::store::{TxStage, VaultKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BITCOIND: &str = "btcpayserver/bitcoin:31.0";
const ELECTRS: &str = "vulpemventures/electrs:latest";
const WALLET: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
const WAIT: Duration = Duration::from_secs(60);

// --- the containers -------------------------------------------------------------

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("docker runs");
    assert!(
        output.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A regtest node and an electrs on a network of their own, removed
/// when dropped.
struct Chain {
    network: String,
    node: String,
    electrs: String,
    electrum: SocketAddr,
    esplora: SocketAddr,
    /// An address of the node's wallet, which mines.
    miner: String,
}

impl Chain {
    fn start() -> Self {
        let tag = format!("gerfaut-rt-{}", std::process::id());
        let network = tag.clone();
        let node = format!("{tag}-node");
        let electrs = format!("{tag}-electrs");
        docker(&["network", "create", &network]);
        docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &node,
            "--network",
            &network,
            "--entrypoint",
            "bitcoind",
            BITCOIND,
            "-regtest",
            "-server=1",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            "-rpcuser=rt",
            "-rpcpassword=rt",
            "-fallbackfee=0.0001",
            "-listen=0",
            "-printtoconsole=0",
        ]);
        let mut chain = Chain {
            network,
            node,
            electrs,
            electrum: "127.0.0.1:0".parse().unwrap(),
            esplora: "127.0.0.1:0".parse().unwrap(),
            miner: String::new(),
        };
        // The node takes a moment to open its RPC.
        let mut tries = 0;
        while Command::new("docker")
            .args([
                "exec",
                &chain.node,
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=rt",
            ])
            .args(["-rpcpassword=rt", "createwallet", "node"])
            .output()
            .map(|output| !output.status.success())
            .unwrap_or(true)
        {
            tries += 1;
            assert!(tries < 60, "the node never answered");
            std::thread::sleep(Duration::from_millis(500));
        }
        chain.miner = chain.cli(&["getnewaddress"]);
        chain.cli(&["generatetoaddress", "101", &chain.miner.clone()]);
        let daemon = format!("{}:18443", chain.node);
        docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &chain.electrs,
            "--network",
            &chain.network,
            "-p",
            "127.0.0.1::50001",
            "-p",
            "127.0.0.1::3002",
            ELECTRS,
            "--network",
            "regtest",
            "--daemon-rpc-addr",
            &daemon,
            "--cookie",
            "rt:rt",
            "--jsonrpc-import",
            "--electrum-rpc-addr",
            "0.0.0.0:50001",
            "--http-addr",
            "0.0.0.0:3002",
            "--db-dir",
            "/tmp/db",
        ]);
        let port = |inner: &str| -> SocketAddr {
            docker(&["port", &chain.electrs, inner])
                .lines()
                .find(|line| line.starts_with("127.0.0.1:"))
                .expect("a published port")
                .parse()
                .unwrap()
        };
        chain.electrum = port("50001");
        chain.esplora = port("3002");
        chain
    }

    fn cli(&self, args: &[&str]) -> String {
        docker(
            &[
                &["exec", &self.node, "bitcoin-cli", "-regtest", "-rpcuser=rt"][..],
                &["-rpcpassword=rt", "-rpcwallet=node"],
                args,
            ]
            .concat(),
        )
    }

    fn pay(&self, address: &str, btc: &str) -> String {
        self.cli(&["sendtoaddress", address, btc])
    }

    fn mine(&self) {
        self.cli(&["generatetoaddress", "1", &self.miner]);
    }

    /// Takes the tip block out of the chain: its transactions go back to
    /// the mempool.
    fn drop_tip(&self) {
        let tip = self.cli(&["getbestblockhash"]);
        self.cli(&["invalidateblock", &tip]);
    }

    /// Mines a block with nothing in it but its coinbase.
    fn mine_empty(&self) {
        self.cli(&["generateblock", &self.miner, "[]"]);
    }

    /// Takes the block that confirmed `txid` out of the chain, with every
    /// block after it, and mines a longer chain of empty blocks in their
    /// place: the transaction is back in the mempool.
    fn unconfirm(&self, txid: &str) {
        let tx: serde_json::Value = serde_json::from_str(&self.cli(&["gettransaction", txid]))
            .expect("the node's wallet sent it");
        let block = tx["blockhash"].as_str().expect("confirmed").to_owned();
        let height: u64 = self.cli(&["getblockcount"]).parse().unwrap();
        self.cli(&["invalidateblock", &block]);
        let left: u64 = self.cli(&["getblockcount"]).parse().unwrap();
        for _ in left..=height {
            self.mine_empty();
        }
    }

    /// Waits until electrs serves `path` with a success, and returns it.
    async fn served(&self, path: &str) -> String {
        let url = format!("http://{}{path}", self.esplora);
        let started = std::time::Instant::now();
        loop {
            if let Ok(response) = reqwest::get(&url).await
                && response.status().is_success()
                && let Ok(text) = response.text().await
            {
                return text;
            }
            assert!(started.elapsed() < WAIT, "electrs never served {path}");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Waits until electrs has indexed the node's tip: its hash, so that
    /// a block replaced at the same height counts.
    async fn indexed(&self) {
        let tip = self.cli(&["getbestblockhash"]);
        let started = std::time::Instant::now();
        while self.served("/blocks/tip/hash").await != tip {
            assert!(started.elapsed() < WAIT, "electrs never reached {tip}");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.electrs, &self.node])
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

// --- a tap on the wire ----------------------------------------------------------

/// Bytes both ways between Gerfaut and the server, and the lines
/// Gerfaut sent: a JSON-RPC request each over Electrum, the request line
/// and headers over HTTP.
#[derive(Default)]
struct Tap {
    up: AtomicU64,
    down: AtomicU64,
    lines: Mutex<Vec<String>>,
}

/// What went over the tap between two readings.
struct Window {
    bytes: u64,
    lines: Vec<String>,
}

impl Tap {
    fn mark(&self) -> (u64, usize) {
        (
            self.up.load(Ordering::SeqCst) + self.down.load(Ordering::SeqCst),
            self.lines.lock().unwrap().len(),
        )
    }

    fn since(&self, mark: (u64, usize)) -> Window {
        let (bytes, _) = self.mark();
        Window {
            bytes: bytes - mark.0,
            lines: self.lines.lock().unwrap()[mark.1..].to_vec(),
        }
    }
}

impl Window {
    /// The Electrum methods asked for, with their first parameter.
    fn calls(&self) -> Vec<(String, String)> {
        self.lines
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|call| {
                (
                    call["method"].as_str().unwrap_or_default().to_owned(),
                    match &call["params"][0] {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    },
                )
            })
            .collect()
    }

    fn params_of(&self, method: &str) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|(asked, _)| asked == method)
            .map(|(_, param)| param)
            .collect()
    }

    /// The paths of the HTTP requests.
    fn paths(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|line| line.strip_prefix("GET "))
            .filter_map(|rest| rest.split(' ').next())
            .map(str::to_owned)
            .collect()
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    tap: Arc<Tap>,
    outgoing: bool,
) {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut pending = Vec::new();
    loop {
        let read = match from.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let counter = if outgoing { &tap.up } else { &tap.down };
        counter.fetch_add(read as u64, Ordering::SeqCst);
        if outgoing {
            pending.extend_from_slice(&buffer[..read]);
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                let line = String::from_utf8_lossy(&line).trim().to_owned();
                if !line.is_empty() {
                    tap.lines.lock().unwrap().push(line);
                }
            }
        }
        if to.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

/// A port on loopback that forwards to `target`, through the tap.
async fn tap_to(target: SocketAddr) -> (SocketAddr, Arc<Tap>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tap = Arc::new(Tap::default());
    let counting = tap.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = TcpStream::connect(target).await else {
                continue;
            };
            let (client_read, client_write) = client.into_split();
            let (server_read, server_write) = server.into_split();
            tokio::spawn(pump(client_read, server_write, counting.clone(), true));
            tokio::spawn(pump(server_read, client_write, counting.clone(), false));
        }
    });
    (address, tap)
}

// --- the wallet ------------------------------------------------------------------

async fn watching(dir: &std::path::Path, backend: BackendConfig) -> (WalletManager, String) {
    let manager = WalletManager::open(dir, VaultKey::Raw([9; 32])).unwrap();
    manager.set_active_network(Network::Regtest).await.unwrap();
    manager
        .set_backend(Network::Regtest, backend)
        .await
        .unwrap();
    let id = manager
        .add_wallet("Regtest", &parse_input(WALLET).unwrap(), Network::Regtest)
        .await
        .unwrap()
        .id;
    (manager, id)
}

/// The receive address at `index` of the watched wallet.
fn receive_address(index: u32) -> String {
    let descriptor = WALLET.replace("<0;1>", "0");
    bdk_wallet::Wallet::create_single(descriptor)
        .network(BitcoinNetwork::Regtest)
        .create_wallet_no_persist()
        .unwrap()
        .peek_address(bdk_wallet::KeychainKind::External, index)
        .address
        .to_string()
}

fn script_of(address: &str) -> Vec<u8> {
    address
        .parse::<Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_bytes()
}

/// The Electrum script hash of an address: SHA-256 of its script,
/// reversed.
fn electrum_hash(address: &str) -> String {
    let mut digest = sha256::Hash::hash(&script_of(address)).to_byte_array();
    digest.reverse();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The Esplora script hash of an address: SHA-256 of its script.
fn esplora_hash(address: &str) -> String {
    sha256::Hash::hash(&script_of(address))
        .to_byte_array()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Waits for the watch to announce `txid` at `stage`, and for the sync
/// behind it to be handed out.
async fn announced(events: &mut LiveEvents, txid: &str, stage: TxStage) {
    let started = std::time::Instant::now();
    let mut seen = false;
    loop {
        let left = WAIT.saturating_sub(started.elapsed());
        match tokio::time::timeout(left, events.next()).await {
            Ok(Some(LiveEvent::Transaction(tx))) if tx.txid == txid && tx.stage == stage => {
                seen = true;
            }
            Ok(Some(LiveEvent::WalletSynced { .. })) if seen => return,
            Ok(Some(LiveEvent::SyncFailed { message, .. })) => panic!("a sync failed: {message}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch stopped"),
            Err(_) => panic!("{txid} was never announced {stage:?}"),
        }
    }
}

/// Waits until the watch has read every script, then for a quiet moment
/// in which nothing may be synced: nothing moved.
async fn settled(events: &mut LiveEvents) {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(LiveEvent::Status(status))) if status.pushed_scripts > 0 => break,
            Ok(Some(LiveEvent::WalletSynced { report })) => {
                panic!("nothing moved, and the watch synced: {report:?}")
            }
            Ok(Some(_)) => {}
            other => panic!("the watch never subscribed: {other:?}"),
        }
    }
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(2), events.next()).await {
        assert!(
            !matches!(
                event,
                LiveEvent::WalletSynced { .. } | LiveEvent::Transaction(_)
            ),
            "nothing moved, and the watch said {event:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker: runs a regtest node and electrs"]
async fn a_sync_reads_only_what_the_wallet_lacks() {
    let chain = Chain::start();
    // Two payments to the first two receive addresses, confirmed.
    let first = receive_address(0);
    let second = receive_address(1);
    let funding = [chain.pay(&first, "0.5"), chain.pay(&second, "0.25")];
    chain.mine();
    chain.indexed().await;

    // --- over Electrum --------------------------------------------------------
    let (electrum, wire) = tap_to(chain.electrum).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(
        dir.path(),
        BackendConfig::CustomElectrum {
            url: format!("tcp://{electrum}"),
        },
    )
    .await;
    let mark = wire.mark();
    let import = manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(import.new_txs.len(), 2);
    println!("electrum, first sync: {} bytes", wire.since(mark).bytes);

    // Nothing new: every history read, nothing the wallet holds fetched
    // again, no confirmation proven twice.
    let mark = wire.mark();
    let again = manager.sync_wallet(&wallet).await.unwrap();
    assert!(again.new_txs.is_empty() && again.confirmed_txs.is_empty());
    let window = wire.since(mark);
    println!(
        "electrum, a sync with nothing new: {} bytes, {:?}",
        window.bytes,
        window.calls()
    );
    assert!(window.params_of("blockchain.transaction.get").is_empty());
    assert!(
        window
            .params_of("blockchain.transaction.get_merkle")
            .is_empty()
    );
    assert!(window.bytes < 16_000, "{} bytes", window.bytes);

    // The watch starts: every status matches what the wallet holds, and
    // nothing is synced.
    let mut events = manager.live_start().await.unwrap();
    settled(&mut events).await;

    // A payment to the next address: the watch names that script, and
    // the sync it runs reads that one, fetching the payment and the
    // coins it spends, for the fee, and nothing the wallet holds.
    let third = receive_address(2);
    let mark = wire.mark();
    let paid = chain.pay(&third, "0.125");
    announced(&mut events, &paid, TxStage::Mempool).await;
    let window = wire.since(mark);
    println!(
        "electrum, a payment pushed and synced: {} bytes, {:?}",
        window.bytes,
        window.calls()
    );
    assert_eq!(
        window.params_of("blockchain.scripthash.get_history"),
        vec![electrum_hash(&third)]
    );
    let fetched = window.params_of("blockchain.transaction.get");
    assert!(fetched.contains(&paid), "{fetched:?}");
    assert!(
        !fetched.iter().any(|txid| funding.contains(txid)),
        "{fetched:?}"
    );
    assert!(window.bytes < 16_000, "{} bytes", window.bytes);

    // A block takes it: that script again, no transaction fetched, one
    // confirmation proven.
    let mark = wire.mark();
    chain.mine();
    announced(&mut events, &paid, TxStage::Confirmed).await;
    let window = wire.since(mark);
    println!(
        "electrum, a confirmation pushed and synced: {} bytes, {:?}",
        window.bytes,
        window.calls()
    );
    assert_eq!(
        window.params_of("blockchain.scripthash.get_history"),
        vec![electrum_hash(&third)]
    );
    assert!(window.params_of("blockchain.transaction.get").is_empty());
    assert_eq!(
        window.params_of("blockchain.transaction.get_merkle"),
        vec![paid.clone()]
    );
    assert!(window.bytes < 16_000, "{} bytes", window.bytes);
    manager.live_stop().await;

    // The fee of the payment is known: the coins it spends were fetched.
    let snapshot = manager.wallet_snapshot(&wallet).await.unwrap();
    let payment = snapshot.txs.iter().find(|tx| tx.txid == paid).unwrap();
    assert!(payment.fee_sats.is_some());

    // --- over Esplora ---------------------------------------------------------
    chain.indexed().await;
    let (esplora, esplora_wire) = tap_to(chain.esplora).await;
    let dir = tempfile::tempdir().unwrap();
    let (esplora_manager, esplora_wallet) = watching(
        dir.path(),
        BackendConfig::CustomEsplora {
            url: format!("http://{esplora}"),
        },
    )
    .await;
    let import = esplora_manager.sync_wallet(&esplora_wallet).await.unwrap();
    assert_eq!(import.new_txs.len(), 3);

    // Nothing new: the counters of each of the three scripts, and the
    // twenty receive addresses past them; no history of a script the
    // wallet holds, no transaction.
    let mark = esplora_wire.mark();
    let again = esplora_manager.sync_wallet(&esplora_wallet).await.unwrap();
    assert!(again.new_txs.is_empty() && again.confirmed_txs.is_empty());
    let window = esplora_wire.since(mark);
    let paths = window.paths();
    println!(
        "esplora, a sync with nothing new: {} bytes, {} requests",
        window.bytes,
        paths.len()
    );
    for held in [&first, &second, &third] {
        let counters = format!("/scripthash/{}", esplora_hash(held));
        assert!(paths.contains(&counters), "{paths:?}");
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with(&format!("{counters}/"))),
            "{paths:?}"
        );
    }
    assert!(!paths.iter().any(|path| path.starts_with("/tx/")));
    assert!(window.bytes < 40_000, "{} bytes", window.bytes);

    // The first address paid again: its history is read, down to what
    // the wallet holds, and no other.
    let reused = chain.pay(&first, "0.0625");
    chain.served(&format!("/tx/{reused}")).await;
    let mark = esplora_wire.mark();
    let found = esplora_manager.sync_wallet(&esplora_wallet).await.unwrap();
    assert_eq!(found.new_txs.len(), 1);
    let window = esplora_wire.since(mark);
    let paths = window.paths();
    println!(
        "esplora, a payment found: {} bytes, {} requests",
        window.bytes,
        paths.len()
    );
    let read: Vec<&String> = paths
        .iter()
        .filter(|path| {
            [&first, &second, &third]
                .iter()
                .any(|held| path.starts_with(&format!("/scripthash/{}/", esplora_hash(held))))
        })
        .collect();
    assert_eq!(
        read,
        vec![&format!("/scripthash/{}/txs", esplora_hash(&first))],
        "{paths:?}"
    );
    assert!(window.bytes < 40_000, "{} bytes", window.bytes);

    // Mined, then mined again in another block at the same height by a
    // reorganisation: the counters of the script are what they were, and
    // the history is read all the same, the block the wallet holds for
    // it being gone.
    chain.mine();
    chain.indexed().await;
    let confirmed = esplora_manager.sync_wallet(&esplora_wallet).await.unwrap();
    assert_eq!(confirmed.confirmed_txs.len(), 1);
    chain.drop_tip();
    chain.mine();
    chain.indexed().await;
    let mark = esplora_wire.mark();
    esplora_manager.sync_wallet(&esplora_wallet).await.unwrap();
    let paths = esplora_wire.since(mark).paths();
    assert!(
        paths.contains(&format!("/scripthash/{}/txs", esplora_hash(&first))),
        "{paths:?}"
    );

    // --- a reorganisation, over Electrum ----------------------------------------
    // A reorganisation takes the block that confirmed the payment away,
    // and the chain that replaces it leaves it in the mempool: a sync
    // sees the confirmation gone without fetching the transaction again.
    chain.unconfirm(&paid);
    chain.indexed().await;
    let mark = wire.mark();
    manager.sync_wallet(&wallet).await.unwrap();
    let window = wire.since(mark);
    assert!(
        !window
            .params_of("blockchain.transaction.get")
            .contains(&paid)
    );
    let pending = |manager: &WalletManager, wallet: &str| {
        let manager = manager.clone();
        let wallet = wallet.to_owned();
        let paid = paid.clone();
        async move {
            let snapshot = manager.wallet_snapshot(&wallet).await.unwrap();
            let payment = snapshot.txs.into_iter().find(|tx| tx.txid == paid).unwrap();
            payment.confirmations == 0
        }
    };
    assert!(
        pending(&manager, &wallet).await,
        "the reorganisation was missed"
    );
    // Mined again, in another block: proven again, and confirmed.
    chain.mine();
    chain.indexed().await;
    let mark = wire.mark();
    manager.sync_wallet(&wallet).await.unwrap();
    let window = wire.since(mark);
    assert!(
        !window
            .params_of("blockchain.transaction.get")
            .contains(&paid)
    );
    assert!(
        window
            .params_of("blockchain.transaction.get_merkle")
            .contains(&paid)
    );
    assert!(!pending(&manager, &wallet).await);
    // And the wallet agrees with the node on every transaction it holds.
    let snapshot = manager.wallet_snapshot(&wallet).await.unwrap();
    for tx in &snapshot.txs {
        let seen: serde_json::Value =
            serde_json::from_str(&chain.cli(&["gettransaction", &tx.txid])).unwrap();
        let node_confirmations = seen["confirmations"].as_i64().unwrap_or(0).max(0);
        assert_eq!(
            i64::from(tx.confirmations),
            node_confirmations,
            "{}: {seen}",
            tx.txid
        );
    }
}
