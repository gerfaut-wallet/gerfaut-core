//! Esplora backend: descriptor wallet sync and single-address tracking.

use std::time::Duration;

use bdk_esplora::esplora_client::{self, api};
use bdk_wallet::bitcoin::address::Address;

use bdk_wallet::bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

pub(crate) mod page;
pub(crate) mod sync;

use page::PageTx;

use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState, tx_extras};

/// Concurrent requests during scans.
pub(crate) const PARALLEL_REQUESTS: usize = 4;
/// The largest answer read, once decompressed: a page of the biggest
/// transactions there are, with room to spare. A server that sends more
/// is not answering the question, and is cut off rather than buffered.
const MAX_BODY: usize = 32 << 20;
/// The largest page of a history read, once decompressed: 25 confirmed
/// transactions and the unconfirmed ones, each a few kilobytes, the
/// largest a node relays a few hundred.
const PAGE_MAX: usize = 8 << 20;
/// What one sync, or one reading of an address, may read in all, once
/// decompressed: the first sync of a wallet with some twenty thousand
/// transactions. A server that sends more is refused rather than read
/// until memory runs out, a page at a time.
const RUN_MAX: usize = 64 << 20;
/// Tries of a request a server turned away for being busy: a public
/// instance answers a burst with 429, and a moment later with the data.
const TRIES: u32 = 4;
/// The longest refusal read from a broadcast: the node's reason is one
/// line, and a page of text is cut to its first 200 characters anyway.
const REFUSAL_MAX: usize = 64 << 10;
/// Address history pages fetched per request round (25 confirmed txs
/// each). A sync stays fast; anything older is fetched on demand by
/// [`fetch_address_history`], so nothing stays out of reach.
pub(crate) const HISTORY_PAGES_PER_ROUND: usize = 40;

/// How long opening a connection may take: the TCP handshake and the
/// TLS one. A dead host fails here, fast enough for the fallback to the
/// next endpoint to happen within a tolerable delay.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a whole request may take, connection included. One budget
/// for both used to cut blockstream.info off at twenty seconds on an
/// address with a few hundred transactions, which it needs longer than
/// that to answer; a slow answer is not a dead host.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Onion endpoints get more room. The connect budget is spent around
/// the SOCKS handshake, and behind that handshake Tor builds a circuit
/// to the onion service, which regularly takes half a minute: a slow
/// circuit must not read as a dead host. The circuit then carries less
/// than a plain connection, so the whole request gets two minutes.
const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const TOR_TIMEOUT: Duration = Duration::from_secs(120);

/// The two budgets a client was built with. A timeout is described by
/// the one that ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    connect: Duration,
    total: Duration,
}

/// A client for one instance, with its budgets kept beside it. Every
/// request goes through [`Client::fetch`], which holds the answer to
/// [`MAX_BODY`] once decompressed, and turns what fails into sentences:
/// a server that sends a small gzip of a huge body is cut off, not
/// buffered.
#[derive(Debug)]
pub(crate) struct Client {
    http: reqwest::Client,
    /// The instance's address, without a trailing slash.
    base: String,
    budget: Budget,
    /// What was read so far, decompressed, and how much may be.
    spent: std::sync::atomic::AtomicUsize,
    run_max: usize,
}

impl Client {
    /// The body of `path` under the instance's address, decompressed and
    /// held to [`MAX_BODY`]; `None` when the server has nothing there
    /// (404). A busy server is asked again a few times, a little later
    /// each time.
    async fn fetch(&self, path: &str, max: usize) -> Result<Option<Vec<u8>>, String> {
        let url = format!("{}{path}", self.base);
        let mut wait = Duration::from_millis(250);
        let mut tries = 1;
        let response = loop {
            let response = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| describe_request(&e, self.budget))?;
            let status = response.status().as_u16();
            if tries < TRIES && matches!(status, 429 | 500 | 502 | 503 | 504) {
                tokio::time::sleep(wait).await;
                wait *= 2;
                tries += 1;
                continue;
            }
            if status == 404 {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(describe_status(status));
            }
            break response;
        };
        self.body(response, max).await.map(Some)
    }

    /// The body of an answer, read a chunk at a time, decompressed, and
    /// refused past `max` bytes.
    async fn body(&self, mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| describe_request(&e, self.budget))?
        {
            if body.len() + chunk.len() > max {
                return Err(if max >= 1 << 20 {
                    format!("the server sent an answer longer than {} MiB", max >> 20)
                } else {
                    format!("the server sent an answer longer than {} KiB", max >> 10)
                });
            }
            let spent = self
                .spent
                .fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed)
                .saturating_add(chunk.len());
            if spent > self.run_max {
                return Err(format!(
                    "the server sent more than {} MiB for one sync",
                    self.run_max >> 20
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// The body of `path`, which must be there.
    pub(crate) async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, String> {
        self.fetch(path, MAX_BODY)
            .await?
            .ok_or_else(|| describe_status(404))
    }

    /// A page of a history, read as it is listed, held to a few
    /// megabytes.
    pub(crate) async fn get_page(&self, path: &str) -> Result<Vec<PageTx>, String> {
        let body = self
            .fetch(path, PAGE_MAX)
            .await?
            .ok_or_else(|| describe_status(404))?;
        serde_json::from_slice(&body).map_err(|_| "unexpected response".to_owned())
    }

    /// The same, read as JSON.
    pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, String> {
        let body = self.get_bytes(path).await?;
        serde_json::from_slice(&body).map_err(|_| "unexpected response".to_owned())
    }

    /// The same, `None` when the server has nothing there.
    async fn get_json_opt<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, String> {
        match self.fetch(path, MAX_BODY).await? {
            Some(body) => serde_json::from_slice(&body)
                .map(Some)
                .map_err(|_| "unexpected response".to_owned()),
            None => Ok(None),
        }
    }

    /// The body of `path` as one line of text, parsed.
    async fn get_parsed<T: std::str::FromStr>(&self, path: &str) -> Result<T, String> {
        let body = self.get_bytes(path).await?;
        std::str::from_utf8(&body)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or_else(|| "unexpected response".to_owned())
    }

    /// The height of the server's tip.
    pub(crate) async fn height(&self) -> Result<u32, String> {
        self.get_parsed("/blocks/tip/height").await
    }

    /// The hash of the server's tip.
    pub(crate) async fn tip_hash(&self) -> Result<BlockHash, String> {
        self.get_parsed("/blocks/tip/hash").await
    }

    /// The counters of a script.
    pub(crate) async fn scripthash_stats(
        &self,
        script: &ScriptBuf,
    ) -> Result<api::ScriptHashStats, String> {
        self.get_json(&sync::script_path(script)).await
    }

    async fn address_stats(&self, address: &Address) -> Result<api::AddressStats, String> {
        self.get_json(&format!("/address/{address}")).await
    }

    /// A page of an address's history: the unconfirmed transactions and
    /// the latest confirmed ones, or the confirmed ones after `after`.
    async fn address_txs(
        &self,
        address: &Address,
        after: Option<Txid>,
    ) -> Result<Vec<PageTx>, String> {
        match after {
            Some(txid) => {
                self.get_page(&format!("/address/{address}/txs/chain/{txid}"))
                    .await
            }
            None => self.get_page(&format!("/address/{address}/txs")).await,
        }
    }

    async fn address_utxos(&self, address: &Address) -> Result<Vec<api::Utxo>, String> {
        self.get_json(&format!("/address/{address}/utxo")).await
    }

    /// A transaction, `None` when the server does not know it.
    pub(crate) async fn tx(&self, txid: &Txid) -> Result<Option<Transaction>, String> {
        match self.fetch(&format!("/tx/{txid}/raw"), MAX_BODY).await? {
            Some(bytes) => bdk_wallet::bitcoin::consensus::deserialize(&bytes)
                .map(Some)
                .map_err(|_| "unexpected response".to_owned()),
            None => Ok(None),
        }
    }

    /// Whether the server knows a transaction. What it says of it is
    /// skipped as it is parsed.
    async fn knows_tx(&self, txid: &Txid) -> Result<bool, String> {
        self.get_json_opt::<serde::de::IgnoredAny>(&format!("/tx/{txid}"))
            .await
            .map(|found| found.is_some())
    }

    async fn tx_status(&self, txid: &Txid) -> Result<api::TxStatus, String> {
        self.get_json(&format!("/tx/{txid}/status")).await
    }

    /// Whether an output is spent, `None` when the server cannot say.
    async fn output_status(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<api::OutputStatus>, String> {
        self.get_json_opt(&format!("/tx/{txid}/outspend/{vout}"))
            .await
    }

    /// Hands a transaction to the server. The node's refusal comes back
    /// as the error, from a body held to a few kilobytes.
    async fn post_tx(&self, tx: &Transaction) -> Result<(), String> {
        let response = self
            .http
            .post(format!("{}/tx", self.base))
            .body(bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx))
            .send()
            .await
            .map_err(|e| describe_request(&e, self.budget))?;
        // Accepted: whatever else the server says is not read.
        if response.status().is_success() {
            return Ok(());
        }
        let body = self.body(response, REFUSAL_MAX).await?;
        Err(node_message(&String::from_utf8_lossy(&body)))
    }
}

/// The counters an Esplora server keeps for a script, confirmed and
/// unconfirmed apart: how many transactions touch it, and the coins they
/// paid to it and spent from it. A transaction that arrives, leaves the
/// mempool or confirms moves them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub chain: Tally,
    pub mempool: Tally,
}

/// One side of [`Counts`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub txs: u64,
    pub funded: u64,
    pub funded_sats: u64,
    pub spent: u64,
    pub spent_sats: u64,
}

impl Counts {
    pub(crate) fn of(stats: &esplora_client::api::ScriptHashStats) -> Self {
        let tally = |side: &esplora_client::api::ScriptHashTxsSummary| Tally {
            txs: u64::from(side.tx_count),
            funded: u64::from(side.funded_txo_count),
            funded_sats: side.funded_txo_sum,
            spent: u64::from(side.spent_txo_count),
            spent_sats: side.spent_txo_sum,
        };
        Counts {
            chain: tally(&stats.chain_stats),
            mempool: tally(&stats.mempool_stats),
        }
    }
}

/// A client for one instance. `proxy` is the Tor SOCKS proxy the caller
/// resolved for onion hosts; an onion URL without one is refused here,
/// before anything could look the name up.
pub(crate) fn client(url: &str, proxy: Option<&str>) -> Result<Client, String> {
    let budget = if crate::chain::is_onion(url) {
        Budget {
            connect: TOR_CONNECT_TIMEOUT,
            total: TOR_TIMEOUT,
        }
    } else {
        Budget {
            connect: CONNECT_TIMEOUT,
            total: TIMEOUT,
        }
    };
    build(url, proxy, budget)
}

/// The HTTP client is built here rather than through the crate's own
/// builder, which knows one timeout: connecting and answering are two
/// different waits, and a host that is down must not get the budget of
/// a host that is slow.
fn build(url: &str, proxy: Option<&str>, budget: Budget) -> Result<Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(budget.connect)
        .timeout(budget.total);
    if crate::chain::is_onion(url) {
        let proxy = proxy.ok_or_else(|| crate::chain::tor::no_route(url))?;
        // socks5h: the proxy resolves the name; .onion never touches DNS.
        let proxy = reqwest::Proxy::all(format!("socks5h://{proxy}"))
            .map_err(|e| format!("invalid Tor proxy address: {e}"))?;
        builder = builder.proxy(proxy);
    }
    let http = builder
        .build()
        .map_err(|e| format!("could not set up the HTTP client: {e}"))?;
    Ok(Client {
        http,
        base: url.trim_end_matches('/').to_owned(),
        budget,
        spent: std::sync::atomic::AtomicUsize::new(0),
        run_max: usize::MAX,
    })
}

/// A client for one sync, or one reading of an address: the same, and
/// what it reads in all held to [`RUN_MAX`].
pub(crate) fn client_for_run(url: &str, proxy: Option<&str>) -> Result<Client, String> {
    let mut client = client(url, proxy)?;
    client.run_max = RUN_MAX;
    Ok(client)
}

// --- errors ---------------------------------------------------------------

fn describe_status(status: u16) -> String {
    let reason = match status {
        400 => "bad request",
        401 | 403 => "access refused",
        404 => "not found",
        429 => "rate limited",
        500..=599 => "server error",
        _ => "unexpected status",
    };
    format!("HTTP {status}: {reason}")
}

/// What went wrong on the way to the server, by asking the error and
/// what it wraps rather than reading their text: `reqwest` says only
/// "error sending request", the cause sits several layers below.
fn describe_request(error: &reqwest::Error, budget: Budget) -> String {
    if error.is_timeout() {
        return if error.is_connect() {
            format!("could not connect within {} s", budget.connect.as_secs())
        } else {
            format!("timed out after {} s", budget.total.as_secs())
        };
    }
    describe_failure(error)
}

/// The same, a timeout aside: what the budgets say about one is the
/// caller's, the rest reads the same for every client of the crate.
pub(crate) fn describe_failure(error: &reqwest::Error) -> String {
    if error.is_connect() {
        // The TLS library's own error type, however deep it is wrapped.
        // Its words are the ones to keep: which certificate check
        // failed, or what came back in place of a handshake.
        if let Some(cause) = find_cause(error, &mut |cause| cause.is::<rustls::Error>()) {
            return format!("TLS handshake failed: {cause}");
        }
        // The connector names the step that failed; the resolver's own
        // words hang below it and vary by platform.
        if find_cause(error, &mut |cause| cause.to_string() == "dns error").is_some() {
            return "host not found".to_owned();
        }
        // The proxy step names itself too, and the SOCKS client's own
        // words hang below it: a refusal, or a handshake cut short.
        if let Some(cause) = find_cause(error, &mut |cause| {
            cause.to_string().contains("socks proxy")
        }) {
            return match cause.source() {
                Some(reason) => {
                    let reason = reason.to_string();
                    let reason = reason.strip_prefix("SOCKS error: ").unwrap_or(&reason);
                    format!("could not connect through Tor: {reason}")
                }
                None => "could not connect through Tor".to_owned(),
            };
        }
        return "could not connect".to_owned();
    }
    if error.is_body() || error.is_decode() {
        return "unexpected response".to_owned();
    }
    "request failed".to_owned()
}

/// The first error for which `matches` holds, among the error itself,
/// its `source` chain, and whatever an `io::Error` along the way
/// wraps: an `io::Error` reports the source of what it wraps, not the
/// wrapped error itself, so a plain walk would step over it.
fn find_cause<'e>(
    error: &'e (dyn std::error::Error + 'static),
    matches: &mut dyn FnMut(&(dyn std::error::Error + 'static)) -> bool,
) -> Option<&'e (dyn std::error::Error + 'static)> {
    if matches(error) {
        return Some(error);
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>()
        && let Some(inner) = io.get_ref()
        && let Some(found) = find_cause(inner, matches)
    {
        return Some(found);
    }
    error
        .source()
        .and_then(|source| find_cause(source, matches))
}

/// One round of address history: the transactions fetched and, when
/// older ones remain, the cursor to continue from.
#[derive(Debug)]
pub(crate) struct HistoryRound {
    pub txs: Vec<AddressTx>,
    /// Txid to pass as `from` to fetch the next round; `None` when the
    /// history is exhausted.
    pub cursor: Option<String>,
}

/// Fetches the complete state of a single watched address.
pub(crate) async fn fetch_address_state(
    client: &Client,
    address: &str,
    network: Network,
) -> Result<AddressWatchState, String> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();

    let tip_height = client.height().await?;
    let stats = client.address_stats(&address).await?;

    let round = history_round(
        client,
        &address,
        &our_script,
        network,
        None,
        Some(stats.chain_stats.tx_count as usize),
    )
    .await?;

    let utxos = client
        .address_utxos(&address)
        .await?
        .into_iter()
        .map(|utxo| AddressUtxo {
            txid: utxo.txid.to_string(),
            vout: utxo.vout,
            value_sats: utxo.value.to_sat(),
            height: utxo.status.block_height,
            timestamp: utxo.status.block_time,
        })
        .collect();

    Ok(AddressWatchState {
        txs: round.txs,
        utxos,
        tip_height,
        funded_sats: stats.chain_stats.funded_txo_sum + stats.mempool_stats.funded_txo_sum,
        spent_sats: stats.chain_stats.spent_txo_sum + stats.mempool_stats.spent_txo_sum,
        truncated: round.cursor.is_some(),
        history_cursor: round.cursor,
    })
}

/// Fetches the next round of older transactions, continuing after
/// `from`. Used by "load older transactions": the balance and the UTXO
/// set already cover the full history, only the list grows.
pub(crate) async fn fetch_address_history(
    client: &Client,
    address: &str,
    network: Network,
    from: &str,
) -> Result<HistoryRound, String> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();
    let from: Txid = from
        .parse()
        .map_err(|_| format!("invalid history cursor: {from}"))?;
    history_round(client, &address, &our_script, network, Some(from), None).await
}

pub(crate) fn parse_address(address: &str, network: Network) -> Result<Address, String> {
    address
        .parse::<Address<_>>()
        .map_err(|e| format!("invalid address: {e}"))?
        .require_network(network.to_bitcoin())
        .map_err(|e| format!("address/network mismatch: {e}"))
}

/// Pages through the address history from `from` (newest first when
/// `None`), at most [`HISTORY_PAGES_PER_ROUND`] pages.
async fn history_round(
    client: &Client,
    address: &Address,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
    from: Option<Txid>,
    confirmed_total: Option<usize>,
) -> Result<HistoryRound, String> {
    // Each page is read into what the app shows as soon as it arrives,
    // and dropped: forty pages are never held as the server spelled them.
    let mut txs: Vec<AddressTx> = Vec::new();
    let mut confirmed = 0usize;
    let mut last_seen: Option<Txid> = None;
    let mut read = |page: Vec<PageTx>, txs: &mut Vec<AddressTx>| {
        for tx in page {
            if tx.status.confirmed {
                confirmed += 1;
                last_seen = Some(tx.txid);
            }
            txs.push(to_address_tx(tx, our_script, network));
        }
        (confirmed, last_seen)
    };
    let (mut confirmed_so_far, mut last) = read(client.address_txs(address, from).await?, &mut txs);
    let mut cursor: Option<String> = None;
    let mut pages = 1usize;
    loop {
        // The whole history is in hand: `confirmed_total` counts it from
        // the address stats, so no probing request is needed.
        if let Some(total) = confirmed_total
            && confirmed_so_far >= total
        {
            break;
        }
        let Some(last_seen) = last else {
            break;
        };
        if pages >= HISTORY_PAGES_PER_ROUND {
            cursor = Some(last_seen.to_string());
            break;
        }
        let page = client.address_txs(address, Some(last_seen)).await?;
        pages += 1;
        if page.is_empty() {
            break;
        }
        (confirmed_so_far, last) = read(page, &mut txs);
    }
    Ok(HistoryRound { txs, cursor })
}

/// One esplora transaction as seen from the watched address.
fn to_address_tx(
    tx: PageTx,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
) -> AddressTx {
    let received: u64 = tx
        .vout
        .iter()
        .filter(|v| v.scriptpubkey == *our_script)
        .map(|v| v.value)
        .sum();
    let spent: u64 = tx
        .vin
        .iter()
        .filter_map(|v| v.prevout.as_ref())
        .filter(|p| p.scriptpubkey == *our_script)
        .map(|p| p.value)
        .sum();
    let inputs = tx
        .vin
        .iter()
        .map(|vin| match &vin.prevout {
            Some(prevout) => TxIo {
                address: script_address(&prevout.scriptpubkey, network),
                value_sats: Some(prevout.value),
                is_mine: prevout.scriptpubkey == *our_script,
                prev_txid: Some(vin.txid.to_string()),
                prev_vout: Some(vin.vout),
                ..TxIo::default()
            },
            // A coinbase input spends nothing, and Esplora sends no
            // prevout with it: the outpoint would be all zeroes.
            None => TxIo::default(),
        })
        .collect();
    let outputs = tx
        .vout
        .iter()
        .map(|vout| TxIo {
            address: script_address(&vout.scriptpubkey, network),
            value_sats: Some(vout.value),
            is_mine: vout.scriptpubkey == *our_script,
            change: false,
            op_return: tx_extras::op_return_of(&vout.scriptpubkey),
            ..TxIo::default()
        })
        .collect();
    // A coinbase transaction has no fee; Esplora reports 0.
    let is_coinbase = tx.vin.first().is_some_and(|vin| vin.is_coinbase);
    // The prevouts Esplora attaches to each input make the deep
    // analysis (taproot spend, sigops) as accurate as the API is.
    let prevouts: std::collections::HashMap<OutPoint, TxOut> = tx
        .vin
        .iter()
        .filter_map(|vin| {
            vin.prevout.as_ref().map(|p| {
                (
                    OutPoint::new(vin.txid, vin.vout),
                    TxOut {
                        value: Amount::from_sat(p.value),
                        script_pubkey: p.scriptpubkey.clone(),
                    },
                )
            })
        })
        .collect();
    let extras = tx_extras::analyze(&tx.to_tx(), |op| prevouts.get(op).cloned());
    AddressTx {
        txid: tx.txid.to_string(),
        net_sats: received as i64 - spent as i64,
        fee_sats: (!is_coinbase).then_some(tx.fee),
        height: tx.status.block_height,
        timestamp: tx.status.block_time,
        vsize: tx.weight.div_ceil(4),
        inputs,
        outputs,
        extras: Some(extras),
    }
}

pub(crate) fn script_address(
    script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
) -> Option<String> {
    Address::from_script(script, network.to_bitcoin())
        .ok()
        .map(|a| a.to_string())
}

// --- broadcast ------------------------------------------------------------

/// Hands a signed transaction to the network through this instance.
/// The instance's own node validates it; its refusal comes back as the
/// message, verbatim, which is the most useful thing to show.
///
/// Esplora wraps the node's refusal in an HTTP error whose body is the
/// reason, in one of two spellings:
/// `sendrawtransaction RPC error: {"code":-26,"message":"..."}` (the
/// mempool instances) or `sendrawtransaction RPC error -26: ...`
/// (blockstream.info). The message is kept, the wrapping dropped.
/// Anything else is a failure to reach the node, described as such.
pub(crate) async fn broadcast(client: &Client, tx: &Transaction) -> Result<(), String> {
    client.post_tx(tx).await
}

/// Longest refusal shown, in characters, as for any other sentence a
/// server writes.
const NODE_MESSAGE_MAX: usize = 200;

/// The reason inside a `sendrawtransaction` refusal, whichever way the
/// server spelled it; the whole text when it is not one. Shown as the
/// node's words, so kept to one short line: a server that answers a
/// page of text, or instructions of its own, gets its first 200
/// characters on screen, control characters dropped.
pub(crate) fn node_message(text: &str) -> String {
    let words = node_words(text);
    let mut kept = words.chars().filter(|c| !c.is_control());
    let mut short: String = kept.by_ref().take(NODE_MESSAGE_MAX).collect();
    if kept.next().is_some() {
        short.push('\u{2026}');
    }
    short
}

fn node_words(text: &str) -> String {
    // A body quoted inside another error arrives with its quotes
    // escaped: read it as if it were not.
    let text = text.replace("\\\"", "\"");
    if let Some(start) = text.find("\"message\":\"") {
        let rest = &text[start + 11..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_owned();
        }
    }
    if let Some(start) = text.find("RPC error -") {
        let rest = &text[start..];
        if let Some(colon) = rest.find(": ") {
            return rest[colon + 2..].trim().to_owned();
        }
    }
    text.trim().to_owned()
}

/// The output an input spends, and whether it is already spent.
pub(crate) struct PrevoutFacts {
    pub txout: Option<TxOut>,
    pub spent: Option<bool>,
}

/// Fetches a previous output. `None` in `txout` means the backend does
/// not know the transaction at all.
pub(crate) async fn fetch_prevout(
    client: &Client,
    outpoint: OutPoint,
) -> Result<PrevoutFacts, String> {
    let tx = client.tx(&outpoint.txid).await?;
    let Some(tx) = tx else {
        return Ok(PrevoutFacts {
            txout: None,
            spent: None,
        });
    };
    let txout = crate::chain::output_at(&tx, outpoint)?;
    let spent = client
        .output_status(&outpoint.txid, outpoint.vout)
        .await
        .ok()
        .flatten()
        .map(|status| status.spent);
    Ok(PrevoutFacts { txout, spent })
}

/// Where a transaction stands: unknown, in the mempool, or at a height.
pub(crate) struct TxStanding {
    pub found: bool,
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub tip_height: u32,
}

pub(crate) async fn tx_standing(client: &Client, txid: &Txid) -> Result<TxStanding, String> {
    let tip_height = client.height().await?;
    let found = client.knows_tx(txid).await?;
    if !found {
        return Ok(TxStanding {
            found: false,
            confirmed: false,
            block_height: None,
            tip_height,
        });
    }
    let status = client.tx_status(txid).await?;
    Ok(TxStanding {
        found: true,
        confirmed: status.confirmed,
        block_height: status.block_height,
        tip_height,
    })
}

#[cfg(test)]
mod error_tests {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Budgets short enough to test: the connection has five seconds,
    /// the whole request one.
    const BUDGET: Budget = Budget {
        connect: Duration::from_secs(5),
        total: Duration::from_secs(1),
    };
    /// Budgets that let a connection fail on its own terms: Windows
    /// takes a second or two to give up on a closed loopback port, and
    /// a name lookup can take as long to come back empty.
    const PATIENT: Budget = Budget {
        connect: Duration::from_secs(15),
        total: Duration::from_secs(30),
    };

    #[test]
    fn a_status_is_a_code_and_a_reason() {
        assert_eq!(describe_status(429), "HTTP 429: rate limited");
        assert_eq!(describe_status(503), "HTTP 503: server error");
        assert_eq!(describe_status(500), "HTTP 500: server error");
        assert_eq!(describe_status(404), "HTTP 404: not found");
        assert_eq!(describe_status(400), "HTTP 400: bad request");
        assert_eq!(describe_status(403), "HTTP 403: access refused");
        assert_eq!(describe_status(418), "HTTP 418: unexpected status");
    }

    /// A server that accepts the connection and never answers: the
    /// request budget runs out, and the message says by how much.
    #[tokio::test]
    async fn a_server_that_never_answers_is_a_timeout_with_its_budget() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Held open, never written to.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let client = build(&format!("http://{address}"), None, BUDGET).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(error, "timed out after 1 s");
    }

    #[tokio::test]
    async fn a_closed_port_is_a_failure_to_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(error, "could not connect");
    }

    #[tokio::test]
    async fn an_unknown_host_is_said_to_be_one() {
        // `.invalid` is reserved never to resolve, whatever the resolver.
        let client = build("http://esplora.invalid", None, PATIENT).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(error, "host not found");
    }

    /// A server that answers the handshake with something that is not
    /// TLS: the library's own words say what came back.
    #[tokio::test]
    async fn a_tls_failure_keeps_the_reason() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                // The whole ClientHello is read first, its length from
                // the record header: a socket dropped with unread bytes
                // resets the connection, and the client would report
                // the reset rather than what was sent back.
                let mut header = [0u8; 5];
                if stream.read_exact(&mut header).await.is_err() {
                    continue;
                }
                let mut hello = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
                let _ = stream.read_exact(&mut hello).await;
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                // Held until the client has read its answer and gone.
                let mut rest = [0u8; 1];
                let _ = stream.read(&mut rest).await;
            }
        });
        let client = build(&format!("https://{address}"), None, PATIENT).unwrap();
        let described = client.height().await.unwrap_err();
        assert!(
            described.starts_with("TLS handshake failed: received corrupt message"),
            "{described}"
        );
    }

    /// A proxy that turns the handshake down: the SOCKS client's own
    /// words say why, without its "SOCKS error" preamble.
    #[tokio::test]
    async fn a_socks_refusal_keeps_the_reason() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 64];
                let _ = stream.read(&mut greeting).await;
                // No acceptable authentication method, RFC 1928.
                let _ = stream.write_all(&[5, 0xFF]).await;
                let mut rest = [0u8; 1];
                let _ = stream.read(&mut rest).await;
            }
        });
        let onion = "http://gerfautexample000000000000000000000000000000000000000.onion/api";
        let client = build(onion, Some(&proxy.to_string()), PATIENT).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(
            error,
            "could not connect through Tor: server does not support user/pass authentication"
        );
    }

    /// A server that answers with `status` and `body` gzipped, whatever
    /// is asked.
    async fn gzipping(status: &'static str, body: Vec<u8>) -> std::net::SocketAddr {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&body).unwrap();
        let gzipped = encoder.finish().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let gzipped = gzipped.clone();
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-encoding: gzip\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        gzipped.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&gzipped).await;
                });
            }
        });
        address
    }

    /// A small gzip of a huge body, from any request a client makes:
    /// the tip polling reads, the counters of a script, the page of an
    /// address. The answer is cut off past its cap, never held whole.
    #[tokio::test]
    async fn a_gzip_bomb_is_cut_off_whatever_is_asked() {
        let bomb = vec![b'0'; MAX_BODY + (1 << 20)];
        let address = gzipping("200 OK", bomb.clone()).await;
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        let cut = "the server sent an answer longer than 32 MiB";
        assert_eq!(client.height().await.unwrap_err(), cut);
        assert_eq!(client.tip_hash().await.unwrap_err(), cut);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        assert_eq!(client.scripthash_stats(&script).await.unwrap_err(), cut);
        let txid: Txid = "01".repeat(32).parse().unwrap();
        assert_eq!(client.tx(&txid).await.unwrap_err(), cut);
        let address = parse_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Network::Signet,
        )
        .unwrap();
        assert_eq!(client.address_utxos(&address).await.unwrap_err(), cut);
        // And a broadcast, whose refusal is read to a few kilobytes.
        let address = gzipping("400 Bad Request", bomb).await;
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        assert_eq!(
            broadcast(&client, &tx).await.unwrap_err(),
            "the server sent an answer longer than 64 KiB"
        );
    }

    /// A gzipped answer of a sensible size reads as it always did.
    #[tokio::test]
    async fn a_gzipped_answer_is_read() {
        let address = gzipping("200 OK", b"812345\n".to_vec()).await;
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        assert_eq!(client.height().await.unwrap(), 812_345);
    }

    /// A page of a history is held to a few megabytes, and one sync to a
    /// few dozen in all, however the server spreads them over its
    /// answers: past that the sync fails, rather than read on.
    #[tokio::test]
    async fn a_sync_reads_so_much_and_no_more() {
        let address = gzipping("200 OK", vec![b' '; PAGE_MAX + 1]).await;
        let url = format!("http://{address}");
        let paged = client_for_run(&url, None).unwrap();
        assert_eq!(
            paged.get_page("/scripthash/00/txs").await.unwrap_err(),
            "the server sent an answer longer than 8 MiB"
        );

        let address = gzipping("200 OK", vec![b' '; 20 << 20]).await;
        let url = format!("http://{address}");
        let one_sync = client_for_run(&url, None).unwrap();
        for _ in 0..3 {
            one_sync.get_bytes("/blocks").await.unwrap();
        }
        assert_eq!(
            one_sync.get_bytes("/blocks").await.unwrap_err(),
            "the server sent more than 64 MiB for one sync"
        );
        // A client that serves a watch, not one sync, has no such cap.
        let watching = super::client(&url, None).unwrap();
        for _ in 0..4 {
            watching.get_bytes("/blocks").await.unwrap();
        }
    }

    #[test]
    fn budgets_follow_the_kind_of_host() {
        assert_eq!(
            client("https://mempool.space/api", None).unwrap().budget,
            Budget {
                connect: CONNECT_TIMEOUT,
                total: TIMEOUT,
            }
        );
        let onion = "http://gerfautexample000000000000000000000000000000000000000.onion/api";
        assert!(client(onion, None).unwrap_err().starts_with("tor: "));
        assert_eq!(
            client(onion, Some("127.0.0.1:9050")).unwrap().budget,
            Budget {
                connect: TOR_CONNECT_TIMEOUT,
                total: TOR_TIMEOUT,
            }
        );
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::node_message;

    #[test]
    fn the_node_reason_is_kept_whichever_spelling() {
        let mempool = r#"sendrawtransaction RPC error: {"code":-27,"message":"Transaction outputs already in utxo set"}"#;
        assert_eq!(
            node_message(mempool),
            "Transaction outputs already in utxo set"
        );
        let blockstream = "sendrawtransaction RPC error -26: mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)";
        assert_eq!(
            node_message(blockstream),
            "mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"
        );
        let escaped = r#"{\"code\":-26,\"message\":\"bad-txns-inputs-missingorspent\"}"#;
        assert_eq!(node_message(escaped), "bad-txns-inputs-missingorspent");
        assert_eq!(node_message("connection refused"), "connection refused");
        // A page of text, or a sentence of the server's own, is cut to
        // one short line.
        let long = node_message(&format!("send it again to\n{}", "x".repeat(1 << 20)));
        assert_eq!(long.chars().count(), 201);
        assert!(long.starts_with("send it again tox") && long.ends_with('\u{2026}'));
    }
}
