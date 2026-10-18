//! Esplora backend: descriptor wallet sync and single-address tracking.

use std::time::Duration;

use bdk_wallet::bitcoin::address::Address;

use bdk_wallet::bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

pub(crate) mod api;
pub(crate) mod page;
pub(crate) mod sync;

use page::PageTx;

use crate::chain::{Failure, Fault};
use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState, tx_extras};

/// Concurrent requests during scans.
pub(crate) const PARALLEL_REQUESTS: usize = 4;
/// The largest answer read, once decompressed: a page of the biggest
/// transactions there are, with room to spare. A server that sends more
/// is not answering the question, and is cut off rather than buffered.
const MAX_BODY: usize = 32 << 20;
/// The largest JSON answer read, once decompressed. It is parsed as it
/// arrives, and what is not kept, the assembly of each script and each
/// witness, costs nothing: this only stops a server that never ends.
/// Four of the largest inscriptions there are fit in one page.
const JSON_MAX: usize = 64 << 20;
/// Chunks of an answer read ahead of its parsing.
const CHUNKS_AHEAD: usize = 8;
/// Tries of a request a server failed with an error of its own, which a
/// moment later it may not.
const TRIES: u32 = 4;
/// The shortest wait after a server limited the rate of requests (429),
/// whatever it named: mempool.space bans a client that keeps coming
/// back too soon.
const RATE_WAIT_MIN: Duration = Duration::from_secs(5);
/// The longest wait a request sits through before it is asked again, a
/// single time; past it the request fails at once, saying how long the
/// server asked for.
const RATE_WAIT_MAX: Duration = Duration::from_secs(60);
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
    /// What a sync kept so far of the transactions it read, and how
    /// much it may.
    kept: crate::chain::Kept,
    /// The longest wait the server asked for since it was last read:
    /// see [`Client::take_rate_limit`].
    rate_limit: std::sync::Mutex<Option<Duration>>,
}

impl Client {
    /// The answer to `path` under the instance's address, its body not
    /// read yet; `None` when the server has nothing there (404). A server
    /// that fails with an error of its own is asked again a few times, a
    /// little later each time. One that limits the rate of requests is
    /// asked again once, after the wait it named, five seconds at least
    /// and a little more so that clients do not come back together, when
    /// that wait is a minute at most. One that closed the connection
    /// before it answered is asked again at once, a single time: a
    /// connection kept open for the next request, which the server
    /// closes as that request goes out, is the lot of every client.
    async fn open(&self, path: &str) -> Result<Option<reqwest::Response>, Fault> {
        let url = format!("{}{path}", self.base);
        let mut wait = Duration::from_millis(250);
        let mut tries = 1;
        let mut limited = false;
        let mut reopened = false;
        let response = loop {
            let response = match self.http.get(&url).send().await {
                Ok(response) => response,
                Err(error) if !reopened && closed_early(&error) => {
                    reopened = true;
                    continue;
                }
                Err(error) => return Err(describe_request(&error, self.budget)),
            };
            let status = response.status().as_u16();
            if status == 429 {
                let named = retry_after(response.headers()).unwrap_or_default();
                let pause = named.max(RATE_WAIT_MIN);
                self.limited(pause);
                if limited || pause > RATE_WAIT_MAX {
                    return Err(rate_limited(pause));
                }
                limited = true;
                tokio::time::sleep(pause.mul_f64(1.0 + 0.2 * rand::random::<f64>())).await;
                continue;
            }
            if tries < TRIES && matches!(status, 500 | 502 | 503 | 504) {
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
        Ok(Some(response))
    }

    /// The body of `path`, decompressed and held to `max`; `None` when
    /// the server has nothing there.
    async fn fetch(&self, path: &str, max: usize) -> Result<Option<Vec<u8>>, Fault> {
        match self.open(path).await? {
            Some(response) => self.body(response, max).await.map(Some),
            None => Ok(None),
        }
    }

    /// The JSON answer to `path`, parsed as it arrives and decompresses,
    /// never held whole: what the reading skips, it never keeps. `None`
    /// when the server has nothing there.
    async fn stream_json<T>(&self, path: &str) -> Result<Option<T>, Fault>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        let Some(mut response) = self.open(path).await? else {
            return Ok(None);
        };
        let (chunks, arriving) = tokio::sync::mpsc::channel(CHUNKS_AHEAD);
        let parsing = tokio::task::spawn_blocking(move || {
            let reader = std::io::BufReader::with_capacity(
                64 << 10,
                ChunkReader {
                    arriving,
                    chunk: None,
                    at: 0,
                },
            );
            serde_json::from_reader::<_, T>(reader)
        });
        let mut read = 0usize;
        let pumped: Result<(), Fault> = async {
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| describe_request(&e, self.budget))?
            {
                read = read.saturating_add(chunk.len());
                if read > JSON_MAX {
                    return Err(Fault::other(too_long(JSON_MAX)));
                }
                // The parsing ended early: it says why below.
                if chunks.send(chunk).await.is_err() {
                    break;
                }
            }
            Ok(())
        }
        .await;
        drop(chunks);
        let parsed = parsing
            .await
            .map_err(|_| Fault::other("unexpected response"))?;
        pumped?;
        parsed
            .map(Some)
            .map_err(|_| Fault::other("unexpected response"))
    }

    /// Notes that the server asked for `pause` before the next request.
    fn limited(&self, pause: Duration) {
        let mut asked = self
            .rate_limit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *asked = (*asked).max(Some(pause));
    }

    /// The longest wait the server asked for since this was last called,
    /// if it limited the rate of requests meanwhile, a request that went
    /// through on its second try included: whoever asks it at a pace
    /// learns it is too fast.
    pub(crate) fn take_rate_limit(&self) -> Option<Duration> {
        self.rate_limit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// Counts `bytes` of transactions against what one sync may keep.
    pub(crate) fn keep(&self, bytes: usize) -> Result<(), Fault> {
        Ok(self.kept.add(bytes)?)
    }

    /// The body of an answer, read a chunk at a time, decompressed, and
    /// refused past `max` bytes.
    async fn body(&self, mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, Fault> {
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| describe_request(&e, self.budget))?
        {
            if body.len() + chunk.len() > max {
                return Err(Fault::other(too_long(max)));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// The body of `path`, which must be there.
    pub(crate) async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, Fault> {
        self.fetch(path, MAX_BODY)
            .await?
            .ok_or_else(|| describe_status(404))
    }

    /// A page of a history, read as it is listed: see [`PageTx`].
    pub(crate) async fn get_page(&self, path: &str) -> Result<Vec<PageTx>, Fault> {
        self.get_json(path).await
    }

    /// The JSON answer to `path`, which must be there: see
    /// [`Self::stream_json`].
    pub(crate) async fn get_json<T>(&self, path: &str) -> Result<T, Fault>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        self.stream_json(path)
            .await?
            .ok_or_else(|| describe_status(404))
    }

    /// The same, `None` when the server has nothing there.
    async fn get_json_opt<T>(&self, path: &str) -> Result<Option<T>, Fault>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        self.stream_json(path).await
    }

    /// The body of `path` as one line of text, parsed.
    async fn get_parsed<T: std::str::FromStr>(&self, path: &str) -> Result<T, Fault> {
        let body = self.get_bytes(path).await?;
        std::str::from_utf8(&body)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or_else(|| Fault::other("unexpected response"))
    }

    /// The height of the server's tip.
    pub(crate) async fn height(&self) -> Result<u32, Fault> {
        self.get_parsed("/blocks/tip/height").await
    }

    /// The hash of the server's tip.
    pub(crate) async fn tip_hash(&self) -> Result<BlockHash, Fault> {
        self.get_parsed("/blocks/tip/hash").await
    }

    /// The counters of a script.
    pub(crate) async fn scripthash_stats(
        &self,
        script: &ScriptBuf,
    ) -> Result<api::ScriptHashStats, Fault> {
        self.get_json(&sync::script_path(script)).await
    }

    async fn address_stats(&self, address: &Address) -> Result<api::AddressStats, Fault> {
        self.get_json(&format!("/address/{address}")).await
    }

    /// A page of an address's history: the unconfirmed transactions and
    /// the latest confirmed ones, or the confirmed ones after `after`.
    async fn address_txs(
        &self,
        address: &Address,
        after: Option<Txid>,
    ) -> Result<Vec<PageTx>, Fault> {
        match after {
            Some(txid) => {
                self.get_page(&format!("/address/{address}/txs/chain/{txid}"))
                    .await
            }
            None => self.get_page(&format!("/address/{address}/txs")).await,
        }
    }

    async fn address_utxos(&self, address: &Address) -> Result<Vec<api::Utxo>, Fault> {
        self.get_json(&format!("/address/{address}/utxo")).await
    }

    /// A transaction, `None` when the server does not know it.
    pub(crate) async fn tx(&self, txid: &Txid) -> Result<Option<Transaction>, Fault> {
        match self.fetch(&format!("/tx/{txid}/raw"), MAX_BODY).await? {
            Some(bytes) => bdk_wallet::bitcoin::consensus::deserialize(&bytes)
                .map(Some)
                .map_err(|_| Fault::other("unexpected response")),
            None => Ok(None),
        }
    }

    /// Whether the server knows a transaction. What it says of it is
    /// skipped as it is parsed.
    async fn knows_tx(&self, txid: &Txid) -> Result<bool, Fault> {
        self.get_json_opt::<serde::de::IgnoredAny>(&format!("/tx/{txid}"))
            .await
            .map(|found| found.is_some())
    }

    async fn tx_status(&self, txid: &Txid) -> Result<api::TxStatus, Fault> {
        self.get_json(&format!("/tx/{txid}/status")).await
    }

    /// Whether an output is spent, `None` when the server cannot say.
    async fn output_status(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<api::OutputStatus>, Fault> {
        self.get_json_opt(&format!("/tx/{txid}/outspend/{vout}"))
            .await
    }

    /// Hands a transaction to the server, and returns the txid it
    /// answers with. Only the node's verdict comes back as a refusal: a
    /// 400 whose body, held to a few kilobytes, is bitcoind's refusal in
    /// the words of electrs ([`crate::chain::node_verdict`]). Any other
    /// status, a proxy's page, a 2xx that is no txid, is the way there
    /// failing.
    async fn post_tx(&self, tx: &Transaction) -> Result<Txid, Failure> {
        let response = self
            .http
            .post(format!("{}/tx", self.base))
            .body(bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx))
            .send()
            .await
            .map_err(|e| Failure::Transport(describe_request(&e, self.budget)))?;
        let status = response.status().as_u16();
        let body = self
            .body(response, REFUSAL_MAX)
            .await
            .map_err(Failure::Transport)?;
        let text = String::from_utf8_lossy(&body);
        if (200..300).contains(&status) {
            // Esplora answers with the txid, and nothing else.
            return text.trim().parse().map_err(|_| {
                Failure::Transport(Fault::other(format!(
                    "the server answered {} instead of a txid",
                    crate::chain::server_words(text.trim())
                )))
            });
        }
        if status == 400
            && let Some(words) = crate::chain::node_verdict(&text)
        {
            return Err(Failure::Refused(words));
        }
        Err(Failure::Transport(describe_status(status)))
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
    pub(crate) fn of(stats: &api::ScriptHashStats) -> Self {
        let tally = |side: &api::ScriptHashTxsSummary| Tally {
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
pub(crate) fn client(url: &str, proxy: Option<&str>) -> Result<Client, Fault> {
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
fn build(url: &str, proxy: Option<&str>, budget: Budget) -> Result<Client, Fault> {
    // An Esplora API does not redirect. One that does would send the
    // scripts of the wallet where the route was never checked: in the
    // clear, or an onion name to the system's resolver.
    let mut builder = crate::chain::http_client()
        .connect_timeout(budget.connect)
        .timeout(budget.total)
        .redirect(reqwest::redirect::Policy::none());
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
        kept: crate::chain::Kept::up_to(usize::MAX),
        rate_limit: std::sync::Mutex::new(None),
    })
}

/// A client for one sync: the same, and what it keeps of the
/// transactions it reads held to [`crate::chain::KEEP_MAX`].
pub(crate) fn client_for_run(url: &str, proxy: Option<&str>) -> Result<Client, Fault> {
    let mut client = client(url, proxy)?;
    client.kept = crate::chain::Kept::up_to(crate::chain::KEEP_MAX);
    Ok(client)
}

/// The error of an answer longer than `max`.
fn too_long(max: usize) -> String {
    if max >= 1 << 20 {
        format!("the server sent an answer longer than {} MiB", max >> 20)
    } else {
        format!("the server sent an answer longer than {} KiB", max >> 10)
    }
}

/// The chunks of an answer as they arrive, read by a parser on a thread
/// of its own; the end of the answer when they stop.
struct ChunkReader<B> {
    arriving: tokio::sync::mpsc::Receiver<B>,
    chunk: Option<B>,
    at: usize,
}

impl<B: AsRef<[u8]>> std::io::Read for ChunkReader<B> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(chunk) = &self.chunk {
                let left = &chunk.as_ref()[self.at..];
                if !left.is_empty() {
                    let n = left.len().min(buf.len());
                    buf[..n].copy_from_slice(&left[..n]);
                    self.at += n;
                    return Ok(n);
                }
            }
            match self.arriving.blocking_recv() {
                Some(chunk) => {
                    self.chunk = Some(chunk);
                    self.at = 0;
                }
                None => return Ok(0),
            }
        }
    }
}

// --- errors ---------------------------------------------------------------

/// The wait a `Retry-After` header names, in seconds or as the date to
/// come back at, a day at most. A date already past, or written in one
/// of the obsolete forms, reads as none: the shortest wait applies.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    let seconds = match value.parse::<u64>() {
        Ok(seconds) => seconds,
        Err(_) => http_date(value)?.checked_sub(crate::now_secs())?,
    };
    Some(Duration::from_secs(seconds.min(24 * 60 * 60)))
}

/// An HTTP date in the form servers send, `Sun, 06 Nov 1994 08:49:37
/// GMT`, as unix seconds.
fn http_date(text: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: [&str; 6] = text
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    let [_weekday, day, month, year, time, "GMT"] = parts else {
        return None;
    };
    let day: u32 = day.parse().ok().filter(|day| (1..=31).contains(day))?;
    let month = MONTHS.iter().position(|name| *name == month)? as u32 + 1;
    let year: i64 = year
        .parse()
        .ok()
        .filter(|year| (1970..=9999).contains(year))?;
    let [hours, minutes, seconds]: [u64; 3] = time
        .split(':')
        .map(|part| part.parse().ok())
        .collect::<Option<Vec<u64>>>()?
        .try_into()
        .ok()?;
    if hours > 23 || minutes > 59 || seconds > 60 {
        return None;
    }
    let days = u64::try_from(crate::format::days_from_civil(year, month, day)).ok()?;
    days.checked_mul(86_400)?
        .checked_add(hours * 3_600 + minutes * 60 + seconds)
}

/// A server that limited the rate of requests, and the wait it asked for:
/// an outage.
fn rate_limited(pause: Duration) -> Fault {
    Fault::outage(format!(
        "{}, try again in {} s",
        describe_status(429),
        pause.as_secs()
    ))
}

/// A status that is no success, in words: an outage for a 429 or a 5xx,
/// read from the status, not from the words.
fn describe_status(status: u16) -> Fault {
    let reason = match status {
        400 => "bad request",
        401 | 403 => "access refused",
        404 => "not found",
        429 => "rate limited",
        500..=599 => "server error",
        _ => "unexpected status",
    };
    let words = format!("HTTP {status}: {reason}");
    if status == 429 || (500..=599).contains(&status) {
        Fault::outage(words)
    } else {
        Fault::other(words)
    }
}

/// What went wrong on the way to the server, by asking the error and
/// what it wraps rather than reading their text: `reqwest` says only
/// "error sending request", the cause sits several layers below.
fn describe_request(error: &reqwest::Error, budget: Budget) -> Fault {
    if error.is_timeout() {
        return Fault::outage(if error.is_connect() {
            format!("could not connect within {} s", budget.connect.as_secs())
        } else {
            format!("timed out after {} s", budget.total.as_secs())
        });
    }
    fault_of(error)
}

/// The same, a timeout aside, in words: what the budgets say about one is
/// the caller's, the rest reads the same for every client of the crate.
pub(crate) fn describe_failure(error: &reqwest::Error) -> String {
    fault_of(error).detail().to_owned()
}

/// [`describe_failure`], and its kind, read from what the error is: a
/// connection that failed, its TLS or its name, or one cut short, is an
/// outage; a failure through the Tor proxy is this device's.
fn fault_of(error: &reqwest::Error) -> Fault {
    if error.is_connect() {
        // The TLS library's own error type, however deep it is wrapped.
        // Its words are the ones to keep: which certificate check
        // failed, or what came back in place of a handshake.
        if let Some(cause) = find_cause(error, &mut |cause| cause.is::<rustls::Error>()) {
            return Fault::outage(format!("TLS handshake failed: {cause}"));
        }
        // The connector names the step that failed; the resolver's own
        // words hang below it and vary by platform.
        if find_cause(error, &mut |cause| cause.to_string() == "dns error").is_some() {
            return Fault::outage("host not found");
        }
        // The proxy step names itself too, and the SOCKS client's own
        // words hang below it: a refusal, or a handshake cut short.
        if let Some(cause) = find_cause(error, &mut |cause| {
            cause.to_string().contains("socks proxy")
        }) {
            return Fault::other(match cause.source() {
                Some(reason) => {
                    let reason = reason.to_string();
                    let reason = reason.strip_prefix("SOCKS error: ").unwrap_or(&reason);
                    format!("could not connect through Tor: {reason}")
                }
                None => "could not connect through Tor".to_owned(),
            });
        }
        return Fault::outage("could not connect");
    }
    if error.is_body() || error.is_decode() {
        return Fault::other("unexpected response");
    }
    if closed_early(error) {
        return Fault::outage("the connection was closed");
    }
    Fault::other("request failed")
}

/// Whether the server hung up before it answered, once connected: a
/// reset, or a connection that ended first, in the words of hyper.
fn closed_early(error: &reqwest::Error) -> bool {
    use std::io::ErrorKind;
    !error.is_connect()
        && !error.is_timeout()
        && find_cause(error, &mut |cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                )
            }) || cause
                .to_string()
                .starts_with("connection closed before message completed")
        })
        .is_some()
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

/// Fetches the complete state of a single watched address. `held` is
/// what the wallet holds of it, which spares reading again the pages it
/// already has: see [`history_round`].
pub(crate) async fn fetch_address_state(
    client: &Client,
    address: &str,
    network: Network,
    held: &[AddressTx],
) -> Result<AddressWatchState, Fault> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();
    check_network(client, network).await?;

    let tip_height = read_tip(client, network).await?;
    let stats = client.address_stats(&address).await?;

    let round = history_round(
        client,
        &address,
        &our_script,
        network,
        tip_height,
        None,
        Some(stats.chain_stats.tx_count as usize),
        held,
    )
    .await?;

    let utxos = coins(
        client,
        network,
        tip_height,
        &our_script,
        client.address_utxos(&address).await?,
        &round,
        held,
    )
    .await?;

    Ok(AddressWatchState {
        txs: round.txs,
        utxos,
        tip_height,
        truncated: round.cursor.is_some(),
        history_cursor: round.cursor,
    })
}

/// The coins of the address, as far as what was read vouches for each,
/// as over Electrum ([`crate::chain::electrum::address`]). A coin of a
/// transaction of the round must be an output of it that pays the
/// address that much, or the server is refused, and it is as confirmed as
/// that transaction. When older transactions remain past the round, a
/// coin of one of them, no higher than the round's oldest confirmation,
/// is confirmed where the server puts it, at the time the wallet has for
/// it, if the wallet holds its transaction there paying it, or if this
/// session proved it there on the same server
/// ([`crate::chain::proof::proven_coin`]). Otherwise its transaction is
/// read again, counted against what the sync may keep, found to pay it,
/// and its confirmation proven. Any other coin is taken as unconfirmed.
/// A coin listed twice counts once.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn coins(
    client: &Client,
    network: Network,
    tip: u32,
    ours: &bdk_wallet::bitcoin::ScriptBuf,
    utxos: Vec<api::Utxo>,
    round: &HistoryRound,
    held: &[AddressTx],
) -> Result<Vec<AddressUtxo>, Fault> {
    use crate::chain::proof::{ProvenCoin, pays, proven_coin, remember_coin};
    use bdk_wallet::chain::BlockId;
    use std::collections::{HashMap, HashSet};
    let in_round: HashMap<&str, &AddressTx> =
        round.txs.iter().map(|tx| (tx.txid.as_str(), tx)).collect();
    let held: HashMap<&str, &AddressTx> = held.iter().map(|tx| (tx.txid.as_str(), tx)).collect();
    let oldest = round.txs.iter().filter_map(|tx| tx.height).min();
    let mut seen = HashSet::new();
    let utxos: Vec<(String, api::Utxo)> = utxos
        .into_iter()
        .filter(|utxo| seen.insert((utxo.txid, utxo.vout)))
        .map(|utxo| (utxo.txid.to_string(), utxo))
        .collect();
    let proven_as = |utxo: &api::Utxo, height: u32| ProvenCoin {
        script: ours.clone(),
        value: utxo.value,
        height,
        time: None,
    };
    let outpoint = |utxo: &api::Utxo| OutPoint::new(utxo.txid, utxo.vout);

    // Where each coin past the round stands: vouched for, at the time
    // given, or its transaction to read again and prove.
    let mut vouched: HashMap<(Txid, u32), Option<u64>> = HashMap::new();
    let mut unread: Vec<(Txid, BlockId)> = Vec::new();
    let mut to_read: HashSet<(Txid, BlockId)> = HashSet::new();
    for (txid, utxo) in &utxos {
        let block = match (utxo.status.block_height, utxo.status.block_hash, oldest) {
            (Some(height), Some(hash), Some(oldest))
                if round.cursor.is_some()
                    && height <= oldest
                    && !in_round.contains_key(txid.as_str()) =>
            {
                BlockId { height, hash }
            }
            _ => continue,
        };
        let from_held = held
            .get(txid.as_str())
            .filter(|tx| tx.height == Some(block.height) && tx.pays(utxo.vout, utxo.value))
            .map(|tx| tx.timestamp);
        match from_held.or_else(|| {
            proven_coin(
                network,
                &client.base,
                outpoint(utxo),
                &proven_as(utxo, block.height),
            )
        }) {
            Some(time) => {
                vouched.insert((utxo.txid, utxo.vout), time);
            }
            None => {
                if to_read.insert((utxo.txid, block)) {
                    unread.push((utxo.txid, block));
                }
            }
        }
    }

    // Each transaction read again is counted, checked against every coin
    // listed of it, and dropped.
    let mut listed_of: HashMap<Txid, Vec<&api::Utxo>> = HashMap::new();
    for (_, utxo) in &utxos {
        listed_of.entry(utxo.txid).or_default().push(utxo);
    }
    let mut read: HashSet<Txid> = HashSet::new();
    for chunk in unread.chunks(PARALLEL_REQUESTS) {
        let txs = futures_util::future::try_join_all(chunk.iter().map(|(txid, _)| client.tx(txid)))
            .await?;
        for ((txid, _), tx) in chunk.iter().zip(txs) {
            let Some(tx) = tx else {
                continue;
            };
            if tx.compute_txid() != *txid {
                return Err(Fault::other(
                    "the server answered with another transaction than the one asked for"
                        .to_owned(),
                ));
            }
            client.keep(tx.total_size())?;
            let paid = listed_of
                .get(txid)
                .into_iter()
                .flatten()
                .all(|utxo| pays(&tx, utxo.vout, ours, utxo.value));
            if !paid {
                return Err(Fault::coin_not_paid());
            }
            read.insert(*txid);
        }
    }
    let unread: Vec<(Txid, BlockId)> = unread
        .into_iter()
        .filter(|(txid, _)| read.contains(txid))
        .collect();
    let times = sync::prove_confirmations(client, network, tip, &unread).await?;
    for ((txid, block), time) in unread.iter().zip(times) {
        let Some(time) = time else {
            continue;
        };
        for utxo in listed_of.get(txid).into_iter().flatten() {
            if utxo.status.block_height == Some(block.height) {
                vouched.insert((utxo.txid, utxo.vout), Some(time));
                let coin = ProvenCoin {
                    time: Some(time),
                    ..proven_as(utxo, block.height)
                };
                remember_coin(network, &client.base, outpoint(utxo), coin);
            }
        }
    }

    let mut coins = Vec::with_capacity(utxos.len());
    for (txid, utxo) in utxos {
        let (height, timestamp) = match in_round.get(txid.as_str()) {
            Some(tx) => {
                if !tx.pays(utxo.vout, utxo.value) {
                    return Err(Fault::coin_not_paid());
                }
                (tx.height, tx.timestamp)
            }
            None => match vouched.get(&(utxo.txid, utxo.vout)) {
                Some(time) => (utxo.status.block_height, *time),
                None => (None, None),
            },
        };
        coins.push(AddressUtxo {
            txid,
            vout: utxo.vout,
            value_sats: utxo.value,
            height,
            timestamp,
        });
    }
    Ok(coins)
}

/// Fetches the next round of older transactions, continuing after
/// `from`. Used by "load older transactions": the balance and the UTXO
/// set already cover the full history, only the list grows.
pub(crate) async fn fetch_address_history(
    client: &Client,
    address: &str,
    network: Network,
    from: &str,
) -> Result<HistoryRound, Fault> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();
    let from: Txid = from
        .parse()
        .map_err(|_| format!("invalid history cursor: {from}"))?;
    check_network(client, network).await?;
    let tip = read_tip(client, network).await?;
    history_round(
        client,
        &address,
        &our_script,
        network,
        tip,
        Some(from),
        None,
        &[],
    )
    .await
}

/// The server's tip, proven as a descriptor wallet's is: its latest
/// blocks chain, each with the work of its height, under any height a
/// chain of `network` can have reached ([`sync::proven_tip`]). It once
/// was the height alone, which made every confirmation as deep as a
/// server cared to say.
async fn read_tip(client: &Client, network: Network) -> Result<u32, Fault> {
    sync::proven_tip(client, network).await
}

/// Refuses a server whose genesis block is not the network's. Testnet,
/// testnet4 and signet spell an address alike, and a server of another
/// of them answers for it, with transactions the wallet's network never
/// saw. A descriptor wallet's sync finds that out walking the wallet's
/// chain down to the server's; a watched address keeps no chain, and
/// asks.
pub(crate) async fn check_network(client: &Client, network: Network) -> Result<(), Fault> {
    let text = client.get_bytes("/block-height/0").await?;
    let genesis: BlockHash = std::str::from_utf8(&text)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or_else(|| Fault::other("unexpected response"))?;
    if !crate::chain::is_genesis_of(network, genesis) {
        return Err(Fault::other(crate::chain::ANOTHER_NETWORK));
    }
    Ok(())
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
///
/// Every transaction read must hash to the txid listed, the ones the
/// wallet holds too: a proof is of a txid, and a server would otherwise
/// pass off any transaction of a block as one paying the address, or
/// rewrite what one the wallet holds pays. What the coins its inputs
/// spend were is the server's word still, as the fee is. A confirmation
/// read that the wallet does not hold at the same height is then proven
/// ([`sync::prove_confirmations`]); an unsure proof leaves it
/// unconfirmed. One it holds there keeps the time it holds.
///
/// A confirmation above `tip`, the tip the server gave before, is weighed
/// by [`crate::chain::proof::above_the_tip`].
///
/// A page that lists only transactions of `held`, what the wallet holds,
/// each at the height it holds it, ends the reading: the history below
/// it is what the wallet holds, and the round is filled from there. An
/// address paid a thousand times reads one page a sync, not forty. When
/// what the wallet holds below would come to more than the server counts,
/// the pages are read on.
#[allow(clippy::too_many_arguments)]
async fn history_round(
    client: &Client,
    address: &Address,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
    tip: u32,
    from: Option<Txid>,
    confirmed_total: Option<usize>,
    held: &[AddressTx],
) -> Result<HistoryRound, Fault> {
    let known: std::collections::HashMap<&str, Option<u32>> = held
        .iter()
        .map(|tx| (tx.txid.as_str(), tx.height))
        .collect();
    let held_times: std::collections::HashMap<(&str, Option<u32>), Option<u64>> = held
        .iter()
        .map(|tx| ((tx.txid.as_str(), tx.height), tx.timestamp))
        .collect();
    // Each page is read into what the app shows as soon as it arrives,
    // and dropped: forty pages are never held as the server spelled them.
    // What is kept of them, every input and output of each transaction,
    // counts against what one sync may keep.
    let mut txs: Vec<AddressTx> = Vec::new();
    let mut confirmed = 0usize;
    let mut last_seen: Option<Txid> = None;
    let mut claimed: Vec<(Txid, bdk_wallet::chain::BlockId)> = Vec::new();
    let mut read = |page: Vec<PageTx>, txs: &mut Vec<AddressTx>| {
        let mut all_held = true;
        for tx in page {
            if tx.status.confirmed {
                confirmed += 1;
                last_seen = Some(tx.txid);
            }
            let whole = tx.to_tx();
            if whole.compute_txid() != tx.txid {
                return Err(Fault::other(
                    "the server answered with another transaction than the one it listed",
                ));
            }
            if let (true, Some(height), Some(hash)) = (
                tx.status.confirmed,
                tx.status.block_height,
                tx.status.block_hash,
            ) && known.get(tx.txid.to_string().as_str()) != Some(&Some(height))
            {
                let block = bdk_wallet::chain::BlockId { height, hash };
                if !claimed.contains(&(tx.txid, block)) {
                    claimed.push((tx.txid, block));
                }
            }
            let tx = to_address_tx(tx, &whole, our_script, network);
            all_held &= known.get(tx.txid.as_str()) == Some(&tx.height);
            client.keep(crate::chain::held_by(&tx))?;
            txs.push(tx);
        }
        Ok::<_, Fault>((confirmed, last_seen, all_held))
    };
    let (mut confirmed_so_far, mut last, mut all_held) =
        read(client.address_txs(address, from).await?, &mut txs)?;
    // The transactions the server sent this round, ahead of those filled
    // from what the wallet holds.
    let mut sent = txs.len();
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
        if all_held
            && let Some(total) = confirmed_total
            && let Some(filled) = fill_from_held(client, &mut txs, held, confirmed_so_far, total)?
        {
            confirmed_so_far += filled;
            if confirmed_so_far < total {
                cursor = txs
                    .iter()
                    .rev()
                    .find(|tx| tx.height.is_some())
                    .map(|tx| tx.txid.clone());
            }
            break;
        }
        if pages >= HISTORY_PAGES_PER_ROUND {
            cursor = Some(last_seen.to_string());
            break;
        }
        let page = client.address_txs(address, Some(last_seen)).await?;
        pages += 1;
        if page.is_empty() {
            break;
        }
        (confirmed_so_far, last, all_held) = read(page, &mut txs)?;
        sent = txs.len();
    }
    check_spent(&txs[..sent], held)?;
    let times = sync::prove_confirmations(client, network, tip, &claimed).await?;
    let proven: std::collections::HashMap<(String, u32), Option<u64>> = claimed
        .iter()
        .zip(times)
        .map(|((txid, block), time)| ((txid.to_string(), block.height), time))
        .collect();
    for tx in &mut txs {
        let Some(height) = tx.height else {
            continue;
        };
        match proven.get(&(tx.txid.clone(), height)) {
            Some(Some(time)) => tx.timestamp = Some(*time),
            Some(None) => {
                tx.height = None;
                tx.timestamp = None;
            }
            None => {
                if let Some(time) = held_times.get(&(tx.txid.as_str(), Some(height))) {
                    tx.timestamp = *time;
                }
            }
        }
    }
    Ok(HistoryRound { txs, cursor })
}

/// Refuses a server that says a coin a transaction it sent this round
/// (`sent`) spends is other than what the transaction that pays it
/// pays, when that one is in the round or the wallet holds it
/// ([`crate::chain::proof::COIN_NOT_PAID`]): what it pays hashes to its
/// txid, the coin Esplora attaches to an input does not. A coin of the
/// address is one of them as long as the address has fewer transactions
/// than a round holds and the server lists the transaction that paid it
/// in the address's history: what a transaction spends of the address,
/// and so what it sends, is then the word of the transaction that paid
/// it, and the server cannot make it more, nor pass off a spend of the
/// address as one of someone else's. One that leaves that transaction
/// out, its counters lowered to match, still has its word taken for the
/// coin, which moves what the transaction shows sent and its fee, never
/// the balance, read from the coins ([`coins`]). A transaction the
/// wallet holds is held to what it pays and whether it pays the
/// address, the address spelled as a release before this one may have
/// spelled it being left aside. A coin whose transaction is past the
/// round, or someone else's paid by a transaction the address had no
/// part in, is the server's word still, and with it the fee and the
/// facts read of the input: proving it would cost reading that
/// transaction, a request for each payer's, and for a busy address
/// whose coins are old, a request for each coin it spends in the first
/// page, read at every sync.
fn check_spent(sent: &[AddressTx], held: &[AddressTx]) -> Result<(), Fault> {
    use std::collections::HashMap;
    let read: HashMap<&str, &AddressTx> = sent.iter().map(|tx| (tx.txid.as_str(), tx)).collect();
    let kept: HashMap<&str, &AddressTx> = held
        .iter()
        .filter(|tx| !tx.outputs.is_empty())
        .map(|tx| (tx.txid.as_str(), tx))
        .collect();
    for input in sent.iter().flat_map(|tx| &tx.inputs) {
        let (Some(txid), Some(vout), Some(_)) =
            (&input.prev_txid, input.prev_vout, input.value_sats)
        else {
            continue;
        };
        let (paying, fresh) = match (read.get(txid.as_str()), kept.get(txid.as_str())) {
            (Some(paying), _) => (paying, true),
            (None, Some(paying)) => (paying, false),
            (None, None) => continue,
        };
        let agrees = paying.outputs.get(vout as usize).is_some_and(|output| {
            output.value_sats == input.value_sats
                && output.is_mine == input.is_mine
                && (!fresh || output.address == input.address)
        });
        if !agrees {
            return Err(Fault::coin_not_paid());
        }
    }
    Ok(())
}

/// Fills a round read down to a page the wallet holds whole from the
/// confirmed transactions it holds below that page, as many as a round
/// takes. `None`, and nothing filled, when those and what was read
/// would come to more than the server counts: what the wallet holds
/// below is then not the server's history, and the pages are read on.
fn fill_from_held(
    client: &Client,
    txs: &mut Vec<AddressTx>,
    held: &[AddressTx],
    confirmed_so_far: usize,
    total: usize,
) -> Result<Option<usize>, Fault> {
    let Some(below) = txs.iter().rev().find_map(|tx| tx.height) else {
        return Ok(None);
    };
    let taken: std::collections::HashSet<&str> = txs.iter().map(|tx| tx.txid.as_str()).collect();
    let older: Vec<&AddressTx> = held
        .iter()
        .filter(|tx| tx.height.is_some_and(|height| height <= below))
        .filter(|tx| !taken.contains(tx.txid.as_str()))
        .collect();
    if confirmed_so_far + older.len() > total {
        return Ok(None);
    }
    let room = (HISTORY_PAGES_PER_ROUND * PAGE).saturating_sub(confirmed_so_far);
    let older: Vec<AddressTx> = older.into_iter().take(room).cloned().collect();
    for tx in &older {
        client.keep(crate::chain::held_by(tx))?;
    }
    let filled = older.len();
    txs.extend(older);
    Ok(Some(filled))
}

/// Confirmed transactions an Esplora server lists in a page of a
/// history, a script's or an address's.
const PAGE: usize = 25;

/// One esplora transaction as seen from the watched address. `whole` is
/// the transaction itself, as [`PageTx::to_tx`] builds it.
fn to_address_tx(
    tx: PageTx,
    whole: &Transaction,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
) -> AddressTx {
    // Amounts as the server tells them: summed without wrapping around,
    // as the Electrum path and the balance do.
    let received: u64 = tx
        .vout
        .iter()
        .filter(|v| v.scriptpubkey == *our_script)
        .map(|v| v.value)
        .fold(0, u64::saturating_add);
    let spent: u64 = tx
        .vin
        .iter()
        .filter_map(|v| v.prevout.as_ref())
        .filter(|p| p.scriptpubkey == *our_script)
        .map(|p| p.value)
        .fold(0, u64::saturating_add);
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
    // The fee, from the coins spent as the inputs list them, as over
    // Electrum: none for a coinbase, nor for an input without its coin.
    // The server's own figure for it would be one more claim, which
    // nothing checks against the coins.
    let is_coinbase = tx.vin.first().is_some_and(|vin| vin.is_coinbase);
    let paid_in = tx.vin.iter().try_fold(0u64, |sum, vin| {
        sum.checked_add(vin.prevout.as_ref()?.value)
    });
    let paid_out = tx
        .vout
        .iter()
        .try_fold(0u64, |sum, vout| sum.checked_add(vout.value));
    let fee = match (is_coinbase, paid_in, paid_out) {
        (false, Some(paid_in), Some(paid_out)) => paid_in.checked_sub(paid_out),
        _ => None,
    };
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
    let extras = tx_extras::analyze(whole, |op| prevouts.get(op).cloned());
    AddressTx {
        txid: tx.txid.to_string(),
        net_sats: crate::chain::net_sats(received, spent),
        fee_sats: fee,
        // Confirmed in a block it names, or not confirmed at all: a
        // height alone names no block to prove it in.
        height: tx
            .status
            .block_height
            .filter(|_| tx.status.confirmed && tx.status.block_hash.is_some()),
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
/// The instance's own node validates it; its refusal comes back as a
/// refusal in the node's words, which is the most useful thing to show.
///
/// Esplora wraps the node's refusal in a 400 whose body is the reason,
/// in one of two spellings:
/// `sendrawtransaction RPC error: {"code":-26,"message":"..."}` (the
/// mempool instances) or `sendrawtransaction RPC error -26: ...`
/// (blockstream.info): see [`crate::chain::node_verdict`]. Anything
/// else is a failure of the way there, and the next endpoint may take it.
pub(crate) async fn broadcast(client: &Client, tx: &Transaction) -> Result<Txid, Failure> {
    client.post_tx(tx).await
}

/// The output an input spends, whether it is already spent, and by
/// which transaction.
pub(crate) struct PrevoutFacts {
    pub txout: Option<TxOut>,
    pub spent: Option<bool>,
    pub spent_by: Option<crate::broadcast::SpentBy>,
}

/// Fetches a previous output. `None` in `txout` means the backend does
/// not know the transaction at all.
pub(crate) async fn fetch_prevout(
    client: &Client,
    outpoint: OutPoint,
) -> Result<PrevoutFacts, Failure> {
    // Nothing a lookup gets back is the node's verdict on a transaction:
    // whatever fails is the way there failing.
    let tx = client
        .tx(&outpoint.txid)
        .await
        .map_err(Failure::Transport)?;
    let Some(tx) = tx else {
        return Ok(PrevoutFacts {
            txout: None,
            spent: None,
            spent_by: None,
        });
    };
    let txout = crate::chain::output_at(&tx, outpoint).map_err(Failure::Transport)?;
    let status = client
        .output_status(&outpoint.txid, outpoint.vout)
        .await
        .ok()
        .flatten();
    let spent = status.as_ref().map(|status| status.spent);
    // Named only when the server says both who spends it and where that
    // stands: a spend whose standing is unknown is not taken for one
    // in a block.
    let spent_by =
        match status.and_then(|status| match (status.spent, status.txid, status.status) {
            (true, Some(txid), Some(standing)) => Some((txid, standing.confirmed)),
            _ => None,
        }) {
            // A spend in a block holds the broadcast back: the server shows
            // the transaction that makes it, and it has to spend this coin.
            // One in the mempool holds nothing back, and costs no request.
            Some((txid, confirmed)) => Some(crate::broadcast::SpentBy {
                txid,
                confirmed,
                verified: confirmed && shows_spend(client, txid, outpoint).await,
            }),
            None => None,
        };
    Ok(PrevoutFacts {
        txout,
        spent,
        spent_by,
    })
}

/// Whether the server hands over the transaction `txid`, as that txid
/// commits to it, with `outpoint` among its inputs. Anything else, a
/// server that cannot show it included, is no proof of the spend.
async fn shows_spend(client: &Client, txid: Txid, outpoint: OutPoint) -> bool {
    match client.tx(&txid).await {
        Ok(Some(tx)) => crate::chain::spends(&tx, txid, outpoint),
        _ => false,
    }
}

/// Where a transaction stands: unknown, in the mempool, or at a height.
pub(crate) struct TxStanding {
    pub found: bool,
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub tip_height: u32,
}

/// A confirmation counts once proven, as a sync's
/// ([`sync::prove_confirmations`]): one that cannot be leaves the
/// transaction waiting, and a false proof refuses the server.
pub(crate) async fn tx_standing(
    client: &Client,
    network: Network,
    txid: &Txid,
) -> Result<TxStanding, Fault> {
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
    let block = match (status.confirmed, status.block_height, status.block_hash) {
        (true, Some(height), Some(hash)) => Some(bdk_wallet::chain::BlockId { height, hash }),
        _ => None,
    };
    let proven = match block {
        Some(block) => sync::prove_confirmations(client, network, tip_height, &[(*txid, block)])
            .await?
            .first()
            .is_some_and(Option::is_some),
        None => false,
    };
    Ok(TxStanding {
        found: true,
        confirmed: proven,
        block_height: block.filter(|_| proven).map(|block| block.height),
        tip_height,
    })
}

#[cfg(test)]
mod error_tests {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// What a server answers a posted transaction with, in every form: a
    /// refusal only when a 400 carries the node's verdict in the words of
    /// electrs, Blockstream's or mempool.space's; anything else, another
    /// status, a proxy's page, a node warming up, a body that is no txid,
    /// is the way there failing, and the next endpoint may be asked.
    #[tokio::test]
    async fn only_the_nodes_verdict_refuses_a_posted_transaction() {
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let answer = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let refused = |words: &str| Err(Failure::Refused(words.to_owned()));
        let transport = |text: &str| Err::<Txid, _>(Failure::Transport(Fault::other(text)));
        let down = |text: &str| Err::<Txid, _>(Failure::Transport(Fault::outage(text)));
        let txid = tx.compute_txid().to_string();
        for (status, body, expected) in [
            ("200 OK", txid.as_str(), Ok(tx.compute_txid())),
            (
                "400 Bad Request",
                "sendrawtransaction RPC error -26: min relay fee not met, 0 < 11",
                refused("min relay fee not met, 0 < 11"),
            ),
            (
                "400 Bad Request",
                r#"sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met"}"#,
                refused("min relay fee not met"),
            ),
            (
                "400 Bad Request",
                r#"sendrawtransaction RPC error: {"code":-27,"message":"Transaction outputs already in utxo set"}"#,
                refused("Transaction outputs already in utxo set"),
            ),
            (
                "400 Bad Request",
                "sendrawtransaction RPC error -25: bad-txns-inputs-missingorspent",
                refused("bad-txns-inputs-missingorspent"),
            ),
            (
                "400 Bad Request",
                "sendrawtransaction RPC error -28: Loading block index...",
                transport("HTTP 400: bad request"),
            ),
            (
                "400 Bad Request",
                "Invalid hex string",
                transport("HTTP 400: bad request"),
            ),
            (
                "403 Forbidden",
                "<html><title>Attention Required! | Cloudflare</title></html>",
                transport("HTTP 403: access refused"),
            ),
            (
                "401 Unauthorized",
                "",
                transport("HTTP 401: access refused"),
            ),
            (
                "404 Not Found",
                "Not Found",
                transport("HTTP 404: not found"),
            ),
            (
                "413 Payload Too Large",
                "",
                transport("HTTP 413: unexpected status"),
            ),
            (
                "503 Service Unavailable",
                "busy",
                down("HTTP 503: server error"),
            ),
            ("429 Too Many Requests", "", down("HTTP 429: rate limited")),
            (
                "200 OK",
                "<html>maintenance</html>",
                transport("the server answered <html>maintenance</html> instead of a txid"),
            ),
        ] {
            let (address, _) = answering(vec![answer(status, body)]).await;
            let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
            assert_eq!(broadcast(&client, &tx).await, expected, "{status} {body}");
        }
    }

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

    /// An Esplora sync goes straight to the server, or through the Tor
    /// proxy for an onion, and never through a proxy the environment
    /// names.
    #[test]
    fn a_sync_takes_no_proxy_but_tor() {
        let clear = client("https://esplora.example.org/api", None).unwrap();
        assert!(!crate::chain::takes_a_proxy(&clear.http));
        let onion = client(
            "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api",
            Some("127.0.0.1:9050"),
        )
        .unwrap();
        assert!(crate::chain::takes_a_proxy(&onion.http));
    }

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
        assert!(error.is_outage());
    }

    /// A server that hangs up before it answers, having read the request
    /// or not, is asked again once, on another connection: the second
    /// time, the connection was closed, and that is an outage.
    #[tokio::test]
    async fn a_server_that_hangs_up_closed_the_connection() {
        for read_first in [true, false] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = accepted.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if read_first {
                        let mut request = [0u8; 1024];
                        let _ = stream.read(&mut request).await;
                    }
                }
            });
            let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
            let error = client.height().await.unwrap_err();
            assert_eq!(
                error, "the connection was closed",
                "read first: {read_first}"
            );
            assert!(error.is_outage());
            assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }

    /// A connection the server closes as a request goes out, the race of
    /// a connection kept open for the next request, costs nothing: the
    /// request is asked again on another one.
    #[tokio::test]
    async fn a_connection_closed_under_a_request_is_asked_again() {
        let (address, asked) = answering(vec![
            String::new(),
            "HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\n812345".to_owned(),
        ])
        .await;
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        assert_eq!(client.height().await.unwrap(), 812_345);
        assert_eq!(*asked.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_closed_port_is_a_failure_to_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(error, "could not connect");
        assert!(error.is_outage());
    }

    #[tokio::test]
    async fn an_unknown_host_is_said_to_be_one() {
        // `.invalid` is reserved never to resolve, whatever the resolver.
        let client = build("http://esplora.invalid", None, PATIENT).unwrap();
        let error = client.height().await.unwrap_err();
        assert_eq!(error, "host not found");
        assert!(error.is_outage());
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
        assert!(described.is_outage());
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
        // The route, not the server: it relegates nothing.
        assert!(!error.is_outage());
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
        let txid: Txid = "01".repeat(32).parse().unwrap();
        assert_eq!(client.tx(&txid).await.unwrap_err(), cut);
        // JSON is parsed as it arrives: refused at its first bytes.
        let script = ScriptBuf::from_bytes(vec![0x51]);
        assert!(client.scripthash_stats(&script).await.is_err());
        let address = parse_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Network::Signet,
        )
        .unwrap();
        assert!(client.address_utxos(&address).await.is_err());
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
            Failure::Transport(Fault::other("the server sent an answer longer than 64 KiB"))
        );
    }

    /// A server that answers each request with the next of `answers`,
    /// whole HTTP answers, and the last one past them; and how many
    /// requests it had.
    async fn answering(
        answers: Vec<String>,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::Mutex<usize>>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let asked = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let counted = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = vec![0u8; 4096];
                let _ = stream.read(&mut request).await;
                let answer = {
                    let mut asked = counted.lock().unwrap();
                    *asked += 1;
                    answers[(*asked - 1).min(answers.len() - 1)].clone()
                };
                let _ = stream.write_all(answer.as_bytes()).await;
            }
        });
        (address, asked)
    }

    /// A server that limits the rate of requests is asked again once,
    /// after the wait it named, five seconds at least, and never at once;
    /// past a minute, the request fails at once and says how long the
    /// server asked for. Whoever asks at a pace learns of it either way.
    #[tokio::test]
    async fn a_rate_limit_is_waited_out_once() {
        let limited = |named: &str| {
            format!(
                "HTTP/1.1 429 Too Many Requests\r\n{named}content-length: 0\r\n\
                 connection: close\r\n\r\n"
            )
        };
        let height = "HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\n812345";

        let (long, asked) = answering(vec![limited("retry-after: 120\r\n")]).await;
        let client = build(&format!("http://{long}"), None, PATIENT).unwrap();
        assert_eq!(
            client.height().await.unwrap_err(),
            "HTTP 429: rate limited, try again in 120 s"
        );
        assert_eq!(*asked.lock().unwrap(), 1);
        assert_eq!(client.take_rate_limit(), Some(Duration::from_secs(120)));
        assert_eq!(client.take_rate_limit(), None);

        let (short, asked_short) =
            answering(vec![limited("retry-after: 1\r\n"), height.to_owned()]).await;
        let (again, asked_again) = answering(vec![limited("")]).await;
        let short = build(&format!("http://{short}"), None, PATIENT).unwrap();
        let again = build(&format!("http://{again}"), None, PATIENT).unwrap();
        let started = std::time::Instant::now();
        let (read, refused) = tokio::join!(short.height(), again.height());
        assert!(started.elapsed() >= RATE_WAIT_MIN);
        assert_eq!(read.unwrap(), 812_345);
        assert_eq!(
            refused.unwrap_err(),
            "HTTP 429: rate limited, try again in 5 s"
        );
        assert_eq!(*asked_short.lock().unwrap(), 2);
        assert_eq!(*asked_again.lock().unwrap(), 2);
        assert_eq!(short.take_rate_limit(), Some(RATE_WAIT_MIN));
    }

    /// A server error or a limited rate is an outage, told by its status;
    /// a request the server finds bad is not.
    #[test]
    fn server_errors_and_limited_rates_are_outages() {
        assert!(describe_status(500).is_outage());
        assert!(describe_status(503).is_outage());
        assert!(rate_limited(RATE_WAIT_MIN).is_outage());
        assert!(!describe_status(400).is_outage());
        assert!(!describe_status(404).is_outage());
    }

    /// `Retry-After` names a wait in seconds, or the date to come back at.
    #[test]
    fn a_retry_after_date_is_a_wait_until_then() {
        let named = |value: &str| {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::RETRY_AFTER, value.parse().unwrap());
            retry_after(&headers)
        };
        assert_eq!(named("17"), Some(Duration::from_secs(17)));
        assert_eq!(
            http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        let in_two_minutes = crate::now_secs() + 120;
        let (year, month, day) = crate::format::civil_date(in_two_minutes);
        let time = in_two_minutes % 86_400;
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let date = format!(
            "Mon, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
            months[month as usize - 1],
            time / 3_600,
            time % 3_600 / 60,
            time % 60
        );
        let wait = named(&date).unwrap();
        assert!(
            (Duration::from_secs(115)..=Duration::from_secs(120)).contains(&wait),
            "{date}: {wait:?}"
        );
        assert_eq!(named("Sun, 06 Nov 1994 08:49:37 GMT"), None, "past");
        assert_eq!(named("Sunday, 06-Nov-94 08:49:37 GMT"), None, "obsolete");
        assert_eq!(named("soon"), None);
        assert_eq!(
            http_date("Sun, 06 Nov 99999999999999999 08:49:37 GMT"),
            None
        );
    }

    /// What a sync of an address keeps of each transaction, its raw
    /// bytes and every input and output, counts against what one sync
    /// may keep: a server that lists enough of them fails the sync
    /// instead of filling memory.
    #[tokio::test]
    async fn an_address_keeps_so_much_and_no_more() {
        use crate::testkit::{ADDRESS, FakeMempool, esplora_payment};
        let server = FakeMempool::start(false, 0).await;
        server.state.lock().unwrap().address_txs = (1..=3u8)
            .map(|n| esplora_payment(n, n + 10, 50_000, true))
            .collect();
        let base = format!("http://{}/api", server.address);
        let client = client_for_run(&base, None).unwrap();
        let state = fetch_address_state(&client, ADDRESS, Network::Signet, &[])
            .await
            .unwrap();
        assert_eq!(state.txs.len(), 3);
        let one = crate::chain::held_by(&state.txs[0]);
        assert!(one > state.txs[0].extras.as_ref().unwrap().raw_hex.len());
        let mut tight = client_for_run(&base, None).unwrap();
        tight.kept = crate::chain::Kept::up_to(one * 5 / 2);
        let refused = fetch_address_state(&tight, ADDRESS, Network::Signet, &[])
            .await
            .unwrap_err();
        assert!(
            refused.starts_with("the server sent more than"),
            "{refused}"
        );
    }

    /// A page that lists only what the wallet holds, as it holds it, ends
    /// the reading of an address: the rest of the round comes from what
    /// it holds, and the state is the one a whole reading gives. A first
    /// page with news on it is read, and the page under it.
    #[tokio::test]
    async fn an_address_reads_no_page_past_one_it_holds() {
        use crate::testkit::{ADDRESS, FakeMempool, esplora_payment};
        let server = FakeMempool::start(false, 0).await;
        server.state.lock().unwrap().address_txs = (1..=60u8)
            .map(|n| esplora_payment(n, n + 100, 1_000, true))
            .collect();
        let base = format!("http://{}/api", server.address);
        let fetch = |held: Vec<AddressTx>| {
            let base = base.clone();
            async move {
                let client = client_for_run(&base, None).unwrap();
                fetch_address_state(&client, ADDRESS, Network::Signet, &held)
                    .await
                    .unwrap()
            }
        };
        let pages = || server.state.lock().unwrap().history_pages;

        let whole = fetch(Vec::new()).await;
        assert_eq!((whole.txs.len(), pages()), (60, 3));
        let again = fetch(whole.txs.clone()).await;
        assert_eq!(again, whole);
        assert_eq!(pages(), 4, "one page");

        server
            .state
            .lock()
            .unwrap()
            .address_txs
            .insert(0, esplora_payment(61, 161, 2_000, false));
        let arrived = fetch(again.txs.clone()).await;
        assert_eq!(pages(), 6, "the first page and the one under it");
        assert_eq!(arrived, fetch(Vec::new()).await);
        assert_eq!(arrived.txs.len(), 61);
        assert_eq!(arrived.txs[0].height, None);
    }

    /// A server that redirects is not followed: an Esplora instance
    /// anywhere, and a fixed service elsewhere than its own host over
    /// HTTPS. The redirection fails the request, and nothing reaches the
    /// address it named.
    #[tokio::test]
    async fn a_redirection_is_not_followed() {
        let (elsewhere, reached) = answering(vec![
            "HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\n812345".to_owned(),
        ])
        .await;
        let (redirecting, _) = answering(vec![format!(
            "HTTP/1.1 301 Moved Permanently\r\nlocation: http://{elsewhere}/blocks/tip/height\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        )])
        .await;
        let client = build(&format!("http://{redirecting}"), None, PATIENT).unwrap();
        assert_eq!(
            client.height().await.unwrap_err(),
            "HTTP 301: unexpected status"
        );
        let service = reqwest::Client::builder()
            .redirect(crate::chain::redirects())
            .build()
            .unwrap();
        let answer = service
            .get(format!("http://{redirecting}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(answer.status().as_u16(), 301);
        assert_eq!(*reached.lock().unwrap(), 0);
    }

    /// Amounts a server makes up, past what any coin holds, stop where
    /// a number does: nothing panics in a build that checks, and nothing
    /// wraps around to a payment out in one that does not.
    #[test]
    fn amounts_a_server_makes_up_do_not_wrap_around() {
        use crate::testkit::ADDRESS_SCRIPT;
        let listed = format!(
            r#"{{"txid": "{txid}", "version": 2, "locktime": 0, "weight": 400, "fee": 0,
                "vin": [{{"txid": "{txid}", "vout": 0, "is_coinbase": false, "sequence": 0, "scriptsig": "",
                    "prevout": {{"scriptpubkey": "0014aa", "value": 1}}}}],
                "vout": [{{"scriptpubkey": "{ours}", "value": {max}}},
                    {{"scriptpubkey": "{ours}", "value": {max}}}],
                "status": {{"confirmed": false}}}}"#,
            txid = "01".repeat(32),
            ours = ADDRESS_SCRIPT,
            max = u64::MAX,
        );
        let page: PageTx = serde_json::from_str(&listed).unwrap();
        let ours = ScriptBuf::from_hex(ADDRESS_SCRIPT).unwrap();
        let whole = page.to_tx();
        let read = to_address_tx(page, &whole, &ours, Network::Signet);
        assert_eq!(read.net_sats, i64::MAX);
        assert_eq!(crate::chain::net_sats(0, u64::MAX), -i64::MAX);
    }

    /// A gzipped answer of a sensible size reads as it always did.
    #[tokio::test]
    async fn a_gzipped_answer_is_read() {
        let address = gzipping("200 OK", b"812345\n".to_vec()).await;
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        assert_eq!(client.height().await.unwrap(), 812_345);
    }

    /// A JSON answer is parsed as it arrives, and one that never ends,
    /// valid all along, is cut off past its cap.
    #[tokio::test]
    async fn an_answer_that_never_ends_is_cut_off() {
        let mut endless = b"[".to_vec();
        endless.resize(JSON_MAX + (1 << 20), b' ');
        let address = gzipping("200 OK", endless).await;
        let client = client_for_run(&format!("http://{address}"), None).unwrap();
        assert_eq!(
            client.get_page("/scripthash/00/txs").await.unwrap_err(),
            "the server sent an answer longer than 64 MiB"
        );
    }

    /// What one sync keeps of the transactions it reads is counted, and
    /// past its cap the sync fails; a client that serves a watch keeps
    /// none and has no such cap.
    #[test]
    fn a_sync_keeps_so_much_and_no_more() {
        let one_sync = client_for_run("http://127.0.0.1:9", None).unwrap();
        one_sync.keep(crate::chain::KEEP_MAX - 1).unwrap();
        assert_eq!(
            one_sync.keep(2).unwrap_err(),
            "the server sent more than 256 MiB of transactions for one sync"
        );
        let watching = client("http://127.0.0.1:9", None).unwrap();
        watching.keep(crate::chain::KEEP_MAX).unwrap();
        watching.keep(crate::chain::KEEP_MAX).unwrap();
    }

    /// A history page listing an inscription of the largest kind: a
    /// witness item of 4 MB, spelled twice in the answer, as hex and as
    /// assembly, some 16 MB of JSON. It is read, and what the page keeps
    /// of it is the witness, once, in bytes.
    #[tokio::test]
    async fn a_page_with_the_largest_inscription_is_read() {
        let item = "ab".repeat(4_000_000);
        let entry = format!(
            r#"[{{"txid": "{txid}", "version": 2, "locktime": 0, "size": 4000200, "weight": 4000800, "fee": 1000,
                "vin": [{{"txid": "{txid}", "vout": 0,
                    "prevout": {{"scriptpubkey": "5120aa", "scriptpubkey_type": "v1_p2tr", "value": 10000}},
                    "scriptsig": "", "scriptsig_asm": "",
                    "witness": ["{item}"], "inner_witnessscript_asm": "OP_PUSHBYTES {item}",
                    "is_coinbase": false, "sequence": 4294967293}}],
                "vout": [{{"scriptpubkey": "5120bb", "scriptpubkey_type": "v1_p2tr", "value": 546}}],
                "status": {{"confirmed": false}}}}]"#,
            txid = "01".repeat(32),
        );
        assert!(entry.len() > 16_000_000);
        let address = gzipping("200 OK", entry.into_bytes()).await;
        let client = client_for_run(&format!("http://{address}"), None).unwrap();
        let page = client.get_page("/scripthash/00/txs").await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].vin[0].witness.nth(0).unwrap().len(), 4_000_000);
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
