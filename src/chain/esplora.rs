//! Esplora backend: descriptor wallet sync and single-address tracking.

use std::ops::Deref;
use std::time::Duration;

use bdk_esplora::EsploraAsyncExt;
use bdk_esplora::esplora_client::{self, AsyncClient};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

use bdk_wallet::bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};

use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState, tx_extras};

/// Concurrent requests during scans.
const PARALLEL_REQUESTS: usize = 4;
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

/// A client for one instance, with its budgets kept beside it. It
/// dereferences to the underlying client for every request, and turns
/// the errors those return into sentences.
#[derive(Debug)]
pub(crate) struct Client {
    inner: AsyncClient,
    budget: Budget,
}

impl Deref for Client {
    type Target = AsyncClient;

    fn deref(&self) -> &AsyncClient {
        &self.inner
    }
}

impl Client {
    /// The error as a sentence the sync report can show.
    pub(crate) fn describe(&self, error: &esplora_client::Error) -> String {
        describe(error, self.budget)
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
        inner: AsyncClient::from_client(url.to_owned(), http),
        budget,
    })
}

pub(crate) async fn full_scan(
    client: &Client,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
) -> Result<FullScanResponse<KeychainKind>, String> {
    client
        .inner
        .full_scan(request, stop_gap as usize, PARALLEL_REQUESTS)
        .await
        .map_err(|e| client.describe(&e))
}

pub(crate) async fn sync(
    client: &Client,
    request: SyncRequest<(KeychainKind, u32)>,
) -> Result<SyncResponse, String> {
    client
        .inner
        .sync(request, PARALLEL_REQUESTS)
        .await
        .map_err(|e| client.describe(&e))
}

// --- errors ---------------------------------------------------------------

/// The error as a sentence a person can act on. The crate's own
/// `Display` is its `Debug`: `Reqwest(reqwest::Error { kind: Request,
/// source: TimedOut })` is what reached the sync report until now.
fn describe(error: &esplora_client::Error, budget: Budget) -> String {
    use esplora_client::Error;
    match error {
        Error::Reqwest(error) => describe_request(error, budget),
        Error::HttpResponse { status, message: _ } => describe_status(*status),
        Error::TransactionNotFound(_) => "transaction not found".to_owned(),
        Error::HeaderHeightNotFound(_) | Error::HeaderHashNotFound(_) => {
            "block not found".to_owned()
        }
        Error::InvalidHttpHeaderName(_) | Error::InvalidHttpHeaderValue(_) => {
            "invalid request header".to_owned()
        }
        // A number, a status code, hex or consensus bytes that do not
        // parse, a body that is not what the endpoint promised: the
        // server answered, with something else.
        _ => "unexpected response".to_owned(),
    }
}

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

    let tip_height = client.get_height().await.map_err(|e| client.describe(&e))?;
    let stats = client
        .get_address_stats(&address)
        .await
        .map_err(|e| client.describe(&e))?;

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
        .get_address_utxos(&address)
        .await
        .map_err(|e| client.describe(&e))?
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

fn parse_address(address: &str, network: Network) -> Result<Address, String> {
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
    let mut raw_txs = client
        .get_address_txs(address, from)
        .await
        .map_err(|e| client.describe(&e))?;
    let mut cursor: Option<String> = None;
    let mut pages = 1usize;
    loop {
        // The whole history is in hand: `confirmed_total` counts it from
        // the address stats, so no probing request is needed.
        if let Some(total) = confirmed_total
            && raw_txs.iter().filter(|t| t.status.confirmed).count() >= total
        {
            break;
        }
        let Some(last_seen) = raw_txs
            .iter()
            .rev()
            .find(|t| t.status.confirmed)
            .map(|t| t.txid)
        else {
            break;
        };
        if pages >= HISTORY_PAGES_PER_ROUND {
            cursor = Some(last_seen.to_string());
            break;
        }
        let page = client
            .get_address_txs(address, Some(last_seen))
            .await
            .map_err(|e| client.describe(&e))?;
        pages += 1;
        if page.is_empty() {
            break;
        }
        raw_txs.extend(page);
    }

    let txs = raw_txs
        .into_iter()
        .map(|tx| to_address_tx(tx, our_script, network))
        .collect();
    Ok(HistoryRound { txs, cursor })
}

/// One esplora transaction as seen from the watched address.
fn to_address_tx(
    tx: esplora_client::api::Tx,
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

fn script_address(script: &bdk_wallet::bitcoin::ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network.to_bitcoin())
        .ok()
        .map(|a| a.to_string())
}

// --- broadcast ------------------------------------------------------------

/// Hands a signed transaction to the network through this instance.
/// The instance's own node validates it; its refusal comes back as the
/// message, verbatim, which is the most useful thing to show.
pub(crate) async fn broadcast(client: &Client, tx: &Transaction) -> Result<(), String> {
    client
        .inner
        .broadcast(tx)
        .await
        .map_err(|e| broadcast_error(client, &e))
}

/// Esplora wraps the node's refusal in an HTTP error whose body is the
/// reason, in one of two spellings:
/// `sendrawtransaction RPC error: {"code":-26,"message":"..."}` (the
/// mempool instances) or `sendrawtransaction RPC error -26: ...`
/// (blockstream.info). Keep the message, drop the wrapping. Anything
/// else is a failure to reach the node, described as such.
fn broadcast_error(client: &Client, error: &esplora_client::Error) -> String {
    match error {
        esplora_client::Error::HttpResponse { message, .. } => node_message(message),
        other => client.describe(other),
    }
}

/// The reason inside a `sendrawtransaction` refusal, whichever way the
/// server spelled it; the whole text when it is not one.
pub(crate) fn node_message(text: &str) -> String {
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
    let tx = client
        .get_tx(&outpoint.txid)
        .await
        .map_err(|e| client.describe(&e))?;
    let Some(tx) = tx else {
        return Ok(PrevoutFacts {
            txout: None,
            spent: None,
        });
    };
    let txout = tx.output.get(outpoint.vout as usize).cloned();
    let spent = client
        .get_output_status(&outpoint.txid, outpoint.vout as u64)
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
    let tip_height = client.get_height().await.map_err(|e| client.describe(&e))?;
    let found = client
        .get_tx_info(txid)
        .await
        .map_err(|e| client.describe(&e))?
        .is_some();
    if !found {
        return Ok(TxStanding {
            found: false,
            confirmed: false,
            block_height: None,
            tip_height,
        });
    }
    let status = client
        .get_tx_status(txid)
        .await
        .map_err(|e| client.describe(&e))?;
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

    use bdk_wallet::bitcoin::hashes::Hash;
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
        let status = |status| {
            describe(
                &esplora_client::Error::HttpResponse {
                    status,
                    message: "<html><body>a page nobody should see</body></html>".to_owned(),
                },
                BUDGET,
            )
        };
        assert_eq!(status(429), "HTTP 429: rate limited");
        assert_eq!(status(503), "HTTP 503: server error");
        assert_eq!(status(500), "HTTP 500: server error");
        assert_eq!(status(404), "HTTP 404: not found");
        assert_eq!(status(400), "HTTP 400: bad request");
        assert_eq!(status(403), "HTTP 403: access refused");
        assert_eq!(status(418), "HTTP 418: unexpected status");
    }

    #[test]
    fn the_other_variants_read_as_sentences() {
        use esplora_client::Error;
        assert_eq!(
            describe(&Error::TransactionNotFound(Txid::all_zeros()), BUDGET),
            "transaction not found"
        );
        assert_eq!(
            describe(&Error::HeaderHeightNotFound(7), BUDGET),
            "block not found"
        );
        assert_eq!(
            describe(&Error::InvalidResponse, BUDGET),
            "unexpected response"
        );
        assert_eq!(
            describe(&Error::Parsing("x".parse::<u32>().unwrap_err()), BUDGET),
            "unexpected response"
        );
        // And none of them is the debug form the crate displays.
        assert!(!describe(&Error::InvalidResponse, BUDGET).contains("InvalidResponse"));
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
        let error = client.get_height().await.unwrap_err();
        assert!(
            matches!(error, esplora_client::Error::Reqwest(_)),
            "{error:?}"
        );
        assert_eq!(client.describe(&error), "timed out after 1 s");
    }

    #[tokio::test]
    async fn a_closed_port_is_a_failure_to_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = build(&format!("http://{address}"), None, PATIENT).unwrap();
        let error = client.get_height().await.unwrap_err();
        assert_eq!(client.describe(&error), "could not connect");
    }

    #[tokio::test]
    async fn an_unknown_host_is_said_to_be_one() {
        // `.invalid` is reserved never to resolve, whatever the resolver.
        let client = build("http://esplora.invalid", None, PATIENT).unwrap();
        let error = client.get_height().await.unwrap_err();
        assert_eq!(client.describe(&error), "host not found");
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
        let error = client.get_height().await.unwrap_err();
        let described = client.describe(&error);
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
        let error = client.get_height().await.unwrap_err();
        assert_eq!(
            client.describe(&error),
            "could not connect through Tor: server does not support user/pass authentication"
        );
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
    }
}
