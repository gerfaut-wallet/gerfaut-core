//! Electrum backend: descriptor wallet sync over the user's own server.
//!
//! The Electrum client is blocking; callers run these functions inside
//! `spawn_blocking`.
//!
//! TLS connections are opened by [`crate::chain::tls`] rather than by
//! `electrum-client`, so the certificate a self-hosted server presents
//! goes through Gerfaut's own verifier: a public authority, or the
//! fingerprint the user accepted for that host.

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::raw_client::{ElectrumSslStream, RawClient};
use bdk_electrum::electrum_client::{self, Client, Config, ElectrumApi, Param, Socks5Config};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

use super::tls::{self, ConnectError, Verdict};

/// Requests per Electrum batch call.
const BATCH_SIZE: usize = 10;
/// Socket timeout. Without it a stalled server blocks the sync forever
/// inside `spawn_blocking`, with no way to cancel.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Onion endpoints get more room: Tor circuits are slow to build.
const TOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Name Gerfaut announces in `server.version`.
const CLIENT_NAME: &str = "gerfaut";
/// Protocol version asked for, as an exact range. `electrum-client`
/// reads block headers in the 1.4 shape unless it negotiated the version
/// itself, which it cannot do on a stream Gerfaut opened: pinning both
/// sides to 1.4 keeps the wire and the parser in agreement.
const PROTOCOL: &str = "1.4";

/// Default ports of the Electrum protocol.
const SSL_PORT: u16 = 50002;
const TCP_PORT: u16 = 50001;

/// One Electrum server, with the certificate fingerprint the user
/// accepted for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub url: String,
    pub pin: Option<String>,
}

impl Target {
    pub(crate) fn new(url: impl Into<String>, pin: Option<String>) -> Self {
        Target {
            url: url.into(),
            pin,
        }
    }
}

/// What a settings screen needs to know about a server's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Inspection {
    /// Plain TCP: there is no certificate, and anything on the path
    /// reads the traffic.
    NotTls,
    /// A Tor hidden service: the onion address is the server's identity.
    Tor,
    /// A TLS server, and what its certificate amounts to.
    Tls(Verdict),
}

/// Splits `ssl://host:port` into its parts. A bare `host:port` is TLS,
/// the way every Electrum client has always read it.
fn parse(url: &str) -> Result<(bool, String, u16), String> {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("ssl".to_owned(), url),
    };
    let tls = match scheme.as_str() {
        "ssl" | "tls" => true,
        "tcp" => false,
        other => return Err(format!("{other}:// is not an Electrum address")),
    };
    let rest = rest.split(['/', '?']).next().unwrap_or_default();
    let default_port = if tls { SSL_PORT } else { TCP_PORT };
    let port_of = |port: &str| {
        port.parse::<u16>()
            .map_err(|_| format!("{port} is not a port number"))
    };
    // An IPv6 literal is bracketed precisely so its own colons are not
    // read as a port separator.
    let (host, port) = match rest.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| "the address opens a bracket it never closes".to_owned())?;
            match tail.strip_prefix(':') {
                Some(port) => (host, port_of(port)?),
                None => (host, default_port),
            }
        }
        None => match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port_of(port)?),
            _ => (rest, default_port),
        },
    };
    if host.is_empty() {
        return Err("the address has no host".to_owned());
    }
    Ok((tls, host.to_owned(), port))
}

/// The key a trusted fingerprint is stored under: the host and port
/// that identify the socket, scheme and path stripped.
pub fn certificate_key(url: &str) -> String {
    match parse(url) {
        Ok((_, host, port)) => format!("{host}:{port}"),
        Err(_) => url.to_owned(),
    }
}

/// A connected client, whichever transport carries it.
enum Transport {
    /// TLS opened by Gerfaut: the certificate check is ours.
    Pinned(RawClient<ElectrumSslStream>),
    /// Plain TCP or a Tor circuit, driven by the crate's own client.
    Crate(Client),
}

/// Opens the connection. `proxy` is the Tor SOCKS proxy the caller
/// resolved for onion servers; an onion address without one is refused
/// before anything could look the name up.
fn connect(target: &Target, proxy: Option<&str>) -> Result<Transport, ConnectError> {
    let (tls_wanted, host, port) = parse(&target.url).map_err(ConnectError::Io)?;

    // Tor: the .onion address is the server's public key, and the
    // circuit proves the endpoint holds it. A certificate on top adds
    // encryption inside an encrypted tunnel and authenticates nothing,
    // so it is not what is trusted here — the address is.
    if crate::chain::is_onion(&target.url) {
        let proxy =
            proxy.ok_or_else(|| ConnectError::Io(crate::chain::tor::no_route(&target.url)))?;
        let config = Config::builder()
            .socks5(Some(Socks5Config::new(proxy)))
            .timeout(Some(TOR_TIMEOUT))
            .validate_domain(false)
            .build();
        return Client::from_config(&target.url, config)
            .map(Transport::Crate)
            .map_err(|e| ConnectError::Io(e.to_string()));
    }

    if !tls_wanted {
        let config = Config::builder().timeout(Some(TIMEOUT)).build();
        return Client::from_config(&target.url, config)
            .map(Transport::Crate)
            .map_err(|e| ConnectError::Io(e.to_string()));
    }

    let stream = tls::connect(&host, port, target.pin.as_deref(), TIMEOUT)?;
    let raw = RawClient::from(stream);
    negotiate(&raw)?;
    Ok(Transport::Pinned(raw))
}

/// `server.version` is the first call an Electrum server expects, and
/// the one that fixes the protocol version. The crate does this itself
/// on the connections it opens; on ours, we do it.
fn negotiate(raw: &RawClient<ElectrumSslStream>) -> Result<(), ConnectError> {
    raw.raw_call(
        "server.version",
        vec![
            Param::String(CLIENT_NAME.to_owned()),
            Param::StringVec(vec![PROTOCOL.to_owned(), PROTOCOL.to_owned()]),
        ],
    )
    .map(|_| ())
    .map_err(|e| ConnectError::Io(e.to_string()))
}

/// Runs one operation against a connected client, whichever transport
/// carries it: the same code over two concrete types.
macro_rules! on_client {
    ($target:expr, $proxy:expr, |$client:ident| $body:expr) => {
        match connect($target, $proxy).map_err(|e| e.to_string())? {
            Transport::Pinned(raw) => {
                let $client = BdkElectrumClient::new(raw);
                $body
            }
            Transport::Crate(inner) => {
                let $client = BdkElectrumClient::new(inner);
                $body
            }
        }
    };
}

/// What the settings screen shows about this server's certificate.
pub(crate) fn inspect_blocking(target: &Target) -> Result<Inspection, String> {
    let (tls_wanted, host, port) = parse(&target.url)?;
    if crate::chain::is_onion(&target.url) {
        return Ok(Inspection::Tor);
    }
    if !tls_wanted {
        return Ok(Inspection::NotTls);
    }
    tls::inspect(&host, port, target.pin.as_deref(), TIMEOUT)
        .map(Inspection::Tls)
        .map_err(|e| e.to_string())
}

pub(crate) fn full_scan_blocking(
    target: &Target,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
    proxy: Option<&str>,
) -> Result<FullScanResponse<KeychainKind>, String> {
    on_client!(target, proxy, |client| client
        .full_scan(request, stop_gap as usize, BATCH_SIZE, true)
        .map_err(|e| e.to_string()))
}

pub(crate) fn sync_blocking(
    target: &Target,
    request: SyncRequest<(KeychainKind, u32)>,
    proxy: Option<&str>,
) -> Result<SyncResponse, String> {
    on_client!(target, proxy, |client| client
        .sync(request, BATCH_SIZE, true)
        .map_err(|e| e.to_string()))
}

// --- broadcast ------------------------------------------------------------

pub(crate) fn broadcast_blocking(
    target: &Target,
    tx: &Transaction,
    proxy: Option<&str>,
) -> Result<Txid, String> {
    on_client!(target, proxy, |client| client
        .inner
        .transaction_broadcast(tx)
        .map_err(|e| broadcast_error(&e)))
}

/// Electrum returns the node's refusal as a protocol error whose
/// message is the reason; keep that.
fn broadcast_error(error: &electrum_client::Error) -> String {
    match error {
        electrum_client::Error::Protocol(value) => {
            let text = value
                .get("message")
                .and_then(|m| m.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            crate::chain::esplora::node_message(&text)
        }
        other => other.to_string(),
    }
}

/// The output an input spends. Electrum has no "is it spent" call
/// without the script's whole history, which is more than a preview
/// needs: spent-ness stays unknown here and the node says so on
/// broadcast.
pub(crate) fn fetch_prevout_blocking(
    target: &Target,
    outpoint: OutPoint,
    proxy: Option<&str>,
) -> Result<Option<TxOut>, String> {
    on_client!(
        target,
        proxy,
        |client| match client.inner.transaction_get(&outpoint.txid) {
            Ok(tx) => Ok(tx.output.get(outpoint.vout as usize).cloned()),
            Err(electrum_client::Error::Protocol(_)) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    )
}

/// Where a transaction stands, read off the history of one of its
/// output scripts: height 0 means mempool, a height means confirmed,
/// absence means the server does not have it.
pub(crate) fn tx_standing_blocking(
    target: &Target,
    txid: &Txid,
    script: &ScriptBuf,
    proxy: Option<&str>,
) -> Result<(bool, Option<u32>, u32), String> {
    on_client!(target, proxy, |client| {
        let tip = client
            .inner
            .block_headers_subscribe()
            .map_err(|e| e.to_string())?
            .height as u32;
        let history = client
            .inner
            .script_get_history(script)
            .map_err(|e| e.to_string())?;
        let entry = history.iter().find(|entry| entry.tx_hash == *txid);
        Ok(match entry {
            None => (false, None, tip),
            Some(entry) if entry.height > 0 => (true, Some(entry.height as u32), tip),
            Some(_) => (true, None, tip),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_splits_into_transport_host_and_port() {
        assert_eq!(
            parse("ssl://electrum.example:50002").unwrap(),
            (true, "electrum.example".to_owned(), 50002)
        );
        assert_eq!(
            parse("tcp://192.168.1.10:50001").unwrap(),
            (false, "192.168.1.10".to_owned(), 50001)
        );
        // No scheme means TLS, the Electrum convention.
        assert_eq!(
            parse("electrum.example:51002").unwrap(),
            (true, "electrum.example".to_owned(), 51002)
        );
        // No port means the protocol default, per transport.
        assert_eq!(parse("ssl://host").unwrap().2, SSL_PORT);
        assert_eq!(parse("tcp://host").unwrap().2, TCP_PORT);
        // An IPv6 literal keeps its own colons.
        assert_eq!(
            parse("ssl://[2001:db8::1]:50002").unwrap(),
            (true, "2001:db8::1".to_owned(), 50002)
        );
        assert!(parse("http://host:50002").is_err());
        assert!(parse("ssl://host:not-a-port").is_err());
    }

    /// Live. The whole trust-on-first-use path against real servers:
    /// a certificate a public authority signs needs no acceptance, one a
    /// server signed itself is described precisely and refused until it
    /// is accepted, then it carries real data, and a different
    /// certificate on the same host is refused again.
    #[test]
    #[ignore = "talks to public Electrum servers"]
    fn a_self_signed_server_asks_once_and_then_serves() {
        let vouched = Target::new("ssl://electrum.blockstream.info:50002", None);
        assert_eq!(
            inspect_blocking(&vouched).unwrap(),
            Inspection::Tls(Verdict::Trusted),
            "blockstream's certificate is signed by a public authority"
        );

        // One of the servers Sparrow ships that signs its own.
        let url = "ssl://electrum.emzy.de:50002";
        let Inspection::Tls(Verdict::Unknown {
            fingerprint,
            reason,
            subject,
            expires,
        }) = inspect_blocking(&Target::new(url, None)).unwrap()
        else {
            panic!("emzy's Electrum server is expected to sign its own certificate");
        };
        assert!(tls::is_fingerprint(&fingerprint), "{fingerprint}");
        assert!(!reason.is_empty());
        // The certificate says who it is and until when, even the one
        // written in a version webpki refuses to read.
        assert!(subject.is_some_and(|s| !s.is_empty()));
        assert!(expires.is_some_and(|at| at > 1_700_000_000));

        // Accepted once: the connection opens, and the server answers
        // with real chain data over it.
        let accepted = Target::new(url, Some(fingerprint.clone()));
        assert_eq!(
            inspect_blocking(&accepted).unwrap(),
            Inspection::Tls(Verdict::Pinned)
        );
        let pizza: Txid = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
            .parse()
            .unwrap();
        let txout = fetch_prevout_blocking(&accepted, OutPoint::new(pizza, 0), None)
            .expect("an accepted certificate carries Electrum traffic")
            .expect("the server knows that transaction");
        assert_eq!(txout.value.to_sat(), 1_000_000_000_000);

        // Any other certificate on that host is refused, and named.
        let elsewhere = Target::new(url, Some(["AA"; 32].join(":")));
        match inspect_blocking(&elsewhere).unwrap() {
            Inspection::Tls(Verdict::Changed { presented, stored }) => {
                assert_eq!(presented, fingerprint);
                assert_eq!(stored, ["AA"; 32].join(":"));
            }
            other => panic!("a changed certificate must be refused, got {other:?}"),
        }
    }

    #[test]
    fn the_trust_key_is_the_socket_scheme_and_path_stripped() {
        assert_eq!(
            certificate_key("ssl://electrum.example:50002"),
            "electrum.example:50002"
        );
        // Two spellings of the same server share one accepted certificate.
        assert_eq!(
            certificate_key("electrum.example:50002"),
            certificate_key("ssl://electrum.example:50002")
        );
        // A default port is spelled out, so the key never depends on how
        // the user typed the address.
        assert_eq!(certificate_key("ssl://host"), "host:50002");
    }
}
