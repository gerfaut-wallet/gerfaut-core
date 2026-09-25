//! Chain data sources: backend configuration and synchronization.

pub mod connect;
pub(crate) mod electrum;
pub(crate) mod esplora;
pub mod public;
pub(crate) mod tls;
pub mod tor;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};
use serde::{Deserialize, Serialize};
use url::{Host, ParseError, Url};

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::wallet::AddressWatchState;

/// Where a wallet's chain data comes from.
///
/// One configuration per network is stored in the settings; wallets on
/// that network all use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendConfig {
    /// One of the public servers listed in [`public`]. Without a chosen
    /// operator, the public Esplora instances are tried in order. The
    /// honest default: the server that answers sees the wallet's
    /// addresses, and the settings screen says so.
    ///
    /// The tag stays `public_esplora`, the spelling every stored vault
    /// already carries, and `server` is omitted when unset so an
    /// automatic configuration serializes exactly as it always did.
    #[serde(rename = "public_esplora")]
    Public {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
    /// The user's own Esplora-compatible HTTP endpoint.
    CustomEsplora { url: String },
    /// The user's own Electrum server, `ssl://host:port` or
    /// `tcp://host:port`.
    CustomElectrum { url: String },
}

impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Public { server: None }
    }
}

impl BackendConfig {
    /// Short human-readable identifier for sync reports and logs:
    /// the host, never a full URL with potential credentials.
    pub fn label(&self, network: Network) -> String {
        match self {
            BackendConfig::Public { server } => server
                .as_deref()
                .and_then(|id| public::find(network, id))
                .map(|entry| entry.label().to_owned())
                .or_else(|| {
                    network
                        .default_esplora_urls()
                        .first()
                        .and_then(|url| host_of(url))
                })
                .unwrap_or_else(|| "public esplora".to_owned()),
            BackendConfig::CustomEsplora { url } | BackendConfig::CustomElectrum { url } => {
                host_of(url).unwrap_or_else(|| "custom backend".to_owned())
            }
        }
    }

    /// The configuration with a custom address in the form the settings
    /// store it in ([`connect::stored_form`]), or the reason the address
    /// cannot be read. Everything that takes a configuration from
    /// outside the settings screen goes through here too: a vault
    /// written before addresses were stored that way, a backup made by
    /// such a vault. Read as typed, `tcp://x.onion:50001:extra` names no
    /// host to the URL parser, so no onion, and would reach the
    /// resolver in the clear. An address already in that form comes
    /// back byte for byte.
    pub fn canonical(self) -> CoreResult<Self> {
        use connect::ScannedBackendKind::{Electrum, Esplora};
        Ok(match self {
            BackendConfig::CustomEsplora { url } => BackendConfig::CustomEsplora {
                url: connect::stored_form(Esplora, &url)?,
            },
            BackendConfig::CustomElectrum { url } => BackendConfig::CustomElectrum {
                url: connect::stored_form(Electrum, &url)?,
            },
            public @ BackendConfig::Public { .. } => public,
        })
    }
}

/// Whether a backend URL points at a Tor hidden service. Onion hosts
/// are routed through the Tor proxy [`tor`] resolves, never looked up.
///
/// Host names have no case, and a QR code prints them in capitals: an
/// address read as `.ONION` is the same hidden service, and taking it
/// for a clearnet host would hand its name to the resolver.
pub(crate) fn is_onion(url: &str) -> bool {
    host_of(url).is_some_and(|host| is_onion_host(&host))
}

/// Whether a bare host name is a hidden service, in whatever case it
/// was spelled, and with or without the trailing dot a fully qualified
/// name may carry: `x.onion.` names the same service as `x.onion`, and
/// a resolver handed either would tell the world about it. Compared on
/// bytes: the name may be anything a camera decoded, and a byte index
/// into the middle of a character would panic.
pub(crate) fn is_onion_host(host: &str) -> bool {
    const SUFFIX: &[u8] = b".onion";
    let bytes = host.as_bytes();
    let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
    bytes.len() >= SUFFIX.len() && bytes[bytes.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX)
}

/// Whether reaching this list means going through Tor. The manager asks
/// before resolving a route, so clearnet-only syncs never touch Tor.
pub(crate) fn needs_tor(endpoints: &[Endpoint]) -> bool {
    endpoints.iter().any(Endpoint::is_onion)
}

/// The host of a server address, without any userinfo.
pub(crate) fn host_of(url: &str) -> Option<String> {
    host_and_port(url).map(|(host, _)| host)
}

/// The host of a server address and the port it names, read by the
/// URL parser the HTTP client reads with, so that whatever the two
/// could disagree on is settled the client's way: under `http` and
/// `https` a `\` ends the host, `%2E` is a dot, capitals are not, and
/// the userinfo before an `@` is not the host. `ssl://` and `tcp://`
/// are not schemes the standard knows; a host under them is read as
/// written, then given the same reading, and a bare `host:port` is
/// read as `ssl://`, the way the Electrum client reads it. An IPv6
/// literal comes back without its brackets. `None` for anything that
/// names no host a client could connect to.
pub(crate) fn host_and_port(url: &str) -> Option<(String, Option<u16>)> {
    let text = if url.contains("://") {
        Cow::Borrowed(url)
    } else {
        Cow::Owned(format!("ssl://{url}"))
    };
    let parsed = Url::parse(&text).ok()?;
    let host = host_of_parsed(&parsed)?;
    Some((host, parsed.port()))
}

/// The host of a parsed URL in canonical form. Under a standard
/// scheme the parser already read it; under any other it is the text
/// as written, and this is where it gets the same reading.
pub(crate) fn host_of_parsed(parsed: &Url) -> Option<String> {
    let host = match parsed.host()? {
        Host::Domain(domain) => canonical_host(domain).ok()?,
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    (!host.is_empty()).then_some(host)
}

/// A host as the URL standard reads it: percent-decoded, in lower
/// case, an IP address in its canonical spelling, an IPv6 literal with
/// or without brackets given back without them, and the trailing dot
/// of a fully qualified name dropped. Refuses whatever a host cannot
/// contain, a `\` or a space among them.
pub(crate) fn canonical_host(host: &str) -> Result<String, ParseError> {
    let literal = if host.contains(':') && !host.starts_with('[') {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
    };
    let host = match Host::parse(&literal)? {
        Host::Domain(domain) => domain.strip_suffix('.').unwrap_or(&domain).to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    if host.is_empty() {
        return Err(ParseError::EmptyHost);
    }
    Ok(host)
}

/// One concrete server to talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Esplora(String),
    Electrum(electrum::Target),
}

impl Endpoint {
    fn url(&self) -> &str {
        match self {
            Endpoint::Esplora(url) => url.as_str(),
            Endpoint::Electrum(target) => target.url.as_str(),
        }
    }

    pub(crate) fn label(&self) -> String {
        host_of(self.url()).unwrap_or_else(|| "backend".to_owned())
    }

    pub(crate) fn is_onion(&self) -> bool {
        is_onion(self.url())
    }
}

/// Certificate fingerprints the user accepted, by `host:port`. Kept in
/// the encrypted vault and handed to every Electrum connection.
pub type TrustedCerts = BTreeMap<String, String>;

/// The fingerprint accepted for this server, if any.
fn pin_for(certs: &TrustedCerts, url: &str) -> Option<String> {
    certs.get(&electrum::certificate_key(url)).cloned()
}

/// Resolves a backend configuration into concrete endpoints, in the
/// order they should be tried. A custom address is read in its stored
/// form whatever form the vault holds it in, and one that has none is
/// refused here, before anything could connect to it.
pub(crate) fn endpoints(
    config: &BackendConfig,
    network: Network,
    certs: &TrustedCerts,
) -> CoreResult<Vec<Endpoint>> {
    let config = &config.clone().canonical()?;
    match config {
        // A chosen operator is the only endpoint: the point of picking
        // one is that no other host sees these addresses.
        BackendConfig::Public { server: Some(id) } => match public::find(network, id) {
            Some(entry) => Ok(vec![match entry.protocol() {
                public::ServerProtocol::Esplora => Endpoint::Esplora(entry.url().to_owned()),
                public::ServerProtocol::Electrum => Endpoint::Electrum(electrum::Target::new(
                    entry.url(),
                    pin_for(certs, entry.url()),
                )),
            }]),
            // A server dropped by a later version must not brick syncs:
            // fall back to the rotation, which the settings also show.
            None => automatic_endpoints(network),
        },
        BackendConfig::Public { server: None } => automatic_endpoints(network),
        BackendConfig::CustomEsplora { url } => Ok(vec![Endpoint::Esplora(url.clone())]),
        BackendConfig::CustomElectrum { url } => Ok(vec![Endpoint::Electrum(
            electrum::Target::new(url.clone(), pin_for(certs, url)),
        )]),
    }
}

/// The public Esplora rotation: every operator for the network, tried in
/// order so that one blocked or down instance never looks like an empty
/// wallet.
fn automatic_endpoints(network: Network) -> CoreResult<Vec<Endpoint>> {
    let urls = network.default_esplora_urls();
    if urls.is_empty() {
        return Err(CoreError::BackendUnavailable(format!(
            "no public backend exists for {network}; configure your own node"
        )));
    }
    Ok(urls
        .iter()
        .map(|url| Endpoint::Esplora((*url).to_owned()))
        .collect())
}

/// How long a whole sync attempt against one endpoint may take, every
/// request together. Each request has a timeout of its own; this bounds
/// their sum, which a server answering just fast enough to stay under
/// every one of them would otherwise make endless. Past it the attempt
/// is abandoned and the next endpoint tried.
const SCAN_DEADLINE: Duration = Duration::from_secs(10 * 60);
/// Through Tor, where everything is slower.
const TOR_SCAN_DEADLINE: Duration = Duration::from_secs(20 * 60);

fn scan_deadline(endpoint: &Endpoint) -> Duration {
    if endpoint.is_onion() {
        TOR_SCAN_DEADLINE
    } else {
        SCAN_DEADLINE
    }
}

/// `work`, given up once `deadline` has passed.
async fn within<T>(
    deadline: Duration,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(deadline, work)
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {} s", deadline.as_secs())))
}

/// A prepared sync request for a descriptor wallet.
pub(crate) enum EngineRequest {
    Full(FullScanRequest<KeychainKind>),
    /// The scripts the wallet revealed, and a full scan of its receive
    /// addresses from the first one it has not: where a payment to an
    /// address it never showed lands, one another app or the signing
    /// device handed out. That scan stops, as a full scan does, once
    /// the gap limit of addresses in a row shows nothing.
    Incremental(
        SyncRequest<(KeychainKind, u32)>,
        FullScanRequest<KeychainKind>,
    ),
}

/// The matching response, to apply back onto the wallet.
pub(crate) enum EngineResponse {
    Full(FullScanResponse<KeychainKind>),
    Incremental(SyncResponse, FullScanResponse<KeychainKind>),
}

impl EngineResponse {
    /// Refuses a response that holds an amount no transaction can
    /// carry: an output, or the outputs of one transaction together,
    /// above the 21 million bitcoin there will ever be. Nothing in a
    /// block can, but an unconfirmed transaction is only the server's
    /// word, and the wallet engine adds amounts up with a panic on
    /// overflow: once stored, such a transaction brought down every
    /// later look at the wallet.
    pub(crate) fn check_amounts(&self) -> Result<(), String> {
        let updates = match self {
            EngineResponse::Full(full) => vec![&full.tx_update],
            EngineResponse::Incremental(sync, tail) => vec![&sync.tx_update, &tail.tx_update],
        };
        let refused = || "the server sent a transaction worth more than every bitcoin".to_owned();
        for update in updates {
            for tx in &update.txs {
                tx.output
                    .iter()
                    .try_fold(0u64, |sum, out| sum.checked_add(out.value.to_sat()))
                    .filter(|&total| total <= bdk_wallet::bitcoin::Amount::MAX_MONEY.to_sat())
                    .ok_or_else(refused)?;
            }
            if update
                .txouts
                .values()
                .any(|out| out.value > bdk_wallet::bitcoin::Amount::MAX_MONEY)
            {
                return Err(refused());
            }
        }
        Ok(())
    }
}

/// Runs one sync attempt against one endpoint, within the deadline of
/// a scan. The error is a plain string: the caller owns retry logic and
/// error wrapping. Dropping the future abandons the attempt, an
/// Electrum connection included.
///
/// `proxy`, here and below, is the Tor SOCKS proxy the caller resolved
/// for this operation; `None` when no endpoint of the list is an onion.
pub(crate) async fn sync_engine(
    endpoint: &Endpoint,
    request: EngineRequest,
    stop_gap: u32,
    proxy: Option<&str>,
) -> Result<EngineResponse, String> {
    let deadline = scan_deadline(endpoint);
    match (endpoint, request) {
        (Endpoint::Esplora(url), EngineRequest::Full(request)) => {
            let client = esplora::client(url, proxy)?;
            within(deadline, esplora::full_scan(&client, request, stop_gap))
                .await
                .map(EngineResponse::Full)
        }
        (Endpoint::Esplora(url), EngineRequest::Incremental(request, tail)) => {
            let client = esplora::client(url, proxy)?;
            within(deadline, async {
                let synced = esplora::sync(&client, request).await?;
                let tail = esplora::full_scan(&client, tail, stop_gap).await?;
                Ok(EngineResponse::Incremental(synced, tail))
            })
            .await
        }
        (Endpoint::Electrum(target), EngineRequest::Full(request)) => {
            electrum::full_scan(target, request, stop_gap, proxy, deadline)
                .await
                .map(EngineResponse::Full)
        }
        (Endpoint::Electrum(target), EngineRequest::Incremental(request, tail)) => {
            electrum::sync(target, request, tail, stop_gap, proxy, deadline)
                .await
                .map(|(synced, tail)| EngineResponse::Incremental(synced, tail))
        }
    }
}

/// Fetches the state of a single watched address from one endpoint,
/// within the deadline of a scan: the same state from an Esplora or an
/// Electrum server.
pub(crate) async fn fetch_address_state(
    endpoint: &Endpoint,
    address: &str,
    network: Network,
    proxy: Option<&str>,
) -> Result<AddressWatchState, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            within(
                scan_deadline(endpoint),
                esplora::fetch_address_state(&client, address, network),
            )
            .await
        }
        Endpoint::Electrum(target) => {
            within(
                scan_deadline(endpoint),
                electrum::address::fetch_state(target, address, network, proxy),
            )
            .await
        }
    }
}

/// Hands a signed transaction to one endpoint. Returns the host that
/// accepted it; the node's refusal comes back as the error text.
pub(crate) async fn broadcast(
    endpoint: &Endpoint,
    tx: &Transaction,
    proxy: Option<&str>,
) -> Result<(), String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            esplora::broadcast(&client, tx).await
        }
        Endpoint::Electrum(target) => electrum::broadcast(target, tx, proxy).await.map(|_| ()),
    }
}

/// What a server's certificate amounts to, for a settings screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CertificateStatus {
    /// Plain TCP: there is no certificate, and anything on the path
    /// reads the traffic.
    NotTls,
    /// A Tor hidden service: the onion address is the server's identity,
    /// so no certificate has to vouch for it.
    Tor,
    /// A public certificate authority vouches for it.
    Trusted,
    /// It is exactly the certificate accepted for this host.
    Pinned { fingerprint: String },
    /// No authority vouches for it and this host has no accepted
    /// certificate yet: the user decides, once, with what the
    /// certificate says about itself in front of them.
    Unknown {
        fingerprint: String,
        reason: String,
        subject: Option<String>,
        expires: Option<i64>,
    },
    /// This host was accepted with a different certificate. Something
    /// changed on the server, or something sits in between.
    Changed { stored: String, presented: String },
    /// The server could not be reached, so nothing can be said about
    /// its certificate.
    Unreachable { detail: String },
}

/// One server's certificate, and where it is stored from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReport {
    /// `host:port`: what the acceptance is recorded against.
    pub host: String,
    #[serde(flatten)]
    pub status: CertificateStatus,
}

/// What the settings screen should say about an Electrum server's
/// certificate, and the fingerprint to offer for acceptance.
pub(crate) async fn inspect_certificate(
    url: String,
    pin: Option<String>,
) -> Result<electrum::Inspection, String> {
    electrum::inspect(&electrum::Target::new(url, pin)).await
}

/// What one endpoint knows about a coin about to be spent.
pub(crate) struct PrevoutFacts {
    pub txout: Option<TxOut>,
    /// `None` when the endpoint cannot say (Electrum).
    pub spent: Option<bool>,
}

pub(crate) async fn fetch_prevout(
    endpoint: &Endpoint,
    outpoint: OutPoint,
    proxy: Option<&str>,
) -> Result<PrevoutFacts, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            let facts = esplora::fetch_prevout(&client, outpoint).await?;
            Ok(PrevoutFacts {
                txout: facts.txout,
                spent: facts.spent,
            })
        }
        Endpoint::Electrum(target) => {
            let txout = electrum::fetch_prevout(target, outpoint, proxy).await?;
            Ok(PrevoutFacts { txout, spent: None })
        }
    }
}

/// Where a transaction stands at one endpoint. `script` is one of the
/// transaction's output scripts, the handle Electrum needs.
pub(crate) struct TxStanding {
    pub found: bool,
    pub block_height: Option<u32>,
    pub tip_height: u32,
}

pub(crate) async fn tx_standing(
    endpoint: &Endpoint,
    txid: Txid,
    script: ScriptBuf,
    proxy: Option<&str>,
) -> Result<TxStanding, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            let standing = esplora::tx_standing(&client, &txid).await?;
            Ok(TxStanding {
                found: standing.found,
                block_height: standing
                    .confirmed
                    .then_some(standing.block_height)
                    .flatten(),
                tip_height: standing.tip_height,
            })
        }
        Endpoint::Electrum(target) => {
            let (found, block_height, tip_height) =
                electrum::tx_standing(target, txid, script, proxy).await?;
            Ok(TxStanding {
                found,
                block_height,
                tip_height,
            })
        }
    }
}

/// Fetches an older round of address history from one endpoint.
pub(crate) async fn fetch_address_history(
    endpoint: &Endpoint,
    address: &str,
    network: Network,
    from: &str,
    proxy: Option<&str>,
) -> Result<esplora::HistoryRound, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            within(
                scan_deadline(endpoint),
                esplora::fetch_address_history(&client, address, network, from),
            )
            .await
        }
        Endpoint::Electrum(target) => {
            within(
                scan_deadline(endpoint),
                electrum::address::fetch_history(target, address, network, from, proxy),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hidden service is one whatever case its name was read in: a QR
    /// code prints capitals, and a `.ONION` taken for a clearnet host
    /// would be looked up and reached outside Tor.
    #[test]
    fn an_onion_host_is_one_in_any_case() {
        const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567";
        assert!(is_onion(&format!("tcp://{ONION}.onion:50001")));
        assert!(is_onion(&format!(
            "tcp://{}.ONION:50001",
            ONION.to_ascii_uppercase()
        )));
        assert!(is_onion(&format!("http://{ONION}.Onion/api")));
        assert!(!is_onion("ssl://electrum.example.org:50002"));
        assert!(!is_onion("ssl://onion.example.org:50002"));
        // Nothing a camera decodes may panic the check.
        assert!(!is_onion_host("a\u{e9}\u{e9}\u{e9}\u{e9}"));
        assert!(!is_onion_host("\u{e9}\u{e9}"));
        assert!(is_onion_host("\u{e9}.onion"));
        assert!(needs_tor(&[Endpoint::Electrum(electrum::Target::new(
            format!("tcp://{}.ONION:50001", ONION.to_ascii_uppercase()),
            None
        ))]));
    }

    /// A fragment glued to the name is not part of the host, and the
    /// backend parser already reads it that way: an onion followed by
    /// `#` must not be taken for a clearnet host and reached outside Tor.
    #[test]
    fn a_fragment_does_not_hide_an_onion_host() {
        assert!(is_onion("http://abc.onion#frag"));
        assert!(is_onion("http://abc.onion?q"));
        assert_eq!(
            host_of("http://abc.onion#frag").as_deref(),
            Some("abc.onion")
        );
        assert!(needs_tor(&[Endpoint::Esplora(
            "http://abc.onion#frag".to_owned()
        )]));
    }

    /// The host is read with the parser the HTTP client reads with, so
    /// a disguised onion goes through Tor and a disguised clearnet host
    /// does not: the two never mean different machines.
    #[test]
    fn a_host_is_read_the_way_the_client_connects_to_it() {
        // Under a standard scheme a backslash ends the host: the client
        // would reach evil.com, in the clear, with `/.onion` as a path.
        assert_eq!(
            host_of("https://evil.com\\.onion").as_deref(),
            Some("evil.com")
        );
        assert!(!is_onion("https://evil.com\\.onion"));
        // A percent-encoded dot is a dot to the client: an onion, and
        // one that must never reach a resolver.
        assert_eq!(
            host_of("https://evil%2Eonion").as_deref(),
            Some("evil.onion")
        );
        assert!(is_onion("https://evil%2Eonion"));
        assert!(is_onion("https://EVIL%2eONION/api"));
        // A fully qualified name is the same name.
        assert_eq!(host_of("https://x.onion.").as_deref(), Some("x.onion"));
        assert!(is_onion("https://x.onion."));
        assert!(is_onion_host("X.ONION."));
        // The userinfo is not the host, whatever it holds.
        assert_eq!(
            host_and_port("https://user:Pass@Host.Example:3002/api"),
            Some(("host.example".to_owned(), Some(3002)))
        );
        assert_eq!(
            host_of("https://x.onion@evil.com/").as_deref(),
            Some("evil.com")
        );
        assert!(!is_onion("https://x.onion@evil.com/"));

        // The Electrum schemes, and a bare address, read the same way.
        assert_eq!(
            host_and_port("ssl://xxx.onion:50002"),
            Some(("xxx.onion".to_owned(), Some(50002)))
        );
        assert!(is_onion("ssl://xxx.onion:50002"));
        assert_eq!(
            host_and_port("tcp://XXX%2Eonion:50001"),
            Some(("xxx.onion".to_owned(), Some(50001)))
        );
        assert!(is_onion("tcp://XXX%2Eonion:50001"));
        assert!(is_onion("tcp://xxx.onion.:50001"));
        assert_eq!(
            host_and_port("node.example:50001"),
            Some(("node.example".to_owned(), Some(50001)))
        );
        assert_eq!(
            host_and_port("ssl://user:pass@node.example"),
            Some(("node.example".to_owned(), None))
        );
        // Under a scheme the standard does not know a backslash is not
        // a character a host may hold: there is no host to name, and
        // nothing to route through Tor.
        assert_eq!(host_of("ssl://evil.com\\.onion:50002"), None);
        assert!(!is_onion("ssl://evil.com\\.onion:50002"));

        // An IPv6 literal, bracketed on the way in, bare on the way out.
        assert_eq!(
            host_and_port("ssl://[2001:DB8::1]:50002"),
            Some(("2001:db8::1".to_owned(), Some(50002)))
        );
        assert_eq!(
            host_and_port("https://[::1]:3002/api"),
            Some(("::1".to_owned(), Some(3002)))
        );

        // Nothing to connect to.
        assert_eq!(host_of("https://"), None);
        assert_eq!(host_of("ssl://:50002"), None);
        assert_eq!(host_of("https://host name/"), None);
        assert_eq!(host_of(""), None);
    }

    #[test]
    fn labels_are_hosts_only() {
        assert_eq!(
            BackendConfig::default().label(Network::Mainnet),
            "mempool.space"
        );
        assert_eq!(
            BackendConfig::CustomEsplora {
                url: "https://user:pass@node.example.org:3002/api".to_owned()
            }
            .label(Network::Mainnet),
            "node.example.org"
        );
        assert_eq!(
            BackendConfig::CustomElectrum {
                url: "ssl://fulcrum.example.org:50002".to_owned()
            }
            .label(Network::Signet),
            "fulcrum.example.org"
        );
        assert_eq!(
            BackendConfig::Public {
                server: Some("electrum:electrum.blockstream.info".to_owned())
            }
            .label(Network::Mainnet),
            "electrum.blockstream.info:50002"
        );
    }

    /// Vaults written before the operator choice existed carry a bare
    /// `{"type":"public_esplora"}`, and must keep reading and writing
    /// that exact shape while nothing is chosen.
    #[test]
    fn the_automatic_public_backend_keeps_its_stored_shape() {
        let stored: BackendConfig = serde_json::from_str(r#"{"type":"public_esplora"}"#).unwrap();
        assert_eq!(stored, BackendConfig::default());
        assert_eq!(
            serde_json::to_string(&stored).unwrap(),
            r#"{"type":"public_esplora"}"#
        );
        let chosen = BackendConfig::Public {
            server: Some("blockstream.info".to_owned()),
        };
        assert_eq!(
            serde_json::to_string(&chosen).unwrap(),
            r#"{"type":"public_esplora","server":"blockstream.info"}"#
        );
        assert_eq!(
            serde_json::from_str::<BackendConfig>(
                r#"{"type":"public_esplora","server":"blockstream.info"}"#
            )
            .unwrap(),
            chosen
        );
    }

    #[test]
    fn a_chosen_operator_is_the_only_endpoint() {
        let none = TrustedCerts::new();
        let esplora = BackendConfig::Public {
            server: Some("mempool.emzy.de".to_owned()),
        };
        assert_eq!(
            endpoints(&esplora, Network::Testnet4, &none).unwrap(),
            vec![Endpoint::Esplora(
                "https://mempool.emzy.de/testnet4/api".to_owned()
            )]
        );
        let electrum = BackendConfig::Public {
            server: Some("electrum:blackie.c3-soft.com".to_owned()),
        };
        assert_eq!(
            endpoints(&electrum, Network::Testnet4, &none).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "ssl://blackie.c3-soft.com:57010",
                None
            ))]
        );
    }

    /// The fingerprint the user accepted travels with the endpoint,
    /// whether the server comes from the catalogue or from their own
    /// configuration, and however they spelled the address.
    #[test]
    fn an_accepted_certificate_reaches_the_endpoint() {
        let mut certs = TrustedCerts::new();
        certs.insert(
            "blackie.c3-soft.com:57010".to_owned(),
            "AA:BB".repeat(16).trim_end_matches(':').to_owned(),
        );
        let pinned = certs.values().next().cloned();
        let catalogue = BackendConfig::Public {
            server: Some("electrum:blackie.c3-soft.com".to_owned()),
        };
        assert_eq!(
            endpoints(&catalogue, Network::Testnet4, &certs).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "ssl://blackie.c3-soft.com:57010",
                pinned.clone()
            ))]
        );
        let own = BackendConfig::CustomElectrum {
            url: "blackie.c3-soft.com:57010".to_owned(),
        };
        // Read in the form the settings store, the fingerprint with it.
        assert_eq!(
            endpoints(&own, Network::Testnet4, &certs).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "ssl://blackie.c3-soft.com:57010",
                pinned
            ))]
        );
        // A server with nothing accepted for it carries no fingerprint.
        let other = BackendConfig::CustomElectrum {
            url: "ssl://elsewhere.example:50002".to_owned(),
        };
        assert_eq!(
            endpoints(&other, Network::Testnet4, &certs).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "ssl://elsewhere.example:50002",
                None
            ))]
        );
    }

    /// A vault written before custom addresses were stored in canonical
    /// form still holds them as typed. They are read in that form on
    /// the way to a connection, and one that has none is refused before
    /// anything connects: to the URL parser `tcp://x.onion:50001:extra`
    /// names no host, so no onion, and the resolver would see the name.
    #[test]
    fn a_stored_address_is_read_in_canonical_form() {
        let none = TrustedCerts::new();
        let electrum = BackendConfig::CustomElectrum {
            url: "Node.Example.ORG.:50002".to_owned(),
        };
        assert_eq!(
            endpoints(&electrum, Network::Signet, &none).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "ssl://node.example.org:50002",
                None
            ))]
        );
        let esplora = BackendConfig::CustomEsplora {
            url: "HTTPS://Esplora.Example.ORG./api/".to_owned(),
        };
        assert_eq!(
            endpoints(&esplora, Network::Signet, &none).unwrap(),
            vec![Endpoint::Esplora(
                "https://esplora.example.org/api".to_owned()
            )]
        );
        for unreadable in [
            BackendConfig::CustomElectrum {
                url: "tcp://x.onion:50001:extra".to_owned(),
            },
            BackendConfig::CustomEsplora {
                url: "x.onion/api".to_owned(),
            },
        ] {
            assert!(
                matches!(
                    endpoints(&unreadable, Network::Signet, &none),
                    Err(CoreError::InvalidInput { kind: "server", .. })
                ),
                "{unreadable:?}"
            );
        }
    }

    #[test]
    fn automatic_and_unknown_operators_rotate_over_every_instance() {
        let none = TrustedCerts::new();
        let automatic = endpoints(&BackendConfig::default(), Network::Mainnet, &none).unwrap();
        assert_eq!(automatic.len(), 3);
        let retired = BackendConfig::Public {
            server: Some("gone.example.org".to_owned()),
        };
        assert_eq!(
            endpoints(&retired, Network::Mainnet, &none).unwrap(),
            automatic
        );
        // A network without a public instance still says so.
        assert!(endpoints(&BackendConfig::default(), Network::Regtest, &none).is_err());
    }

    /// A server may say anything about a transaction still out of a
    /// block. One that sums past every bitcoin is refused before the
    /// wallet engine, which would panic adding it up at every look.
    #[test]
    fn a_response_worth_more_than_every_bitcoin_is_refused() {
        use bdk_wallet::bitcoin::{Amount, absolute, transaction};
        use std::sync::Arc;
        let tx = |values: &[u64]| {
            Arc::new(Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: Vec::new(),
                output: values
                    .iter()
                    .map(|&value| TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: ScriptBuf::new(),
                    })
                    .collect(),
            })
        };
        let full = |txs: Vec<Arc<Transaction>>, txouts: Vec<u64>| {
            let mut response = FullScanResponse::<KeychainKind>::default();
            response.tx_update.txs = txs;
            response.tx_update.txouts = txouts
                .into_iter()
                .enumerate()
                .map(|(vout, value)| {
                    (
                        OutPoint::new(Txid::from_byte_array([7; 32]), vout as u32),
                        TxOut {
                            value: Amount::from_sat(value),
                            script_pubkey: ScriptBuf::new(),
                        },
                    )
                })
                .collect();
            response
        };
        let max = Amount::MAX_MONEY.to_sat();
        use bdk_wallet::bitcoin::hashes::Hash;

        assert!(
            EngineResponse::Full(full(vec![tx(&[max])], vec![max]))
                .check_amounts()
                .is_ok()
        );
        for response in [
            full(vec![tx(&[1 << 63, 1 << 63])], Vec::new()),
            full(vec![tx(&[max, 1])], Vec::new()),
            full(Vec::new(), vec![max + 1]),
        ] {
            assert!(EngineResponse::Full(response).check_amounts().is_err());
            let tail = full(vec![tx(&[max, max])], Vec::new());
            assert!(
                EngineResponse::Incremental(SyncResponse::default(), tail)
                    .check_amounts()
                    .is_err()
            );
        }
    }
}
