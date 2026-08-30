//! Chain data sources: backend configuration and synchronization.

pub mod connect;
pub(crate) mod electrum;
pub(crate) mod esplora;
pub mod public;
pub(crate) mod tls;
pub mod tor;

use std::collections::BTreeMap;

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};
use serde::{Deserialize, Serialize};

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

    /// The HTTP base fee estimates should come from, when this backend
    /// speaks Esplora: the user's own node, or the public server they
    /// picked. `None` means no preference, so the public rotation
    /// answers.
    pub(crate) fn fee_base(&self, network: Network) -> Option<&str> {
        match self {
            BackendConfig::Public { server } => server
                .as_deref()
                .and_then(|id| public::find(network, id))
                .filter(|entry| entry.protocol() == public::ServerProtocol::Esplora)
                .map(|entry| entry.url()),
            BackendConfig::CustomEsplora { url } => Some(url.as_str()),
            BackendConfig::CustomElectrum { .. } => None,
        }
    }

    /// Whether fee estimates may fall back to the public servers. A
    /// user running their own node asked for exactly one host: an empty
    /// fee card beats a silent call to a public one.
    pub(crate) fn fees_may_fall_back(&self) -> bool {
        !matches!(self, BackendConfig::CustomEsplora { .. })
    }
}

/// Whether a backend URL points at a Tor hidden service. Onion hosts
/// are routed through the Tor proxy [`tor`] resolves, never looked up.
pub(crate) fn is_onion(url: &str) -> bool {
    host_of(url).is_some_and(|host| host.ends_with(".onion"))
}

/// Whether reaching this list means going through Tor. The manager asks
/// before resolving a route, so clearnet-only syncs never touch Tor.
pub(crate) fn needs_tor(endpoints: &[Endpoint]) -> bool {
    endpoints.iter().any(Endpoint::is_onion)
}

/// Extracts the host part of a URL-ish string, without any userinfo.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host_port = rest.split(['/', '?']).next()?;
    let host = host_port.rsplit_once('@').map_or(host_port, |(_, h)| h);
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_owned())
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
/// order they should be tried.
pub(crate) fn endpoints(
    config: &BackendConfig,
    network: Network,
    certs: &TrustedCerts,
) -> CoreResult<Vec<Endpoint>> {
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

/// A prepared sync request for a descriptor wallet.
pub(crate) enum EngineRequest {
    Full(FullScanRequest<KeychainKind>),
    Incremental(SyncRequest<(KeychainKind, u32)>),
}

/// The matching response, to apply back onto the wallet.
pub(crate) enum EngineResponse {
    Full(FullScanResponse<KeychainKind>),
    Incremental(SyncResponse),
}

/// Runs one sync attempt against one endpoint. The error is a plain
/// string: the caller owns retry logic and error wrapping.
///
/// `proxy`, here and below, is the Tor SOCKS proxy the caller resolved
/// for this operation; `None` when no endpoint of the list is an onion.
pub(crate) async fn sync_engine(
    endpoint: &Endpoint,
    request: EngineRequest,
    stop_gap: u32,
    proxy: Option<&str>,
) -> Result<EngineResponse, String> {
    match (endpoint, request) {
        (Endpoint::Esplora(url), EngineRequest::Full(request)) => {
            let client = esplora::client(url, proxy)?;
            esplora::full_scan(&client, request, stop_gap)
                .await
                .map(EngineResponse::Full)
                .map_err(|e| e.to_string())
        }
        (Endpoint::Esplora(url), EngineRequest::Incremental(request)) => {
            let client = esplora::client(url, proxy)?;
            esplora::sync(&client, request)
                .await
                .map(EngineResponse::Incremental)
                .map_err(|e| e.to_string())
        }
        (Endpoint::Electrum(target), EngineRequest::Full(request)) => {
            let target = target.clone();
            let proxy = proxy.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                electrum::full_scan_blocking(&target, request, stop_gap, proxy.as_deref())
            })
            .await
            .map_err(|e| e.to_string())?
            .map(EngineResponse::Full)
        }
        (Endpoint::Electrum(target), EngineRequest::Incremental(request)) => {
            let target = target.clone();
            let proxy = proxy.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                electrum::sync_blocking(&target, request, proxy.as_deref())
            })
            .await
            .map_err(|e| e.to_string())?
            .map(EngineResponse::Incremental)
        }
    }
}

/// Fetches the state of a single watched address from one endpoint.
///
/// Only Esplora backends can serve this today; an Electrum endpoint is
/// reported as unavailable with an actionable message.
pub(crate) async fn fetch_address_state(
    endpoint: &Endpoint,
    address: &str,
    network: Network,
    proxy: Option<&str>,
) -> Result<AddressWatchState, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url, proxy)?;
            esplora::fetch_address_state(&client, address, network).await
        }
        Endpoint::Electrum(_) => Err("single-address wallets need an Esplora backend for now; \
             switch the backend or import a descriptor"
            .to_owned()),
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
        Endpoint::Electrum(target) => {
            let target = target.clone();
            let tx = tx.clone();
            let proxy = proxy.map(str::to_owned);
            tokio::task::spawn_blocking(move || {
                electrum::broadcast_blocking(&target, &tx, proxy.as_deref())
            })
            .await
            .map_err(|e| e.to_string())?
            .map(|_| ())
        }
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
    tokio::task::spawn_blocking(move || {
        electrum::inspect_blocking(&electrum::Target::new(url, pin))
    })
    .await
    .map_err(|e| e.to_string())?
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
            let target = target.clone();
            let proxy = proxy.map(str::to_owned);
            let txout = tokio::task::spawn_blocking(move || {
                electrum::fetch_prevout_blocking(&target, outpoint, proxy.as_deref())
            })
            .await
            .map_err(|e| e.to_string())??;
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
            let target = target.clone();
            let proxy = proxy.map(str::to_owned);
            let (found, block_height, tip_height) = tokio::task::spawn_blocking(move || {
                electrum::tx_standing_blocking(&target, &txid, &script, proxy.as_deref())
            })
            .await
            .map_err(|e| e.to_string())??;
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
            esplora::fetch_address_history(&client, address, network, from).await
        }
        Endpoint::Electrum(_) => Err("single-address wallets need an Esplora backend for now;              switch the backend or import a descriptor"
            .to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            endpoints(&own, Network::Testnet4, &certs).unwrap(),
            vec![Endpoint::Electrum(electrum::Target::new(
                "blackie.c3-soft.com:57010",
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

    #[test]
    fn fee_estimates_follow_the_backend() {
        assert_eq!(BackendConfig::default().fee_base(Network::Mainnet), None);
        assert_eq!(
            BackendConfig::Public {
                server: Some("mempool.emzy.de".to_owned())
            }
            .fee_base(Network::Mainnet),
            Some("https://mempool.emzy.de/api")
        );
        // An Electrum server serves no HTTP fee endpoint.
        assert_eq!(
            BackendConfig::Public {
                server: Some("electrum:blockstream.info".to_owned())
            }
            .fee_base(Network::Mainnet),
            None
        );
        let own = BackendConfig::CustomEsplora {
            url: "https://node.example.org/api".to_owned(),
        };
        assert_eq!(
            own.fee_base(Network::Mainnet),
            Some("https://node.example.org/api")
        );
        assert!(!own.fees_may_fall_back());
        assert!(BackendConfig::default().fees_may_fall_back());
    }
}
