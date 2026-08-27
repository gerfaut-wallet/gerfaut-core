//! Chain data sources: backend configuration and synchronization.

pub(crate) mod electrum;
pub(crate) mod esplora;
pub mod public;

use bdk_wallet::KeychainKind;
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

/// Local Tor SOCKS proxy, the default of both the Tor daemon and the
/// Tor Browser bundle's expert bundle.
pub const TOR_SOCKS_PROXY: &str = "127.0.0.1:9050";

/// Whether a backend URL points at a Tor hidden service. Onion hosts
/// are routed through the local Tor proxy automatically.
pub(crate) fn is_onion(url: &str) -> bool {
    host_of(url).is_some_and(|host| host.ends_with(".onion"))
}

/// Extracts the host part of a URL-ish string, without any userinfo.
fn host_of(url: &str) -> Option<String> {
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
    Electrum(String),
}

impl Endpoint {
    pub(crate) fn label(&self) -> String {
        match self {
            Endpoint::Esplora(url) | Endpoint::Electrum(url) => {
                host_of(url).unwrap_or_else(|| "backend".to_owned())
            }
        }
    }
}

/// Resolves a backend configuration into concrete endpoints, in the
/// order they should be tried.
pub(crate) fn endpoints(config: &BackendConfig, network: Network) -> CoreResult<Vec<Endpoint>> {
    match config {
        // A chosen operator is the only endpoint: the point of picking
        // one is that no other host sees these addresses.
        BackendConfig::Public { server: Some(id) } => match public::find(network, id) {
            Some(entry) => Ok(vec![match entry.protocol() {
                public::ServerProtocol::Esplora => Endpoint::Esplora(entry.url().to_owned()),
                public::ServerProtocol::Electrum => Endpoint::Electrum(entry.url().to_owned()),
            }]),
            // A server dropped by a later version must not brick syncs:
            // fall back to the rotation, which the settings also show.
            None => automatic_endpoints(network),
        },
        BackendConfig::Public { server: None } => automatic_endpoints(network),
        BackendConfig::CustomEsplora { url } => Ok(vec![Endpoint::Esplora(url.clone())]),
        BackendConfig::CustomElectrum { url } => Ok(vec![Endpoint::Electrum(url.clone())]),
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
pub(crate) async fn sync_engine(
    endpoint: &Endpoint,
    request: EngineRequest,
    stop_gap: u32,
) -> Result<EngineResponse, String> {
    match (endpoint, request) {
        (Endpoint::Esplora(url), EngineRequest::Full(request)) => {
            let client = esplora::client(url).map_err(|e| e.to_string())?;
            esplora::full_scan(&client, request, stop_gap)
                .await
                .map(EngineResponse::Full)
                .map_err(|e| e.to_string())
        }
        (Endpoint::Esplora(url), EngineRequest::Incremental(request)) => {
            let client = esplora::client(url).map_err(|e| e.to_string())?;
            esplora::sync(&client, request)
                .await
                .map(EngineResponse::Incremental)
                .map_err(|e| e.to_string())
        }
        (Endpoint::Electrum(url), EngineRequest::Full(request)) => {
            let url = url.clone();
            tokio::task::spawn_blocking(move || {
                electrum::full_scan_blocking(&url, request, stop_gap)
            })
            .await
            .map_err(|e| e.to_string())?
            .map(EngineResponse::Full)
            .map_err(|e| e.to_string())
        }
        (Endpoint::Electrum(url), EngineRequest::Incremental(request)) => {
            let url = url.clone();
            tokio::task::spawn_blocking(move || electrum::sync_blocking(&url, request))
                .await
                .map_err(|e| e.to_string())?
                .map(EngineResponse::Incremental)
                .map_err(|e| e.to_string())
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
) -> Result<AddressWatchState, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url).map_err(|e| e.to_string())?;
            esplora::fetch_address_state(&client, address, network).await
        }
        Endpoint::Electrum(_) => Err("single-address wallets need an Esplora backend for now; \
             switch the backend or import a descriptor"
            .to_owned()),
    }
}

/// Fetches an older round of address history from one endpoint.
pub(crate) async fn fetch_address_history(
    endpoint: &Endpoint,
    address: &str,
    network: Network,
    from: &str,
) -> Result<esplora::HistoryRound, String> {
    match endpoint {
        Endpoint::Esplora(url) => {
            let client = esplora::client(url).map_err(|e| e.to_string())?;
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
        let esplora = BackendConfig::Public {
            server: Some("mempool.emzy.de".to_owned()),
        };
        assert_eq!(
            endpoints(&esplora, Network::Testnet4).unwrap(),
            vec![Endpoint::Esplora(
                "https://mempool.emzy.de/testnet4/api".to_owned()
            )]
        );
        let electrum = BackendConfig::Public {
            server: Some("electrum:blackie.c3-soft.com".to_owned()),
        };
        assert_eq!(
            endpoints(&electrum, Network::Testnet4).unwrap(),
            vec![Endpoint::Electrum(
                "ssl://blackie.c3-soft.com:57010".to_owned()
            )]
        );
    }

    #[test]
    fn automatic_and_unknown_operators_rotate_over_every_instance() {
        let automatic = endpoints(&BackendConfig::default(), Network::Mainnet).unwrap();
        assert_eq!(automatic.len(), 3);
        let retired = BackendConfig::Public {
            server: Some("gone.example.org".to_owned()),
        };
        assert_eq!(endpoints(&retired, Network::Mainnet).unwrap(), automatic);
        // A network without a public instance still says so.
        assert!(endpoints(&BackendConfig::default(), Network::Regtest).is_err());
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
