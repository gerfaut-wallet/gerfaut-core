//! Chain data sources: backend configuration and synchronization.

use serde::{Deserialize, Serialize};

use crate::network::Network;

/// Where a wallet's chain data comes from.
///
/// One configuration per network is stored in the settings; wallets on
/// that network all use it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendConfig {
    /// The default public Esplora instances for the network, tried in
    /// order. The honest default: the server operator sees the wallet's
    /// addresses, and the settings screen says so.
    #[default]
    PublicEsplora,
    /// The user's own Esplora-compatible HTTP endpoint.
    CustomEsplora { url: String },
    /// The user's own Electrum server, `ssl://host:port` or
    /// `tcp://host:port`.
    CustomElectrum { url: String },
}

impl BackendConfig {
    /// Short human-readable identifier for sync reports and logs:
    /// the host, never a full URL with potential credentials.
    pub fn label(&self, network: Network) -> String {
        match self {
            BackendConfig::PublicEsplora => network
                .default_esplora_urls()
                .first()
                .and_then(|url| host_of(url))
                .unwrap_or_else(|| "public esplora".to_owned()),
            BackendConfig::CustomEsplora { url } | BackendConfig::CustomElectrum { url } => {
                host_of(url).unwrap_or_else(|| "custom backend".to_owned())
            }
        }
    }
}

/// Extracts the host part of a URL-ish string, without any userinfo.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host_port = rest.split(['/', '?']).next()?;
    let host = host_port.rsplit_once('@').map_or(host_port, |(_, h)| h);
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_hosts_only() {
        assert_eq!(
            BackendConfig::PublicEsplora.label(Network::Mainnet),
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
    }
}
