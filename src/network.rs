//! Supported Bitcoin networks and their default public backends.

use serde::{Deserialize, Serialize};

/// Networks Gerfaut can operate on.
///
/// Testnet v3 is intentionally absent: it is being sunset in favor of
/// Testnet 4, and inputs carrying v3 version bytes are treated as Testnet 4
/// material (the encodings are identical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Signet,
    Testnet4,
    Regtest,
}

impl Network {
    /// All networks, in display order.
    pub const ALL: [Network; 4] = [
        Network::Mainnet,
        Network::Signet,
        Network::Testnet4,
        Network::Regtest,
    ];

    /// Mapping to the `rust-bitcoin` network type.
    pub fn to_bitcoin(self) -> bdk_wallet::bitcoin::Network {
        use bdk_wallet::bitcoin::Network as B;
        match self {
            Network::Mainnet => B::Bitcoin,
            Network::Signet => B::Signet,
            Network::Testnet4 => B::Testnet4,
            Network::Regtest => B::Regtest,
        }
    }

    /// Mapping from the `rust-bitcoin` network type.
    ///
    /// Testnet v3 maps to [`Network::Testnet4`]: address and key encodings
    /// are shared between the two, only the chain differs, and Gerfaut only
    /// syncs against Testnet 4.
    pub fn from_bitcoin(network: bdk_wallet::bitcoin::Network) -> Self {
        use bdk_wallet::bitcoin::Network as B;
        match network {
            B::Bitcoin => Network::Mainnet,
            B::Signet => Network::Signet,
            B::Testnet | B::Testnet4 => Network::Testnet4,
            B::Regtest => Network::Regtest,
        }
    }

    /// Default public Esplora endpoints for this network, in priority order.
    ///
    /// Empty for regtest: a local backend must be configured explicitly.
    pub fn default_esplora_urls(self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &["https://mempool.space/api", "https://blockstream.info/api"],
            Network::Signet => &[
                "https://mempool.space/signet/api",
                "https://blockstream.info/signet/api",
            ],
            Network::Testnet4 => &["https://mempool.space/testnet4/api"],
            Network::Regtest => &[],
        }
    }

    /// Stable machine identifier, also used in serialized form.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Signet => "signet",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Network {
    type Err = crate::CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "bitcoin" => Ok(Network::Mainnet),
            "signet" => Ok(Network::Signet),
            "testnet4" | "testnet" => Ok(Network::Testnet4),
            "regtest" => Ok(Network::Regtest),
            other => Err(crate::CoreError::InvalidInput {
                kind: "network",
                detail: format!("unknown network `{other}`"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_roundtrip() {
        for network in Network::ALL {
            assert_eq!(Network::from_bitcoin(network.to_bitcoin()), network);
        }
    }

    #[test]
    fn testnet3_maps_to_testnet4() {
        assert_eq!(
            Network::from_bitcoin(bdk_wallet::bitcoin::Network::Testnet),
            Network::Testnet4
        );
    }

    #[test]
    fn serde_uses_lowercase() {
        assert_eq!(
            serde_json::to_string(&Network::Testnet4).unwrap(),
            "\"testnet4\""
        );
    }

    #[test]
    fn every_network_but_regtest_has_public_backends() {
        for network in Network::ALL {
            if network == Network::Regtest {
                assert!(network.default_esplora_urls().is_empty());
            } else {
                assert!(!network.default_esplora_urls().is_empty());
            }
        }
    }
}
