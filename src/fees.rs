//! Recommended network fee rates, for display.
//!
//! Keyless sources, asked in the order the backend settings imply: the
//! host that already serves the wallet first. Informative display data:
//! failures degrade the UI to a quiet dash, never block anything.
//! Regtest has no fee market.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::price::get_json_through;

/// Recommended fee rates in sat/vB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeeEstimates {
    /// Likely next block.
    pub fastest: f64,
    /// Within roughly 30 minutes.
    pub half_hour: f64,
    /// Within roughly an hour.
    pub hour: f64,
    /// No hurry.
    pub economy: f64,
    /// Relay floor.
    pub minimum: f64,
    /// Unix timestamp, seconds, when the estimates were fetched.
    pub at: u64,
}

fn fee_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "fees".to_owned(),
        detail,
    }
}

/// Public API bases for a network, in priority order: the same
/// operators as the chain backends, so that an instance blocked from
/// the user's network does not leave the card empty. Empty for regtest,
/// which has no fee market.
fn api_bases(network: Network) -> &'static [&'static str] {
    network.default_esplora_urls()
}

/// Whether fee estimates exist for this network at all.
pub fn supports(network: Network) -> bool {
    !api_bases(network).is_empty()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetches the recommended fee rates for a network, honouring the
/// backend the user configured.
///
/// Fee estimates follow the chain backend: whoever serves the wallet's
/// addresses already knows this user, so asking them costs nothing more.
/// A user running their own Esplora is asked alone, with no public
/// fallback — an empty fee card beats a silent call to a host they
/// deliberately left behind.
pub async fn fetch_fees_for(
    network: Network,
    backend: &crate::chain::BackendConfig,
    proxy: Option<&str>,
) -> CoreResult<FeeEstimates> {
    let preferred = backend.fee_base(network);
    let mut bases: Vec<&str> = preferred.into_iter().collect();
    if backend.fees_may_fall_back() {
        for base in api_bases(network) {
            if !bases.contains(base) {
                bases.push(base);
            }
        }
    }
    if bases.is_empty() {
        return Err(fee_error(format!("no fee estimates on {network}")));
    }
    let mut last_error = None;
    for base in bases {
        // An onion host without a route is not asked at all: the point
        // of Tor is that the name never reaches this machine's DNS.
        let route = if crate::chain::is_onion(base) {
            match proxy {
                Some(proxy) => Some(proxy),
                None => {
                    last_error = Some(fee_error(crate::chain::tor::no_route(base)));
                    continue;
                }
            }
        } else {
            None
        };
        match fetch_from(base, route).await {
            Ok(fees) => return Ok(fees),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("at least one base was tried"))
}

/// Asks one host, in both flavours: the mempool projects publish named
/// targets, a plain Esplora publishes a block-to-rate map. The error
/// reported is the second one, the only shape every Esplora serves.
async fn fetch_from(base: &str, proxy: Option<&str>) -> CoreResult<FeeEstimates> {
    if let Ok(value) = get_json_through(&format!("{base}/v1/fees/recommended"), proxy).await
        && let Ok(fees) = parse_fees(&value)
    {
        return Ok(fees);
    }
    parse_esplora_fees(&get_json_through(&format!("{base}/fee-estimates"), proxy).await?)
}

/// Fetches the recommended fee rates from the public servers.
pub async fn fetch_fees(network: Network) -> CoreResult<FeeEstimates> {
    fetch_fees_for(network, &crate::chain::BackendConfig::default(), None).await
}

/// mempool.space shape: `{"fastestFee": n, "halfHourFee": n, ...}`.
fn parse_fees(value: &serde_json::Value) -> CoreResult<FeeEstimates> {
    let field = |name: &str| {
        value[name]
            .as_f64()
            .filter(|rate| rate.is_finite() && *rate > 0.0)
            .ok_or_else(|| fee_error("unexpected response shape".to_owned()))
    };
    Ok(FeeEstimates {
        fastest: field("fastestFee")?,
        half_hour: field("halfHourFee")?,
        hour: field("hourFee")?,
        economy: field("economyFee")?,
        minimum: field("minimumFee")?,
        at: now_secs(),
    })
}

/// Plain Esplora shape: `{"1": rate, "2": rate, ..., "1008": rate}`,
/// the rate that gets a transaction confirmed within that many blocks.
/// The named targets are read off the nearest block Esplora publishes.
fn parse_esplora_fees(value: &serde_json::Value) -> CoreResult<FeeEstimates> {
    let map = value
        .as_object()
        .ok_or_else(|| fee_error("unexpected response shape".to_owned()))?;
    let mut targets: Vec<(u32, f64)> = map
        .iter()
        .filter_map(|(blocks, rate)| Some((blocks.parse::<u32>().ok()?, rate.as_f64()?)))
        .filter(|(_, rate)| rate.is_finite() && *rate > 0.0)
        .collect();
    targets.sort_by_key(|(blocks, _)| *blocks);
    if targets.is_empty() {
        return Err(fee_error("unexpected response shape".to_owned()));
    }
    // Nearest published target at or after the one asked for, else the
    // slowest the server publishes.
    let at = |blocks: u32| {
        targets
            .iter()
            .find(|(published, _)| *published >= blocks)
            .or_else(|| targets.last())
            .map(|(_, rate)| *rate)
            .expect("targets is not empty")
    };
    Ok(FeeEstimates {
        fastest: at(1),
        half_hour: at(3),
        hour: at(6),
        economy: at(144),
        minimum: at(1008),
        at: now_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::BackendConfig;

    #[test]
    fn recommended_fees_parse() {
        let value = serde_json::json!({
            "fastestFee": 12, "halfHourFee": 8.5, "hourFee": 4,
            "economyFee": 2, "minimumFee": 1
        });
        let fees = parse_fees(&value).unwrap();
        assert_eq!(fees.fastest, 12.0);
        assert_eq!(fees.half_hour, 8.5);
        assert_eq!(fees.minimum, 1.0);
    }

    #[test]
    fn malformed_or_zero_rates_are_refused() {
        assert!(parse_fees(&serde_json::json!({"fastestFee": 12})).is_err());
        assert!(
            parse_fees(&serde_json::json!({
                "fastestFee": 0, "halfHourFee": 1, "hourFee": 1,
                "economyFee": 1, "minimumFee": 1
            }))
            .is_err()
        );
    }

    #[test]
    fn regtest_has_no_fee_market() {
        assert!(!supports(Network::Regtest));
        assert!(supports(Network::Mainnet));
        assert!(supports(Network::Signet));
    }

    #[test]
    fn plain_esplora_estimates_parse() {
        let value = serde_json::json!({
            "1": 12.0, "2": 10.0, "3": 8.5, "6": 4.0, "144": 2.0, "1008": 1.02
        });
        let fees = parse_esplora_fees(&value).unwrap();
        assert_eq!(fees.fastest, 12.0);
        assert_eq!(fees.half_hour, 8.5);
        assert_eq!(fees.hour, 4.0);
        assert_eq!(fees.economy, 2.0);
        assert_eq!(fees.minimum, 1.02);
        // A server that publishes fewer targets still answers: each name
        // takes the nearest target at or after it.
        let sparse = parse_esplora_fees(&serde_json::json!({"2": 9.0, "10": 3.0})).unwrap();
        assert_eq!(sparse.fastest, 9.0);
        assert_eq!(sparse.hour, 3.0);
        assert_eq!(sparse.minimum, 3.0);
        assert!(parse_esplora_fees(&serde_json::json!({})).is_err());
        assert!(parse_esplora_fees(&serde_json::json!([1, 2])).is_err());
    }

    #[test]
    fn a_self_hosted_esplora_is_asked_alone() {
        let own = BackendConfig::CustomEsplora {
            url: "https://node.example.org/api".to_owned(),
        };
        assert!(!own.fees_may_fall_back());
        assert!(BackendConfig::default().fees_may_fall_back());
        assert!(
            BackendConfig::CustomElectrum {
                url: "ssl://node.example.org:50002".to_owned()
            }
            .fees_may_fall_back()
        );
    }

    #[tokio::test]
    #[ignore = "talks to the public fee API"]
    async fn mainnet_fees_answer_plausibly() {
        // Some networks block the provider entirely: only assert the
        // shape when it answers, like the price source tests do.
        match fetch_fees(Network::Mainnet).await {
            Ok(fees) => assert!(fees.fastest >= fees.minimum),
            Err(error) => eprintln!("mempool.space unreachable: {error}"),
        }
    }

    #[tokio::test]
    #[ignore = "talks to the public fee API"]
    async fn every_public_esplora_serves_fees() {
        for network in [Network::Mainnet, Network::Signet, Network::Testnet4] {
            for server in crate::chain::public::public_servers(network) {
                if server.protocol != crate::chain::public::ServerProtocol::Esplora {
                    continue;
                }
                let backend = BackendConfig::Public {
                    server: Some(server.id.clone()),
                };
                match fetch_fees_for(network, &backend, None).await {
                    Ok(fees) => assert!(fees.fastest >= fees.minimum, "{}", server.label),
                    Err(error) => eprintln!("{} on {network} unreachable: {error}", server.label),
                }
            }
        }
    }
}
