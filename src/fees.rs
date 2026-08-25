//! Recommended network fee rates, for display.
//!
//! One keyless source, mempool.space, which serves per-network
//! endpoints. Informative display data: failures degrade the UI to a
//! quiet dash, never block anything. Regtest has no fee market.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::price::get_json;

/// Recommended fee rates in sat/vB, as published by mempool.space.
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

/// The mempool.space API base for a network, when it has a fee market.
fn api_base(network: Network) -> Option<&'static str> {
    match network {
        Network::Mainnet => Some("https://mempool.space/api"),
        Network::Signet => Some("https://mempool.space/signet/api"),
        Network::Testnet4 => Some("https://mempool.space/testnet4/api"),
        Network::Regtest => None,
    }
}

/// Whether fee estimates exist for this network at all.
pub fn supports(network: Network) -> bool {
    api_base(network).is_some()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetches the recommended fee rates for a network.
pub async fn fetch_fees(network: Network) -> CoreResult<FeeEstimates> {
    let base =
        api_base(network).ok_or_else(|| fee_error(format!("no fee estimates on {network}")))?;
    let value = get_json(&format!("{base}/v1/fees/recommended")).await?;
    parse_fees(&value)
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    #[ignore = "talks to the public fee API"]
    async fn mainnet_fees_answer_plausibly() {
        let fees = fetch_fees(Network::Mainnet).await.unwrap();
        assert!(fees.fastest >= fees.minimum);
    }
}
