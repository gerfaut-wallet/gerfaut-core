//! Fiat price quotes for display.
//!
//! One shared implementation so mobile and desktop show the same figure
//! from the same source. Quotes are informative display data: failures
//! degrade the UI to amounts without fiat, never block anything.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Where the quote comes from. All endpoints are public and keyless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceSource {
    Coingecko,
    Kraken,
    MempoolSpace,
}

impl PriceSource {
    pub const ALL: [PriceSource; 3] = [
        PriceSource::Coingecko,
        PriceSource::Kraken,
        PriceSource::MempoolSpace,
    ];

    pub fn label(self) -> &'static str {
        match self {
            PriceSource::Coingecko => "CoinGecko",
            PriceSource::Kraken => "Kraken",
            PriceSource::MempoolSpace => "mempool.space",
        }
    }
}

/// Display currencies offered in the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FiatCurrency {
    Eur,
    Usd,
    Gbp,
    Chf,
}

impl FiatCurrency {
    pub const ALL: [FiatCurrency; 4] = [
        FiatCurrency::Eur,
        FiatCurrency::Usd,
        FiatCurrency::Gbp,
        FiatCurrency::Chf,
    ];

    /// ISO 4217 code, uppercase.
    pub fn code(self) -> &'static str {
        match self {
            FiatCurrency::Eur => "EUR",
            FiatCurrency::Usd => "USD",
            FiatCurrency::Gbp => "GBP",
            FiatCurrency::Chf => "CHF",
        }
    }
}

/// One BTC priced in a fiat currency, at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceQuote {
    /// Price of 1 BTC in the currency.
    pub rate: f64,
    pub currency: FiatCurrency,
    pub source: PriceSource,
    /// Unix timestamp, seconds, when the quote was fetched.
    pub at: u64,
}

fn http_client() -> CoreResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("gerfaut")
        .build()
        .map_err(|e| CoreError::Internal(format!("http client: {e}")))
}

async fn get_json(url: &str) -> CoreResult<serde_json::Value> {
    let response = http_client()?
        .get(url)
        .send()
        .await
        .map_err(|e| price_error(e.to_string()))?;
    if !response.status().is_success() {
        return Err(price_error(format!("http {}", response.status())));
    }
    response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| price_error(e.to_string()))
}

fn price_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "price".to_owned(),
        detail,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetches the current BTC price from one source.
pub async fn fetch_price(source: PriceSource, currency: FiatCurrency) -> CoreResult<PriceQuote> {
    let rate = match source {
        PriceSource::Coingecko => {
            let code = currency.code().to_lowercase();
            let value = get_json(&format!(
                "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={code}"
            ))
            .await?;
            value["bitcoin"][&code]
                .as_f64()
                .ok_or_else(|| price_error("unexpected response shape".to_owned()))?
        }
        PriceSource::Kraken => {
            let pair = format!("XBT{}", currency.code());
            let value = get_json(&format!(
                "https://api.kraken.com/0/public/Ticker?pair={pair}"
            ))
            .await?;
            let result = value["result"]
                .as_object()
                .and_then(|o| o.values().next())
                .ok_or_else(|| price_error("unexpected response shape".to_owned()))?;
            result["c"][0]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .ok_or_else(|| price_error("unexpected response shape".to_owned()))?
        }
        PriceSource::MempoolSpace => {
            let value = get_json("https://mempool.space/api/v1/prices").await?;
            value[currency.code()]
                .as_f64()
                .ok_or_else(|| price_error("unexpected response shape".to_owned()))?
        }
    };
    if !rate.is_finite() || rate <= 0.0 {
        return Err(price_error(format!("implausible rate {rate}")));
    }
    Ok(PriceQuote {
        rate,
        currency,
        source,
        at: now_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_spellings_are_stable() {
        assert_eq!(
            serde_json::to_string(&PriceSource::MempoolSpace).unwrap(),
            "\"mempool_space\""
        );
        assert_eq!(
            serde_json::to_string(&FiatCurrency::Eur).unwrap(),
            "\"eur\""
        );
    }

    #[tokio::test]
    #[ignore = "talks to public price APIs"]
    async fn sources_answer_with_plausible_rates() {
        // Some networks block individual providers; require that every
        // reachable source gives a plausible rate and at least one is
        // reachable at all.
        let mut reachable = 0;
        for source in PriceSource::ALL {
            match fetch_price(source, FiatCurrency::Eur).await {
                Ok(quote) => {
                    reachable += 1;
                    assert!(quote.rate > 1_000.0, "{source:?} gave {}", quote.rate);
                }
                Err(error) => eprintln!("{source:?} unreachable: {error}"),
            }
        }
        assert!(reachable >= 1, "no price source reachable");
    }
}
