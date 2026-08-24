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

    /// Chart ranges this source can serve without an API key.
    ///
    /// CoinGecko caps keyless history at 365 days; mempool.space only
    /// publishes daily closes, too coarse under a month.
    pub fn supports(self, range: PriceRange) -> bool {
        match self {
            PriceSource::Kraken => true,
            PriceSource::Coingecko => range != PriceRange::Max,
            PriceSource::MempoolSpace => {
                matches!(range, PriceRange::Month | PriceRange::Year | PriceRange::Max)
            }
        }
    }
}

/// Time span of a price chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceRange {
    Day,
    Week,
    Month,
    Year,
    Max,
}

impl PriceRange {
    pub const ALL: [PriceRange; 5] = [
        PriceRange::Day,
        PriceRange::Week,
        PriceRange::Month,
        PriceRange::Year,
        PriceRange::Max,
    ];

    /// Seconds of history covered; `None` means everything the source has.
    fn cutoff_secs(self) -> Option<u64> {
        match self {
            PriceRange::Day => Some(86_400),
            PriceRange::Week => Some(7 * 86_400),
            PriceRange::Month => Some(30 * 86_400),
            PriceRange::Year => Some(365 * 86_400),
            PriceRange::Max => None,
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

// --- history -----------------------------------------------------------

/// One point of a price series.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PricePoint {
    /// Unix timestamp, seconds.
    pub t: u64,
    /// Price of 1 BTC in the currency at that time.
    pub rate: f64,
}

/// A BTC price series in a fiat currency, oldest point first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceHistory {
    pub points: Vec<PricePoint>,
    pub currency: FiatCurrency,
    pub source: PriceSource,
    pub range: PriceRange,
    /// Unix timestamp, seconds, when the series was fetched.
    pub at: u64,
}

/// Enough for a chart at any width; series are thinned above this.
const MAX_POINTS: usize = 480;

/// Fetches a BTC price series from one source. The source must support
/// the range (`PriceSource::supports`); callers hide unsupported ranges.
pub async fn fetch_price_history(
    source: PriceSource,
    currency: FiatCurrency,
    range: PriceRange,
) -> CoreResult<PriceHistory> {
    if !source.supports(range) {
        return Err(price_error(format!(
            "{} cannot serve this range",
            source.label()
        )));
    }
    let mut points = match source {
        PriceSource::Coingecko => {
            let days = match range {
                PriceRange::Day => "1",
                PriceRange::Week => "7",
                PriceRange::Month => "30",
                PriceRange::Year | PriceRange::Max => "365",
            };
            let code = currency.code().to_lowercase();
            let value = get_json(&format!(
                "https://api.coingecko.com/api/v3/coins/bitcoin/market_chart?vs_currency={code}&days={days}"
            ))
            .await?;
            parse_coingecko_history(&value)?
        }
        PriceSource::Kraken => {
            // 720 candles per call: the interval decides the span.
            let interval = match range {
                PriceRange::Day => 5,
                PriceRange::Week => 30,
                PriceRange::Month => 240,
                PriceRange::Year => 1440,
                PriceRange::Max => 10080,
            };
            let pair = format!("XBT{}", currency.code());
            let value = get_json(&format!(
                "https://api.kraken.com/0/public/OHLC?pair={pair}&interval={interval}"
            ))
            .await?;
            parse_kraken_history(&value)?
        }
        PriceSource::MempoolSpace => {
            // One endpoint, the full daily history for every currency.
            let value = get_json("https://mempool.space/api/v1/historical-price").await?;
            parse_mempool_history(&value, currency)?
        }
    };
    points.retain(|p| p.rate.is_finite() && p.rate > 0.0);
    points.sort_by_key(|p| p.t);
    points.dedup_by_key(|p| p.t);
    let now = now_secs();
    if let Some(cutoff) = range.cutoff_secs() {
        let oldest = now.saturating_sub(cutoff);
        points.retain(|p| p.t >= oldest);
    }
    let points = thin_series(points, MAX_POINTS);
    if points.len() < 2 {
        return Err(price_error("not enough points for a chart".to_owned()));
    }
    Ok(PriceHistory {
        points,
        currency,
        source,
        range,
        at: now,
    })
}

/// CoinGecko market_chart: `{"prices": [[ms, price], ...]}`.
fn parse_coingecko_history(value: &serde_json::Value) -> CoreResult<Vec<PricePoint>> {
    let rows = value["prices"]
        .as_array()
        .ok_or_else(|| price_error("unexpected response shape".to_owned()))?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let ms = row.get(0)?.as_f64()?;
            let rate = row.get(1)?.as_f64()?;
            Some(PricePoint {
                t: (ms / 1000.0) as u64,
                rate,
            })
        })
        .collect())
}

/// Kraken OHLC: `{"result": {"<pair>": [[time, o, h, l, close, ...]], "last": n}}`.
/// The pair key varies (`XXBTZUSD`...): take the entry that is an array.
fn parse_kraken_history(value: &serde_json::Value) -> CoreResult<Vec<PricePoint>> {
    let result = value["result"]
        .as_object()
        .ok_or_else(|| price_error("unexpected response shape".to_owned()))?;
    let rows = result
        .iter()
        .find_map(|(key, entry)| (key != "last").then(|| entry.as_array()).flatten())
        .ok_or_else(|| price_error("unexpected response shape".to_owned()))?;
    Ok(rows
        .iter()
        .filter_map(|candle| {
            let t = candle.get(0)?.as_u64()?;
            let close = candle.get(4)?.as_str()?.parse::<f64>().ok()?;
            Some(PricePoint { t, rate: close })
        })
        .collect())
}

/// mempool.space historical prices: `{"prices": [{"time": s, "USD": n, ...}]}`.
fn parse_mempool_history(
    value: &serde_json::Value,
    currency: FiatCurrency,
) -> CoreResult<Vec<PricePoint>> {
    let rows = value["prices"]
        .as_array()
        .ok_or_else(|| price_error("unexpected response shape".to_owned()))?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let t = row["time"].as_u64()?;
            let rate = row[currency.code()].as_f64()?;
            Some(PricePoint { t, rate })
        })
        .collect())
}

/// Thins a sorted series to at most `max` points, keeping both ends.
fn thin_series(points: Vec<PricePoint>, max: usize) -> Vec<PricePoint> {
    if points.len() <= max || max < 2 {
        return points;
    }
    let last = points.len() - 1;
    let mut thinned: Vec<PricePoint> = (0..max - 1)
        .map(|i| points[i * last / (max - 1)])
        .collect();
    thinned.push(points[last]);
    thinned
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
        assert_eq!(serde_json::to_string(&PriceRange::Max).unwrap(), "\"max\"");
        assert_eq!(serde_json::to_string(&PriceRange::Day).unwrap(), "\"day\"");
    }

    #[test]
    fn range_support_matches_keyless_capabilities() {
        for range in PriceRange::ALL {
            assert!(PriceSource::Kraken.supports(range));
        }
        assert!(PriceSource::Coingecko.supports(PriceRange::Day));
        assert!(!PriceSource::Coingecko.supports(PriceRange::Max));
        assert!(!PriceSource::MempoolSpace.supports(PriceRange::Day));
        assert!(!PriceSource::MempoolSpace.supports(PriceRange::Week));
        assert!(PriceSource::MempoolSpace.supports(PriceRange::Max));
    }

    #[test]
    fn coingecko_history_parses() {
        let value = serde_json::json!({
            "prices": [[1700000000000.0_f64, 35000.5], [1700003600000.0_f64, 35100.0]],
            "market_caps": [], "total_volumes": []
        });
        let points = parse_coingecko_history(&value).unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].t, 1_700_000_000);
        assert_eq!(points[0].rate, 35000.5);
    }

    #[test]
    fn kraken_history_skips_the_last_cursor() {
        // "last" sorts before the pair key in a BTreeMap: the parser must
        // not trip on it.
        let value = serde_json::json!({
            "error": [],
            "result": {
                "last": 1700003600,
                "XXBTZEUR": [
                    [1700000000, "1.0", "2.0", "0.5", "34000.1", "1.5", "10.0", 42],
                    [1700003600, "1.0", "2.0", "0.5", "34100.2", "1.5", "10.0", 42]
                ]
            }
        });
        let points = parse_kraken_history(&value).unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[1].rate, 34100.2);
    }

    #[test]
    fn mempool_history_reads_the_requested_currency() {
        let value = serde_json::json!({
            "prices": [
                {"time": 1700000000, "USD": 35000.0, "EUR": 32000.0},
                {"time": 1700086400, "USD": 35500.0, "EUR": 32400.0}
            ],
            "exchangeRates": {}
        });
        let points = parse_mempool_history(&value, FiatCurrency::Eur).unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].rate, 32000.0);
        let usd = parse_mempool_history(&value, FiatCurrency::Usd).unwrap();
        assert_eq!(usd[1].rate, 35500.0);
    }

    #[test]
    fn thinning_keeps_both_ends_and_the_cap() {
        let points: Vec<PricePoint> = (0..2000)
            .map(|i| PricePoint {
                t: i,
                rate: 1.0 + i as f64,
            })
            .collect();
        let thinned = thin_series(points.clone(), 480);
        assert_eq!(thinned.len(), 480);
        assert_eq!(thinned[0].t, 0);
        assert_eq!(thinned[479].t, 1999);
        // Short series pass through untouched.
        assert_eq!(thin_series(points[..10].to_vec(), 480).len(), 10);
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

    #[tokio::test]
    #[ignore = "talks to public price APIs"]
    async fn histories_answer_with_plausible_series() {
        let mut reachable = 0;
        for source in PriceSource::ALL {
            for range in PriceRange::ALL {
                if !source.supports(range) {
                    continue;
                }
                match fetch_price_history(source, FiatCurrency::Usd, range).await {
                    Ok(history) => {
                        reachable += 1;
                        assert!(history.points.len() >= 2, "{source:?} {range:?} too short");
                        assert!(history.points.len() <= MAX_POINTS);
                        assert!(
                            history.points.windows(2).all(|w| w[0].t < w[1].t),
                            "{source:?} {range:?} not sorted"
                        );
                    }
                    Err(error) => eprintln!("{source:?} {range:?} unreachable: {error}"),
                }
            }
        }
        assert!(reachable >= 1, "no history source reachable");
    }
}
