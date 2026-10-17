//! Fiat price quotes for display.
//!
//! One shared implementation so mobile and desktop show the same figure
//! from the same source. Quotes are informative display data: failures
//! degrade the UI to amounts without fiat, never block anything.
//!
//! The requests go out through [`crate::WalletManager::fetch_price`]
//! and [`crate::WalletManager::fetch_price_history`] and nowhere else,
//! because they have to take the route the syncs take. A price asked
//! every minute beside the Tor circuits of an onion backend would show
//! the source this device's address, timed next to them: with an onion
//! backend configured the request goes through the same Tor proxy, and
//! when Tor cannot be had it does not go at all.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::now_secs;

/// Where the quote comes from. All endpoints are public and keyless.
///
/// Kraken was a source until its terms were read again: they forbid a
/// third-party application that reads their data without their written
/// consent. A vault that stored it reads it as mempool.space, which
/// quotes the same seven currencies, so its other preferences stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceSource {
    Coingecko,
    #[serde(alias = "kraken")]
    MempoolSpace,
}

impl PriceSource {
    pub const ALL: [PriceSource; 2] = [PriceSource::Coingecko, PriceSource::MempoolSpace];

    pub fn label(self) -> &'static str {
        match self {
            PriceSource::Coingecko => "CoinGecko",
            PriceSource::MempoolSpace => "mempool.space",
        }
    }

    /// Whether this source quotes a currency without an API key.
    ///
    /// mempool.space publishes seven; CoinGecko publishes them all.
    pub fn supports_currency(self, currency: FiatCurrency) -> bool {
        match self {
            PriceSource::Coingecko => true,
            PriceSource::MempoolSpace => currency.reach() == CurrencyReach::Every,
        }
    }

    /// Chart ranges this source can serve without an API key.
    ///
    /// CoinGecko caps keyless history at 365 days; mempool.space only
    /// publishes daily closes, too coarse under a month.
    pub fn supports(self, range: PriceRange) -> bool {
        match self {
            PriceSource::Coingecko => range != PriceRange::Max,
            PriceSource::MempoolSpace => {
                matches!(
                    range,
                    PriceRange::Month | PriceRange::Year | PriceRange::Max
                )
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

/// How many price sources quote a currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrencyReach {
    /// Every source quotes it: the seven mempool.space publishes.
    Every,
    /// CoinGecko alone quotes it.
    CoingeckoOnly,
}

/// The one table behind [`FiatCurrency`]: variant, ISO 4217 code,
/// English name, and which sources quote it. Order is display order.
macro_rules! fiat_currencies {
    ($($variant:ident, $code:literal, $name:literal, $reach:ident;)+) => {
        /// Display currencies offered in the settings.
        ///
        /// The first seven are quoted by every source. The rest are the
        /// currencies of the most populous countries and of the places
        /// where Bitcoin is most used; CoinGecko is the only keyless
        /// source that publishes them.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum FiatCurrency {
            $($variant,)+
        }

        impl FiatCurrency {
            /// Every currency, in display order.
            pub const ALL: &'static [FiatCurrency] = &[$(FiatCurrency::$variant,)+];

            /// ISO 4217 code, uppercase.
            pub fn code(self) -> &'static str {
                match self {
                    $(FiatCurrency::$variant => $code,)+
                }
            }

            /// Its English name, to read beside the code: a list of
            /// thirty codes is not a list anyone can read.
            pub fn name(self) -> &'static str {
                match self {
                    $(FiatCurrency::$variant => $name,)+
                }
            }

            /// Which sources quote this currency.
            pub fn reach(self) -> CurrencyReach {
                match self {
                    $(FiatCurrency::$variant => CurrencyReach::$reach,)+
                }
            }
        }
    };
}

fiat_currencies! {
    Eur, "EUR", "Euro", Every;
    Usd, "USD", "US dollar", Every;
    Gbp, "GBP", "Pound sterling", Every;
    Chf, "CHF", "Swiss franc", Every;
    Jpy, "JPY", "Japanese yen", Every;
    Cad, "CAD", "Canadian dollar", Every;
    Aud, "AUD", "Australian dollar", Every;
    Inr, "INR", "Indian rupee", CoingeckoOnly;
    Cny, "CNY", "Chinese yuan", CoingeckoOnly;
    Brl, "BRL", "Brazilian real", CoingeckoOnly;
    Ngn, "NGN", "Nigerian naira", CoingeckoOnly;
    Idr, "IDR", "Indonesian rupiah", CoingeckoOnly;
    Pkr, "PKR", "Pakistani rupee", CoingeckoOnly;
    Bdt, "BDT", "Bangladeshi taka", CoingeckoOnly;
    Rub, "RUB", "Russian ruble", CoingeckoOnly;
    Mxn, "MXN", "Mexican peso", CoingeckoOnly;
    Php, "PHP", "Philippine peso", CoingeckoOnly;
    Vnd, "VND", "Vietnamese dong", CoingeckoOnly;
    Try, "TRY", "Turkish lira", CoingeckoOnly;
    Ars, "ARS", "Argentine peso", CoingeckoOnly;
    Krw, "KRW", "South Korean won", CoingeckoOnly;
    Zar, "ZAR", "South African rand", CoingeckoOnly;
    Thb, "THB", "Thai baht", CoingeckoOnly;
    Uah, "UAH", "Ukrainian hryvnia", CoingeckoOnly;
    Pln, "PLN", "Polish zloty", CoingeckoOnly;
    Sek, "SEK", "Swedish krona", CoingeckoOnly;
    Sgd, "SGD", "Singapore dollar", CoingeckoOnly;
    Hkd, "HKD", "Hong Kong dollar", CoingeckoOnly;
    Aed, "AED", "UAE dirham", CoingeckoOnly;
    Nzd, "NZD", "New Zealand dollar", CoingeckoOnly;
}

/// How often the price is asked while the fiat value is on, and how
/// long a failure waits for the next try: often enough that no amount
/// is priced at the rate of an hour ago, seldom enough for an endpoint
/// that asks for no key.
pub const REFRESH_SECS: u64 = 60;

/// What the settings offer for the fiat value, and how often its price
/// is asked: one table for both apps, which offer what it lists, in its
/// order, and nothing it does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceTable {
    /// Every currency on offer, in display order: the ones every source
    /// quotes first.
    pub currencies: Vec<CurrencyEntry>,
    /// Every source, in display order.
    pub sources: Vec<SourceEntry>,
    /// Seconds from one price to the next while the fiat value is on,
    /// and from a failure to the next try: [`REFRESH_SECS`].
    pub refresh_secs: u64,
}

/// One currency of the [`PriceTable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyEntry {
    pub currency: FiatCurrency,
    /// ISO 4217 code: the identifier, in capitals.
    pub code: String,
    /// Its English name.
    pub name: String,
    /// How many sources quote it, which is how the settings group it.
    pub reach: CurrencyReach,
    /// The sources that quote it, in display order: the ones a settings
    /// screen lets the user pick with it.
    pub sources: Vec<PriceSource>,
}

/// One source of the [`PriceTable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub source: PriceSource,
    /// Its name, as it writes it.
    pub label: String,
    /// The chart ranges it serves without a key, shortest first.
    pub ranges: Vec<PriceRange>,
}

/// The currencies and sources on offer, and how often a price is asked.
pub fn price_table() -> PriceTable {
    PriceTable {
        currencies: FiatCurrency::ALL
            .iter()
            .map(|&currency| CurrencyEntry {
                currency,
                code: currency.code().to_owned(),
                name: currency.name().to_owned(),
                reach: currency.reach(),
                sources: PriceSource::ALL
                    .into_iter()
                    .filter(|source| source.supports_currency(currency))
                    .collect(),
            })
            .collect(),
        sources: PriceSource::ALL
            .into_iter()
            .map(|source| SourceEntry {
                source,
                label: source.label().to_owned(),
                ranges: PriceRange::ALL
                    .into_iter()
                    .filter(|&range| source.supports(range))
                    .collect(),
            })
            .collect(),
        refresh_secs: REFRESH_SECS,
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

/// An HTTP client, optionally through a SOCKS proxy.
///
/// `socks5h` and not `socks5`: the proxy resolves the name, so a
/// `.onion` host never reaches this machine's DNS resolver.
pub(crate) fn client_through(proxy: Option<&str>) -> CoreResult<reqwest::Client> {
    let mut builder = crate::chain::http_client()
        .timeout(std::time::Duration::from_secs(if proxy.is_some() {
            60
        } else {
            15
        }))
        .user_agent("gerfaut")
        .redirect(crate::chain::redirects());
    if let Some(proxy) = proxy {
        builder = builder.proxy(
            reqwest::Proxy::all(format!("socks5h://{proxy}"))
                .map_err(|e| CoreError::Internal(format!("tor proxy: {e}")))?,
        );
    }
    builder
        .build()
        .map_err(|e| CoreError::Internal(format!("http client: {e}")))
}

/// One GET for a JSON answer, through `proxy` when there is one.
async fn get_json(url: &str, proxy: Option<&str>) -> CoreResult<serde_json::Value> {
    let mut response = client_through(proxy)?
        .get(url)
        .send()
        .await
        .map_err(|e| price_error(e.to_string()))?;
    if !response.status().is_success() {
        return Err(price_error(format!("http {}", response.status())));
    }
    // Read a chunk at a time, once decompressed: a small gzip of a huge
    // body is cut off, not held whole.
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| price_error(e.to_string()))?
    {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err(price_error("the answer is far too large".to_owned()));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| price_error(e.to_string()))
}

/// Largest price answer read: the whole daily history of every currency
/// mempool.space serves fits several times over.
const MAX_ANSWER: usize = 32 << 20;

fn price_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "price".to_owned(),
        detail,
    }
}

/// Refuses a currency the source does not quote, before anything is
/// sent or any route resolved.
pub(crate) fn check_quote(source: PriceSource, currency: FiatCurrency) -> CoreResult<()> {
    if !source.supports_currency(currency) {
        return Err(price_error(format!(
            "{} does not quote {}",
            source.label(),
            currency.code()
        )));
    }
    Ok(())
}

/// Refuses a range or a currency the source cannot serve, before
/// anything is sent or any route resolved.
pub(crate) fn check_history(
    source: PriceSource,
    currency: FiatCurrency,
    range: PriceRange,
) -> CoreResult<()> {
    if !source.supports(range) {
        return Err(price_error(format!(
            "{} cannot serve this range",
            source.label()
        )));
    }
    check_quote(source, currency)
}

/// Fetches the current BTC price from one source, through `proxy` when
/// the manager resolved one. The source must quote the currency
/// ([`PriceSource::supports_currency`]); the preferences never hold a
/// pair that does not.
pub(crate) async fn fetch_price(
    source: PriceSource,
    currency: FiatCurrency,
    proxy: Option<&str>,
) -> CoreResult<PriceQuote> {
    check_quote(source, currency)?;
    let rate = match source {
        PriceSource::Coingecko => {
            let code = currency.code().to_lowercase();
            let value = get_json(
                &format!(
                    "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={code}"
                ),
                proxy,
            )
            .await?;
            value["bitcoin"][&code]
                .as_f64()
                .ok_or_else(|| price_error("unexpected response shape".to_owned()))?
        }
        PriceSource::MempoolSpace => {
            let value = get_json("https://mempool.space/api/v1/prices", proxy).await?;
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

/// Fetches a BTC price series from one source, through `proxy` when
/// the manager resolved one. The source must support the range
/// (`PriceSource::supports`); callers hide unsupported ranges.
pub(crate) async fn fetch_price_history(
    source: PriceSource,
    currency: FiatCurrency,
    range: PriceRange,
    proxy: Option<&str>,
) -> CoreResult<PriceHistory> {
    check_history(source, currency, range)?;
    let mut points = match source {
        PriceSource::Coingecko => {
            let days = match range {
                PriceRange::Day => "1",
                PriceRange::Week => "7",
                PriceRange::Month => "30",
                PriceRange::Year | PriceRange::Max => "365",
            };
            let code = currency.code().to_lowercase();
            let value = get_json(
                &format!(
                    "https://api.coingecko.com/api/v3/coins/bitcoin/market_chart?vs_currency={code}&days={days}"
                ),
                proxy,
            )
            .await?;
            parse_coingecko_history(&value)?
        }
        PriceSource::MempoolSpace => {
            // One endpoint, the full daily history for every currency.
            let value = get_json("https://mempool.space/api/v1/historical-price", proxy).await?;
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
    let mut thinned: Vec<PricePoint> = (0..max - 1).map(|i| points[i * last / (max - 1)]).collect();
    thinned.push(points[last]);
    thinned
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The price goes out straight, or through the Tor proxy, and never
    /// through a proxy the environment names.
    #[test]
    fn a_price_takes_no_proxy_but_tor() {
        assert!(!crate::chain::takes_a_proxy(&client_through(None).unwrap()));
        assert!(crate::chain::takes_a_proxy(
            &client_through(Some("127.0.0.1:9050")).unwrap()
        ));
    }

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

    /// Kraken left the sources: a vault or an app that still spells it
    /// reads mempool.space, which quotes the same seven currencies, and
    /// nothing writes it again.
    #[test]
    fn kraken_reads_as_mempool_space() {
        assert_eq!(
            serde_json::from_str::<PriceSource>("\"kraken\"").unwrap(),
            PriceSource::MempoolSpace
        );
        assert_eq!(
            serde_json::to_string(&PriceSource::MempoolSpace).unwrap(),
            "\"mempool_space\""
        );
        assert!(serde_json::from_str::<PriceSource>("\"bitstamp\"").is_err());
    }

    #[test]
    fn currency_codes_are_unique_iso_4217() {
        let codes: std::collections::BTreeSet<&str> =
            FiatCurrency::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(codes.len(), FiatCurrency::ALL.len());
        for currency in FiatCurrency::ALL {
            let code = currency.code();
            assert_eq!(code.len(), 3, "{code}");
            assert!(code.chars().all(|c| c.is_ascii_uppercase()), "{code}");
        }
    }

    /// The apps write a code as the identifier in capitals, the way the
    /// table spells it: the two never part.
    #[test]
    fn a_code_is_its_identifier_in_capitals() {
        for currency in FiatCurrency::ALL {
            let id = serde_json::to_value(currency).unwrap();
            assert_eq!(id.as_str().unwrap().to_uppercase(), currency.code());
        }
    }

    /// The table lists every currency and every source in display
    /// order, each currency with the sources that quote it and each
    /// source with the ranges it serves.
    #[test]
    fn the_table_is_the_one_behind_the_types() {
        let table = price_table();
        assert_eq!(table.refresh_secs, 60);
        let currencies: Vec<FiatCurrency> = table
            .currencies
            .iter()
            .map(|entry| entry.currency)
            .collect();
        assert_eq!(currencies, FiatCurrency::ALL);
        for entry in &table.currencies {
            assert_eq!(entry.code, entry.currency.code());
            assert!(!entry.name.is_empty());
            assert_eq!(entry.reach, entry.currency.reach());
            for source in PriceSource::ALL {
                assert_eq!(
                    entry.sources.contains(&source),
                    source.supports_currency(entry.currency),
                    "{} from {source:?}",
                    entry.code
                );
            }
        }
        let sources: Vec<PriceSource> = table.sources.iter().map(|entry| entry.source).collect();
        assert_eq!(sources, PriceSource::ALL);
        let mempool = &table.sources[1];
        assert_eq!(mempool.label, "mempool.space");
        assert_eq!(
            mempool.ranges,
            [PriceRange::Month, PriceRange::Year, PriceRange::Max]
        );
        assert_eq!(
            serde_json::to_value(&table.currencies[0]).unwrap(),
            serde_json::json!({
                "currency": "eur",
                "code": "EUR",
                "name": "Euro",
                "reach": "every",
                "sources": ["coingecko", "mempool_space"],
            })
        );
    }

    #[test]
    fn every_source_quotes_the_seven_shared_currencies() {
        let shared: Vec<&FiatCurrency> = FiatCurrency::ALL
            .iter()
            .filter(|c| c.reach() == CurrencyReach::Every)
            .collect();
        assert_eq!(shared.len(), 7);
        for currency in &shared {
            for source in PriceSource::ALL {
                assert!(
                    source.supports_currency(**currency),
                    "{source:?} misses {}",
                    currency.code()
                );
            }
        }
        // The shared seven come first: the settings list them before the
        // ones only one source can serve.
        assert!(
            FiatCurrency::ALL[..7]
                .iter()
                .all(|c| c.reach() == CurrencyReach::Every)
        );
    }

    #[test]
    fn the_wider_list_is_coingecko_alone() {
        let wide: Vec<&FiatCurrency> = FiatCurrency::ALL
            .iter()
            .filter(|c| c.reach() == CurrencyReach::CoingeckoOnly)
            .collect();
        assert!(wide.len() >= 20, "the wider list is too thin");
        for currency in wide {
            assert!(PriceSource::Coingecko.supports_currency(*currency));
            assert!(!PriceSource::MempoolSpace.supports_currency(*currency));
        }
    }

    #[tokio::test]
    async fn a_source_refuses_a_currency_it_does_not_quote() {
        // Refused before any request goes out.
        let error = fetch_price(PriceSource::MempoolSpace, FiatCurrency::Inr, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("INR"), "{error}");
        assert!(
            fetch_price_history(
                PriceSource::MempoolSpace,
                FiatCurrency::Ngn,
                PriceRange::Year,
                None
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn range_support_matches_keyless_capabilities() {
        // Every range has a source.
        for range in PriceRange::ALL {
            assert!(
                PriceSource::ALL
                    .into_iter()
                    .any(|source| source.supports(range))
            );
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
            match fetch_price(source, FiatCurrency::Eur, None).await {
                Ok(quote) => {
                    reachable += 1;
                    assert!(quote.rate > 1_000.0, "{source:?} gave {}", quote.rate);
                }
                Err(error) => eprintln!("{source:?} unreachable: {error}"),
            }
        }
        assert!(reachable >= 1, "no price source reachable");
    }

    /// Cross-checks the table against the live APIs: every currency
    /// listed must actually come back with a rate.
    ///
    /// One request per source, never one per currency: the keyless
    /// CoinGecko endpoint rate-limits a burst within seconds, and
    /// sweeping thirty codes one by one would test the limiter instead
    /// of the table.
    #[tokio::test]
    #[ignore = "talks to public price APIs"]
    async fn every_listed_currency_is_really_quoted() {
        let codes: Vec<String> = FiatCurrency::ALL
            .iter()
            .map(|c| c.code().to_lowercase())
            .collect();
        let value = get_json(
            &format!(
                "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={}",
                codes.join(",")
            ),
            None,
        )
        .await
        .expect("CoinGecko unreachable");
        for code in &codes {
            let rate = value["bitcoin"][code].as_f64();
            assert!(rate.is_some_and(|r| r > 100.0), "CoinGecko misses {code}");
        }

        // The seven shared ones, from mempool.space.
        let mempool = get_json("https://mempool.space/api/v1/prices", None)
            .await
            .expect("mempool.space unreachable");
        for currency in FiatCurrency::ALL {
            if currency.reach() != CurrencyReach::Every {
                continue;
            }
            assert!(
                mempool[currency.code()].as_f64().is_some_and(|r| r > 100.0),
                "mempool.space misses {}",
                currency.code()
            );
        }
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
                match fetch_price_history(source, FiatCurrency::Usd, range, None).await {
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
