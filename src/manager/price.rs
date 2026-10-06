//! The fiat price, by the route the syncs take: see [`crate::price`].

use crate::error::CoreResult;
use crate::price::{self, FiatCurrency, PriceHistory, PriceQuote, PriceRange, PriceSource};

use super::WalletManager;

impl WalletManager {
    /// Fetches the current BTC price from one source. It takes the
    /// route the update check takes: through the Tor proxy a sync would
    /// resolve when [`Self::uses_tor`] says so, and when that proxy
    /// cannot be had it fails with [`crate::CoreError::Tor`] before any
    /// request exists. A currency the source does not quote is refused
    /// first, with nothing resolved and nothing sent.
    pub async fn fetch_price(
        &self,
        source: PriceSource,
        currency: FiatCurrency,
    ) -> CoreResult<PriceQuote> {
        price::check_quote(source, currency)?;
        let proxy = self.beside_syncs_proxy().await?;
        price::fetch_price(source, currency, proxy.as_deref()).await
    }

    /// Fetches a BTC price series from one source, by the same route as
    /// [`Self::fetch_price`]. A range or a currency the source cannot
    /// serve is refused first, with nothing resolved and nothing sent.
    pub async fn fetch_price_history(
        &self,
        source: PriceSource,
        currency: FiatCurrency,
        range: PriceRange,
    ) -> CoreResult<PriceHistory> {
        price::check_history(source, currency, range)?;
        let proxy = self.beside_syncs_proxy().await?;
        price::fetch_price_history(source, currency, range, proxy.as_deref()).await
    }
}

#[cfg(test)]
mod tests;
