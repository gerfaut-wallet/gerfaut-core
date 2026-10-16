//! The fiat price, by the preferences and by the route the syncs take:
//! see [`crate::price`].

use crate::error::CoreResult;
use crate::price::{self, PriceHistory, PriceQuote, PriceRange};

use super::WalletManager;

impl WalletManager {
    /// The current BTC price, in the currency and from the source the
    /// preferences name ([`crate::prefs::Preferences`]). The apps ask
    /// again every [`price::REFRESH_SECS`], and only while something on
    /// screen shows it: the fiat value, or a widget placed for it.
    ///
    /// It takes the route the update check takes: through the Tor proxy
    /// a sync would resolve when [`Self::uses_tor`] says so, and when
    /// that proxy cannot be had it fails with [`crate::CoreError::Tor`]
    /// before any request exists.
    pub async fn fetch_price(&self) -> CoreResult<PriceQuote> {
        let preferences = self.preferences().await;
        let (source, currency) = (preferences.price_source, preferences.fiat_currency);
        price::check_quote(source, currency)?;
        let proxy = self.beside_syncs_proxy().await?;
        price::fetch_price(source, currency, proxy.as_deref()).await
    }

    /// A BTC price series over `range`, by the same preferences and the
    /// same route as [`Self::fetch_price`]. A range the source cannot
    /// serve is refused first, with nothing resolved and nothing sent.
    pub async fn fetch_price_history(&self, range: PriceRange) -> CoreResult<PriceHistory> {
        let preferences = self.preferences().await;
        let (source, currency) = (preferences.price_source, preferences.fiat_currency);
        price::check_history(source, currency, range)?;
        let proxy = self.beside_syncs_proxy().await?;
        price::fetch_price_history(source, currency, range, proxy.as_deref()).await
    }
}

#[cfg(test)]
mod tests;
