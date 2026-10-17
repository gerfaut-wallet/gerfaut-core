//! The preferences both apps keep with the same meaning.
//!
//! The unit, the masked amounts, the fiat value with its currency and
//! its source, the alerts, and the warning before an explorer opens:
//! the desktop and Android offer each of them, and each means the same
//! thing on both. They are one record of the vault, with their defaults
//! and their rules here, so that no app decides what a vault that never
//! stored one shows, nor which pair of currency and source can be.
//!
//! What only one app has, or what each app means in its own way (the
//! theme, the sidebar, the welcome tour, a home screen widget), stays
//! in [`crate::store::Settings::app_prefs`]. None of it goes into a
//! backup.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::price::{FiatCurrency, PriceSource};

/// The unit every amount is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    #[default]
    Btc,
    Sats,
}

/// The preferences both apps keep, as the vault holds them. A field a
/// vault never stored reads as its default, and the pair of currency
/// and source read is made one that exists, as [`Preferences::change`]
/// makes it: a record that holds a currency and no source, or a source
/// that does not quote the currency, never loads a price that fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Stored")]
pub struct Preferences {
    /// The unit of every amount. BTC by default.
    pub unit: Unit,
    /// Amounts hidden on screen, and in what a notification says.
    pub masked: bool,
    /// The fiat value beside every amount. Off by default: a price is a
    /// request to a third party, which learns that a bitcoin wallet
    /// opened here just now, and the screens ask for none until this
    /// says yes. A home screen widget placed for the price is an opt-in
    /// of its own.
    pub fiat: bool,
    /// The currency of the fiat value. The euro by default.
    pub fiat_currency: FiatCurrency,
    /// Where the price comes from. mempool.space by default, for the
    /// seven currencies it quotes: it is already among the servers the
    /// syncs ask, so the price adds no third party. CoinGecko for the
    /// others. Always one that quotes [`Self::fiat_currency`]: see
    /// [`Preferences::change`].
    pub price_source: PriceSource,
    /// A notification when a transaction shows up and when it confirms.
    /// Off by default: watching keeps a connection open, which tells the
    /// server how long the app stays up.
    pub notify_new_tx: bool,
    /// The warning before a transaction opens in an external explorer was
    /// read and accepted: it is not shown again.
    pub explorer_ack: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            unit: Unit::Btc,
            masked: false,
            fiat: false,
            fiat_currency: FiatCurrency::Eur,
            price_source: PriceSource::MempoolSpace,
            notify_new_tx: false,
            explorer_ack: false,
        }
    }
}

/// The preferences as a record holds them, before the pair of currency
/// and source is made one that exists.
#[derive(Deserialize)]
#[serde(default)]
struct Stored {
    unit: Unit,
    masked: bool,
    fiat: bool,
    fiat_currency: FiatCurrency,
    price_source: PriceSource,
    notify_new_tx: bool,
    explorer_ack: bool,
}

impl Default for Stored {
    fn default() -> Self {
        let Preferences {
            unit,
            masked,
            fiat,
            fiat_currency,
            price_source,
            notify_new_tx,
            explorer_ack,
        } = Preferences::default();
        Stored {
            unit,
            masked,
            fiat,
            fiat_currency,
            price_source,
            notify_new_tx,
            explorer_ack,
        }
    }
}

impl From<Stored> for Preferences {
    fn from(stored: Stored) -> Self {
        let Stored {
            unit,
            masked,
            fiat,
            fiat_currency,
            price_source,
            notify_new_tx,
            explorer_ack,
        } = stored;
        Preferences {
            unit,
            masked,
            fiat,
            fiat_currency,
            price_source,
            notify_new_tx,
            explorer_ack,
        }
        .quotable()
    }
}

/// A change to some of the [`Preferences`]: a field left out keeps its
/// value. One field at a time is the usual change, so that two made in
/// a row never undo each other. Written the way the apps send it, a
/// field that keeps its value left out rather than null.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PreferencesChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<Unit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat_currency: Option<FiatCurrency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_source: Option<PriceSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_new_tx: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_ack: Option<bool>,
}

/// The source that quotes every currency on offer: where the source
/// goes when the currency leaves it nothing to quote.
const QUOTES_EVERY_CURRENCY: PriceSource = PriceSource::Coingecko;

impl Preferences {
    /// These preferences with `change` applied, and the pair of currency
    /// and source made one that exists: the currency wins, the source
    /// follows. A currency only CoinGecko publishes, picked while the
    /// source is mempool.space, moves the source to CoinGecko rather
    /// than leave a pair that no source can quote; a source picked that
    /// does not quote the currency gives way the same.
    pub fn change(mut self, change: &PreferencesChange) -> Self {
        let PreferencesChange {
            unit,
            masked,
            fiat,
            fiat_currency,
            price_source,
            notify_new_tx,
            explorer_ack,
        } = *change;
        self.unit = unit.unwrap_or(self.unit);
        self.masked = masked.unwrap_or(self.masked);
        self.fiat = fiat.unwrap_or(self.fiat);
        self.fiat_currency = fiat_currency.unwrap_or(self.fiat_currency);
        self.price_source = price_source.unwrap_or(self.price_source);
        self.notify_new_tx = notify_new_tx.unwrap_or(self.notify_new_tx);
        self.explorer_ack = explorer_ack.unwrap_or(self.explorer_ack);
        self.quotable()
    }

    /// The same preferences, with a source that quotes the currency.
    pub(crate) fn quotable(mut self) -> Self {
        if !self.price_source.supports_currency(self.fiat_currency) {
            self.price_source = QUOTES_EVERY_CURRENCY;
        }
        self
    }
}

// --- what earlier builds kept ------------------------------------------

/// The app preferences earlier builds kept these preferences under,
/// before the vault had a record of them: the unit, the fiat value, its
/// currency and its source, the alerts, and the explorer warning. The
/// two apps wrote the same keys, as strings.
const LEGACY_UNIT: &str = "display.unit";
const LEGACY_FIAT: &str = "display.fiat";
const LEGACY_FIAT_CURRENCY: &str = "display.fiat_currency";
const LEGACY_PRICE_SOURCE: &str = "display.fiat_source";
const LEGACY_NOTIFY_NEW_TX: &str = "notify.new_tx";
const LEGACY_EXPLORER_ACK: &str = "privacy.explorer_ack";
/// The masked amounts, which each app kept under a key of its own.
const LEGACY_MASKED_DESKTOP: &str = "desktop.masked";
const LEGACY_MASKED_MOBILE: &str = "mobile.masked";

/// Every key above: none of them is an app preference any more.
pub(crate) const LEGACY_KEYS: [&str; 8] = [
    LEGACY_UNIT,
    LEGACY_FIAT,
    LEGACY_FIAT_CURRENCY,
    LEGACY_PRICE_SOURCE,
    LEGACY_NOTIFY_NEW_TX,
    LEGACY_EXPLORER_ACK,
    LEGACY_MASKED_DESKTOP,
    LEGACY_MASKED_MOBILE,
];

/// The masked amounts of the app this build runs in come first: of the
/// two keys, the one this app wrote is the one its user set.
fn own_masked_first() -> [&'static str; 2] {
    if cfg!(target_os = "android") {
        [LEGACY_MASKED_MOBILE, LEGACY_MASKED_DESKTOP]
    } else {
        [LEGACY_MASKED_DESKTOP, LEGACY_MASKED_MOBILE]
    }
}

/// Takes the preferences earlier builds kept among the app preferences,
/// read the way the apps read them, and removes their keys. A switch is
/// on only for an explicit `"1"`, as every one of them was off by
/// default; a value this build cannot read is the default. Of the two
/// keys of the masked amounts, the app's own counts, the other only
/// when it is alone.
pub(crate) fn adopt(app_prefs: &mut BTreeMap<String, String>) -> Preferences {
    adopt_with(app_prefs, own_masked_first())
}

fn adopt_with(
    app_prefs: &mut BTreeMap<String, String>,
    masked_keys: [&'static str; 2],
) -> Preferences {
    let defaults = Preferences::default();
    let switch = |key: &str| app_prefs.get(key).map(|value| value == "1");
    let adopted = Preferences {
        unit: variant(app_prefs, LEGACY_UNIT).unwrap_or(defaults.unit),
        masked: masked_keys
            .iter()
            .find_map(|key| switch(key))
            .unwrap_or(defaults.masked),
        fiat: switch(LEGACY_FIAT).unwrap_or(defaults.fiat),
        fiat_currency: variant(app_prefs, LEGACY_FIAT_CURRENCY).unwrap_or(defaults.fiat_currency),
        price_source: variant(app_prefs, LEGACY_PRICE_SOURCE).unwrap_or(defaults.price_source),
        notify_new_tx: switch(LEGACY_NOTIFY_NEW_TX).unwrap_or(defaults.notify_new_tx),
        explorer_ack: switch(LEGACY_EXPLORER_ACK).unwrap_or(defaults.explorer_ack),
    }
    .quotable();
    app_prefs.retain(|key, _| !LEGACY_KEYS.contains(&key.as_str()));
    adopted
}

/// The variant of a serde enum an app preference spells, if it spells
/// one.
fn variant<T: serde::de::DeserializeOwned>(
    app_prefs: &BTreeMap<String, String>,
    key: &str,
) -> Option<T> {
    let value = app_prefs.get(key)?;
    serde_json::from_value(serde_json::Value::String(value.clone())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// The defaults: BTC, nothing hidden, no fiat, the euro from
    /// mempool.space, no alerts, the warning still up.
    #[test]
    fn the_defaults_ask_no_new_third_party() {
        let defaults = Preferences::default();
        assert_eq!(defaults.unit, Unit::Btc);
        assert!(!defaults.masked);
        assert!(!defaults.fiat);
        assert_eq!(defaults.fiat_currency, FiatCurrency::Eur);
        assert_eq!(defaults.price_source, PriceSource::MempoolSpace);
        assert!(
            defaults
                .price_source
                .supports_currency(defaults.fiat_currency)
        );
        assert!(!defaults.notify_new_tx);
        assert!(!defaults.explorer_ack);
        // A vault that stored none of them, or some, reads the rest as
        // the defaults.
        assert_eq!(serde_json::from_str::<Preferences>("{}").unwrap(), defaults);
        let some: Preferences = serde_json::from_str(r#"{"unit":"sats"}"#).unwrap();
        assert_eq!(
            some,
            Preferences {
                unit: Unit::Sats,
                ..defaults
            }
        );
    }

    #[test]
    fn serde_spellings_are_stable() {
        let prefs = Preferences {
            unit: Unit::Sats,
            masked: true,
            fiat: true,
            fiat_currency: FiatCurrency::Try,
            price_source: PriceSource::Coingecko,
            notify_new_tx: true,
            explorer_ack: true,
        };
        assert_eq!(
            serde_json::to_value(prefs).unwrap(),
            serde_json::json!({
                "unit": "sats",
                "masked": true,
                "fiat": true,
                "fiat_currency": "try",
                "price_source": "coingecko",
                "notify_new_tx": true,
                "explorer_ack": true,
            })
        );
    }

    /// A record whose source does not quote its currency, or that holds
    /// a currency and no source, loads with a source that quotes it:
    /// the default, mempool.space, gives way to CoinGecko, and the rest
    /// stands.
    #[test]
    fn a_record_loads_with_a_source_that_quotes_its_currency() {
        let alone: Preferences = serde_json::from_str(r#"{"fiat_currency":"inr"}"#).unwrap();
        assert_eq!(alone.fiat_currency, FiatCurrency::Inr);
        assert_eq!(alone.price_source, PriceSource::Coingecko);

        let unquoted: Preferences = serde_json::from_str(
            r#"{"unit":"sats","fiat":true,"fiat_currency":"ngn","price_source":"mempool_space"}"#,
        )
        .unwrap();
        assert_eq!(
            unquoted,
            Preferences {
                unit: Unit::Sats,
                fiat: true,
                fiat_currency: FiatCurrency::Ngn,
                price_source: PriceSource::Coingecko,
                ..Preferences::default()
            }
        );

        // A pair that exists loads as it was.
        let quoted: Preferences =
            serde_json::from_str(r#"{"fiat_currency":"usd","price_source":"coingecko"}"#).unwrap();
        assert_eq!(quoted.price_source, PriceSource::Coingecko);
        let usd: Preferences = serde_json::from_str(r#"{"fiat_currency":"usd"}"#).unwrap();
        assert_eq!(usd.price_source, PriceSource::MempoolSpace);
    }

    /// A record that names Kraken, which left the sources, reads as
    /// mempool.space, and every other preference it holds stands.
    #[test]
    fn a_record_on_kraken_reads_as_mempool_space() {
        let stored: Preferences = serde_json::from_str(
            r#"{"unit":"sats","masked":true,"fiat":true,"fiat_currency":"jpy",
                "price_source":"kraken","notify_new_tx":true,"explorer_ack":true}"#,
        )
        .unwrap();
        assert_eq!(
            stored,
            Preferences {
                unit: Unit::Sats,
                masked: true,
                fiat: true,
                fiat_currency: FiatCurrency::Jpy,
                price_source: PriceSource::MempoolSpace,
                notify_new_tx: true,
                explorer_ack: true,
            }
        );
        assert_eq!(
            serde_json::to_value(stored).unwrap()["price_source"],
            "mempool_space"
        );
    }

    /// A change names what it changes, and nothing else moves.
    #[test]
    fn a_change_moves_what_it_names_alone() {
        let before = Preferences {
            masked: true,
            ..Preferences::default()
        };
        let after = before.change(&PreferencesChange {
            unit: Some(Unit::Sats),
            ..PreferencesChange::default()
        });
        assert_eq!(
            after,
            Preferences {
                unit: Unit::Sats,
                ..before
            }
        );
        assert_eq!(before.change(&PreferencesChange::default()), before);
        let change: PreferencesChange = serde_json::from_str(r#"{"fiat":true}"#).unwrap();
        assert_eq!(
            change,
            PreferencesChange {
                fiat: Some(true),
                ..PreferencesChange::default()
            }
        );
    }

    /// A field an app misspells is refused, not ignored: the change it
    /// meant would otherwise go nowhere and say nothing.
    #[test]
    fn a_change_with_a_field_nobody_knows_is_refused() {
        assert!(
            serde_json::from_str::<PreferencesChange>(r#"{"fiat_source":"coingecko"}"#).is_err()
        );
    }

    /// The currency wins, the source follows: whatever is changed, the
    /// pair kept is one a source quotes.
    #[test]
    fn the_currency_wins_and_the_source_follows() {
        let on_mempool = Preferences::default().change(&PreferencesChange {
            price_source: Some(PriceSource::MempoolSpace),
            ..PreferencesChange::default()
        });
        assert_eq!(on_mempool.price_source, PriceSource::MempoolSpace);

        // A currency mempool.space does not quote takes the source with it.
        let inr = on_mempool.change(&PreferencesChange {
            fiat_currency: Some(FiatCurrency::Inr),
            ..PreferencesChange::default()
        });
        assert_eq!(inr.fiat_currency, FiatCurrency::Inr);
        assert_eq!(inr.price_source, PriceSource::Coingecko);

        // One it quotes leaves the source where it is.
        let usd = on_mempool.change(&PreferencesChange {
            fiat_currency: Some(FiatCurrency::Usd),
            ..PreferencesChange::default()
        });
        assert_eq!(usd.price_source, PriceSource::MempoolSpace);

        // A source that does not quote the currency gives way to it.
        let refused = inr.change(&PreferencesChange {
            price_source: Some(PriceSource::MempoolSpace),
            ..PreferencesChange::default()
        });
        assert_eq!(refused.fiat_currency, FiatCurrency::Inr);
        assert_eq!(refused.price_source, PriceSource::Coingecko);

        // Every pair the rule can leave is quoted.
        for currency in FiatCurrency::ALL {
            for source in PriceSource::ALL {
                let kept = Preferences::default().change(&PreferencesChange {
                    fiat_currency: Some(*currency),
                    price_source: Some(source),
                    ..PreferencesChange::default()
                });
                assert_eq!(kept.fiat_currency, *currency);
                assert!(kept.price_source.supports_currency(*currency));
            }
        }
    }

    /// The source the rule falls back on quotes every currency on offer.
    #[test]
    fn the_fallback_source_quotes_every_currency() {
        for currency in FiatCurrency::ALL {
            assert!(QUOTES_EVERY_CURRENCY.supports_currency(*currency));
        }
    }

    /// What the desktop wrote is read the way it read it, and its keys
    /// leave the app preferences; what is the desktop's alone stays.
    #[test]
    fn the_preferences_of_a_desktop_vault_are_adopted() {
        let mut app_prefs = prefs(&[
            ("desktop.theme", "dark"),
            ("desktop.sidebar", "collapsed"),
            ("desktop.masked", "1"),
            ("display.unit", "sats"),
            ("display.fiat", "1"),
            ("display.fiat_currency", "usd"),
            ("display.fiat_source", "kraken"),
            ("notify.new_tx", "1"),
            ("privacy.explorer_ack", "1"),
            ("onboarding.seen", "1"),
            ("home.price_range", "year"),
            ("update.auto", "0"),
        ]);
        let adopted = adopt_with(
            &mut app_prefs,
            [LEGACY_MASKED_DESKTOP, LEGACY_MASKED_MOBILE],
        );
        assert_eq!(
            adopted,
            Preferences {
                unit: Unit::Sats,
                masked: true,
                fiat: true,
                fiat_currency: FiatCurrency::Usd,
                // Kraken left the sources: mempool.space quotes the same.
                price_source: PriceSource::MempoolSpace,
                notify_new_tx: true,
                explorer_ack: true,
            }
        );
        assert_eq!(
            app_prefs,
            prefs(&[
                ("desktop.theme", "dark"),
                ("desktop.sidebar", "collapsed"),
                ("onboarding.seen", "1"),
                ("home.price_range", "year"),
                ("update.auto", "0"),
            ])
        );
    }

    /// The same for Android, whose masked amounts had a key of their own.
    #[test]
    fn the_preferences_of_an_android_vault_are_adopted() {
        let mut app_prefs = prefs(&[
            ("mobile.theme", "system"),
            ("mobile.masked", "1"),
            ("display.unit", "btc"),
            ("display.fiat", "0"),
            ("display.fiat_currency", "try"),
            ("notify.new_tx", "0"),
            ("notify.details", "0"),
            ("widgets.balances", "1"),
            ("updates.auto", "1"),
        ]);
        let adopted = adopt_with(
            &mut app_prefs,
            [LEGACY_MASKED_MOBILE, LEGACY_MASKED_DESKTOP],
        );
        // No source stored, and a currency only CoinGecko quotes: the
        // default source gives way to it.
        assert_eq!(
            adopted,
            Preferences {
                masked: true,
                fiat_currency: FiatCurrency::Try,
                price_source: PriceSource::Coingecko,
                ..Preferences::default()
            }
        );
        assert_eq!(
            app_prefs,
            prefs(&[
                ("mobile.theme", "system"),
                ("notify.details", "0"),
                ("widgets.balances", "1"),
                ("updates.auto", "1"),
            ])
        );
    }

    /// Of the two keys of the masked amounts, the app's own wins; the
    /// other counts only alone.
    #[test]
    fn the_masked_amounts_of_the_app_that_writes_win() {
        let both = || prefs(&[("desktop.masked", "0"), ("mobile.masked", "1")]);
        let desktop_first = [LEGACY_MASKED_DESKTOP, LEGACY_MASKED_MOBILE];
        let mobile_first = [LEGACY_MASKED_MOBILE, LEGACY_MASKED_DESKTOP];
        assert!(!adopt_with(&mut both(), desktop_first).masked);
        assert!(adopt_with(&mut both(), mobile_first).masked);
        assert!(adopt_with(&mut prefs(&[("mobile.masked", "1")]), desktop_first).masked);
        let mut emptied = both();
        adopt_with(&mut emptied, desktop_first);
        assert!(emptied.is_empty());
        // The build in use puts its own key first.
        let own = if cfg!(target_os = "android") {
            LEGACY_MASKED_MOBILE
        } else {
            LEGACY_MASKED_DESKTOP
        };
        assert_eq!(own_masked_first()[0], own);
    }

    /// Nothing stored is the defaults. A value no build wrote, or a pair
    /// no source quotes, reads the way the apps read it: the default,
    /// and the currency with a source that quotes it.
    #[test]
    fn what_cannot_be_read_is_the_default() {
        assert_eq!(adopt(&mut BTreeMap::new()), Preferences::default());
        let mut odd = prefs(&[
            ("display.unit", "mbtc"),
            ("display.fiat", "yes"),
            ("display.fiat_currency", "xyz"),
            ("display.fiat_source", "bitstamp"),
            ("notify.new_tx", "true"),
            ("privacy.explorer_ack", ""),
            ("desktop.masked", "on"),
        ]);
        assert_eq!(adopt(&mut odd), Preferences::default());
        assert!(odd.is_empty());

        let mut unquoted = prefs(&[
            ("display.fiat_currency", "ngn"),
            ("display.fiat_source", "mempool_space"),
        ]);
        let adopted = adopt(&mut unquoted);
        assert_eq!(adopted.fiat_currency, FiatCurrency::Ngn);
        assert_eq!(adopted.price_source, PriceSource::Coingecko);
    }
}
