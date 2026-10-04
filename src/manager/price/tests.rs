//! The route of the price, against a vault on disk and a stand-in for
//! a system Tor. Nothing here reaches a price source: the proxy writes
//! down the host it was asked for and refuses to connect.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::chain::BackendConfig;
use crate::chain::tor::{TorMode, TorSettings, socks};
use crate::error::CoreError;
use crate::manager::tests::support::{closed_port, manager};
use crate::network::Network;
use crate::price::{FiatCurrency, PriceRange, PriceSource};

const ONION: &str = "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001";

/// A system Tor that answers the probe, writes down every host a
/// request names, and refuses to connect: what was asked of it is all
/// there is to see, and nothing leaves this machine.
async fn refusing_tor() -> (String, Arc<Mutex<Vec<(String, u16)>>>) {
    let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy = listener.local_addr().unwrap().to_string();
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client
                    .write_all(&[socks::VERSION, socks::NO_AUTH])
                    .await
                    .ok()?;
                // A probe hangs up here; a request names its host.
                let mut head = [0u8; 5];
                client.read_exact(&mut head).await.ok()?;
                let mut name = vec![0u8; usize::from(head[4]) + 2];
                client.read_exact(&mut name).await.ok()?;
                let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
                name.truncate(name.len() - 2);
                seen.lock()
                    .unwrap()
                    .push((String::from_utf8_lossy(&name).into_owned(), port));
                // Connection refused.
                client
                    .write_all(&[socks::VERSION, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                Some(())
            });
        }
    });
    (proxy, asked)
}

/// A manager whose mainnet backend is an onion, while the network on
/// screen is signet, and whose Tor is the system one at `proxy`.
async fn onion_manager(dir: &std::path::Path, proxy: String) -> crate::WalletManager {
    let manager = manager(dir).await;
    manager
        .set_backend(
            Network::Mainnet,
            BackendConfig::CustomElectrum {
                url: ONION.to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(proxy),
        })
        .await
        .unwrap();
    manager
}

fn is_price_failure(error: &CoreError) -> bool {
    matches!(error, CoreError::Sync { backend, .. } if backend == "price")
}

/// With clearnet backends only, nothing goes through Tor and nothing
/// probes for it, even with a system Tor set that is not there.
#[tokio::test]
async fn without_an_onion_backend_the_price_goes_straight() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed_port().await),
        })
        .await
        .unwrap();
    assert!(!manager.uses_tor().await);
    assert_eq!(manager.beside_syncs_proxy().await.unwrap(), None);
}

/// An onion backend on any network, even one that is not on screen,
/// sends every price request through the Tor proxy, by name.
#[tokio::test]
async fn with_an_onion_backend_the_price_goes_through_tor() {
    let (proxy, asked) = refusing_tor().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), proxy).await;
    assert!(manager.uses_tor().await);

    for source in PriceSource::ALL {
        let error = manager
            .fetch_price(source, FiatCurrency::Usd)
            .await
            .unwrap_err();
        assert!(is_price_failure(&error), "{source:?}: {error}");
    }
    let error = manager
        .fetch_price_history(PriceSource::Kraken, FiatCurrency::Usd, PriceRange::Year)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");

    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            ("api.coingecko.com".to_owned(), 443),
            ("api.kraken.com".to_owned(), 443),
            ("mempool.space".to_owned(), 443),
            ("api.kraken.com".to_owned(), 443),
        ],
        "every host went to the proxy, by name, and nowhere else"
    );
}

/// Tor is needed and is not there: a Tor error, before any request.
#[tokio::test]
async fn without_the_tor_it_needs_no_price_goes() {
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), closed_port().await).await;

    let started = Instant::now();
    let refused = manager
        .fetch_price(PriceSource::Coingecko, FiatCurrency::Eur)
        .await
        .unwrap_err();
    assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
    let refused = manager
        .fetch_price_history(PriceSource::Coingecko, FiatCurrency::Eur, PriceRange::Week)
        .await
        .unwrap_err();
    assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no price source is contacted, let alone looked up"
    );
}

/// A pair the source cannot serve is refused before a route is
/// resolved: no Tor started for a request that would not go anyway.
#[tokio::test]
async fn an_unserved_pair_is_refused_before_any_route() {
    let (proxy, asked) = refusing_tor().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = onion_manager(dir.path(), proxy).await;

    let error = manager
        .fetch_price(PriceSource::Kraken, FiatCurrency::Inr)
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");
    assert!(error.to_string().contains("INR"), "{error}");
    let error = manager
        .fetch_price_history(
            PriceSource::MempoolSpace,
            FiatCurrency::Usd,
            PriceRange::Day,
        )
        .await
        .unwrap_err();
    assert!(is_price_failure(&error), "{error}");
    assert!(asked.lock().unwrap().is_empty());
}
