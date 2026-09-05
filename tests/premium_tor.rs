//! Which way the premium client goes when the settings lead to Tor.
//!
//! A person who reaches their own node through an onion address chose
//! not to show where they are. The premium server used to be reached
//! in the clear all the same, from the same process, with the key and
//! the descriptors: the one thing the onion backend was hiding. Now the
//! client takes the route the backend takes, and fails closed when that
//! route is not there.
//!
//! Loopback only: a fake Tor that answers the SOCKS5 greeting and
//! counts what reaches it, a fake premium server that records what
//! reaches it. Nothing here touches the network.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use gerfaut_core::chain::BackendConfig;
use gerfaut_core::chain::tor::{TorMode, TorSettings};
use gerfaut_core::store::VaultKey;
use gerfaut_core::{CoreError, Network, WalletManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A well-formed v3 shape, not a real service; nothing connects to it.
const ONION: &str =
    "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion/api";

/// A fake Tor: answers the SOCKS5 greeting, counts every connection,
/// forwards nothing. A request that goes through it goes nowhere.
async fn fake_tor() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting).await;
            let _ = stream.write_all(&[5, 0]).await;
        }
    });
    (address, hits)
}

/// A fake premium server: records the request head, answers
/// `/v1/health` the way the real one does.
async fn fake_api() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let _ = sender.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let body = r#"{"ok":true,"network":"bitcoin","node":{"headers":1,"blocks":1,"initial_block_download":false,"verification_progress":1.0},"engine":{"tip_height":1},"now":1790000000}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (address, receiver)
}

/// A vault whose Tor is the system proxy at `socks`.
async fn manager_through(dir: &std::path::Path, socks: &str) -> WalletManager {
    let manager = WalletManager::open(dir, VaultKey::Raw([9u8; 32])).unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(socks.to_owned()),
        })
        .await
        .unwrap();
    manager
}

/// The backend of the active network is an onion.
async fn onion_backend(manager: &WalletManager) {
    let network = manager.settings().await.active_network;
    manager
        .set_backend(
            network,
            BackendConfig::CustomEsplora {
                url: ONION.to_owned(),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn an_onion_backend_sends_the_premium_client_through_tor() {
    let (socks, hits) = fake_tor().await;
    let (api, mut seen) = fake_api().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_through(dir.path(), &socks.to_string()).await;
    onion_backend(&manager).await;

    // Resolving the route probes the proxy once, before the client
    // exists.
    let client = manager
        .premium_client(&format!("http://{api}"))
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // The request goes to the proxy, where the fake Tor drops it; the
    // server in the clear never hears of it.
    let outcome = tokio::time::timeout(Duration::from_secs(5), client.health())
        .await
        .expect("no hang");
    assert!(outcome.is_err(), "the fake Tor forwards nothing");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "the request went through Tor"
    );
    assert!(
        seen.try_recv().is_err(),
        "the premium server was reached in the clear"
    );
}

#[tokio::test]
async fn a_clearnet_backend_keeps_the_premium_client_in_the_clear() {
    let (socks, hits) = fake_tor().await;
    let (api, mut seen) = fake_api().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_through(dir.path(), &socks.to_string()).await;

    let client = manager
        .premium_client(&format!("http://{api}"))
        .await
        .unwrap();
    let health = tokio::time::timeout(Duration::from_secs(5), client.health())
        .await
        .expect("no hang")
        .expect("the request reaches the server directly");
    assert!(health.ok);
    let request = seen.recv().await.unwrap();
    assert!(request.starts_with("GET /v1/health HTTP/1.1"), "{request}");
    // Tor was never probed, let alone used.
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// The Tor the settings lead to does not answer: no client is built,
/// and nothing goes out in the clear instead.
#[tokio::test]
async fn an_onion_backend_without_tor_builds_no_premium_client() {
    let (api, mut seen) = fake_api().await;
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address.to_string()
    };
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_through(dir.path(), &closed).await;
    onion_backend(&manager).await;

    let error = manager
        .premium_client(&format!("http://{api}"))
        .await
        .expect_err("fails closed");
    assert!(matches!(error, CoreError::Tor(_)), "{error}");
    assert!(seen.try_recv().is_err());

    // A backend on another network changes nothing: the active one
    // decides.
    let other = if manager.settings().await.active_network == Network::Signet {
        Network::Mainnet
    } else {
        Network::Signet
    };
    manager
        .set_backend(other, BackendConfig::default())
        .await
        .unwrap();
    assert!(matches!(
        manager.premium_client(&format!("http://{api}")).await,
        Err(CoreError::Tor(_))
    ));
}

/// A key just typed, not stored yet, takes the same route as the
/// stored one: the licence check is the first thing that would leave
/// in the clear otherwise.
#[tokio::test]
async fn a_key_not_yet_stored_takes_the_same_route() {
    let (socks, hits) = fake_tor().await;
    let (api, mut seen) = fake_api().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_through(dir.path(), &socks.to_string()).await;
    onion_backend(&manager).await;

    let client = manager
        .premium_client_with_key(
            &format!("http://{api}"),
            Some("ABCD-EFGH-IJKM-NPQR".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(client.key(), Some("abcdefghijkmnpqr"));
    assert!(
        manager.premium_state().await.key.is_none(),
        "nothing stored"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(5), client.health())
        .await
        .expect("no hang");
    assert!(outcome.is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(seen.try_recv().is_err());
}
