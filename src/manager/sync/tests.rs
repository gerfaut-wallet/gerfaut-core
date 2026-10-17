//! Syncs, against a vault on disk and no server at all, or the fake
//! servers of `crate::testkit` where the order of the servers matters.

use super::*;
use crate::input::parse_input;
use crate::manager::tests::support::{MULTIPATH, manager};

#[test]
fn deep_history_survives_a_sync() {
    let tx = |txid: &str, height: Option<u32>| AddressTx {
        txid: txid.to_owned(),
        net_sats: 0,
        fee_sats: None,
        height,
        timestamp: None,
        vsize: 100,
        inputs: vec![],
        outputs: vec![],
        extras: None,
    };
    // The user had loaded two rounds; a sync only refetches the newest.
    let previous = AddressWatchState {
        txs: vec![
            tx("aa", Some(900)),
            tx("bb", Some(500)),
            tx("cc", Some(100)),
        ],
        history_cursor: Some("cc".to_owned()),
        truncated: true,
        ..Default::default()
    };
    let mut fresh = AddressWatchState {
        txs: vec![tx("new", None), tx("aa", Some(900))],
        history_cursor: Some("aa".to_owned()),
        truncated: true,
        ..Default::default()
    };
    keep_older_history(&mut fresh, &previous);
    let ids: Vec<&str> = fresh.txs.iter().map(|t| t.txid.as_str()).collect();
    assert_eq!(ids, vec!["new", "aa", "bb", "cc"], "older rounds are kept");
    assert_eq!(
        fresh.history_cursor.as_deref(),
        Some("cc"),
        "the deeper cursor wins"
    );
}

#[test]
fn a_replaced_transaction_is_not_resurrected() {
    let tx = |txid: &str, height: Option<u32>| AddressTx {
        txid: txid.to_owned(),
        net_sats: 0,
        fee_sats: None,
        height,
        timestamp: None,
        vsize: 100,
        inputs: vec![],
        outputs: vec![],
        extras: None,
    };
    // "gone" sat inside the fresh window and vanished from the chain.
    let previous = AddressWatchState {
        txs: vec![tx("gone", Some(950)), tx("old", Some(10))],
        ..Default::default()
    };
    let mut fresh = AddressWatchState {
        txs: vec![tx("kept", Some(900))],
        ..Default::default()
    };
    keep_older_history(&mut fresh, &previous);
    let ids: Vec<&str> = fresh.txs.iter().map(|t| t.txid.as_str()).collect();
    assert_eq!(
        ids,
        vec!["kept", "old"],
        "only settled history is carried over"
    );
}

#[tokio::test]
async fn load_more_history_refuses_descriptor_wallets() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let error = manager.load_more_history(&meta.id).await.unwrap_err();
    assert!(
        error.to_string().contains("full history"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn load_more_history_is_a_no_op_without_a_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
    let meta = manager
        .add_wallet("Watch", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(manager.load_more_history(&meta.id).await.unwrap(), 0);
}

#[tokio::test]
async fn regtest_public_backend_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Regtest", &parsed, Network::Regtest)
        .await
        .unwrap();
    assert!(matches!(
        manager.sync_wallet(&meta.id).await,
        Err(CoreError::BackendUnavailable(_))
    ));
}

/// The server that answered the last sync goes first in the next one,
/// told by its protocol and port as well as its host. Blockstream's
/// Electrum server, `blockstream.info:700`, answering a sync the live
/// watch asked for used to put Blockstream's web API, at the same host
/// and with limits of its own, ahead of the rotation in every sync
/// after it.
#[test]
fn the_server_that_answered_is_told_by_protocol_and_port() {
    let none = chain::TrustedCerts::new();
    let rotation =
        chain::endpoints(&chain::BackendConfig::default(), Network::Mainnet, &none).unwrap();
    let electrum = chain::endpoints(
        &chain::BackendConfig::Public {
            server: Some("electrum:blockstream.info".to_owned()),
        },
        Network::Mainnet,
        &none,
    )
    .unwrap()
    .remove(0);
    let web = rotation[1].clone();
    assert_eq!(web.label(), "blockstream.info");
    assert_eq!(electrum.label(), web.label(), "one host for both");

    // Electrum answered: the rotation keeps its order.
    assert_eq!(
        sync_order(rotation.clone(), Some(&electrum.key()), None),
        rotation
    );
    // The web API answered: it goes first.
    assert_eq!(
        sync_order(rotation.clone(), Some(&web.key()), None),
        vec![web.clone(), rotation[0].clone(), rotation[2].clone()]
    );
    // A stamp written before servers were told apart names none.
    assert_eq!(sync_order(rotation.clone(), None, None), rotation);
    // The server of the watch comes before the one that answered.
    assert_eq!(
        sync_order(rotation.clone(), Some(&web.key()), Some(electrum.clone())),
        vec![electrum, web, rotation[0].clone(), rotation[2].clone()]
    );
}

/// The servers of a mainnet rotation, and the Electrum server of its
/// second operator.
fn mainnet() -> (Vec<Endpoint>, Endpoint) {
    let none = chain::TrustedCerts::new();
    let rotation =
        chain::endpoints(&chain::BackendConfig::default(), Network::Mainnet, &none).unwrap();
    let electrum = chain::endpoints(
        &chain::BackendConfig::Public {
            server: Some("electrum:blockstream.info".to_owned()),
        },
        Network::Mainnet,
        &none,
    )
    .unwrap()
    .remove(0);
    (rotation, electrum)
}

/// A server that failed while a later one answered is tried after the
/// others for five minutes, then ten, twenty, forty, and an hour at
/// most, each time it fails so again before it answers; one answer and
/// it starts over. A failure seen again while it is relegated, by a
/// sync that started before it was, does not count twice.
#[tokio::test(start_paused = true)]
async fn a_server_that_fails_where_another_answers_is_tried_last_for_longer_each_time() {
    use tokio::time::{Instant, advance};
    let (rotation, _) = mainnet();
    let (mempool, blockstream, emzy) = (&rotation[0], &rotation[1], &rotation[2]);
    let mut relegated = Relegations::default();
    let order = |relegated: &Relegations| relegated.order(rotation.clone(), None, Instant::now());
    assert_eq!(order(&relegated), rotation);

    for minutes in [5, 10, 20, 40, 60, 60] {
        relegated.answered(blockstream, &[mempool], Instant::now());
        assert_eq!(
            order(&relegated),
            [blockstream.clone(), emzy.clone(), mempool.clone()]
        );
        relegated.answered(blockstream, &[mempool], Instant::now());
        advance(Duration::from_secs(minutes * 60 - 1)).await;
        assert_eq!(order(&relegated)[2], *mempool, "{minutes} min");
        advance(Duration::from_secs(1)).await;
        assert_eq!(order(&relegated), rotation, "{minutes} min");
    }

    relegated.answered(mempool, &[], Instant::now());
    relegated.answered(emzy, &[mempool, blockstream], Instant::now());
    assert_eq!(
        order(&relegated),
        [emzy.clone(), mempool.clone(), blockstream.clone()]
    );
    advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(order(&relegated), rotation, "back to five minutes");
}

/// The server of the live watch stays first, whatever it did: behind
/// another, it would show the wallet to a second operator. The others
/// are relegated behind it as behind any other.
#[tokio::test(start_paused = true)]
async fn the_server_of_the_watch_is_never_put_behind_another() {
    use tokio::time::Instant;
    let (rotation, electrum) = mainnet();
    let mut relegated = Relegations::default();
    relegated.answered(&rotation[0], &[&electrum, &rotation[1]], Instant::now());
    let watched = sync_order(rotation.clone(), None, Some(electrum.clone()));
    assert_eq!(
        relegated.order(watched, Some(&electrum), Instant::now()),
        [
            electrum.clone(),
            rotation[0].clone(),
            rotation[2].clone(),
            rotation[1].clone()
        ]
    );
}

/// A second watched address: the P2WSH test vector of BIP-173.
const SECOND_ADDRESS: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

/// What the syncs asked of a fake mempool instance so far, forgotten.
fn asked(server: &crate::testkit::FakeMempool) -> Vec<String> {
    std::mem::take(&mut server.state.lock().unwrap().paths)
}

/// The rotation of the automatic backend, one server that fails and one
/// that answers: the first sync asks both, and the next one, of another
/// wallet, asks only the one that answered. When every server fails,
/// none is relegated: the next sync asks them in their order.
#[tokio::test]
async fn a_sync_tries_last_the_server_that_failed_where_another_answered() {
    use crate::testkit::FakeMempool;
    let flaky = FakeMempool::start(false, 0).await;
    let steady = FakeMempool::start(false, 0).await;
    let _stand_in = crate::chain::public::stand_in(
        &[
            format!("http://{}/api", flaky.address),
            format!("http://{}/api", steady.address),
        ],
        &[],
    );
    let other_network = Some(bdk_wallet::bitcoin::Network::Testnet4);
    let watching = |address: &'static str| async move {
        let dir = tempfile::tempdir().unwrap();
        let watcher = manager(dir.path()).await;
        let wallet = watcher
            .add_wallet(address, &parse_input(address).unwrap(), Network::Signet)
            .await
            .unwrap()
            .id;
        (dir, watcher, wallet)
    };

    let (_dir, watcher, first) = watching(crate::testkit::ADDRESS).await;
    let second = watcher
        .add_wallet(
            "Second",
            &parse_input(SECOND_ADDRESS).unwrap(),
            Network::Signet,
        )
        .await
        .unwrap()
        .id;
    flaky.state.lock().unwrap().genesis = other_network;
    watcher.sync_wallet(&first).await.unwrap();
    assert!(!asked(&flaky).is_empty());
    assert!(!asked(&steady).is_empty());
    // The other wallet has no server it last synced with.
    watcher.sync_wallet(&second).await.unwrap();
    assert_eq!(asked(&flaky), Vec::<String>::new());
    assert!(!asked(&steady).is_empty());

    // Every server fails, on another manager: none is relegated.
    let (_dir, watcher, wallet) = watching(SECOND_ADDRESS).await;
    steady.state.lock().unwrap().genesis = other_network;
    assert!(watcher.sync_wallet(&wallet).await.is_err());
    flaky.state.lock().unwrap().genesis = None;
    steady.state.lock().unwrap().genesis = None;
    asked(&flaky);
    asked(&steady);
    watcher.sync_wallet(&wallet).await.unwrap();
    assert!(!asked(&flaky).is_empty());
    assert_eq!(asked(&steady), Vec::<String>::new());
}
