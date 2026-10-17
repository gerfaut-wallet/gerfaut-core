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

/// The rotation of the automatic backend, one server that is down and
/// one that answers: the first sync asks both, and the next one, of
/// another wallet, asks only the one that answered. A server that
/// refuses one request, here one of another network, is not relegated
/// for it. When every server is down, none is: the next sync asks them
/// in their order.
#[tokio::test]
async fn a_sync_tries_last_a_server_that_was_down_where_another_answered() {
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
    let watching = |addresses: &'static [&'static str]| async move {
        let dir = tempfile::tempdir().unwrap();
        let watcher = manager(dir.path()).await;
        let mut wallets = Vec::new();
        for address in addresses {
            let parsed = parse_input(address).unwrap();
            let wallet = watcher.add_wallet(address, &parsed, Network::Signet).await;
            wallets.push(wallet.unwrap().id);
        }
        (dir, watcher, wallets)
    };
    let both = &[crate::testkit::ADDRESS, SECOND_ADDRESS];

    let (_dir, watcher, wallets) = watching(both).await;
    flaky.state.lock().unwrap().down = true;
    watcher.sync_wallet(&wallets[0]).await.unwrap();
    assert!(!asked(&flaky).is_empty());
    assert!(!asked(&steady).is_empty());
    // The other wallet has no server it last synced with.
    watcher.sync_wallet(&wallets[1]).await.unwrap();
    assert_eq!(asked(&flaky), Vec::<String>::new());
    assert!(!asked(&steady).is_empty());

    // A refusal of what was asked: the next wallet asks it first again.
    let (_dir, watcher, wallets) = watching(both).await;
    {
        let mut flaky = flaky.state.lock().unwrap();
        flaky.down = false;
        flaky.genesis = Some(bdk_wallet::bitcoin::Network::Testnet4);
    }
    watcher.sync_wallet(&wallets[0]).await.unwrap();
    assert!(!asked(&flaky).is_empty());
    watcher.sync_wallet(&wallets[1]).await.unwrap();
    assert!(!asked(&flaky).is_empty(), "relegated for one refusal");
    flaky.state.lock().unwrap().genesis = None;

    // Every server is down: none is relegated.
    let (_dir, watcher, wallets) = watching(&[SECOND_ADDRESS]).await;
    flaky.state.lock().unwrap().down = true;
    steady.state.lock().unwrap().down = true;
    assert!(watcher.sync_wallet(&wallets[0]).await.is_err());
    flaky.state.lock().unwrap().down = false;
    steady.state.lock().unwrap().down = false;
    asked(&flaky);
    asked(&steady);
    watcher.sync_wallet(&wallets[0]).await.unwrap();
    assert!(!asked(&flaky).is_empty());
    assert_eq!(asked(&steady), Vec::<String>::new());
}

/// A relegation over for an hour is forgotten: the next outage, days
/// later, relegates the server for five minutes again, not for longer.
#[tokio::test(start_paused = true)]
async fn an_old_relegation_is_forgotten() {
    use tokio::time::{Instant, advance};
    let (rotation, _) = mainnet();
    let (mempool, blockstream) = (&rotation[0], &rotation[1]);
    let mut relegated = Relegations::default();
    let last = |relegated: &Relegations| {
        relegated.order(rotation.clone(), None, Instant::now())[2].clone()
    };
    for minutes in [5, 10, 20] {
        relegated.answered(blockstream, &[mempool], Instant::now());
        advance(Duration::from_secs(minutes * 60)).await;
    }
    // Within the hour after the last one: twice as long again.
    advance(Duration::from_secs(59 * 60)).await;
    relegated.answered(blockstream, &[mempool], Instant::now());
    advance(Duration::from_secs(39 * 60)).await;
    assert_eq!(last(&relegated), *mempool);
    advance(Duration::from_secs(60)).await;
    assert_eq!(
        relegated.order(rotation.clone(), None, Instant::now()),
        rotation
    );
    // Past the hour: five minutes, as the first time.
    advance(Duration::from_secs(60 * 60)).await;
    relegated.answered(blockstream, &[mempool], Instant::now());
    advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        relegated.order(rotation.clone(), None, Instant::now()),
        rotation
    );
}

/// The older history of a watched address goes first to the server the
/// watch talks to, as a sync does, and is never put behind another: it
/// already sees the address.
#[tokio::test]
async fn older_history_goes_first_to_the_server_of_the_watch() {
    use crate::testkit::{FakeElectrum, FakeMempool};
    let rotation = FakeMempool::start(false, 0).await;
    let live = FakeElectrum::start().await;
    let _stand_in = crate::chain::public::stand_in(
        &[format!("http://{}/api", rotation.address)],
        &[format!("tcp://{}", live.address)],
    );
    let dir = tempfile::tempdir().unwrap();
    let watcher = manager(dir.path()).await;
    watcher.set_active_network(Network::Signet).await.unwrap();
    let parsed = parse_input(crate::testkit::ADDRESS).unwrap();
    let wallet = watcher
        .add_wallet("Watch", &parsed, Network::Signet)
        .await
        .unwrap();
    let _events = watcher.live_start_with(None).await.unwrap();
    let started = std::time::Instant::now();
    while watcher.live_server().is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the watch never connected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_, served) = watcher.live_server().unwrap();
    let (config, certs) = watcher.state.lock().await.chain_setup(Network::Signet);
    let meta = watcher.list_wallets(None).await.remove(0);
    assert_eq!(meta.id, wallet.id);
    let order = watcher
        .sync_endpoints(&meta, &config, &certs, None)
        .unwrap();
    assert_eq!(order[0], served);
    // Down for a sync, it stays first all the same.
    watcher.answered_after(&order[1], &[&served]);
    let order = watcher
        .sync_endpoints(&meta, &config, &certs, None)
        .unwrap();
    assert_eq!(order[0], served);
    watcher.live_stop().await;
}

/// A sync that fails once the server has answered, the vault not saved,
/// relegates nothing: what failed may well be this device. The next
/// wallet asks the first server first.
#[tokio::test]
async fn a_sync_that_fails_after_the_answer_relegates_nothing() {
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
    let dir = tempfile::tempdir().unwrap();
    let watcher = manager(dir.path()).await;
    let mut wallets = Vec::new();
    for address in [crate::testkit::ADDRESS, SECOND_ADDRESS] {
        let parsed = parse_input(address).unwrap();
        let wallet = watcher.add_wallet(address, &parsed, Network::Signet).await;
        wallets.push(wallet.unwrap().id);
    }
    flaky.state.lock().unwrap().down = true;
    watcher.state.lock().await.vault.fail_saves(true);
    assert!(watcher.sync_wallet(&wallets[0]).await.is_err());
    assert!(!asked(&steady).is_empty(), "the other one answered");
    watcher.state.lock().await.vault.fail_saves(false);
    flaky.state.lock().unwrap().down = false;
    asked(&flaky);
    watcher.sync_wallet(&wallets[1]).await.unwrap();
    assert!(!asked(&flaky).is_empty(), "relegated by a sync that failed");
}

/// What a sync fails with is decided on the kind of each failure, never
/// on its words: a server the core refused for a proof that does not
/// hold makes the sync fail under `false_proof`, and only one that was
/// down is relegated. A server's own refusal, in the same words, is a
/// refusal: the sync fails under `sync`, and nobody is relegated.
#[test]
fn a_server_does_not_choose_the_false_proof_code() {
    use crate::chain::Fault;
    use crate::chain::electrum::rpc::CallError;
    use crate::chain::proof::{COIN_NOT_PAID, FALSE_PROOF};
    use crate::error::ErrorCode;
    let server = |host: &str| {
        Endpoint::Electrum(crate::chain::electrum::Target::new(
            format!("ssl://{host}:50002"),
            None,
        ))
    };
    let (down, lying) = (server("a.example.org"), server("b.example.org"));
    let mut attempts = Attempts::default();
    attempts.failed(&down, &Fault::outage("could not connect"));
    attempts.failed(&lying, &Fault::coin_not_paid());
    assert_eq!(attempts.down, [&down]);
    let failed = sync_failure(&[down.clone(), lying.clone()], attempts);
    assert_eq!(failed.code(), ErrorCode::FalseProof, "{failed}");
    assert!(failed.to_string().contains(COIN_NOT_PAID), "{failed}");

    for words in [FALSE_PROOF, COIN_NOT_PAID, "could not connect"] {
        let mut attempts = Attempts::default();
        attempts.failed(&lying, &Fault::from(CallError::refused(words)));
        assert!(attempts.down.is_empty(), "{words}");
        let failed = sync_failure(std::slice::from_ref(&lying), attempts);
        assert_eq!(failed.code(), ErrorCode::Sync, "{failed}");
        assert!(failed.to_string().contains(words), "{failed}");
    }
}
