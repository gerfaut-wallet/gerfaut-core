//! Live alerts end to end: the wallet manager, its vault, and the fake
//! servers of [`crate::testkit`].

use std::time::Duration;

use super::*;
use crate::store::VaultKey;
use crate::testkit::{
    ADDRESS, ADDRESS_SCRIPT, FakeElectrum, FakeMempool, esplora_payment, nowhere, transaction,
};

fn key() -> VaultKey {
    VaultKey::Raw([7; 32])
}

/// A manager whose signet backend is `backend`, watching [`ADDRESS`].
async fn watching(
    dir: &std::path::Path,
    backend: crate::chain::BackendConfig,
) -> (WalletManager, String) {
    let manager = WalletManager::open(dir, key()).unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager.set_backend(Network::Signet, backend).await.unwrap();
    let parsed = crate::input::parse_input(ADDRESS).unwrap();
    let wallet = manager
        .add_wallet("Watched", &parsed, Network::Signet)
        .await
        .unwrap();
    (manager, wallet.id)
}

fn staged(claimed: &[LiveTx]) -> Vec<(String, TxStage)> {
    claimed
        .iter()
        .map(|tx| (tx.txid.clone(), tx.stage))
        .collect()
}

fn txid(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// A sync whose caller announces nothing loses nothing: what it found
/// waits in the vault, across a restart, for the next claim, whoever
/// makes it, and goes out once.
#[tokio::test]
async fn what_a_sync_finds_waits_for_whoever_claims() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    // The import: an old payment, already confirmed, is no news.
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x10, 0x20, 1_000, true)];
    let import = manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(import.new_txs.len(), 1);
    assert!(
        manager
            .claim_announcements(&import)
            .await
            .unwrap()
            .is_empty()
    );

    // A payment lands; the sync that sees it claims nothing.
    server
        .state
        .lock()
        .unwrap()
        .address_txs
        .insert(0, esplora_payment(0x11, 0x21, 50_000, false));
    let unannounced = manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(unannounced.new_txs.len(), 1);
    // Another caller's sync lists nothing new, and its claim gets it.
    let later = manager.sync_wallet(&wallet).await.unwrap();
    assert!(later.new_txs.is_empty());
    assert_eq!(
        staged(&manager.claim_announcements(&later).await.unwrap()),
        [(txid(0x11), TxStage::Mempool)]
    );
    assert!(
        manager
            .claim_announcements(&later)
            .await
            .unwrap()
            .is_empty()
    );

    // It confirms, and the process dies before anyone claims.
    server.state.lock().unwrap().address_txs[0] = esplora_payment(0x11, 0x21, 50_000, true);
    let confirmed = manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(confirmed.confirmed_txs.len(), 1);
    drop(manager);
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(
        staged(&reopened.claim_announcements(&confirmed).await.unwrap()),
        [(txid(0x11), TxStage::Confirmed)]
    );
    assert!(
        reopened
            .claim_announcements(&confirmed)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Two callers sync the same wallet at the same moment: one runs the
/// sync, the other waits and gets it with nothing listed. Each claims
/// after its sync, and the payment comes out exactly once between them.
#[tokio::test]
async fn two_syncs_at_once_announce_a_payment_once() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    for round in 0..5u8 {
        server
            .state
            .lock()
            .unwrap()
            .address_txs
            .insert(0, esplora_payment(0x40 + round, 0x60 + round, 1_000, false));
        let claim_after_sync = || async {
            let report = manager.sync_wallet(&wallet).await.unwrap();
            manager.claim_announcements(&report).await.unwrap()
        };
        let (one, other) = tokio::join!(claim_after_sync(), claim_after_sync());
        let all: Vec<LiveTx> = one.into_iter().chain(other).collect();
        assert_eq!(
            staged(&all),
            [(txid(0x40 + round), TxStage::Mempool)],
            "round {round}"
        );
    }
}

/// A wallet removed takes its unclaimed news with it.
#[tokio::test]
async fn a_removed_wallet_leaves_no_news_behind() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x11, 0x21, 5_000, false)];
    manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(manager.news_waiting(&wallet).await, 1);
    manager.remove_wallet(&wallet).await.unwrap();
    assert!(manager.state.lock().await.payload.unclaimed.is_empty());
}

// --- a watch that starts --------------------------------------------------------

const WAIT: Duration = Duration::from_secs(10);
/// How long nothing more may come for the count to be the final one.
const QUIET: Duration = Duration::from_millis(400);

fn timings() -> crate::watch::Timings {
    crate::watch::Timings {
        quiet: Duration::from_millis(40),
        burst: Duration::from_millis(200),
        gap: Duration::from_millis(150),
        keepalive: Duration::from_secs(3600),
        pong: Duration::from_millis(400),
        backoff_first: Duration::from_millis(20),
        backoff_cap: Duration::from_millis(100),
        stable: Duration::from_secs(1),
        connect: Duration::from_secs(5),
        tor_connect: Duration::from_secs(5),
        poll: Duration::from_millis(100),
        reprobe: Duration::from_secs(3600),
    }
}

/// The transactions the watch hands out up to its first sync of
/// `wallet`, and for a quiet moment past it: anything then would be an
/// announcement too many.
async fn caught_up(events: &mut LiveEvents, wallet: &str) -> Vec<LiveTx> {
    let mut txs = Vec::new();
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(LiveEvent::Transaction(tx))) => txs.push(tx),
            Ok(Some(LiveEvent::WalletSynced { report })) if report.wallet_id == wallet => break,
            Ok(Some(LiveEvent::SyncFailed { message, .. })) => panic!("the sync failed: {message}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch stopped"),
            Err(_) => panic!("no catch-up within {WAIT:?}"),
        }
    }
    while let Ok(Some(event)) = tokio::time::timeout(QUIET, events.next()).await {
        if let LiveEvent::Transaction(tx) = event {
            txs.push(tx);
        }
    }
    txs
}

/// A payment that arrived while nothing ran, the app closed or killed,
/// is announced when the watch starts, once; its confirmation, come
/// while nothing ran either, at the next start, once; and a start with
/// nothing new says nothing.
#[tokio::test]
async fn what_arrived_while_nothing_ran_is_announced_when_the_watch_starts() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();

    let payment = transaction(&[nowhere(1, 0)], &[(ADDRESS_SCRIPT, 42_000)]);
    let paid = payment.compute_txid();
    server.add_tx(&payment);
    server.set_history(ADDRESS_SCRIPT, &[(paid, 0)]);
    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    let said = caught_up(&mut events, &wallet).await;
    assert_eq!(staged(&said), [(paid.to_string(), TxStage::Mempool)]);
    assert_eq!(said[0].net_sats, 42_000);
    manager.live_stop().await;

    server.set_history(ADDRESS_SCRIPT, &[(paid, 90)]);
    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    assert_eq!(
        staged(&caught_up(&mut events, &wallet).await),
        [(paid.to_string(), TxStage::Confirmed)]
    );
    manager.live_stop().await;

    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    assert!(caught_up(&mut events, &wallet).await.is_empty());
    manager.live_stop().await;
}

/// The app opens: its own sync and the watch's catch-up run at the same
/// moment, in whatever order the scheduler gives them. The payment that
/// arrived meanwhile comes out exactly once between the two, whether
/// the app announces what its sync found or announces nothing at all.
#[tokio::test]
async fn an_opening_sync_racing_the_catch_up_announces_once() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    let mut history = Vec::new();
    for round in 0..6u8 {
        let payment = transaction(
            &[nowhere(10 + round, 0)],
            &[(ADDRESS_SCRIPT, 1_000 + u64::from(round))],
        );
        server.add_tx(&payment);
        history.push((payment.compute_txid(), 0));
        server.set_history(ADDRESS_SCRIPT, &history);
        let app_claims = round % 2 == 0;
        let app = async {
            tokio::time::sleep(Duration::from_millis(40 * u64::from(round / 2))).await;
            let report = manager.sync_wallet(&wallet).await.unwrap();
            if app_claims {
                manager.claim_announcements(&report).await.unwrap()
            } else {
                Vec::new()
            }
        };
        let watch = async {
            let mut events = manager.live_start_with(Some(timings())).await.unwrap();
            caught_up(&mut events, &wallet).await
        };
        let (by_app, by_watch) = tokio::join!(app, watch);
        let all: Vec<LiveTx> = by_app.into_iter().chain(by_watch).collect();
        assert_eq!(
            staged(&all),
            [(payment.compute_txid().to_string(), TxStage::Mempool)],
            "round {round}"
        );
        manager.live_stop().await;
    }
}
