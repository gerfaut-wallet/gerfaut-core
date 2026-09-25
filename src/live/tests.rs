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
        retries: [Duration::from_millis(20), Duration::from_millis(50)],
        hold: Duration::from_millis(100),
        hold_cap: Duration::from_millis(400),
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

/// The transactions the watch hands out once it has read every script,
/// up to a second in which nothing more comes: whether it syncs depends
/// on what the host's own sync, racing it, already found.
async fn settled(events: &mut LiveEvents) -> Vec<LiveTx> {
    let mut txs = Vec::new();
    let mut subscribed = false;
    loop {
        let wait = if subscribed {
            Duration::from_secs(1)
        } else {
            WAIT
        };
        match tokio::time::timeout(wait, events.next()).await {
            Ok(Some(LiveEvent::Transaction(tx))) => txs.push(tx),
            Ok(Some(LiveEvent::Status(status))) if status.pushed_scripts > 0 => subscribed = true,
            Ok(Some(LiveEvent::SyncFailed { message, .. })) => panic!("the sync failed: {message}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch stopped"),
            Err(_) if subscribed => return txs,
            Err(_) => panic!("never subscribed within {WAIT:?}"),
        }
    }
}

/// Once the watch has read every script, nothing more for a while: no
/// sync, since nothing moved, and nothing to announce.
async fn quiet_start(events: &mut LiveEvents) {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(LiveEvent::Status(status))) if status.pushed_scripts > 0 => break,
            Ok(Some(LiveEvent::Status(_) | LiveEvent::NewBlock { .. })) => {}
            Ok(Some(other)) => panic!("expected a quiet start, got {other:?}"),
            Ok(None) => panic!("the watch stopped"),
            Err(_) => panic!("never subscribed within {WAIT:?}"),
        }
    }
    while let Ok(Some(event)) = tokio::time::timeout(QUIET, events.next()).await {
        assert!(
            matches!(event, LiveEvent::Status(_) | LiveEvent::NewBlock { .. }),
            "expected a quiet start, got {event:?}"
        );
    }
}

/// A payment that arrived while nothing ran, the app closed or killed,
/// is announced when the watch starts, once; its confirmation, come
/// while nothing ran either, at the next start, once; and a start with
/// nothing new says nothing, and syncs nothing.
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
    quiet_start(&mut events).await;
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
            settled(&mut events).await
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

/// A host sync finds a payment and claims nothing, before the watch
/// starts and while it runs. The watch has no sync of its own to run,
/// nothing having moved since, and announces the payment all the same,
/// once.
#[tokio::test]
async fn what_a_host_sync_left_unclaimed_is_announced_by_the_watch() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();

    let before = transaction(&[nowhere(1, 0)], &[(ADDRESS_SCRIPT, 3_000)]);
    server.add_tx(&before);
    server.set_history(ADDRESS_SCRIPT, &[(before.compute_txid(), 0)]);
    manager.sync_wallet(&wallet).await.unwrap();
    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    assert_eq!(
        staged(&caught_up(&mut events, &wallet).await),
        [(before.compute_txid().to_string(), TxStage::Mempool)]
    );

    // Found by the host while the watch runs, and never pushed.
    let during = transaction(&[nowhere(2, 0)], &[(ADDRESS_SCRIPT, 4_000)]);
    server.add_tx(&during);
    server.set_history(
        ADDRESS_SCRIPT,
        &[(before.compute_txid(), 0), (during.compute_txid(), 0)],
    );
    manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(
        staged(&caught_up(&mut events, &wallet).await),
        [(during.compute_txid().to_string(), TxStage::Mempool)]
    );
    manager.live_stop().await;
}

/// One wallet of the vault pays another: each is told, the first of a
/// payment going out and the second of one coming in, when it enters
/// the mempool and when it confirms, once each, whichever claims first.
#[tokio::test]
async fn a_transfer_between_two_wallets_is_announced_for_each() {
    use bdk_wallet::bitcoin::{Address, ScriptBuf};

    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, payer) = watching(dir.path(), server.backend()).await;
    let theirs = crate::testkit::script(5);
    let other = Address::from_script(
        &ScriptBuf::from_hex(&theirs).unwrap(),
        bdk_wallet::bitcoin::Network::Signet,
    )
    .unwrap()
    .to_string();
    let payee = manager
        .add_wallet(
            "Savings",
            &crate::input::parse_input(&other).unwrap(),
            Network::Signet,
        )
        .await
        .unwrap()
        .id;

    let funding = transaction(&[nowhere(1, 0)], &[(ADDRESS_SCRIPT, 50_000)]);
    server.add_tx(&funding);
    server.set_history(ADDRESS_SCRIPT, &[(funding.compute_txid(), 90)]);
    for wallet in [&payer, &payee] {
        manager.sync_wallet(wallet).await.unwrap();
    }

    let transfer = transaction(
        &[bdk_wallet::bitcoin::OutPoint::new(
            funding.compute_txid(),
            0,
        )],
        &[(theirs.as_str(), 40_000), (ADDRESS_SCRIPT, 9_000)],
    );
    let moved = transfer.compute_txid();
    server.add_tx(&transfer);
    for height in [0, 95] {
        server.set_history(
            ADDRESS_SCRIPT,
            &[(funding.compute_txid(), 90), (moved, height)],
        );
        server.set_history(&theirs, &[(moved, height)]);
        let stage = if height == 0 {
            TxStage::Mempool
        } else {
            TxStage::Confirmed
        };
        // The payee claims first once, the payer the other time.
        let order = if height == 0 {
            [&payee, &payer]
        } else {
            [&payer, &payee]
        };
        for wallet in order {
            let claimed = sync_and_claim(&manager, wallet).await;
            assert_eq!(
                staged(&claimed),
                [(moved.to_string(), stage)],
                "{wallet} at {height}"
            );
            let net = if *wallet == payer { -41_000 } else { 40_000 };
            assert_eq!(claimed[0].net_sats, net);
        }
        for wallet in [&payer, &payee] {
            assert!(sync_and_claim(&manager, wallet).await.is_empty());
        }
    }
}

// --- addresses the wallet never showed ---------------------------------------

/// BIP-84 test vector account, on testnet paths: public.
const DESCRIPTOR: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";

/// The receive script at `index` of [`DESCRIPTOR`], in hex.
fn receive_script(index: u32) -> String {
    bdk_wallet::Wallet::create_single(DESCRIPTOR.to_owned())
        .network(bdk_wallet::bitcoin::Network::Signet)
        .create_wallet_no_persist()
        .unwrap()
        .peek_address(bdk_wallet::KeychainKind::External, index)
        .script_pubkey()
        .to_hex_string()
}

/// A payment of `sats` to `script`, at `height` (0 for the mempool),
/// with the transaction it spends, both on the server.
fn pay(server: &FakeElectrum, n: u8, script: &str, sats: u64, height: i64) -> String {
    let parent = transaction(
        &[nowhere(n, 0)],
        &[(crate::testkit::script(9).as_str(), sats + 1_000)],
    );
    let payment = transaction(
        &[bdk_wallet::bitcoin::OutPoint::new(parent.compute_txid(), 0)],
        &[(script, sats)],
    );
    server.add_tx(&parent);
    server.add_tx(&payment);
    server.set_history(script, &[(payment.compute_txid(), height)]);
    payment.compute_txid().to_string()
}

/// Someone pays the wallet at a receive address it never showed, one
/// another app or the signing device handed out, while nothing runs:
/// five past the next one it would show. The watch that starts next
/// announces it, once; its confirmation and the next such payment are
/// found by a plain sync, whoever runs it.
#[tokio::test]
async fn a_payment_to_an_address_the_wallet_never_showed_is_announced() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_backend(Network::Signet, server.backend())
        .await
        .unwrap();
    let wallet = manager
        .add_wallet(
            "Cold",
            &crate::input::parse_input(DESCRIPTOR).unwrap(),
            Network::Signet,
        )
        .await
        .unwrap()
        .id;
    // Paid at its first address before the import, which finds it.
    pay(&server, 1, &receive_script(0), 10_000, 90);
    let import = manager.sync_wallet(&wallet).await.unwrap();
    assert_eq!(import.new_txs.len(), 1);
    assert!(
        manager
            .claim_announcements(&import)
            .await
            .unwrap()
            .is_empty()
    );

    let unseen = pay(&server, 2, &receive_script(6), 20_000, 0);
    let asked_before = server.state.lock().unwrap().asked.len();
    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    assert_eq!(
        staged(&caught_up(&mut events, &wallet).await),
        [(unseen.clone(), TxStage::Mempool)]
    );
    manager.live_stop().await;
    // The watch saw that one script move, and the sync it ran read that
    // one: its history, the payment, and the coin it spends, for the fee.
    let asked: Vec<String> = server.state.lock().unwrap().asked[asked_before..].to_vec();
    let count = |method: &str| asked.iter().filter(|asked| *asked == method).count();
    assert_eq!(count("blockchain.scripthash.get_history"), 1, "{asked:?}");
    assert_eq!(count("blockchain.transaction.get"), 2, "{asked:?}");

    // A new block takes it.
    server.state.lock().unwrap().height = 101;
    server.set_history(&receive_script(6), &[(unseen.parse().unwrap(), 101)]);
    assert_eq!(
        staged(&sync_and_claim(&manager, &wallet).await),
        [(unseen, TxStage::Confirmed)]
    );
    let next = pay(&server, 3, &receive_script(12), 30_000, 0);
    assert_eq!(
        staged(&sync_and_claim(&manager, &wallet).await),
        [(next, TxStage::Mempool)]
    );

    // What that costs a sync with nothing new: one history for each of
    // the 13 addresses shown, and one for each of the 20 past them.
    let asked_before = server.state.lock().unwrap().asked.len();
    assert!(sync_and_claim(&manager, &wallet).await.is_empty());
    let asked: Vec<String> = server.state.lock().unwrap().asked[asked_before..].to_vec();
    let histories = asked
        .iter()
        .filter(|method| *method == "blockchain.scripthash.get_history")
        .count();
    println!("a sync with nothing new asked {asked:?}");
    assert_eq!(histories, 13 + 20);
    // And nothing the wallet holds: no transaction, no proof of a
    // confirmation it has proven already.
    assert!(
        !asked
            .iter()
            .any(|method| method.starts_with("blockchain.transaction.")),
        "{asked:?}"
    );
}

// --- how soon ---------------------------------------------------------------------

/// The next transaction the watch hands out.
async fn next_announcement(events: &mut LiveEvents) -> LiveTx {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(LiveEvent::Transaction(tx))) => return tx,
            Ok(Some(LiveEvent::SyncFailed { message, .. })) => panic!("the sync failed: {message}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch stopped"),
            Err(_) => panic!("nothing announced within {WAIT:?}"),
        }
    }
}

/// With the watch's own timings, not the short ones of the other tests:
/// a payment enters the mempool right after the watch caught up, and a
/// block takes it half a second after it was announced. The server
/// pushes each change, and each is announced within about a second of
/// the push, however soon it follows the one before.
#[tokio::test]
async fn an_arrival_and_its_confirmation_are_announced_within_a_second() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    let pace = crate::watch::Timings::of(&manager.watch_config().await);
    let mut events = manager.live_start_with(Some(pace)).await.unwrap();
    quiet_start(&mut events).await;

    let payment = transaction(&[nowhere(4, 0)], &[(ADDRESS_SCRIPT, 12_000)]);
    let paid = payment.compute_txid();
    server.add_tx(&payment);
    server.set_history(ADDRESS_SCRIPT, &[(paid, 0)]);
    let pushed = std::time::Instant::now();
    server.set_status(ADDRESS_SCRIPT, "in the mempool");
    let arrival = next_announcement(&mut events).await;
    let arrived_in = pushed.elapsed();
    assert_eq!(staged(&[arrival]), [(paid.to_string(), TxStage::Mempool)]);

    tokio::time::sleep(Duration::from_millis(500)).await;
    server.state.lock().unwrap().height = 101;
    server.set_history(ADDRESS_SCRIPT, &[(paid, 101)]);
    let pushed = std::time::Instant::now();
    server.push(
        serde_json::json!({
            "jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
            "params": [{ "height": 101, "hex": crate::testkit::header_at(101) }],
        })
        .to_string(),
    );
    server.set_status(ADDRESS_SCRIPT, "in a block");
    let confirmation = next_announcement(&mut events).await;
    let confirmed_in = pushed.elapsed();
    assert_eq!(
        staged(&[confirmation]),
        [(paid.to_string(), TxStage::Confirmed)]
    );
    println!("announced {arrived_in:?} and {confirmed_in:?} after the push");
    let second = Duration::from_millis(1_500);
    assert!(arrived_in < second, "the arrival took {arrived_in:?}");
    assert!(
        confirmed_in < second,
        "the confirmation took {confirmed_in:?}"
    );
    manager.live_stop().await;
}

// --- a server that forges changes ---------------------------------------------

/// The next sync of `wallet` the watch hands out, and how long it took
/// to come.
async fn next_sync(events: &mut LiveEvents, wallet: &str) -> (SyncReport, Duration) {
    let started = std::time::Instant::now();
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(LiveEvent::WalletSynced { report })) if report.wallet_id == wallet => {
                return (report, started.elapsed());
            }
            Ok(Some(LiveEvent::SyncFailed { message, .. })) => panic!("the sync failed: {message}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch stopped"),
            Err(_) => panic!("no sync within {WAIT:?}"),
        }
    }
}

/// Past two pushed changes in a row that a sync found nothing behind,
/// the next one waits, twice as long each time, up to the cap. Blocks,
/// reconnections and starts never wait, nor does another wallet, and a
/// sync that finds something ends the wait.
#[test]
fn a_change_no_sync_finds_is_heard_less_and_less_often() {
    let second = Duration::from_secs(1);
    let pace = crate::watch::Timings {
        hold: second,
        hold_cap: second * 5,
        ..timings()
    };
    let pushed = &Asked::of(ChangeReason::Activity, Vec::new());
    let block = &Asked::of(ChangeReason::NewBlock, Vec::new());
    let mut futile = Futile::default();
    for _ in 0..FREE_FUTILE {
        assert_eq!(futile.hold("w", pushed, &pace), Duration::ZERO);
        futile.settle("w", pushed, false);
    }
    let holds: Vec<Duration> = (0..5)
        .map(|_| {
            let hold = futile.hold("w", pushed, &pace);
            futile.settle("w", pushed, false);
            hold
        })
        .collect();
    assert_eq!(holds, [1, 2, 4, 5, 5].map(|n| second * n));
    assert_eq!(futile.hold("w", block, &pace), Duration::ZERO);
    assert_eq!(futile.hold("other", pushed, &pace), Duration::ZERO);
    // A block that finds nothing is no claim of the server's.
    futile.settle("w", block, false);
    assert_eq!(futile.hold("w", pushed, &pace), second * 5);
    futile.settle("w", block, true);
    assert_eq!(futile.hold("w", pushed, &pace), Duration::ZERO);
}

/// A server forges a new status for the watched address again and
/// again, where nothing moved. The first two are synced at once, the
/// next ones wait longer and longer, and a payment that does arrive is
/// still announced.
#[tokio::test]
async fn a_server_that_forges_changes_is_heard_less_and_less() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = watching(dir.path(), server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    let hold = Duration::from_secs(1);
    let pace = crate::watch::Timings {
        hold,
        hold_cap: hold * 2,
        ..timings()
    };
    let mut events = manager.live_start_with(Some(pace)).await.unwrap();
    quiet_start(&mut events).await;

    let mut forged = 0u32;
    let mut forge = || {
        forged += 1;
        server.set_status(ADDRESS_SCRIPT, &format!("forged {forged}"));
    };
    for _ in 0..FREE_FUTILE {
        forge();
        let (report, _) = next_sync(&mut events, &wallet).await;
        assert!(report.new_txs.is_empty());
    }
    forge();
    let (_, waited) = next_sync(&mut events, &wallet).await;
    assert!(waited >= hold, "{waited:?}");
    forge();
    let (_, waited) = next_sync(&mut events, &wallet).await;
    assert!(waited >= hold * 2, "{waited:?}");

    let payment = transaction(&[nowhere(3, 0)], &[(ADDRESS_SCRIPT, 7_000)]);
    server.add_tx(&payment);
    server.set_history(ADDRESS_SCRIPT, &[(payment.compute_txid(), 0)]);
    server.set_status(ADDRESS_SCRIPT, "paid");
    assert_eq!(
        staged(&caught_up(&mut events, &wallet).await),
        [(payment.compute_txid().to_string(), TxStage::Mempool)]
    );
    manager.live_stop().await;
}

// --- replacements ---------------------------------------------------------------

/// Syncs, then claims what the sync found.
async fn sync_and_claim(manager: &WalletManager, wallet: &str) -> Vec<LiveTx> {
    let report = manager.sync_wallet(wallet).await.unwrap();
    manager.claim_announcements(&report).await.unwrap()
}

/// A watched address, synced once with nothing on it, then paid 50 000
/// sats by a transaction spending output 0 of `0x22…`, announced.
async fn paid(server: &FakeMempool, dir: &std::path::Path) -> (WalletManager, String) {
    let (manager, wallet) = watching(dir, server.backend()).await;
    manager.sync_wallet(&wallet).await.unwrap();
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x11, 0x22, 50_000, false)];
    assert_eq!(
        staged(&sync_and_claim(&manager, &wallet).await),
        [(txid(0x11), TxStage::Mempool)]
    );
    (manager, wallet)
}

/// The sender bumps the fee twice: the wallet is told once that the
/// payment is coming, and once that it confirmed.
#[tokio::test]
async fn a_fee_bump_is_announced_once_and_confirms_once() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = paid(&server, dir.path()).await;
    for (bump, sats) in [(0x12, 49_800), (0x13, 49_600)] {
        server.state.lock().unwrap().address_txs = vec![esplora_payment(bump, 0x22, sats, false)];
        assert!(sync_and_claim(&manager, &wallet).await.is_empty());
    }
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x13, 0x22, 49_600, true)];
    let claimed = sync_and_claim(&manager, &wallet).await;
    assert_eq!(staged(&claimed), [(txid(0x13), TxStage::Confirmed)]);
    assert_eq!(claimed[0].net_sats, 49_600);
    // Under the txid it was first announced under, across both bumps.
    assert_eq!(claimed[0].replaces, Some(txid(0x11)));
    assert!(sync_and_claim(&manager, &wallet).await.is_empty());
}

/// The sender replaces the payment with one that no longer pays the
/// address: it vanishes, and that is said once.
#[tokio::test]
async fn a_bump_that_stops_paying_is_announced_as_dropped_once() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = paid(&server, dir.path()).await;
    server.state.lock().unwrap().address_txs = Vec::new();
    let claimed = sync_and_claim(&manager, &wallet).await;
    assert_eq!(
        claimed,
        [LiveTx {
            wallet_id: wallet.clone(),
            txid: txid(0x11),
            net_sats: 50_000,
            stage: TxStage::Dropped,
            replaces: None,
        }]
    );
    assert!(sync_and_claim(&manager, &wallet).await.is_empty());
}

/// The sender replaces the payment with one that leaves the address a
/// single sat: no fee bump. The replacement is announced for what it
/// pays, and the payment announced first as dropped.
#[tokio::test]
async fn a_replacement_that_cuts_the_payment_is_announced() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = paid(&server, dir.path()).await;
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x12, 0x22, 1, false)];
    let claimed = sync_and_claim(&manager, &wallet).await;
    assert_eq!(
        staged(&claimed),
        [
            (txid(0x12), TxStage::Mempool),
            (txid(0x11), TxStage::Dropped)
        ]
    );
    assert_eq!(claimed[0].net_sats, 1);
    assert_eq!(claimed[1].net_sats, 50_000);
    assert!(sync_and_claim(&manager, &wallet).await.is_empty());
}

/// Replaced by a transaction that pays the address and is already in a
/// block: one confirmation, and nothing vanished.
#[tokio::test]
async fn a_replacement_that_confirms_is_announced_once() {
    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let (manager, wallet) = paid(&server, dir.path()).await;
    server.state.lock().unwrap().address_txs = vec![esplora_payment(0x12, 0x22, 49_800, true)];
    assert_eq!(
        staged(&sync_and_claim(&manager, &wallet).await),
        [(txid(0x12), TxStage::Confirmed)]
    );
    assert!(sync_and_claim(&manager, &wallet).await.is_empty());
}

/// The same three cases through the engine of a descriptor wallet: a
/// replacement it sees last in the mempool wins, an eviction removes a
/// payment, a block settles it.
#[test]
fn a_descriptor_wallet_tells_replacements_and_vanished_payments() {
    use bdk_wallet::KeychainKind;
    use bdk_wallet::bitcoin::BlockHash;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};

    use crate::store::VaultPayload;
    use crate::wallet::views;

    /// BIP-84 test vector account, on testnet paths: public.
    const EXTERNAL: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";
    const NOW: u64 = 1_800_000_000;

    let mut engine = bdk_wallet::Wallet::create_single(EXTERNAL)
        .network(bdk_wallet::bitcoin::Network::Signet)
        .create_wallet_no_persist()
        .unwrap();
    let ours = engine
        .reveal_next_address(KeychainKind::External)
        .script_pubkey()
        .to_hex_string();
    let theirs = crate::testkit::script(9);
    let mut payload = VaultPayload::default();
    // One sync: what the engine holds after `change`, against before.
    let mut sync = |engine: &mut bdk_wallet::Wallet, change: &dyn Fn(&mut bdk_wallet::Wallet)| {
        let before = views::known(engine);
        change(engine);
        let moves = views::moves(engine, &before);
        news::record(&mut payload, "w", false, &moves, NOW);
        news::claim(&mut payload, "w", 10, NOW)
    };
    let pays = |n: u8, sats: u64| transaction(&[nowhere(n, 0)], &[(ours.as_str(), sats)]);

    // A payment, then two fee bumps of it, seen later each time.
    let first = pays(1, 50_000);
    let claimed = sync(&mut engine, &|engine| {
        engine.apply_unconfirmed_txs([(first.clone(), 100)])
    });
    assert_eq!(
        staged(&claimed),
        [(first.compute_txid().to_string(), TxStage::Mempool)]
    );
    let mut last = first;
    for (sats, seen_at) in [(49_800, 200), (49_600, 300)] {
        let bump = pays(1, sats);
        let claimed = sync(&mut engine, &|engine| {
            engine.apply_unconfirmed_txs([(bump.clone(), seen_at)])
        });
        assert!(claimed.is_empty(), "{claimed:?}");
        last = bump;
    }
    // A block takes the last one.
    let block = BlockId {
        height: 10,
        hash: BlockHash::from_byte_array([1; 32]),
    };
    let mined = last.compute_txid();
    let claimed = sync(&mut engine, &|engine| {
        let mut update = bdk_wallet::Update {
            chain: Some(engine.latest_checkpoint().push(block).unwrap()),
            ..Default::default()
        };
        update.tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: block,
                confirmation_time: 1_700_000_600,
            },
            mined,
        ));
        engine.apply_update(update).unwrap();
    });
    assert_eq!(staged(&claimed), [(mined.to_string(), TxStage::Confirmed)]);

    // Another payment, evicted: the replacement that paid elsewhere is
    // not the wallet's to see.
    let second = pays(2, 20_000);
    sync(&mut engine, &|engine| {
        engine.apply_unconfirmed_txs([(second.clone(), 400)])
    });
    let elsewhere = transaction(&[nowhere(2, 0)], &[(theirs.as_str(), 19_900)]);
    let claimed = sync(&mut engine, &|engine| {
        engine.apply_unconfirmed_txs([(elsewhere.clone(), 500)]);
        engine.apply_evicted_txs([(second.compute_txid(), 500)]);
    });
    assert_eq!(
        staged(&claimed),
        [(second.compute_txid().to_string(), TxStage::Dropped)]
    );
    assert_eq!(claimed[0].net_sats, 20_000);
    assert!(sync(&mut engine, &|_| {}).is_empty());
}
