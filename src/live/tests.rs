//! Live alerts end to end: the wallet manager, its vault, and the fake
//! servers of [`crate::testkit`].

use super::*;
use crate::store::VaultKey;
use crate::testkit::{ADDRESS, FakeMempool, esplora_payment};

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
