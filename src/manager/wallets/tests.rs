//! The wallets, against a vault on disk.

use super::*;
use crate::backup::{BackupOptions, ImportChoices};
use crate::input::parse_input;
use crate::manager::tests::support::{ADDRESS, BACKUP_PASSWORD, MULTIPATH, key, manager, seeded};
use crate::wallet::AddressWatchState;

#[tokio::test]
async fn add_list_snapshot_descriptor_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;

    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.network, Network::Signet);

    let wallets = manager.list_wallets(Some(Network::Signet)).await;
    assert_eq!(wallets.len(), 1);
    assert!(
        manager
            .list_wallets(Some(Network::Mainnet))
            .await
            .is_empty()
    );

    let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
    assert_eq!(snapshot.balance.total, 0);
    assert!(snapshot.txs.is_empty());
    assert_eq!(snapshot.tip_height, 0);
}

#[tokio::test]
async fn policy_of_a_descriptor_wallet_reads_its_keys() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.policy(&meta.id).await.unwrap();
    assert_eq!(snapshot.kind, policy::PolicyKind::SingleKey);
    assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
    assert_eq!(snapshot.keys.len(), 1);
    assert_eq!(snapshot.keys[0].fingerprint.as_deref(), Some("9a6a2580"));
    assert_eq!(snapshot.keys[0].origin_path.as_deref(), Some("m/84'/1'/0'"));
    assert_eq!(snapshot.branches.len(), 1);
    assert!(snapshot.branches[0].spendable_now);
    assert_eq!(snapshot.coins, 0);
    assert_eq!(
        snapshot.tip_height, None,
        "never synced: no tip to measure from"
    );
    assert!(matches!(
        manager.policy("nope").await,
        Err(CoreError::WalletNotFound(_))
    ));
}

#[tokio::test]
async fn policy_of_a_watched_address_has_no_branches() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let parsed = parse_input(address).unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.policy(&meta.id).await.unwrap();
    assert_eq!(snapshot.kind, policy::PolicyKind::Address);
    assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
    assert_eq!(snapshot.descriptor, address);
    assert_eq!(snapshot.policy, "address");
    assert!(snapshot.keys.is_empty());
    assert!(snapshot.branches.is_empty());
    assert!(!snapshot.has_timelocks);
}

#[tokio::test]
async fn receive_addresses_derive_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    let entries = manager.receive_addresses(&meta.id, 2).await.unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].address.starts_with("tb1"));
    assert_eq!(entries[0].index, 0);
    assert_eq!(entries[2].index, 2);
    // Single-origin descriptor: the absolute path is unambiguous.
    assert_eq!(entries[0].derivation.as_deref(), Some("m/84'/1'/0'/0/0"));
    assert_eq!(entries[2].derivation.as_deref(), Some("m/84'/1'/0'/0/2"));

    // A fresh manager reloads the engine from the vault and derives
    // the same addresses.
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let again = manager.receive_addresses(&meta.id, 2).await.unwrap();
    assert_eq!(again[0].address, entries[0].address);
}

#[tokio::test]
async fn address_list_and_export_read_the_same_state() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();

    // Fresh wallet: one revealed external address, no change yet.
    let list = manager.address_list(&meta.id).await.unwrap();
    assert_eq!(list.external.len(), 1);
    assert_eq!(list.external[0].index, 0);
    assert!(!list.external[0].used);
    assert_eq!(list.external[0].balance_sats, 0);
    assert!(list.internal.is_empty());
    assert!(!list.truncated);

    // Peeking receive addresses reveals further external rows.
    let _ = manager.receive_addresses(&meta.id, 0).await.unwrap();
    let again = manager.address_list(&meta.id).await.unwrap();
    assert!(!again.external.is_empty());
    assert_eq!(again.external[0].address, list.external[0].address);

    // An empty wallet exports a header and nothing else.
    let export = manager
        .export_transactions(&meta.id, &crate::export::ExportOptions::default())
        .await
        .unwrap();
    assert_eq!(export.rows, 0);
    assert!(export.csv.starts_with("txid,date_utc,"));
    assert_eq!(export.csv.lines().count(), 1);
}

#[tokio::test]
async fn duplicates_and_network_mismatch_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    manager
        .add_wallet("One", &parsed, Network::Signet)
        .await
        .unwrap();

    assert!(matches!(
        manager.add_wallet("Two", &parsed, Network::Signet).await,
        Err(CoreError::DuplicateWallet(_))
    ));
    assert!(matches!(
        manager.add_wallet("Three", &parsed, Network::Mainnet).await,
        Err(CoreError::NetworkMismatch { .. })
    ));
}

#[tokio::test]
async fn single_address_wallet_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();

    let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
    assert_eq!(snapshot.balance.total, 0);

    let entries = manager.receive_addresses(&meta.id, 5).await.unwrap();
    assert_eq!(entries.len(), 1, "a single address has a single entry");

    manager.remove_wallet(&meta.id).await.unwrap();
    assert!(manager.list_wallets(None).await.is_empty());
    assert!(matches!(
        manager.wallet_snapshot(&meta.id).await,
        Err(CoreError::WalletNotFound(_))
    ));
}

/// Coins no one can hold, as a hostile server may list them for a
/// watched address, show in its row at the largest balance there
/// is, as in its snapshot, instead of wrapping around.
#[tokio::test]
async fn an_address_row_never_overflows() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
    let meta = manager
        .add_wallet("Watched address", &parsed, Network::Signet)
        .await
        .unwrap();
    let coin = |txid: &str| crate::wallet::AddressUtxo {
        txid: txid.into(),
        vout: 0,
        value_sats: u64::MAX,
        height: Some(1),
        timestamp: None,
    };
    find_record_mut(&mut manager.state.lock().await.payload, &meta.id)
        .unwrap()
        .address_state = Some(crate::wallet::AddressWatchState {
        utxos: vec![coin("aa"), coin("bb")],
        ..Default::default()
    });

    let list = manager.address_list(&meta.id).await.unwrap();
    assert_eq!(list.external[0].balance_sats, u64::MAX);
}

#[tokio::test]
async fn rename_persists() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Old name", &parsed, Network::Signet)
        .await
        .unwrap();
    manager.rename_wallet(&meta.id, "New name").await.unwrap();

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let wallets = manager.list_wallets(None).await;
    assert_eq!(wallets[0].name, "New name");
}

#[tokio::test]
async fn icon_defaults_to_the_wallet_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Cold", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.icon, WalletIcon::Wallet);
    manager
        .set_wallet_icon(&meta.id, WalletIcon::Snowflake)
        .await
        .unwrap();
    assert!(matches!(
        manager.set_wallet_icon("nope", WalletIcon::Key).await,
        Err(CoreError::WalletNotFound(_))
    ));

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(
        manager.list_wallets(None).await[0].icon,
        WalletIcon::Snowflake
    );
}

#[tokio::test]
async fn reorder_persists_and_leaves_the_rest_alone() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut ids = Vec::new();
    for (name, input) in [
        ("A", MULTIPATH),
        ("B", ADDRESS),
        (
            "C",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        ),
    ] {
        let parsed = parse_input(input).unwrap();
        let meta = manager
            .add_wallet(name, &parsed, Network::Signet)
            .await
            .unwrap();
        ids.push(meta.id);
    }
    let names = |wallets: Vec<WalletMeta>| -> Vec<String> {
        wallets.into_iter().map(|meta| meta.name).collect()
    };

    // Only two of the three are named: they swap, the third keeps
    // its slot.
    manager
        .reorder_wallets(&[ids[2].clone(), ids[0].clone()])
        .await
        .unwrap();
    assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);

    let refused = manager
        .reorder_wallets(&[ids[0].clone(), ids[0].clone()])
        .await
        .unwrap_err();
    assert!(
        matches!(refused, CoreError::InvalidInput { .. }),
        "{refused}"
    );
    assert!(matches!(
        manager.reorder_wallets(&["nope".to_owned()]).await,
        Err(CoreError::WalletNotFound(_))
    ));

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);
}

/// A pin is kept in the vault and carried by a backup, and the live
/// watch reads it with whether each wallet holds coins.
#[tokio::test]
async fn a_pinned_wallet_stays_pinned_and_travels_in_a_backup() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, cold, watch) = seeded(source_dir.path()).await;
    assert!(matches!(
        source.set_wallet_live_pinned("nope", true).await,
        Err(CoreError::WalletNotFound(_))
    ));
    source
        .set_wallet_live_pinned(&watch.id, true)
        .await
        .unwrap();
    let flags = async |manager: &WalletManager| {
        manager
            .watch_list(Network::Signet)
            .await
            .into_iter()
            .map(|wallet| (wallet.pinned, wallet.holds_coins))
            .collect::<Vec<_>>()
    };
    assert_eq!(flags(&source).await, [(false, false), (true, false)]);

    // A coin on each: one the cold wallet's engine holds, one in the
    // state of the watched address.
    {
        let mut state = source.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let ours = engine
            .reveal_next_address(bdk_wallet::KeychainKind::External)
            .script_pubkey()
            .to_hex_string();
        engine.apply_unconfirmed_txs([(
            crate::testkit::transaction(
                &[crate::testkit::nowhere(1, 0)],
                &[(ours.as_str(), 50_000)],
            ),
            1_700_000_000,
        )]);
        find_record_mut(&mut state.payload, &watch.id)
            .unwrap()
            .address_state = Some(AddressWatchState {
            utxos: vec![crate::wallet::AddressUtxo {
                txid: "aa".repeat(32),
                vout: 0,
                value_sats: 1_000,
                height: Some(10),
                timestamp: None,
            }],
            ..Default::default()
        });
    }
    assert_eq!(flags(&source).await, [(false, true), (true, true)]);

    // Kept on disk.
    drop(source);
    let source = WalletManager::open(source_dir.path(), key()).unwrap();
    let pinned = |wallets: Vec<WalletMeta>| {
        wallets
            .into_iter()
            .map(|meta| (meta.name, meta.live_pinned))
            .collect::<Vec<_>>()
    };
    let expected = vec![("Cold".to_owned(), false), ("Watch".to_owned(), true)];
    assert_eq!(pinned(source.list_wallets(None).await), expected);

    let options = BackupOptions {
        wallet_ids: None,
        include_settings: false,
    };
    let bundle = source
        .export_backup(&options, BACKUP_PASSWORD)
        .await
        .unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &ImportChoices::default())
        .await
        .unwrap();
    assert_eq!(pinned(target.list_wallets(None).await), expected);

    source
        .set_wallet_live_pinned(&watch.id, false)
        .await
        .unwrap();
    assert!(
        source
            .list_wallets(None)
            .await
            .iter()
            .all(|meta| !meta.live_pinned)
    );
}
