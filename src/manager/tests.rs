//! The rules every call of the facade is held to: a vault that cannot
//! be written changes nothing in memory, and no private key reaches it.

pub(crate) mod support;

use super::*;
use crate::backup::{
    self, BACKUP_VERSION, BackupOptions, BackupPayload, BackupWallet, ImportChoices,
};
use crate::input::{ParsedPayload, parse_input};
use support::{BACKUP_PASSWORD, MULTIPATH, key, manager, seeded};

/// A descriptor with a private key is refused however it arrives:
/// from a backup file written by hand, or from a parsed input the
/// app hands back altered. Nothing reaches the vault.
#[tokio::test]
async fn private_keys_never_reach_the_vault() {
    const TPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
    // The textbook WIF example, public for years.
    const WIF: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let private = [
        format!("wpkh({TPRV}/84'/1'/0'/0/*)"),
        format!("wpkh({WIF})"),
    ];
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;

    for descriptor in &private {
        let mut parsed = parse_input(MULTIPATH).unwrap();
        parsed.payload = ParsedPayload::Descriptors {
            external: descriptor.clone(),
            internal: None,
            script: crate::input::ScriptKind::Segwit,
        };
        let error = manager
            .add_wallet("Hot", &parsed, Network::Signet)
            .await
            .unwrap_err();
        assert!(
            matches!(error, CoreError::PrivateMaterialRejected),
            "{error}"
        );

        let payload = BackupPayload {
            version: BACKUP_VERSION,
            created_at: 1_755_000_000,
            wallets: vec![BackupWallet {
                name: "Hot".to_owned(),
                network: Network::Signet,
                kind: WalletKind::Descriptors {
                    external: descriptor.clone(),
                    internal: None,
                    script: crate::input::ScriptKind::Segwit,
                },
                gap_limit: 20,
                labels: Default::default(),
                created_at: 1_755_000_000,
                live_pinned: false,
            }],
            backends: None,
            electrum_certs: None,
            gap_limit: None,
        };
        let sealed = backup::seal(&payload, BACKUP_PASSWORD).unwrap();
        let source = data_encoding::BASE64.encode(&sealed);
        let error = manager
            .import_backup(
                &source,
                BACKUP_PASSWORD,
                &ImportChoices {
                    indexes: None,
                    apply_settings: false,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, CoreError::PrivateMaterialRejected),
            "{error}"
        );
    }

    assert!(manager.list_wallets(None).await.is_empty());
    drop(manager);
    let raw = crate::store::Vault::open_or_create(dir.path().join(VAULT_FILE), key())
        .unwrap()
        .1;
    let json = serde_json::to_string(&raw).unwrap();
    assert!(!json.contains("prv") && !json.contains(&private[1][5..20]));
}

/// A save that fails must leave the vault in memory exactly as it
/// was. Otherwise the screen shows wallets the disk never received,
/// and the next save, made for anything else, commits an import the
/// user was told had failed.
#[tokio::test]
async fn a_failed_save_changes_nothing_in_memory() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, _, _) = seeded(source_dir.path()).await;
    source.set_gap_limit(50).await.unwrap();
    let bundle = source
        .export_backup(
            &BackupOptions {
                wallet_ids: None,
                include_settings: true,
            },
            BACKUP_PASSWORD,
        )
        .await
        .unwrap();
    let everything = ImportChoices {
        indexes: None,
        apply_settings: true,
    };

    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    // Every save fails from here, before the vault itself is
    // touched, as it would on a full disk.
    let fail_saves = |fail: bool| {
        let target = target.clone();
        async move { target.state.lock().await.vault.fail_saves(fail) }
    };
    fail_saves(true).await;

    let error = target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &everything)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CoreError::Vault(crate::error::VaultError::Io(_))),
        "{error}"
    );
    assert!(target.list_wallets(None).await.is_empty());
    assert_eq!(target.settings().await.gap_limit, 20);
    assert!(
        target
            .preview_backup(&bundle.data, BACKUP_PASSWORD)
            .await
            .unwrap()
            .wallets
            .iter()
            .all(|w| !w.already_watched)
    );
    assert!(
        target
            .add_wallet("Cold", &parse_input(MULTIPATH).unwrap(), Network::Signet)
            .await
            .is_err()
    );
    assert!(target.list_wallets(None).await.is_empty());
    assert!(target.set_gap_limit(30).await.is_err());
    assert_eq!(target.settings().await.gap_limit, 20);

    // The disk back: the same import goes through whole, and a
    // fresh open finds exactly what the report said.
    fail_saves(false).await;
    let report = target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &everything)
        .await
        .unwrap();
    assert_eq!(report.added.len(), 2);
    assert_eq!(target.settings().await.gap_limit, 50);
    let cold = report.added[0].id.clone();

    // Renaming and removing are held to the same rule.
    fail_saves(true).await;
    assert!(target.rename_wallet(&cold, "Renamed").await.is_err());
    assert!(target.remove_wallet(&cold).await.is_err());
    let wallets = target.list_wallets(None).await;
    assert_eq!(wallets.len(), 2);
    assert_eq!(wallets[0].name, "Cold");
    assert!(target.wallet_snapshot(&cold).await.is_ok());
    fail_saves(false).await;

    drop(target);
    let reopened = WalletManager::open(target_dir.path(), key()).unwrap();
    assert_eq!(reopened.list_wallets(None).await.len(), 2);
    assert_eq!(reopened.settings().await.gap_limit, 50);
}
