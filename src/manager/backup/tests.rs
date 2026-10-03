//! Backups end to end: sealed on one vault, read and restored on
//! another, through the file and through the animated QR.

use super::*;
use crate::chain::BackendConfig;
use crate::input::parse_input;
use crate::manager::tests::support::{ADDRESS, BACKUP_PASSWORD, key, manager, seeded};
use crate::network::Network;
use crate::wallet::meta::WalletMeta;

fn fingerprint(byte: &str) -> String {
    vec![byte; 32].join(":")
}

/// A backup handed over by someone else, settings included: what
/// "apply node settings" would put in place is named in the
/// preview, host by host, before the person agrees to it. A backup
/// without settings names nothing.
#[tokio::test]
async fn the_preview_names_what_the_settings_would_apply() {
    let wallet = BackupWallet {
        name: "Friend's wallet".to_owned(),
        network: Network::Signet,
        kind: WalletKind::Descriptors {
            external: "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)".to_owned(),
            internal: None,
            script: crate::input::ScriptKind::Segwit,
        },
        gap_limit: 20,
        labels: Default::default(),
        created_at: 1_755_000_000,
        live_pinned: false,
    };
    let with_settings = BackupPayload {
        version: BACKUP_VERSION,
        created_at: 1_756_000_000,
        wallets: vec![wallet.clone()],
        backends: Some(
            [
                (
                    Network::Signet,
                    BackendConfig::CustomElectrum {
                        url: "ssl://127.0.0.1:1".to_owned(),
                        own_node: false,
                    },
                ),
                (
                    Network::Mainnet,
                    BackendConfig::CustomEsplora {
                        url: "https://user:pass@node.example.org:3002/api".to_owned(),
                        own_node: false,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        ),
        electrum_certs: Some(
            [
                ("127.0.0.1:1".to_owned(), fingerprint("AA")),
                // Not a fingerprint: the import would drop it, so
                // the preview does not promise it.
                ("bogus.example:50002".to_owned(), "nope".to_owned()),
            ]
            .into_iter()
            .collect(),
        ),
        gap_limit: Some(30),
    };
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let text =
        data_encoding::BASE64.encode(&backup::seal(&with_settings, BACKUP_PASSWORD).unwrap());
    let preview = manager
        .preview_backup(&text, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert!(preview.has_settings);
    assert_eq!(
        preview.backends,
        vec![
            BackupBackendPreview {
                network: Network::Mainnet,
                backend: "node.example.org".to_owned(),
            },
            BackupBackendPreview {
                network: Network::Signet,
                backend: "127.0.0.1".to_owned(),
            },
        ]
    );
    assert_eq!(preview.electrum_hosts, vec!["127.0.0.1:1".to_owned()]);
    // What the restore screen receives says it all, and never the
    // credentials a URL may carry.
    let json = serde_json::to_string(&preview).unwrap();
    assert!(
        json.contains(r#""backends":[{"network":"mainnet","backend":"node.example.org"}"#),
        "{json}"
    );
    assert!(
        json.contains(r#""electrum_hosts":["127.0.0.1:1"]"#),
        "{json}"
    );
    assert!(!json.contains("pass@"), "{json}");

    let without = BackupPayload {
        backends: None,
        electrum_certs: None,
        gap_limit: None,
        ..with_settings
    };
    let text = data_encoding::BASE64.encode(&backup::seal(&without, BACKUP_PASSWORD).unwrap());
    let preview = manager
        .preview_backup(&text, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert!(!preview.has_settings);
    assert!(preview.backends.is_empty());
    assert!(preview.electrum_hosts.is_empty());
}

/// A backup carries addresses as the vault that wrote it held
/// them. One from before addresses were stored in canonical form
/// lands in that form, and one the settings screen would have
/// refused does not land at all: the preview does not promise it,
/// and the backend of that network stays as it was.
#[tokio::test]
async fn a_restored_backend_is_stored_canonical_or_left_out() {
    let payload = BackupPayload {
        version: BACKUP_VERSION,
        created_at: 1_756_000_000,
        wallets: Vec::new(),
        backends: Some(
            [
                (
                    Network::Mainnet,
                    BackendConfig::CustomEsplora {
                        url: "HTTPS://Esplora.Example.ORG./api/".to_owned(),
                        own_node: false,
                    },
                ),
                (
                    Network::Signet,
                    BackendConfig::CustomElectrum {
                        url: "tcp://x.onion:50001:extra".to_owned(),
                        own_node: false,
                    },
                ),
                (
                    Network::Testnet4,
                    BackendConfig::Public {
                        server: Some("mempool.emzy.de".to_owned()),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        ),
        electrum_certs: None,
        gap_limit: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let kept = BackendConfig::CustomElectrum {
        url: "ssl://node.example.org:50002".to_owned(),
        own_node: false,
    };
    manager
        .set_backend(Network::Signet, kept.clone())
        .await
        .unwrap();
    let text = data_encoding::BASE64.encode(&backup::seal(&payload, BACKUP_PASSWORD).unwrap());

    let preview = manager
        .preview_backup(&text, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert_eq!(
        preview.backends,
        vec![
            BackupBackendPreview {
                network: Network::Mainnet,
                backend: "esplora.example.org".to_owned(),
            },
            BackupBackendPreview {
                network: Network::Testnet4,
                backend: "mempool.emzy.de".to_owned(),
            },
        ]
    );

    let choices = ImportChoices {
        indexes: None,
        apply_settings: true,
    };
    manager
        .import_backup(&text, BACKUP_PASSWORD, &choices)
        .await
        .unwrap();
    let settings = manager.settings().await;
    assert_eq!(
        settings.backend_for(Network::Mainnet),
        BackendConfig::CustomEsplora {
            url: "https://esplora.example.org/api".to_owned(),
            own_node: false,
        }
    );
    assert_eq!(settings.backend_for(Network::Signet), kept);
    assert_eq!(
        settings.backend_for(Network::Testnet4),
        BackendConfig::Public {
            server: Some("mempool.emzy.de".to_owned()),
        }
    );
}

#[tokio::test]
async fn backup_restores_wallets_in_a_fresh_vault() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, cold, watch) = seeded(source_dir.path()).await;
    source.set_gap_limit(50).await.unwrap();
    let esplora = BackendConfig::CustomEsplora {
        url: "https://esplora.example.org/api".to_owned(),
        own_node: false,
    };
    source
        .set_backend(Network::Signet, esplora.clone())
        .await
        .unwrap();
    source
        .trust_certificate("ssl://electrum.example.org:50002", &fingerprint("AB"))
        .await
        .unwrap();

    let options = BackupOptions {
        wallet_ids: None,
        include_settings: true,
    };
    let bundle = source
        .export_backup(&options, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert_eq!(bundle.wallet_count, 2);
    let file = data_encoding::BASE64
        .decode(bundle.data.as_bytes())
        .unwrap();
    assert_eq!(bundle.size_bytes as usize, file.len());
    assert!(bundle.frames.len() > 1);

    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    let preview = target
        .preview_backup(&bundle.data, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert!(preview.has_settings);
    assert_eq!(preview.wallets.len(), 2);
    assert!(preview.wallets.iter().all(|w| !w.already_watched));
    assert_eq!(preview.wallets[0].name, "Cold");
    assert_eq!(preview.wallets[1].index, 1);

    // Wallets only: the settings stay as they were.
    let wallets_only = ImportChoices {
        indexes: None,
        apply_settings: false,
    };
    let report = target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &wallets_only)
        .await
        .unwrap();
    assert_eq!(report.added.len(), 2);
    assert_eq!(report.skipped, 0);
    assert!(!report.settings_applied);
    let settings = target.settings().await;
    assert_eq!(settings.gap_limit, 20);
    assert_eq!(
        settings.backend_for(Network::Signet),
        BackendConfig::default()
    );

    let restored = target.list_wallets(None).await;
    let identity = |m: &WalletMeta| (m.name.clone(), m.network, m.kind.clone());
    assert_eq!(
        restored.iter().map(identity).collect::<Vec<_>>(),
        vec![identity(&cold), identity(&watch)]
    );
    assert_ne!(restored[0].id, cold.id, "a restored wallet gets its own id");
    assert_eq!(restored[0].recognized_as, RecognizedKind::DescriptorPair);
    assert_eq!(restored[1].recognized_as, RecognizedKind::Address);
    assert_eq!(
        target.receive_addresses(&restored[0].id, 0).await.unwrap()[0].address,
        source.receive_addresses(&cold.id, 0).await.unwrap()[0].address,
        "the restored engine derives the source's addresses"
    );

    // A second pass finds everything already there.
    let preview = target
        .preview_backup(&bundle.data, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert!(preview.wallets.iter().all(|w| w.already_watched));
    let report = target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &wallets_only)
        .await
        .unwrap();
    assert!(report.added.is_empty());
    assert_eq!(report.skipped, 2);

    // Settings when asked; an acceptance made here is never replaced.
    target
        .trust_certificate("ssl://electrum.example.org:50002", &fingerprint("CD"))
        .await
        .unwrap();
    let with_settings = ImportChoices {
        indexes: None,
        apply_settings: true,
    };
    let report = target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &with_settings)
        .await
        .unwrap();
    assert!(report.settings_applied);
    let settings = target.settings().await;
    assert_eq!(settings.gap_limit, 50);
    assert_eq!(settings.backend_for(Network::Signet), esplora);
    assert_eq!(
        settings.electrum_certs.values().collect::<Vec<_>>(),
        vec![&fingerprint("CD")]
    );

    // Everything survived on disk.
    drop(target);
    let target = WalletManager::open(target_dir.path(), key()).unwrap();
    assert_eq!(target.list_wallets(None).await.len(), 2);
    assert_eq!(target.settings().await.gap_limit, 50);
}

#[tokio::test]
async fn backup_picks_wallets_on_both_sides() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, cold, _) = seeded(source_dir.path()).await;
    let only_cold = BackupOptions {
        wallet_ids: Some(vec![cold.id.clone()]),
        include_settings: false,
    };
    let bundle = source
        .export_backup(&only_cold, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert_eq!(bundle.wallet_count, 1);
    let unknown = BackupOptions {
        wallet_ids: Some(vec!["nope".to_owned()]),
        include_settings: false,
    };
    assert!(matches!(
        source.export_backup(&unknown, BACKUP_PASSWORD).await,
        Err(CoreError::WalletNotFound(_))
    ));

    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    let preview = target
        .preview_backup(&bundle.data, BACKUP_PASSWORD)
        .await
        .unwrap();
    assert!(!preview.has_settings);
    assert_eq!(preview.wallets.len(), 1);
    assert_eq!(preview.wallets[0].name, "Cold");

    // Both wallets in, one chosen: the other counts as skipped, and
    // there are no settings to apply.
    let full = source
        .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
        .await
        .unwrap();
    let second_only = ImportChoices {
        indexes: Some(vec![1, 1]),
        apply_settings: true,
    };
    let report = target
        .import_backup(&full.data, BACKUP_PASSWORD, &second_only)
        .await
        .unwrap();
    assert_eq!(report.added.len(), 1);
    assert_eq!(report.added[0].name, "Watch");
    assert_eq!(report.skipped, 1);
    assert!(!report.settings_applied);
    let out_of_range = ImportChoices {
        indexes: Some(vec![7]),
        apply_settings: false,
    };
    let error = target
        .import_backup(&full.data, BACKUP_PASSWORD, &out_of_range)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CoreError::InvalidInput { kind: "backup", .. }),
        "{error}"
    );
}

/// The whole crossing, the way it actually happens: a desktop with
/// a few wallets shows the animated code, a phone reads it frame by
/// frame, and the phone already watches one of those wallets.
///
/// The wallet already there must come back as such and be skipped,
/// never added a second time — the vault would otherwise end up
/// with two records for one descriptor, syncing the same addresses
/// twice and counting the same coins twice.
#[tokio::test]
async fn a_scanned_backup_never_doubles_a_wallet_already_watched() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, _, _) = seeded(source_dir.path()).await;
    let bundle = source
        .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
        .await
        .unwrap();
    assert_eq!(bundle.wallet_count, 2);

    // The phone already watches the address, under a name of its
    // own and with its own id.
    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    let mine = target
        .add_wallet(
            "Already here",
            &parse_input(ADDRESS).unwrap(),
            Network::Signet,
        )
        .await
        .unwrap();

    // The camera reads the loop one frame at a time, joining it
    // wherever it happens to be.
    let frames = &bundle.frames;
    let mut seen: Vec<String> = Vec::new();
    let start = frames.len() / 2;
    let text = loop {
        assert!(
            seen.len() < frames.len(),
            "one turn of the loop should be enough"
        );
        seen.push(frames[(start + seen.len()) % frames.len()].clone());
        let progress = crate::input::qr::assemble(&seen).unwrap();
        assert_eq!(progress.received as usize, seen.len());
        if let Some(text) = progress.text {
            assert!(progress.complete);
            break text;
        }
    };

    let preview = target.preview_backup(&text, BACKUP_PASSWORD).await.unwrap();
    let watched: Vec<_> = preview
        .wallets
        .iter()
        .map(|w| (w.name.as_str(), w.already_watched))
        .collect();
    assert_eq!(watched, vec![("Cold", false), ("Watch", true)]);

    // Restoring everything anyway: the one already here is counted
    // as skipped, and the name it carries on this device stands.
    let report = target
        .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
        .await
        .unwrap();
    assert_eq!(report.added.len(), 1);
    assert_eq!(report.added[0].name, "Cold");
    assert_eq!(report.skipped, 1);

    let wallets = target.list_wallets(None).await;
    assert_eq!(wallets.len(), 2);
    assert_eq!(
        wallets.iter().filter(|w| w.kind == mine.kind).count(),
        1,
        "the address is watched once, not twice"
    );
    assert!(wallets.iter().any(|w| w.name == "Already here"));

    // And a second crossing changes nothing at all.
    let again = target
        .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
        .await
        .unwrap();
    assert!(again.added.is_empty());
    assert_eq!(again.skipped, 2);
    assert_eq!(target.list_wallets(None).await.len(), 2);
}

#[tokio::test]
async fn backup_needs_its_password_and_scans_as_a_qr() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, _, _) = seeded(source_dir.path()).await;
    let error = source
        .export_backup(&BackupOptions::default(), "short")
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            CoreError::InvalidInput {
                kind: "backup password",
                ..
            }
        ),
        "{error}"
    );
    let bundle = source
        .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
        .await
        .unwrap();

    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    assert!(matches!(
        target
            .preview_backup(&bundle.data, "not the password")
            .await,
        Err(CoreError::Vault(
            crate::error::VaultError::WrongKeyOrCorrupted
        ))
    ));
    assert!(matches!(
        target
            .import_backup("not a backup", BACKUP_PASSWORD, &ImportChoices::default())
            .await,
        Err(CoreError::InvalidInput { kind: "backup", .. })
    ));

    // The frames a camera sees assemble into the text the restore
    // accepts, and the wallet import refuses by name.
    let scanned = crate::input::qr::assemble(&bundle.frames).unwrap();
    assert!(scanned.complete);
    let text = scanned.text.unwrap();
    assert!(text.starts_with(crate::backup::BACKUP_PREFIX));
    let report = target
        .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
        .await
        .unwrap();
    assert_eq!(report.added.len(), 2);
    assert!(matches!(
        parse_input(&text),
        Err(CoreError::InvalidInput { kind: "backup", .. })
    ));
}
