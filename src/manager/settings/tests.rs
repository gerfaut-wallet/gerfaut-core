//! Settings, certificates and Tor, against a vault on disk.

use std::time::Instant;

use super::*;
use crate::backup::{BackupOptions, ImportChoices};
use crate::chain::tor::TorMode;
use crate::input::parse_input;
use crate::manager::ensure_engine;
use crate::manager::tests::support::{
    BACKUP_PASSWORD, MULTIPATH, closed_port, key, manager, seeded,
};

#[tokio::test]
async fn gap_limit_is_global_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(meta.gap_limit, 20, "default follows the setting");
    assert_eq!(manager.settings().await.gap_limit, 20);

    manager.set_gap_limit(50).await.unwrap();
    // Every surface presents the new effective value.
    assert_eq!(manager.settings().await.gap_limit, 50);
    assert_eq!(manager.list_wallets(None).await[0].gap_limit, 50);
    assert_eq!(
        manager
            .wallet_snapshot(&meta.id)
            .await
            .unwrap()
            .meta
            .gap_limit,
        50
    );
    // Bounds are enforced.
    assert!(manager.set_gap_limit(0).await.is_err());
    assert!(manager.set_gap_limit(501).await.is_err());

    // A fresh manager reloads the value from the vault.
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(manager.settings().await.gap_limit, 50);
}

#[tokio::test]
async fn settings_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_backend(
            Network::Signet,
            BackendConfig::CustomEsplora {
                url: "https://esplora.example.org/api".to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager
        .set_app_pref("theme".to_owned(), "dark".to_owned())
        .await
        .unwrap();

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let settings = manager.settings().await;
    assert_eq!(settings.active_network, Network::Signet);
    assert_eq!(
        settings.backend_for(Network::Signet),
        BackendConfig::CustomEsplora {
            url: "https://esplora.example.org/api".to_owned(),
            own_node: false,
        }
    );
    assert_eq!(settings.app_prefs.get("theme").unwrap(), "dark");
}

/// A custom address is stored the way a scan reads it, and refused
/// when the parser cannot read it: stored as typed, the sync would
/// see no onion in `tcp://x.onion:50001:extra` and hand it to the
/// resolver in the clear. A refusal leaves the setting as it was.
#[tokio::test]
async fn a_custom_backend_is_stored_canonical_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let electrum = |url: &str| BackendConfig::CustomElectrum {
        url: url.to_owned(),
        own_node: false,
    };
    let esplora = |url: &str| BackendConfig::CustomEsplora {
        url: url.to_owned(),
        own_node: false,
    };

    manager
        .set_backend(Network::Signet, electrum("ssl://node.example.org:50002"))
        .await
        .unwrap();
    for (config, problem) in [
        (electrum("tcp://x.onion:50001:extra"), "more than one colon"),
        (
            electrum("ssl://x.onion:99999"),
            "99999 is not a port number",
        ),
        (esplora("ssl://x.onion:50002"), "http:// or https://"),
    ] {
        let refused = manager
            .set_backend(Network::Signet, config.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, CoreError::InvalidInput { kind: "server", detail } if detail.contains(problem)),
            "{config:?}: {refused}"
        );
    }
    assert_eq!(
        manager.settings().await.backend_for(Network::Signet),
        electrum("ssl://node.example.org:50002"),
        "a refused address leaves the setting as it was"
    );

    manager
        .set_backend(Network::Signet, electrum("SSL://Node.Example.ORG.:50002"))
        .await
        .unwrap();
    assert_eq!(
        manager.settings().await.backend_for(Network::Signet),
        electrum("ssl://node.example.org:50002")
    );
    manager
        .set_backend(
            Network::Signet,
            esplora("HTTPS://Esplora.Example.ORG./api/"),
        )
        .await
        .unwrap();
    assert_eq!(
        manager.settings().await.backend_for(Network::Signet),
        esplora("https://esplora.example.org/api")
    );
    // Already in that form: byte for byte, the key of an accepted
    // certificate among what stays the same.
    for config in [
        electrum("tcp://x.onion:50001"),
        electrum("ssl://[2001:db8::1]:50002"),
        esplora("https://esplora.example.org/api"),
    ] {
        manager
            .set_backend(Network::Signet, config.clone())
            .await
            .unwrap();
        assert_eq!(
            manager.settings().await.backend_for(Network::Signet),
            config
        );
    }
}

/// "This is my node" is stored with the backend, in its canonical
/// form, lifts what the live watch lists of a wallet, and travels in
/// a backup with the rest of the node settings.
#[tokio::test]
async fn the_own_node_switch_lifts_the_list_and_travels_in_a_backup() {
    let source_dir = tempfile::tempdir().unwrap();
    let (source, cold, _) = seeded(source_dir.path()).await;
    {
        let mut state = source.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let _ = engine
            .reveal_addresses_to(bdk_wallet::KeychainKind::External, 999)
            .count();
    }
    let listed = async |manager: &WalletManager| {
        manager
            .watch_list(Network::Signet)
            .await
            .into_iter()
            .find(|wallet| wallet.wallet_id == cold.id)
            .map(|wallet| (wallet.scripts.len(), wallet.unlisted))
            .unwrap()
    };
    assert_eq!(
        listed(&source).await,
        (crate::watch::MAX_SCRIPTS_PER_WALLET, 840)
    );

    source
        .set_backend(
            Network::Signet,
            BackendConfig::CustomElectrum {
                url: "Node.Example.ORG.:50002".to_owned(),
                own_node: true,
            },
        )
        .await
        .unwrap();
    let own = BackendConfig::CustomElectrum {
        url: "ssl://node.example.org:50002".to_owned(),
        own_node: true,
    };
    assert_eq!(source.settings().await.backend_for(Network::Signet), own);
    // Every revealed receive address, and a gap limit past the last
    // one on each keychain.
    assert_eq!(listed(&source).await, (1_000 + 2 * 20, 0));

    let options = BackupOptions {
        wallet_ids: None,
        include_settings: true,
    };
    let bundle = source
        .export_backup(&options, BACKUP_PASSWORD)
        .await
        .unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    let choices = ImportChoices {
        indexes: None,
        apply_settings: true,
    };
    target
        .import_backup(&bundle.data, BACKUP_PASSWORD, &choices)
        .await
        .unwrap();
    assert_eq!(target.settings().await.backend_for(Network::Signet), own);
}

#[tokio::test]
async fn tor_settings_are_checked_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    assert_eq!(manager.settings().await.tor, TorSettings::default());

    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::Embedded,
            socks_proxy: Some(" 127.0.0.1:9150 ".to_owned()),
        })
        .await
        .unwrap();
    let status = manager.tor_status().await;
    assert_eq!(status.mode, TorMode::Embedded);
    assert_eq!(status.socks_proxy, "127.0.0.1:9150");
    assert_eq!(status.embedded_available, cfg!(feature = "embedded-tor"));
    assert_eq!(status.system_socks_trusted, tor::TRUST_LOOPBACK_SOCKS);

    // Blank means the default.
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some("  ".to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(manager.settings().await.tor.socks_proxy, None);

    // A typo is refused before it is stored.
    let error = manager
        .set_tor_settings(TorSettings {
            mode: TorMode::Auto,
            socks_proxy: Some("nonsense".to_owned()),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        CoreError::InvalidInput {
            kind: "tor proxy",
            ..
        }
    ));

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(
        manager.settings().await.tor,
        TorSettings {
            mode: TorMode::System,
            socks_proxy: None
        }
    );
}

#[tokio::test]
async fn an_onion_backend_without_tor_fails_before_any_connection() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Over Tor", &parsed, Network::Signet)
        .await
        .unwrap();
    manager
        .set_backend(
            Network::Signet,
            BackendConfig::CustomEsplora {
                url: "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api"
                    .to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed_port().await),
        })
        .await
        .unwrap();

    let started = Instant::now();
    let error = manager.sync_wallet(&meta.id).await.unwrap_err();
    assert!(matches!(error, CoreError::Tor(_)), "{error}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the onion host is never contacted, let alone looked up"
    );
    assert!(matches!(
        manager.tor_connect().await,
        Err(CoreError::Tor(_))
    ));

    // A workspace sync reports it per wallet, like any other failure.
    let report = manager.sync_all(Some(Network::Signet)).await;
    assert_eq!(report.failures.len(), 1);
    assert!(
        report.failures[0].message.starts_with("tor: "),
        "{}",
        report.failures[0].message
    );
}
