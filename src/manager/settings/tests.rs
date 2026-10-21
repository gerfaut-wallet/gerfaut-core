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

/// The backend and the certificate accepted for its server are written
/// together or not at all: a backend refused after its certificate used
/// to leave the certificate trusted for a server nobody saved.
#[tokio::test]
async fn a_backend_and_its_certificate_are_stored_together_or_not_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let electrum = |url: &str| BackendConfig::CustomElectrum {
        url: url.to_owned(),
        own_node: false,
    };
    let fingerprint = |byte: &str| vec![byte; 32].join(":");
    let before = BackendConfig::CustomEsplora {
        url: "https://esplora.example.org/api".to_owned(),
        own_node: false,
    };
    manager
        .set_backend(Network::Signet, before.clone())
        .await
        .unwrap();
    manager
        .trust_certificate("ssl://other.example.org:50002", &fingerprint("AA"))
        .await
        .unwrap();
    let untouched = |settings: crate::store::Settings| {
        assert_eq!(settings.backend_for(Network::Signet), before);
        assert_eq!(
            settings.electrum_certs.into_iter().collect::<Vec<_>>(),
            vec![("other.example.org:50002".to_owned(), fingerprint("AA"))],
        );
    };

    // Refused, each for its own reason, and nothing written.
    for (config, url, print, problem) in [
        (
            electrum("ssl://node.example.org:50002"),
            "ssl://node.example.org:50002",
            "not a fingerprint".to_owned(),
            "32 hexadecimal bytes",
        ),
        (
            electrum("ssl://node.example.org:50002"),
            "ssl://elsewhere.example.org:50002",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
        (
            electrum("ssl://node.example.org:50002"),
            "ssl://node.example.org:50003",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
        (
            electrum("ssl://x.onion:99999"),
            "ssl://x.onion:99999",
            fingerprint("BB"),
            "99999 is not a port number",
        ),
        (
            BackendConfig::CustomEsplora {
                url: "https://node.example.org/api".to_owned(),
                own_node: false,
            },
            "ssl://node.example.org:50002",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
        (
            BackendConfig::Public {
                server: Some("mempool.space".to_owned()),
            },
            "ssl://mempool.space:60602",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
        // No server named, or one the catalogue does not hold: no
        // rotation to fall back on here, there is nothing to pin.
        (
            BackendConfig::Public {
                server: Some("electrum:nowhere".to_owned()),
            },
            "ssl://mempool.space:60602",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
        (
            BackendConfig::Public { server: None },
            "ssl://mempool.space:60602",
            fingerprint("BB"),
            "not for the Electrum server of this backend",
        ),
    ] {
        let refused = manager
            .set_backend_trusting(Network::Signet, config.clone(), url, &print)
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, CoreError::InvalidInput { detail, .. } if detail.contains(problem)),
            "{config:?} {url}: {refused}"
        );
        untouched(manager.settings().await);
    }
    // Nor on disk.
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    untouched(manager.settings().await);

    // Accepted: both at once, in their stored forms, "This is my node"
    // kept, and both on disk.
    manager
        .set_backend_trusting(
            Network::Signet,
            BackendConfig::CustomElectrum {
                url: "SSL://Node.Example.ORG.:50002".to_owned(),
                own_node: true,
            },
            "ssl://node.example.org:50002",
            &fingerprint("bb"),
        )
        .await
        .unwrap();
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let settings = manager.settings().await;
    assert_eq!(
        settings.backend_for(Network::Signet),
        BackendConfig::CustomElectrum {
            url: "ssl://node.example.org:50002".to_owned(),
            own_node: true,
        }
    );
    assert_eq!(
        settings.electrum_certs.get("node.example.org:50002"),
        Some(&fingerprint("BB"))
    );
    assert_eq!(
        settings.electrum_certs.get("other.example.org:50002"),
        Some(&fingerprint("AA")),
        "another server's certificate stays"
    );

    // A public Electrum server picked by its identifier: its own address.
    manager
        .set_backend_trusting(
            Network::Signet,
            BackendConfig::Public {
                server: Some("electrum:mempool.space".to_owned()),
            },
            "ssl://mempool.space:60602",
            &fingerprint("CC"),
        )
        .await
        .unwrap();
    let settings = manager.settings().await;
    assert_eq!(
        settings.backend_for(Network::Signet),
        BackendConfig::Public {
            server: Some("electrum:mempool.space".to_owned())
        }
    );
    assert_eq!(
        settings.electrum_certs.get("mempool.space:60602"),
        Some(&fingerprint("CC"))
    );
}

/// A save the vault refuses, as on a full disk, takes neither the
/// backend nor its certificate: the one write fails whole, and the
/// settings stay those held before, in memory and on disk.
#[tokio::test]
async fn a_backend_the_vault_refuses_leaves_no_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager.state.lock().await.vault.fail_saves(true);
    let refused = manager
        .set_backend_trusting(
            Network::Signet,
            BackendConfig::CustomElectrum {
                url: "ssl://node.example.org:50002".to_owned(),
                own_node: false,
            },
            "ssl://node.example.org:50002",
            &vec!["BB"; 32].join(":"),
        )
        .await;
    assert!(matches!(refused, Err(CoreError::Vault(_))), "{refused:?}");
    let unchanged = |settings: crate::store::Settings| {
        assert!(settings.electrum_certs.is_empty());
        assert_eq!(
            settings.backend_for(Network::Signet),
            BackendConfig::default()
        );
    };
    unchanged(manager.settings().await);
    drop(manager);
    unchanged(
        WalletManager::open(dir.path(), key())
            .unwrap()
            .settings()
            .await,
    );
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

/// The settings screen asks for a server's certificate before it saves
/// the address: a key or an address typed as its host is refused there
/// too, and never looked up, nor stored.
#[tokio::test]
async fn a_certificate_is_not_asked_of_wallet_material() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let tpub = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";
    for url in [
        format!("ssl://{tpub}:50002"),
        "ssl://tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx:50002".to_owned(),
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:50002:s".to_owned(),
    ] {
        let error = manager.inspect_certificate(&url).await.unwrap_err();
        assert!(
            error.to_string().contains("not the name of a server"),
            "{url}: {error}"
        );
        let refused = manager
            .set_backend(
                Network::Signet,
                BackendConfig::CustomElectrum {
                    url: url.clone(),
                    own_node: false,
                },
            )
            .await;
        assert!(refused.is_err(), "{url}");
    }
}

/// A seed phrase or a private key typed into the host field, port and
/// all, is refused as private material by every call the settings
/// screen makes with it, quoted by none, and stored by none.
#[tokio::test]
async fn a_secret_typed_as_a_host_is_refused_by_every_call() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let seed = ["abandon"; 11].join(" ") + " about";
    let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let fingerprint = vec!["AA"; 32].join(":");
    for url in [
        format!("ssl://{seed}:50002:50002"),
        format!("ssl://[{seed}:50002]:50002"),
        format!("tcp://{seed}:50001"),
        format!("ssl://{wif}:50002:50002"),
    ] {
        let config = BackendConfig::CustomElectrum {
            url: url.clone(),
            own_node: false,
        };
        let refusals = [
            manager.inspect_certificate(&url).await.unwrap_err(),
            manager
                .set_backend(Network::Signet, config.clone())
                .await
                .unwrap_err(),
            manager
                .set_backend_trusting(Network::Signet, config, &url, &fingerprint)
                .await
                .unwrap_err(),
        ];
        for error in refusals {
            assert!(
                matches!(error, CoreError::PrivateMaterialRejected),
                "{url}: {error}"
            );
        }
    }
    let esplora = BackendConfig::CustomEsplora {
        url: format!("https://{seed}:3002/api"),
        own_node: false,
    };
    let error = manager
        .set_backend(Network::Signet, esplora)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CoreError::PrivateMaterialRejected),
        "{error}"
    );

    let settings = manager.settings().await;
    assert_eq!(
        settings.backend_for(Network::Signet),
        BackendConfig::Public { server: None }
    );
    assert!(settings.electrum_certs.is_empty());
}

/// The preferences both apps keep are changed one field at a time, kept
/// across a restart, and never left on a pair no source quotes.
#[tokio::test]
async fn the_shared_preferences_are_typed_and_persisted() {
    use crate::prefs::{Preferences, PreferencesChange, Unit};
    use crate::price::{FiatCurrency, PriceSource};

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    assert_eq!(manager.preferences().await, Preferences::default());

    let stored = manager
        .set_preferences(PreferencesChange {
            unit: Some(Unit::Sats),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();
    assert_eq!(stored.unit, Unit::Sats);
    let stored = manager
        .set_preferences(PreferencesChange {
            price_source: Some(PriceSource::MempoolSpace),
            masked: Some(true),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();
    // The first change stands: a change moves what it names alone.
    assert_eq!(stored.unit, Unit::Sats);
    assert!(stored.masked);

    // The currency wins, the source follows, in what is stored and in
    // what is answered.
    let stored = manager
        .set_preferences(PreferencesChange {
            fiat_currency: Some(FiatCurrency::Brl),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();
    assert_eq!(stored.fiat_currency, FiatCurrency::Brl);
    assert_eq!(stored.price_source, PriceSource::Coingecko);
    assert_eq!(manager.preferences().await, stored);
    assert_eq!(manager.settings().await.preferences, stored);

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(manager.preferences().await, stored);
}

/// A key the shared preferences were once kept under is no app
/// preference: written there, nothing would read it.
#[tokio::test]
async fn a_shared_preference_is_not_an_app_preference() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    for key in crate::prefs::LEGACY_KEYS {
        let refused = manager
            .set_app_pref(key.to_owned(), "1".to_owned())
            .await
            .unwrap_err();
        assert!(
            matches!(refused, CoreError::InvalidInput { .. }),
            "{key}: {refused}"
        );
    }
    assert!(manager.settings().await.app_prefs.is_empty());
    manager
        .set_app_pref("desktop.theme".to_owned(), "dark".to_owned())
        .await
        .unwrap();
}

/// A backup carries none of the preferences, settings included: a
/// restore leaves the ones of the device it lands on as they were.
#[tokio::test]
async fn a_backup_carries_no_preference() {
    use crate::prefs::{Preferences, PreferencesChange, Unit};

    let source_dir = tempfile::tempdir().unwrap();
    let (source, _, _) = seeded(source_dir.path()).await;
    source
        .set_preferences(PreferencesChange {
            unit: Some(Unit::Sats),
            masked: Some(true),
            fiat: Some(true),
            ..PreferencesChange::default()
        })
        .await
        .unwrap();
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

    let target_dir = tempfile::tempdir().unwrap();
    let target = manager(target_dir.path()).await;
    target
        .import_backup(
            &bundle.data,
            BACKUP_PASSWORD,
            &ImportChoices {
                indexes: None,
                apply_settings: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(target.preferences().await, Preferences::default());
}
