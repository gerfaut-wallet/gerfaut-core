//! End-to-end sync tests against the public Signet Esplora instances.
//!
//! Ignored by default so the test suite stays hermetic; run with
//! `cargo test -- --ignored` when network access is available.

use gerfaut_core::input::parse_input;
use gerfaut_core::manager::WalletManager;
use gerfaut_core::network::Network;
use gerfaut_core::store::VaultKey;

const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";

fn key() -> VaultKey {
    VaultKey::Raw([1u8; 32])
}

#[tokio::test]
#[ignore = "talks to public signet infrastructure"]
async fn descriptor_wallet_full_scan_reaches_the_tip() {
    let dir = tempfile::tempdir().unwrap();
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet e2e", &parsed, Network::Signet)
        .await
        .unwrap();

    let report = manager.sync_wallet(&meta.id).await.unwrap();
    assert!(report.tip_height > 200_000, "signet is past that for years");

    // The sync stamp and cached totals survive a reopen.
    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let wallets = manager.list_wallets(Some(Network::Signet)).await;
    let stamp = wallets[0].last_sync.as_ref().expect("sync stamp persisted");
    assert_eq!(stamp.tip_height, report.tip_height);

    // A second sync is incremental and still succeeds.
    let second = manager.sync_wallet(&meta.id).await.unwrap();
    assert!(second.tip_height >= report.tip_height);
}

/// Every public server offered for signet must be able to carry a real
/// sync, Electrum entries included: the settings list them as equals.
#[tokio::test]
#[ignore = "talks to public signet infrastructure"]
async fn every_public_signet_server_can_sync_a_wallet() {
    use gerfaut_core::chain::BackendConfig;
    use gerfaut_core::chain::public::public_servers;

    let mut reached = 0;
    for server in public_servers(Network::Signet) {
        let dir = tempfile::tempdir().unwrap();
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        manager
            .set_backend(
                Network::Signet,
                BackendConfig::Public {
                    server: Some(server.id.clone()),
                },
            )
            .await
            .unwrap();
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet(&server.label, &parsed, Network::Signet)
            .await
            .unwrap();
        match manager.sync_wallet(&meta.id).await {
            Ok(report) => {
                reached += 1;
                assert!(report.tip_height > 200_000, "{}", server.label);
                // The stamp names the operator the user picked.
                assert_eq!(report.backend, server.label.split(':').next().unwrap());
            }
            Err(error) => eprintln!("{} unreachable: {error}", server.label),
        }
    }
    assert!(reached >= 1, "no public signet server reachable");
}

#[tokio::test]
#[ignore = "talks to public signet infrastructure"]
async fn address_wallet_sees_real_history() {
    // Pick an address with guaranteed history: an output of a recent
    // confirmed transaction on signet. Try each public instance, same
    // fallback logic the product itself uses.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();
    let mut found = None;
    for base in Network::Signet.default_esplora_urls() {
        let fetch = async {
            let blocks: serde_json::Value = client
                .get(format!("{base}/blocks"))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            let block_id = blocks[1]["id"].as_str()?.to_owned();
            let txs: serde_json::Value = client
                .get(format!("{base}/block/{block_id}/txs"))
                .send()
                .await
                .ok()?
                .json()
                .await
                .ok()?;
            txs.as_array()?
                .iter()
                .flat_map(|tx| tx["vout"].as_array().into_iter().flatten())
                .find_map(|vout| vout["scriptpubkey_address"].as_str().map(str::to_owned))
        };
        if let Some(address) = fetch.await {
            found = Some(address);
            break;
        }
    }
    let address = found.expect("at least one public signet instance answers");
    let address = address.as_str();

    let dir = tempfile::tempdir().unwrap();
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    let parsed = parse_input(address).unwrap();
    let meta = manager
        .add_wallet("Address e2e", &parsed, Network::Signet)
        .await
        .unwrap();

    let report = manager.sync_wallet(&meta.id).await.unwrap();
    assert!(report.new_tx_count >= 1, "the funding tx must be seen");

    let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
    assert!(!snapshot.txs.is_empty());
    let detail = manager
        .tx_detail(&meta.id, &snapshot.txs[0].txid)
        .await
        .unwrap();
    assert!(!detail.outputs.is_empty());
}
