//! Syncs, against a vault on disk and no server at all.

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
