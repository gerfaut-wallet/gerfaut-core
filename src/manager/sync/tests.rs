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
