//! Previews of a transaction whose coins only the backend can vouch
//! for, against an Esplora on loopback or none at all.

use super::*;
use crate::chain::BackendConfig;
use crate::manager::tests::support::manager;

/// What the loopback Esplora below does with a question it has no
/// answer for.
#[derive(Clone, Copy)]
enum Unknown {
    /// It says so, the way a backend reports a coin it never saw.
    NotFound,
    /// It says nothing at all and drops the connection. A throttled
    /// instance, a timeout and a reset all reach the chain layer as
    /// the same refusal; this one costs no backoff to reproduce.
    NoAnswer,
}

/// An Esplora on loopback that knows exactly one transaction: it
/// serves its bytes and says its first output is unspent, and knows
/// nothing else. What a real backend would answer about a coin the
/// vault does not hold.
async fn esplora_knowing(tx: bdk_wallet::bitcoin::Transaction, unknown: Unknown) -> String {
    esplora_answering(tx, unknown, r#"{"spent":false}"#.to_owned()).await
}

/// The same Esplora, answering `outspend` about the first output of the
/// transaction it knows: Esplora's own body for `/outspend/0`.
async fn esplora_answering(
    tx: bdk_wallet::bitcoin::Transaction,
    unknown: Unknown,
    outspend: String,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let txid = tx.compute_txid().to_string();
    let raw = bdk_wallet::bitcoin::consensus::serialize(&tx);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("");
            let answer: Option<(&str, &str, Vec<u8>)> = if path == format!("/api/tx/{txid}/raw") {
                Some(("200 OK", "application/octet-stream", raw.clone()))
            } else if path == format!("/api/tx/{txid}/outspend/0") {
                Some(("200 OK", "application/json", outspend.clone().into_bytes()))
            } else {
                match unknown {
                    Unknown::NotFound => {
                        Some(("404 Not Found", "text/plain", b"not found".to_vec()))
                    }
                    Unknown::NoAnswer => None,
                }
            };
            if let Some((status, kind, body)) = answer {
                let mut response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend(body);
                let _ = stream.write_all(&response).await;
            }
            let _ = stream.shutdown().await;
        }
    });
    format!("http://{address}/api")
}

/// The same lie with no backend to ask: regtest has no public
/// server and none was configured. The preview cannot catch the
/// lie, so it must say so: the coin is marked unchecked, with the
/// warning a backend that stopped answering would earn.
#[tokio::test]
async fn a_psbt_lie_with_no_backend_at_all_is_marked_unchecked() {
    use crate::broadcast::TxWarningKind;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
        absolute, transaction,
    };

    const CLAIMED: u64 = 10_200;
    const PAID: u64 = 10_000;
    let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x44; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(PAID),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
        }],
    };
    let mut witness = Witness::new();
    witness.push([0x30; 71]);
    witness.push([0x02; 33]);
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(CLAIMED),
        script_pubkey: spk,
    });
    psbt.inputs[0].final_script_witness = Some(witness);
    let text = data_encoding::BASE64.encode(&psbt.serialize());

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let preview = manager
        .preview_transaction(&text, Network::Regtest)
        .await
        .unwrap();
    let kinds: Vec<_> = preview.warnings.iter().map(|w| w.kind).collect();
    assert!(
        kinds.contains(&TxWarningKind::InputUnknown),
        "nobody checked this coin and the preview must say so: {kinds:?}"
    );
    assert!(
        !kinds.contains(&TxWarningKind::InputMismatch),
        "no one contradicted the PSBT either: {kinds:?}"
    );
    assert_eq!(
        preview.inputs[0].value_sats,
        Some(CLAIMED),
        "the value shown is the transaction's own word"
    );
}

/// A finalized PSBT spends a coin no watched wallet holds and
/// declares it worth a tenth of what it is. The backend is asked
/// all the same, and its answer, not the PSBT's, is what the
/// preview goes by: the real fee, and the disagreement in red.
#[tokio::test]
async fn a_psbt_lie_about_an_unwatched_coin_is_caught_by_the_backend() {
    use crate::broadcast::{TxSeverity, TxWarningKind};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
        absolute, transaction,
    };

    const REAL: u64 = 100_000;
    const CLAIMED: u64 = 10_200;
    const PAID: u64 = 10_000;
    let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: spk.clone(),
        }],
    };
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(PAID),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
        }],
    };
    // Finalized: readiness is about presence, and a finalized input
    // never meets the interpreter.
    let mut witness = Witness::new();
    witness.push([0x30; 71]);
    witness.push([0x02; 33]);
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(CLAIMED),
        script_pubkey: spk,
    });
    psbt.inputs[0].final_script_witness = Some(witness);
    let text = data_encoding::BASE64.encode(&psbt.serialize());

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_backend(
            Network::Regtest,
            BackendConfig::CustomEsplora {
                url: esplora_knowing(funding, Unknown::NotFound).await,
                own_node: false,
            },
        )
        .await
        .unwrap();
    let preview = manager
        .preview_transaction(&text, Network::Regtest)
        .await
        .unwrap();
    assert!(preview.ready);
    assert_eq!(preview.inputs[0].value_sats, Some(REAL));
    assert_eq!(preview.fee_sats, Some(REAL - PAID));
    let mismatch = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputMismatch)
        .expect("the backend's word contradicts the PSBT's");
    assert_eq!(mismatch.severity, TxSeverity::Alert);
    assert!(
        mismatch.message.contains("the backend"),
        "{}",
        mismatch.message
    );
    let kinds: Vec<TxWarningKind> = preview.warnings.iter().map(|w| w.kind).collect();
    assert!(kinds.contains(&TxWarningKind::HighFeeShare), "{kinds:?}");
    assert!(!kinds.contains(&TxWarningKind::InputUnknown), "{kinds:?}");
}

/// The same lie, told about the second of two coins, by a PSBT whose
/// word on the first one is true. The backend answers about the
/// first and then stops answering — one throttled request is all it
/// takes — so nothing ever contradicts the second declaration.
///
/// The value shown for that coin, and therefore the whole of the fee,
/// is then the transaction's own arithmetic. A preview that says
/// nothing about it reads as a confirmed 200 sat fee on a transaction
/// that burns 90 000: whatever else it shows, it must say that this
/// coin was never checked.
#[tokio::test]
async fn a_backend_that_stops_answering_confirms_nothing_about_the_rest() {
    use crate::broadcast::TxWarningKind;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
        absolute, transaction,
    };

    /// What each of the two coins is really worth.
    const REAL: u64 = 100_000;
    /// What the PSBT claims the second one is worth.
    const CLAIMED: u64 = 10_200;
    /// Paid out, so the declared fee is an unremarkable 200 sats
    /// while the real one is 90 000: nothing else in the preview
    /// has anything to complain about.
    const PAID: u64 = REAL + CLAIMED - 200;

    let coin = |seed: u8| {
        let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]));
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(REAL),
                script_pubkey: spk.clone(),
            }],
        };
        (funding, spk)
    };
    let (answered, answered_spk) = coin(0x33);
    let (refused, refused_spk) = coin(0x44);
    let spending = |funding: &Transaction| TxIn {
        previous_output: OutPoint::new(funding.compute_txid(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(&answered), spending(&refused)],
        output: vec![TxOut {
            value: Amount::from_sat(PAID),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
        }],
    };
    let mut witness = Witness::new();
    witness.push([0x30; 71]);
    witness.push([0x02; 33]);
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    // The truth about the coin the backend will confirm, so that
    // nothing but the second input is ever in question.
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(REAL),
        script_pubkey: answered_spk,
    });
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(CLAIMED),
        script_pubkey: refused_spk,
    });
    psbt.inputs[0].final_script_witness = Some(witness.clone());
    psbt.inputs[1].final_script_witness = Some(witness);
    let text = data_encoding::BASE64.encode(&psbt.serialize());

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_backend(
            Network::Regtest,
            BackendConfig::CustomEsplora {
                url: esplora_knowing(answered, Unknown::NoAnswer).await,
                own_node: false,
            },
        )
        .await
        .unwrap();
    let preview = manager
        .preview_transaction(&text, Network::Regtest)
        .await
        .unwrap();

    assert!(preview.ready);
    assert_eq!(
        preview.inputs[0].value_sats,
        Some(REAL),
        "the coin the backend did answer about is still read from it"
    );
    assert!(
        !preview.warnings.is_empty(),
        "an input no backend answered about passed for a confirmed one"
    );
    let caution = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputUnknown)
        .expect("the coin nobody confirmed is named");
    assert!(caution.message.contains("Input 1"), "{}", caution.message);
    // The declaration is still all there is to show for that coin,
    // and the fee still follows from it. What changes is that the
    // preview no longer passes either off as established.
    assert_eq!(preview.inputs[1].value_sats, Some(CLAIMED));
    assert_eq!(preview.fee_sats, Some(200));
}

/// A coin worth 50 000 sats to the first address of the watched
/// descriptor wallet, already spent by a transaction paying someone
/// else, the two in a block when `mined`, in the mempool otherwise.
/// Returns the manager, the coin's funding transaction and its spender.
async fn wallet_coin_spent(
    dir: &std::path::Path,
    mined: bool,
) -> (
    WalletManager,
    bdk_wallet::bitcoin::Transaction,
    bdk_wallet::bitcoin::Transaction,
) {
    use crate::manager::tests::support::seeded;
    use crate::testkit::{nowhere, script, transaction};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{BlockHash, OutPoint};
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};

    let (manager, cold, _) = seeded(dir).await;
    let (funding, spender) = {
        let mut state = manager.state.lock().await;
        let engine = ensure_engine(&mut state, &cold.id).unwrap();
        let ours = engine
            .reveal_next_address(bdk_wallet::KeychainKind::External)
            .script_pubkey()
            .to_hex_string();
        let funding = transaction(&[nowhere(1, 0)], &[(ours.as_str(), 50_000)]);
        let spender = transaction(
            &[OutPoint::new(funding.compute_txid(), 0)],
            &[(script(9).as_str(), 49_000)],
        );
        engine.apply_unconfirmed_txs([(funding.clone(), 100), (spender.clone(), 200)]);
        if mined {
            let block = BlockId {
                height: 10,
                hash: BlockHash::from_byte_array([1; 32]),
            };
            let mut update = bdk_wallet::Update {
                chain: Some(engine.latest_checkpoint().push(block).unwrap()),
                ..Default::default()
            };
            for tx in [&funding, &spender] {
                update.tx_update.anchors.insert((
                    ConfirmationBlockTime {
                        block_id: block,
                        confirmation_time: 1_700_000_000,
                    },
                    tx.compute_txid(),
                ));
            }
            engine.apply_update(update).unwrap();
        }
        (funding, spender)
    };
    (manager, funding, spender)
}

/// `tx` with a witness on every input: signed, as far as a preview
/// reads it. The txid does not move.
fn witnessed(mut tx: bdk_wallet::bitcoin::Transaction) -> String {
    use bdk_wallet::bitcoin::Witness;
    for input in &mut tx.input {
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        input.witness = witness;
    }
    bdk_wallet::bitcoin::consensus::encode::serialize_hex(&tx)
}

/// A transaction of the watched wallet, long confirmed, pasted again:
/// its coin is spent in a block, by itself or by another. The preview
/// used to say "Ready to broadcast" beside the red line saying so. The
/// wallet's own view places the spend, and a spend in a block blocks
/// the send.
#[tokio::test]
async fn a_watched_coin_spent_in_a_block_blocks_the_send() {
    use crate::broadcast::TxWarningKind;
    use crate::testkit::script;
    use bdk_wallet::bitcoin::OutPoint;

    let dir = tempfile::tempdir().unwrap();
    let (manager, funding, spender) = wallet_coin_spent(dir.path(), true).await;
    let rival = crate::testkit::transaction(
        &[OutPoint::new(funding.compute_txid(), 0)],
        &[(script(8).as_str(), 48_000)],
    );
    for (pasted, says) in [
        (
            spender,
            "this same transaction, which is already in a block",
        ),
        (rival, "another transaction, which is in a block"),
    ] {
        let preview = manager
            .preview_transaction(&witnessed(pasted), Network::Signet)
            .await
            .unwrap();
        let spent = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputSpent)
            .expect("the spent coin is named");
        assert!(spent.message.contains(says), "{}", spent.message);
        assert!(spent.blocking);
        assert!(!preview.ready);
        assert!(preview.hex.is_none());
    }
}

/// The same coin spent by a transaction still in the mempool: pasting
/// that transaction again, or one that replaces it, is the node's
/// call. Broadcast stays on.
#[tokio::test]
async fn a_watched_coin_spent_in_the_mempool_leaves_the_send_to_the_node() {
    use crate::broadcast::TxWarningKind;

    let dir = tempfile::tempdir().unwrap();
    let (manager, _, spender) = wallet_coin_spent(dir.path(), false).await;
    let preview = manager
        .preview_transaction(&witnessed(spender), Network::Signet)
        .await
        .unwrap();
    let spent = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputSpent)
        .expect("the spent coin is named");
    assert!(
        spent.message.contains("waiting in the mempool"),
        "{}",
        spent.message
    );
    assert!(!spent.blocking);
    assert!(preview.ready);
    assert!(preview.hex.is_some());
}

/// A coin no watched wallet holds: the backend's `outspend` says who
/// spent it and whether that is in a block, and the preview goes by
/// it the way it goes by the wallet.
#[tokio::test]
async fn the_backend_places_a_spend_the_vault_does_not_know() {
    use crate::broadcast::TxWarningKind;
    use crate::testkit::{nowhere, script, transaction};
    use bdk_wallet::bitcoin::OutPoint;

    let funding = transaction(&[nowhere(1, 0)], &[(script(3).as_str(), 50_000)]);
    let pasted = transaction(
        &[OutPoint::new(funding.compute_txid(), 0)],
        &[(script(9).as_str(), 49_000)],
    );
    let other = "77".repeat(32);
    for (confirmed, blocks) in [(true, true), (false, false)] {
        let outspend = format!(
            r#"{{"spent":true,"txid":"{other}","vin":0,"status":{{"confirmed":{confirmed}}}}}"#
        );
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(
                Network::Regtest,
                BackendConfig::CustomEsplora {
                    url: esplora_answering(funding.clone(), Unknown::NotFound, outspend).await,
                    own_node: false,
                },
            )
            .await
            .unwrap();
        let preview = manager
            .preview_transaction(&witnessed(pasted.clone()), Network::Regtest)
            .await
            .unwrap();
        let spent = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputSpent)
            .expect("the backend's answer is named");
        assert_eq!(spent.blocking, blocks, "{}", spent.message);
        assert_eq!(preview.ready, !blocks);
        assert_eq!(preview.inputs[0].value_sats, Some(50_000));
    }
}

/// A taproot address, BIP-350's own testnet example: public, nobody's.
const TAPROOT: &str = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c";

/// A manager watching [`TAPROOT`] on signet, whose server listed one coin
/// at `listed` sats: the outpoint of that coin, and the address script.
async fn listed_coin(
    dir: &std::path::Path,
    listed: u64,
    coin: bdk_wallet::bitcoin::OutPoint,
) -> (WalletManager, bdk_wallet::bitcoin::ScriptBuf) {
    use crate::input::parse_input;
    use crate::wallet::{AddressUtxo, AddressWatchState};
    use std::str::FromStr;

    let manager = manager(dir).await;
    let watch = manager
        .add_wallet("Watch", &parse_input(TAPROOT).unwrap(), Network::Signet)
        .await
        .unwrap();
    crate::manager::find_record_mut(&mut manager.state.lock().await.payload, &watch.id)
        .unwrap()
        .address_state = Some(AddressWatchState {
        utxos: vec![AddressUtxo {
            txid: coin.txid.to_string(),
            vout: coin.vout,
            value_sats: listed,
            height: Some(10),
            timestamp: None,
        }],
        ..Default::default()
    });
    let script = bdk_wallet::bitcoin::Address::from_str(TAPROOT)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    (manager, script)
}

/// A finalized PSBT spending `coin` and paying `paid` sats elsewhere,
/// the coin described by `describe`.
fn psbt_spending_coin(
    coin: bdk_wallet::bitcoin::OutPoint,
    paid: u64,
    describe: impl FnOnce(&mut bdk_wallet::bitcoin::psbt::Input),
) -> String {
    use bdk_wallet::bitcoin::{
        Psbt, ScriptBuf, Sequence, Transaction, TxIn, Witness, absolute, transaction,
    };
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: coin,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(paid),
            script_pubkey: ScriptBuf::from_hex(&crate::testkit::script(9)).unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    let mut witness = Witness::new();
    witness.push([0x30; 64]);
    psbt.inputs[0].final_script_witness = Some(witness);
    describe(&mut psbt.inputs[0]);
    data_encoding::BASE64.encode(&psbt.serialize())
}

/// A watched taproot address whose server lists a coin at 1 000 sats,
/// and a PSBT that describes it, by a witness entry alone, as 100 000
/// and pays 90 000 from it. The listing is no proof: it is shown, the
/// outputs over it are said, and the transaction is not refused on it.
#[tokio::test]
async fn a_listing_never_refuses_a_transaction() {
    use crate::broadcast::{TxReadiness, TxWarningKind};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{OutPoint, Txid};

    let coin = OutPoint::new(Txid::from_byte_array([0x55; 32]), 0);
    let dir = tempfile::tempdir().unwrap();
    let (manager, script) = listed_coin(dir.path(), 1_000, coin).await;
    let text = psbt_spending_coin(coin, 90_000, |input| {
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        });
    });
    let preview = manager
        .preview_transaction(&text, Network::Signet)
        .await
        .unwrap();
    assert_eq!(preview.inputs[0].value_sats, Some(1_000));
    assert!(preview.amounts_declared);
    assert!(
        !preview.warnings.iter().any(|w| w.blocking),
        "{:?}",
        preview.warnings
    );
    assert_eq!(preview.readiness, TxReadiness::Ready);
    assert!(preview.hex.is_some());
    assert!(
        preview
            .warnings
            .iter()
            .any(|w| w.kind == TxWarningKind::InputMismatch)
    );
}
