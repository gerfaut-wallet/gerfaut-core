//! Previews of a transaction whose coins only the backend can vouch
//! for, against an Esplora on loopback or none at all; and the
//! broadcasts the vault keeps once the network took them.

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
    esplora_serving(tx, Vec::new(), unknown, outspend).await
}

/// The same Esplora, which also hands over `also` when asked for them:
/// the transaction its `outspend` names, for one.
async fn esplora_serving(
    tx: bdk_wallet::bitcoin::Transaction,
    also: Vec<bdk_wallet::bitcoin::Transaction>,
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
    let others: Vec<(String, Vec<u8>)> = also
        .iter()
        .map(|other| {
            (
                format!("/api/tx/{}/raw", other.compute_txid()),
                bdk_wallet::bitcoin::consensus::serialize(other),
            )
        })
        .collect();
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
            } else if let Some((_, bytes)) = others.iter().find(|(route, _)| route == path) {
                Some(("200 OK", "application/octet-stream", bytes.clone()))
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

/// The same coin spent by a transaction still in the mempool. Pasting
/// that very transaction again is harmless, and the preview says it is
/// already waiting, in amber; one that would replace it is the node's
/// call. Broadcast stays on for both.
#[tokio::test]
async fn a_watched_coin_spent_in_the_mempool_leaves_the_send_to_the_node() {
    use crate::broadcast::{TxReadiness, TxSeverity, TxWarningKind};
    use crate::testkit::script;
    use bdk_wallet::bitcoin::OutPoint;

    let dir = tempfile::tempdir().unwrap();
    let (manager, funding, spender) = wallet_coin_spent(dir.path(), false).await;
    let again = manager
        .preview_transaction(&witnessed(spender), Network::Signet)
        .await
        .unwrap();
    assert_eq!(again.readiness, TxReadiness::InMempool);
    assert!(again.ready);
    assert!(again.hex.is_some());
    assert!(
        !again
            .warnings
            .iter()
            .any(|w| w.kind == TxWarningKind::InputSpent),
        "{:?}",
        again.warnings
    );
    let waiting = again
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InMempool)
        .expect("the preview says it is already out");
    assert_eq!(waiting.severity, TxSeverity::Info);

    let replacement = crate::testkit::transaction(
        &[OutPoint::new(funding.compute_txid(), 0)],
        &[(script(8).as_str(), 48_000)],
    );
    let preview = manager
        .preview_transaction(&witnessed(replacement), Network::Signet)
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
    assert_eq!(preview.readiness, TxReadiness::Ready);
    assert!(preview.hex.is_some());
}

/// A coin no watched wallet holds: the backend's `outspend` says who
/// spent it and whether that is in a block. A spend in a block holds the
/// send back once the backend shows the transaction that makes it, and
/// it spends this coin; its word alone is a caution. One in the mempool
/// never holds it back.
#[tokio::test]
async fn the_backend_places_a_spend_the_vault_does_not_know() {
    use crate::broadcast::TxWarningKind;
    use crate::testkit::{nowhere, script, transaction};
    use bdk_wallet::bitcoin::OutPoint;

    let funding = transaction(&[nowhere(1, 0)], &[(script(3).as_str(), 50_000)]);
    let coin = OutPoint::new(funding.compute_txid(), 0);
    let pasted = transaction(&[coin], &[(script(9).as_str(), 49_000)]);
    let rival = transaction(&[coin], &[(script(8).as_str(), 48_000)]);
    // A transaction that spends something else, which a lying backend
    // could name in its place.
    let unrelated = transaction(&[nowhere(2, 0)], &[(script(8).as_str(), 48_000)]);
    for (spender, served, confirmed, blocks) in [
        (&rival, true, true, true),
        (&rival, false, true, false),
        (&unrelated, true, true, false),
        (&rival, true, false, false),
    ] {
        let outspend = format!(
            r#"{{"spent":true,"txid":"{}","vin":0,"status":{{"confirmed":{confirmed}}}}}"#,
            spender.compute_txid()
        );
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(
                Network::Regtest,
                BackendConfig::CustomEsplora {
                    url: esplora_serving(
                        funding.clone(),
                        if served {
                            vec![spender.clone()]
                        } else {
                            Vec::new()
                        },
                        Unknown::NotFound,
                        outspend,
                    )
                    .await,
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
        let case = format!("served {served}, confirmed {confirmed}: {}", spent.message);
        assert_eq!(spent.blocking, blocks, "{case}");
        assert_eq!(preview.ready, !blocks, "{case}");
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
/// and pays 90 000 from it. The backend that would show the transaction
/// does not answer. The listing is no proof: it is shown, marked as the
/// server's figure and not the PSBT's, the outputs over it are said, and
/// the transaction is not refused on it.
#[tokio::test]
async fn a_listing_never_refuses_a_transaction() {
    use crate::broadcast::{TxReadiness, TxWarningKind};
    use crate::testkit::{nowhere, script, transaction};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{OutPoint, Txid};

    let coin = OutPoint::new(Txid::from_byte_array([0x55; 32]), 0);
    let dir = tempfile::tempdir().unwrap();
    let (manager, script_pubkey) = listed_coin(dir.path(), 1_000, coin).await;
    let silent = esplora_knowing(
        transaction(&[nowhere(1, 0)], &[(script(3).as_str(), 50_000)]),
        Unknown::NoAnswer,
    )
    .await;
    manager
        .set_backend(
            Network::Signet,
            BackendConfig::CustomEsplora {
                url: silent,
                own_node: false,
            },
        )
        .await
        .unwrap();
    let script = script_pubkey;
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
    assert!(preview.amounts_listed);
    let unchecked = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputUnknown)
        .expect("nobody backed the listing, and the preview says so");
    assert!(
        unchecked.message.contains("listed for Watch"),
        "{}",
        unchecked.message
    );
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

/// The same watched address lists the coin at 1 000 sats, but the PSBT
/// carries the previous transaction, which pays it 100 000. The listing
/// is set aside with what came with it, the wallet's name and its
/// "unspent": the coin goes to the backend like any coin no wallet
/// holds, which says it was spent in a block. The listing never stood in
/// for that answer.
#[tokio::test]
async fn a_contradicted_listing_sends_the_coin_to_the_backend() {
    use crate::broadcast::{TxReadiness, TxWarningKind};
    use crate::testkit::{nowhere, transaction};
    use bdk_wallet::bitcoin::OutPoint;
    use std::str::FromStr;

    let script = bdk_wallet::bitcoin::Address::from_str(TAPROOT)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let funding = transaction(&[nowhere(1, 0)], &[(&script.to_hex_string(), 100_000)]);
    let coin = OutPoint::new(funding.compute_txid(), 0);
    let dir = tempfile::tempdir().unwrap();
    let (manager, _) = listed_coin(dir.path(), 1_000, coin).await;
    let spender = transaction(&[coin], &[(crate::testkit::script(8).as_str(), 99_000)]);
    let other = spender.compute_txid();
    manager
        .set_backend(
            Network::Signet,
            BackendConfig::CustomEsplora {
                url: esplora_serving(
                    funding.clone(),
                    vec![spender],
                    Unknown::NotFound,
                    format!(
                        r#"{{"spent":true,"txid":"{other}","vin":0,"status":{{"confirmed":true}}}}"#
                    ),
                )
                .await,
                own_node: false,
            },
        )
        .await
        .unwrap();
    let text = psbt_spending_coin(coin, 90_000, |input| {
        input.non_witness_utxo = Some(funding.clone());
    });
    let preview = manager
        .preview_transaction(&text, Network::Signet)
        .await
        .unwrap();
    assert_eq!(preview.inputs[0].value_sats, Some(100_000));
    assert_eq!(
        preview.inputs[0].wallet, None,
        "the listing's name went with it"
    );
    let kinds: Vec<TxWarningKind> = preview.warnings.iter().map(|w| w.kind).collect();
    assert!(!kinds.contains(&TxWarningKind::SpendsWatched), "{kinds:?}");
    let mismatch = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputMismatch)
        .expect("the contradicted listing is said");
    assert!(
        mismatch.message.contains("Watch lists"),
        "{}",
        mismatch.message
    );
    // The backend was asked, and its answer, not the listing's
    // "unspent", is what the preview goes by.
    let spent = preview
        .warnings
        .iter()
        .find(|w| w.kind == TxWarningKind::InputSpent)
        .expect("the backend's answer about the coin");
    assert!(spent.blocking);
    assert_eq!(preview.readiness, TxReadiness::Refused);
}

/// A watched address lists a coin; the backend hands over the
/// transaction that pays it, whose txid it checked. The value shown is
/// the transaction's from then on, proven: no mark, no caution when the
/// two agree. A listing the transaction contradicts is said, and the
/// coin keeps its wallet while it sits on the address listed.
#[tokio::test]
async fn the_backend_backs_a_listing_with_its_transaction() {
    use crate::broadcast::TxWarningKind;
    use crate::testkit::{nowhere, transaction};
    use bdk_wallet::bitcoin::OutPoint;
    use std::str::FromStr;

    let script = bdk_wallet::bitcoin::Address::from_str(TAPROOT)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let funding = transaction(&[nowhere(1, 0)], &[(&script.to_hex_string(), 100_000)]);
    let coin = OutPoint::new(funding.compute_txid(), 0);
    for (listed, contradicted) in [(100_000, false), (1_000, true)] {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) = listed_coin(dir.path(), listed, coin).await;
        manager
            .set_backend(
                Network::Signet,
                BackendConfig::CustomEsplora {
                    url: esplora_knowing(funding.clone(), Unknown::NotFound).await,
                    own_node: false,
                },
            )
            .await
            .unwrap();
        let preview = manager
            .preview_transaction(&psbt_spending_coin(coin, 90_000, |_| {}), Network::Signet)
            .await
            .unwrap();
        assert_eq!(preview.inputs[0].value_sats, Some(100_000));
        assert_eq!(preview.fee_sats, Some(10_000));
        assert!(!preview.amounts_declared, "the transaction proves it");
        assert!(!preview.amounts_listed);
        assert_eq!(
            preview.inputs[0].wallet.as_ref().map(|w| w.name.as_str()),
            Some("Watch")
        );
        let kinds: Vec<TxWarningKind> = preview.warnings.iter().map(|w| w.kind).collect();
        assert!(!kinds.contains(&TxWarningKind::InputUnknown), "{kinds:?}");
        assert_eq!(
            kinds.contains(&TxWarningKind::InputMismatch),
            contradicted,
            "{:?}",
            preview.warnings
        );
    }
}

/// A coin no watched wallet holds, behind an Electrum server: the coins
/// of its script say whether it is still there, and its history holds
/// the transaction that spends it, read and checked. Only a spend seen
/// so, in a block, holds the send back.
#[tokio::test]
async fn electrum_says_whether_a_coin_is_spent() {
    use crate::broadcast::{TxReadiness, TxWarningKind};
    use crate::testkit::{FakeElectrum, nowhere, script, transaction};
    use bdk_wallet::bitcoin::OutPoint;

    let funding = transaction(&[nowhere(1, 0)], &[(script(3).as_str(), 50_000)]);
    let funded = funding.compute_txid();
    let coin = OutPoint::new(funded, 0);
    let pasted = transaction(&[coin], &[(script(9).as_str(), 49_000)]);
    let rival = transaction(&[coin], &[(script(8).as_str(), 48_000)]);
    let unrelated = transaction(&[nowhere(2, 0)], &[(script(3).as_str(), 1_000)]);

    /// What the server holds about the coin's script.
    struct Case {
        name: &'static str,
        unspent: bool,
        history: Vec<(bdk_wallet::bitcoin::Transaction, i64)>,
        readiness: TxReadiness,
        spent_blocks: Option<bool>,
    }
    let cases = [
        Case {
            name: "still among the script's coins",
            unspent: true,
            history: vec![],
            readiness: TxReadiness::Ready,
            spent_blocks: None,
        },
        Case {
            name: "spent in a block by a transaction it shows",
            unspent: false,
            history: vec![(rival.clone(), 101)],
            readiness: TxReadiness::Refused,
            spent_blocks: Some(true),
        },
        Case {
            name: "spent in the mempool by another",
            unspent: false,
            history: vec![(rival.clone(), 0)],
            readiness: TxReadiness::Ready,
            spent_blocks: Some(false),
        },
        Case {
            name: "this very transaction waiting in the mempool",
            unspent: false,
            history: vec![(pasted.clone(), 0)],
            readiness: TxReadiness::InMempool,
            spent_blocks: None,
        },
        Case {
            name: "gone from the coins, and nothing in the history spends it",
            unspent: false,
            history: vec![(unrelated.clone(), 101)],
            readiness: TxReadiness::Ready,
            spent_blocks: None,
        },
    ];
    for case in cases {
        let server = FakeElectrum::start().await;
        server.add_tx(&funding);
        for (tx, _) in &case.history {
            server.add_tx(tx);
        }
        let mut history = vec![(funded, 100)];
        history.extend(case.history.iter().map(|(tx, at)| (tx.compute_txid(), *at)));
        server.set_history(&script(3), &history);
        if case.unspent {
            server.set_unspent(&script(3), &[(funded, 0, 100, 50_000)]);
        }
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(Network::Regtest, server.backend())
            .await
            .unwrap();
        let preview = manager
            .preview_transaction(&witnessed(pasted.clone()), Network::Regtest)
            .await
            .unwrap();
        assert_eq!(preview.readiness, case.readiness, "{}", case.name);
        assert_eq!(preview.inputs[0].value_sats, Some(50_000), "{}", case.name);
        let spent = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputSpent);
        assert_eq!(
            spent.map(|w| w.blocking),
            case.spent_blocks,
            "{}: {:?}",
            case.name,
            preview.warnings
        );
    }
}

/// A height lock set at the signer's tip against fee sniping, and a
/// device whose wallets synced a few blocks before: the lock is judged
/// on the height the backend gives at the time of the preview, the node
/// the transaction goes to, not on the wallets' last sync.
#[tokio::test]
async fn a_height_lock_is_judged_on_the_backends_tip() {
    use crate::broadcast::TxWarningKind;
    use crate::testkit::{FakeElectrum, nowhere, script, transaction};
    use bdk_wallet::bitcoin::{OutPoint, absolute};

    let funding = transaction(&[nowhere(1, 0)], &[(script(3).as_str(), 50_000)]);
    let coin = OutPoint::new(funding.compute_txid(), 0);
    let server = FakeElectrum::start().await;
    server.add_tx(&funding);
    server.set_unspent(&script(3), &[(funding.compute_txid(), 0, 90, 50_000)]);
    server.state.lock().unwrap().height = 120;
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_backend(Network::Regtest, server.backend())
        .await
        .unwrap();
    for (lock, locked) in [(120, false), (121, true)] {
        let mut pasted = transaction(&[coin], &[(script(9).as_str(), 49_000)]);
        pasted.lock_time = absolute::LockTime::from_height(lock).unwrap();
        let preview = manager
            .preview_transaction(&witnessed(pasted), Network::Regtest)
            .await
            .unwrap();
        assert_eq!(
            preview
                .warnings
                .iter()
                .any(|w| w.kind == TxWarningKind::Locked),
            locked,
            "lock {lock} at a tip of 120: {:?}",
            preview.warnings
        );
    }
}

// --- recent broadcasts ---------------------------------------------------

/// An Esplora on loopback that takes every transaction posted to it, or
/// refuses each in the node's words when `refusal` says so.
async fn esplora_taking(refusal: Option<&'static str>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            // The whole request, its body too: an answer sent over bytes
            // left unread would go with a reset.
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
            let (status, body) = match refusal {
                None => ("200 OK", "accepted"),
                Some(words) => ("400 Bad Request", words),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    format!("http://{address}/api")
}

/// A manager whose regtest backend is [`esplora_taking`].
async fn sending(dir: &std::path::Path, refusal: Option<&'static str>) -> WalletManager {
    let manager = manager(dir).await;
    manager
        .set_backend(
            Network::Regtest,
            BackendConfig::CustomEsplora {
                url: esplora_taking(refusal).await,
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager
}

/// A transaction the decoder takes for signed, spending a coin of
/// nobody's, as hex: `n` tells two apart.
fn signed(n: u8) -> String {
    use crate::testkit::{nowhere, script, transaction};
    let mut tx = transaction(&[nowhere(n, 0)], &[(&script(n), 50_000)]);
    tx.input[0].witness.push([0x30; 71]);
    tx.input[0].witness.push([0x02; 33]);
    bdk_wallet::bitcoin::consensus::encode::serialize_hex(&tx)
}

/// What the network took is kept with what the apps show of it, read
/// back after a restart, network by network.
#[tokio::test]
async fn a_broadcast_the_network_took_is_kept_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let manager = sending(dir.path(), None).await;
    let hex = signed(1);
    let report = manager
        .broadcast_transaction(Network::Regtest, &hex)
        .await
        .unwrap();

    let kept = manager.recent_broadcasts(Network::Regtest).await;
    assert_eq!(
        kept,
        [RecentBroadcast {
            txid: report.txid,
            network: Network::Regtest,
            hex,
            backend: report.backend,
            at: report.at,
        }]
    );
    assert!(manager.recent_broadcasts(Network::Signet).await.is_empty());
    drop(manager);
    let reopened = WalletManager::open(dir.path(), crate::manager::tests::support::key()).unwrap();
    assert_eq!(reopened.recent_broadcasts(Network::Regtest).await, kept);
}

/// A transaction the node refused was never sent: nothing is kept.
#[tokio::test]
async fn a_refused_broadcast_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let manager = sending(
        dir.path(),
        Some("sendrawtransaction RPC error -26: min relay fee not met"),
    )
    .await;
    let error = manager
        .broadcast_transaction(Network::Regtest, &signed(1))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("min relay fee not met"),
        "{error}"
    );
    assert!(manager.recent_broadcasts(Network::Regtest).await.is_empty());
}

/// Newest first, a transaction sent again moved up rather than listed
/// twice, and one forgotten gone for good, a restart included.
#[tokio::test]
async fn a_forgotten_broadcast_stays_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let manager = sending(dir.path(), None).await;
    let mut txids = Vec::new();
    for hex in [signed(1), signed(2), signed(1)] {
        let report = manager
            .broadcast_transaction(Network::Regtest, &hex)
            .await
            .unwrap();
        txids.push(report.txid);
    }
    let listed = |manager: WalletManager| async move {
        manager
            .recent_broadcasts(Network::Regtest)
            .await
            .into_iter()
            .map(|sent| sent.txid)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        listed(manager.clone()).await,
        [txids[0].as_str(), &txids[1]]
    );

    manager.forget_broadcast(&txids[0]).await.unwrap();
    // Already so: no error.
    manager.forget_broadcast(&txids[0]).await.unwrap();
    assert_eq!(listed(manager.clone()).await, [txids[1].as_str()]);
    drop(manager);
    let reopened = WalletManager::open(dir.path(), crate::manager::tests::support::key()).unwrap();
    assert_eq!(listed(reopened).await, [txids[1].as_str()]);
}

/// A disk that takes no save does not cost a broadcast its answer: the
/// transaction is on the network, and kept for this session. The next
/// save that goes through writes it. Forgetting, which the user
/// decides, is refused instead, and changes nothing.
#[tokio::test]
async fn a_broadcast_kept_where_no_save_goes_through_is_still_answered() {
    let dir = tempfile::tempdir().unwrap();
    let manager = sending(dir.path(), None).await;
    manager.state.lock().await.vault.fail_saves(true);
    let report = manager
        .broadcast_transaction(Network::Regtest, &signed(1))
        .await
        .unwrap();
    assert_eq!(manager.recent_broadcasts(Network::Regtest).await.len(), 1);
    assert!(manager.forget_broadcast(&report.txid).await.is_err());
    assert_eq!(manager.recent_broadcasts(Network::Regtest).await.len(), 1);

    manager.state.lock().await.vault.fail_saves(false);
    manager
        .set_app_pref("desktop.theme".to_owned(), "dark".to_owned())
        .await
        .unwrap();
    drop(manager);
    let reopened = WalletManager::open(dir.path(), crate::manager::tests::support::key()).unwrap();
    let kept = reopened.recent_broadcasts(Network::Regtest).await;
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].txid, report.txid);
}
