//! Broadcasting a transaction somebody else signed.
//!
//! Gerfaut never signs. What it can do is take a finished transaction,
//! whatever the container (a PSBT with every signature in it, or the
//! raw transaction itself), show what it does before anything leaves
//! the machine, hand it to the network, and follow it until it
//! confirms. The decoding here is pure: no key, no network. The
//! [`crate::WalletManager`] adds what only the chain or the watched
//! wallets know (previous outputs, ownership) and does the broadcast.
//!
//! Accepted forms, all detected from the content and never from a file
//! extension: PSBT as base64, as hex, or as the binary file (`.psbt`,
//! magic `psbt\xff`); raw transaction as hex or as the binary file
//! (`.txn`, `.tx`); either of those inside a `ur:crypto-psbt`, a
//! `ur:bytes` or a BBQr envelope pasted or scanned.

use bdk_wallet::bitcoin::consensus::encode;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxOut};
use bdk_wallet::miniscript::psbt::PsbtExt;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::wallet::tx_extras::{OpReturnData, op_return_of};

/// Largest input accepted, in characters: a fully signed transaction
/// with hundreds of inputs fits many times over.
const MAX_INPUT_LEN: usize = 4_000_000;

/// PSBT file magic, BIP-174.
const PSBT_MAGIC: &[u8] = b"psbt\xff";

/// Fee rate above which the preview says so, in sat/vB. Nothing on
/// the chain justifies it outside an emergency, and a wrong unit in the
/// signing software is the usual cause.
pub const HIGH_FEE_RATE_SAT_VB: f64 = 500.0;

/// Fee above this share of what the inputs bring is called out.
pub const HIGH_FEE_SHARE: f64 = 0.10;

fn tx_error(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidInput {
        kind: "transaction",
        detail: detail.into(),
    }
}

/// The container the transaction came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxSource {
    RawTransaction,
    Psbt,
}

/// The wallet a side of the transaction belongs to, when it is one of
/// the watched ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRef {
    pub id: String,
    pub name: String,
}

/// One input of the transaction to broadcast.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxInputPreview {
    pub txid: String,
    pub vout: u32,
    /// Value of the output being spent, when known: from a watched
    /// wallet or from the backend first, from the PSBT only when neither
    /// knows the coin. What the PSBT declares is its author's word.
    pub value_sats: Option<u64>,
    /// Address of the output being spent, when known.
    pub address: Option<String>,
    /// Whether this input carries what the network needs to accept it:
    /// a final script or witness. A PSBT input with partial signatures
    /// that could be finalized counts as signed.
    pub signed: bool,
    /// The watched wallet that owns the coin, when any.
    pub wallet: Option<WalletRef>,
}

/// One output of the transaction to broadcast.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxOutputPreview {
    pub index: u32,
    pub value_sats: u64,
    /// Address, when the script has one.
    pub address: Option<String>,
    /// Decoded OP_RETURN payload, for data-carrying outputs.
    pub op_return: Option<OpReturnData>,
    /// The watched wallet that receives this output, when any.
    pub wallet: Option<WalletRef>,
    /// Output on a watched wallet's change keychain.
    pub change: bool,
}

/// A caution the person should read before broadcasting. Never blocks:
/// the transaction is theirs, the preview only makes it legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxWarningKind {
    /// Some inputs carry no signature: the network will refuse it.
    Unsigned,
    /// The fee rate is far above anything the chain asks for.
    HighFeeRate,
    /// The fee takes a large share of what the inputs bring.
    HighFeeShare,
    /// A time lock keeps the transaction out of the chain for now.
    Locked,
    /// An input was not found on this network.
    InputUnknown,
    /// An input was already spent, by this transaction or another.
    InputSpent,
    /// The PSBT declares a coin other than the one the wallet or the
    /// backend holds at that outpoint: another value, another script.
    InputMismatch,
    /// The fee could not be computed: an input's value is unknown.
    FeeUnknown,
    /// An output below the dust threshold.
    DustOutput,
    /// The transaction spends coins of a watched wallet.
    SpendsWatched,
}

/// How loudly a caution should be read.
///
/// One question decides it, and the core answers it once so the two
/// applications cannot drift into two tables: **can the person lose
/// funds or lose privacy?** Anything else is worth reading, not worth
/// the most expensive colour of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxSeverity {
    /// Funds or privacy are at stake.
    Alert,
    /// Worth reading; nothing is at risk.
    Info,
}

impl TxWarningKind {
    /// The tone this caution is read in.
    pub fn severity(self) -> TxSeverity {
        match self {
            // Believing a transaction went out when it cannot is how a
            // person ships goods against a payment that never lands.
            TxWarningKind::Unsigned | TxWarningKind::InputSpent => TxSeverity::Alert,
            // A fee far above what the chain asks, or eating a large
            // share of the inputs, is money gone the moment it is sent.
            TxWarningKind::HighFeeRate | TxWarningKind::HighFeeShare => TxSeverity::Alert,
            // A PSBT that declares a coin other than the one the chain
            // holds hides what the transaction really costs: the fee it
            // shows is whatever its author chose, and the signature is
            // valid over the real one.
            TxWarningKind::InputMismatch => TxSeverity::Alert,
            // Nothing here costs anything: an input the backend has not
            // indexed, a time lock, a fee that could not be computed, an
            // output under the dust threshold, a coin of a watched
            // wallet being spent. All of them are worth reading.
            TxWarningKind::InputUnknown
            | TxWarningKind::Locked
            | TxWarningKind::FeeUnknown
            | TxWarningKind::DustOutput
            | TxWarningKind::SpendsWatched => TxSeverity::Info,
        }
    }
}

/// A caution with its human-readable text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWarning {
    pub kind: TxWarningKind,
    pub message: String,
    /// The tone to read it in. Derived from `kind`; carried on the wire
    /// so a screen never has to decide, and a kind added later cannot
    /// fall through a hand-written table into an untoned panel.
    pub severity: TxSeverity,
}

impl TxWarning {
    fn new(kind: TxWarningKind, message: impl Into<String>) -> Self {
        TxWarning {
            severity: kind.severity(),
            kind,
            message: message.into(),
        }
    }
}

/// Everything shown before broadcasting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxPreview {
    pub txid: String,
    pub source: TxSource,
    pub network: Network,
    pub inputs: Vec<TxInputPreview>,
    pub outputs: Vec<TxOutputPreview>,
    /// Fee in satoshis, when every input's value is known.
    pub fee_sats: Option<u64>,
    pub fee_rate_sat_vb: Option<f64>,
    /// Virtual size in vbytes.
    pub vsize: u64,
    /// Weight units.
    pub weight: u64,
    /// Serialized size in bytes.
    pub size: u64,
    pub version: i32,
    /// Absolute lock time, as the consensus integer: a block height
    /// below 500 000 000, a unix timestamp above.
    pub locktime: u32,
    /// Whether the transaction signals replaceability (BIP-125).
    pub rbf: bool,
    /// Whether every input is signed and the transaction can be sent.
    pub ready: bool,
    pub warnings: Vec<TxWarning>,
    /// The transaction as the network takes it, hex. Present only when
    /// ready: an unsigned transaction has nothing to broadcast.
    pub hex: Option<String>,
}

/// Outcome of a broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastReport {
    pub txid: String,
    /// Host that accepted the transaction.
    pub backend: String,
    /// Unix timestamp, seconds.
    pub at: u64,
}

/// Where a transaction stands, as the backend sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastStatus {
    pub txid: String,
    /// Whether the backend knows the transaction at all. A transaction
    /// can drop out of the mempool: evicted, replaced, or never relayed.
    pub found: bool,
    pub confirmed: bool,
    pub block_height: Option<u32>,
    /// Confirmations at the time of the check; 0 while pending.
    pub confirmations: u32,
    /// Host that answered.
    pub backend: String,
    /// Unix timestamp, seconds.
    pub at: u64,
}

/// A transaction decoded from any accepted form, before the chain is
/// consulted.
#[derive(Debug, Clone)]
pub struct DecodedTx {
    pub source: TxSource,
    /// The transaction as it will be sent: extracted from the PSBT
    /// when every input could be finalized, the unsigned skeleton
    /// otherwise (for the preview only).
    pub tx: Transaction,
    /// Per input: signed, value and script of the coin spent when the
    /// container carried them.
    pub inputs: Vec<DecodedInput>,
    pub ready: bool,
}

#[derive(Debug, Clone)]
pub struct DecodedInput {
    pub signed: bool,
    pub prevout: Option<TxOut>,
}

/// Decodes a transaction from text: base64 PSBT, hex PSBT, hex raw
/// transaction, or a QR envelope around one of those. Binary files are
/// passed as hex by the apps.
pub fn decode_transaction(input: &str) -> CoreResult<DecodedTx> {
    let text: String = input.split_whitespace().collect();
    if text.is_empty() {
        return Err(tx_error("empty input"));
    }
    if text.len() > MAX_INPUT_LEN {
        return Err(tx_error("input too large"));
    }
    if crate::input::qr::is_envelope(&text) {
        let progress = crate::input::qr::assemble(std::slice::from_ref(&text))?;
        return match progress.text {
            Some(inner) => decode_transaction(&inner),
            None => Err(tx_error(format!(
                "this is part 1 of a {}-part QR code: scan it with the camera",
                progress.total
            ))),
        };
    }
    let bytes = decode_bytes(&text)?;
    decode_bytes_as_transaction(&bytes)
}

/// Decodes raw bytes: a PSBT file or a serialized transaction.
pub fn decode_bytes_as_transaction(bytes: &[u8]) -> CoreResult<DecodedTx> {
    if bytes.starts_with(PSBT_MAGIC) {
        let psbt = Psbt::deserialize(bytes).map_err(|e| tx_error(format!("invalid PSBT: {e}")))?;
        return decode_psbt(psbt);
    }
    let tx: Transaction = encode::deserialize(bytes).map_err(|_| {
        tx_error(
            "not a transaction: expected a PSBT (base64, hex or .psbt file) or a signed \
             transaction (hex or .txn file)",
        )
    })?;
    if tx.input.is_empty() {
        return Err(tx_error("the transaction spends nothing"));
    }
    let inputs = tx
        .input
        .iter()
        .map(|input| DecodedInput {
            signed: !input.script_sig.is_empty() || !input.witness.is_empty(),
            prevout: None,
        })
        .collect::<Vec<_>>();
    let ready = inputs.iter().all(|input| input.signed);
    Ok(DecodedTx {
        source: TxSource::RawTransaction,
        tx,
        inputs,
        ready,
    })
}

/// Text to bytes: hex first (a hex string is unambiguous), base64 next.
fn decode_bytes(text: &str) -> CoreResult<Vec<u8>> {
    if text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return data_encoding::HEXLOWER_PERMISSIVE
            .decode(text.as_bytes())
            .map_err(|_| tx_error("invalid hex"));
    }
    let padded = match text.len() % 4 {
        0 => text.to_owned(),
        rem => format!("{text}{}", "=".repeat(4 - rem)),
    };
    data_encoding::BASE64
        .decode(padded.as_bytes())
        .or_else(|_| data_encoding::BASE64URL.decode(padded.as_bytes()))
        .map_err(|_| tx_error("not hex and not base64"))
}

/// A PSBT is ready when every input can be finalized from what it
/// carries. Finalizing turns partial signatures into the final script
/// or witness; it needs no key, only the signatures already present.
fn decode_psbt(mut psbt: Psbt) -> CoreResult<DecodedTx> {
    if psbt.unsigned_tx.input.is_empty() {
        return Err(tx_error("the PSBT spends nothing"));
    }
    let secp = Secp256k1::verification_only();
    // Inputs the finalizer could not complete are the unsigned ones;
    // the error list names them by index.
    let unfinished: Vec<usize> = match psbt.finalize_mut(&secp) {
        Ok(()) => Vec::new(),
        Err(errors) => errors
            .iter()
            .filter_map(|error| match error {
                bdk_wallet::miniscript::psbt::Error::InputError(_, index) => Some(*index),
                _ => None,
            })
            .collect(),
    };
    let inputs: Vec<DecodedInput> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let final_present =
                input.final_script_sig.is_some() || input.final_script_witness.is_some();
            let prevout = input.witness_utxo.clone().or_else(|| {
                let vout = psbt.unsigned_tx.input[index].previous_output.vout as usize;
                input
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|prev| prev.output.get(vout).cloned())
            });
            DecodedInput {
                signed: final_present && !unfinished.contains(&index),
                prevout,
            }
        })
        .collect();
    let ready = inputs.iter().all(|input| input.signed);
    let tx = if ready {
        psbt.extract_tx_unchecked_fee_rate()
    } else {
        psbt.unsigned_tx.clone()
    };
    Ok(DecodedTx {
        source: TxSource::Psbt,
        tx,
        inputs,
        ready,
    })
}

/// True when the text looks like a transaction rather than wallet
/// material: used by the import classifier to point people at the
/// right page instead of printing "unrecognized".
pub fn looks_like_transaction(input: &str) -> bool {
    decode_transaction(input).is_ok()
}

// --- preview ------------------------------------------------------------

/// What the manager learned about an input beyond the container.
#[derive(Debug, Clone, Default)]
pub struct InputFacts {
    pub prevout: Option<TxOut>,
    pub wallet: Option<WalletRef>,
    /// Whether the backend says the coin is already spent.
    pub spent: Option<bool>,
    /// Whether the backend was asked and did not know the outpoint.
    pub unknown: bool,
}

/// What the manager learned about an output beyond the script.
#[derive(Debug, Clone, Default)]
pub struct OutputFacts {
    pub wallet: Option<WalletRef>,
    pub change: bool,
}

/// Builds the preview from the decoded transaction and the facts the
/// manager gathered. Pure: everything network-bound happened before.
pub fn build_preview(
    decoded: &DecodedTx,
    network: Network,
    input_facts: &[InputFacts],
    output_facts: &[OutputFacts],
    tip_height: Option<u32>,
    now_secs: u64,
) -> TxPreview {
    let tx = &decoded.tx;
    let address_of = |script: &ScriptBuf| {
        Address::from_script(script, network.to_bitcoin())
            .ok()
            .map(|a| a.to_string())
    };

    let inputs: Vec<TxInputPreview> = tx
        .input
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let facts = input_facts.get(i).cloned().unwrap_or_default();
            // What the wallet or the backend holds at that outpoint
            // comes first: the PSBT's own word about the coin it spends
            // is its author's, and a finalized input is never checked
            // against anything. The PSBT fills in only where neither
            // knows the coin.
            let prevout = facts.prevout.or_else(|| decoded.inputs[i].prevout.clone());
            TxInputPreview {
                txid: input.previous_output.txid.to_string(),
                vout: input.previous_output.vout,
                value_sats: prevout.as_ref().map(|p| p.value.to_sat()),
                address: prevout.as_ref().and_then(|p| address_of(&p.script_pubkey)),
                signed: decoded.inputs[i].signed,
                wallet: facts.wallet,
            }
        })
        .collect();

    let outputs: Vec<TxOutputPreview> = tx
        .output
        .iter()
        .enumerate()
        .map(|(i, output)| {
            let facts = output_facts.get(i).cloned().unwrap_or_default();
            TxOutputPreview {
                index: i as u32,
                value_sats: output.value.to_sat(),
                address: address_of(&output.script_pubkey),
                op_return: op_return_of(&output.script_pubkey),
                wallet: facts.wallet,
                change: facts.change,
            }
        })
        .collect();

    let in_total: Option<u64> = inputs
        .iter()
        .map(|i| i.value_sats)
        .try_fold(0u64, |acc, v| v.map(|v| acc + v));
    let out_total: u64 = outputs.iter().map(|o| o.value_sats).sum();
    let fee_sats = in_total.and_then(|total| total.checked_sub(out_total));
    let vsize = tx.vsize() as u64;
    let fee_rate_sat_vb = fee_sats.map(|fee| fee as f64 / vsize as f64);

    let mut warnings = Vec::new();
    let unsigned = inputs.iter().filter(|i| !i.signed).count();
    if unsigned > 0 {
        warnings.push(TxWarning::new(
            TxWarningKind::Unsigned,
            format!(
                "{unsigned} of {} inputs carry no signature: the network will refuse this \
                 transaction. It has to go back to the signer.",
                inputs.len()
            ),
        ));
    }
    for (i, facts) in input_facts.iter().enumerate() {
        // The PSBT and the chain disagree on the coin: a value or a
        // script the signer was shown that is not the one being spent.
        if let (Some(known), Some(claimed)) = (
            facts.prevout.as_ref(),
            decoded.inputs.get(i).and_then(|d| d.prevout.as_ref()),
        ) && known != claimed
        {
            let source = facts
                .wallet
                .as_ref()
                .map_or("the backend", |wallet| wallet.name.as_str());
            let place = |prevout: &TxOut| {
                address_of(&prevout.script_pubkey)
                    .unwrap_or_else(|| format!("script {:x}", prevout.script_pubkey))
            };
            warnings.push(TxWarning::new(
                TxWarningKind::InputMismatch,
                format!(
                    "Input {i} is not what the PSBT says: it declares {} sats on {}, but \
                     {source} knows this coin as {} sats on {}. The fee shown goes by \
                     {source}; whoever built this PSBT was handed a different coin.",
                    claimed.value.to_sat(),
                    place(claimed),
                    known.value.to_sat(),
                    place(known)
                ),
            ));
        }
        if facts.unknown {
            warnings.push(TxWarning::new(
                TxWarningKind::InputUnknown,
                format!(
                    "Input {i} was not found on {network}: the transaction may belong to \
                     another network, or spend a coin this backend does not know."
                ),
            ));
        } else if facts.spent == Some(true) {
            warnings.push(TxWarning::new(
                TxWarningKind::InputSpent,
                format!(
                    "Input {i} is already spent. Either this transaction was broadcast \
                     before, or another one took the coin."
                ),
            ));
        }
    }
    match (fee_sats, fee_rate_sat_vb, in_total) {
        (None, _, _) => warnings.push(TxWarning::new(
            TxWarningKind::FeeUnknown,
            "The fee is unknown: the value of at least one input could not be \
                      established."
                .to_owned(),
        )),
        (Some(fee), Some(rate), Some(total)) => {
            if rate > HIGH_FEE_RATE_SAT_VB {
                warnings.push(TxWarning::new(
                    TxWarningKind::HighFeeRate,
                    format!(
                        "The fee rate is {rate:.0} sat/vB, far above what the chain asks for. \
                         A wrong unit in the signing software is the usual cause."
                    ),
                ));
            }
            if total > 0 && fee as f64 / total as f64 > HIGH_FEE_SHARE {
                warnings.push(TxWarning::new(
                    TxWarningKind::HighFeeShare,
                    format!(
                        "The fee takes {:.0}% of what the inputs bring.",
                        100.0 * fee as f64 / total as f64
                    ),
                ));
            }
        }
        _ => {}
    }
    let locktime = tx.lock_time.to_consensus_u32();
    let locked = if tx.lock_time.is_block_height() {
        tip_height.is_some_and(|tip| locktime > tip + 1)
    } else {
        u64::from(locktime) > now_secs
    };
    if locked {
        warnings.push(TxWarning::new(
            TxWarningKind::Locked,
            if tx.lock_time.is_block_height() {
                format!(
                    "Time-locked until block {locktime}: the network will not accept it before."
                )
            } else {
                "Time-locked until a later date: the network will not accept it before.".to_owned()
            },
        ));
    }
    let dust = outputs
        .iter()
        .filter(|o| o.op_return.is_none() && o.value_sats < 546)
        .count();
    if dust > 0 {
        warnings.push(TxWarning::new(
            TxWarningKind::DustOutput,
            format!(
                "{dust} output{} below 546 sats: most nodes refuse dust.",
                if dust == 1 { "" } else { "s" }
            ),
        ));
    }
    let watched: Vec<&str> = inputs
        .iter()
        .filter_map(|i| i.wallet.as_ref().map(|w| w.name.as_str()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !watched.is_empty() {
        warnings.push(TxWarning::new(
            TxWarningKind::SpendsWatched,
            format!("Spends coins of {}.", watched.join(", ")),
        ));
    }

    let ready = decoded.ready;
    TxPreview {
        txid: tx.compute_txid().to_string(),
        source: decoded.source,
        network,
        inputs,
        outputs,
        fee_sats,
        fee_rate_sat_vb,
        vsize,
        weight: tx.weight().to_wu(),
        size: tx.total_size() as u64,
        version: tx.version.0,
        locktime,
        rbf: tx.is_explicitly_rbf(),
        ready,
        warnings,
        hex: ready.then(|| encode::serialize_hex(tx)),
    }
}

/// Outpoints the transaction spends, in input order.
pub fn outpoints(decoded: &DecodedTx) -> Vec<OutPoint> {
    decoded.tx.input.iter().map(|i| i.previous_output).collect()
}

/// Amount helper for callers that hold satoshis.
pub fn sats(amount: Amount) -> u64 {
    amount.to_sat()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind is named here on purpose: adding one to the enum must
    /// break this test rather than fall silently into a tone. Red is a
    /// budget — it has to stay spendable the day it matters.
    #[test]
    fn every_caution_has_a_tone_and_only_five_are_red() {
        use TxWarningKind::*;
        let table = [
            (Unsigned, TxSeverity::Alert),
            (InputSpent, TxSeverity::Alert),
            (HighFeeRate, TxSeverity::Alert),
            (HighFeeShare, TxSeverity::Alert),
            (InputMismatch, TxSeverity::Alert),
            (InputUnknown, TxSeverity::Info),
            (Locked, TxSeverity::Info),
            (FeeUnknown, TxSeverity::Info),
            (DustOutput, TxSeverity::Info),
            (SpendsWatched, TxSeverity::Info),
        ];
        for (kind, expected) in table {
            assert_eq!(kind.severity(), expected, "{kind:?}");
        }
        let red = table
            .iter()
            .filter(|(_, s)| *s == TxSeverity::Alert)
            .count();
        assert_eq!(red, 5, "red widened without a decision");
    }

    /// The tone travels with the caution: a screen reads it, never
    /// derives it.
    #[test]
    fn a_caution_carries_the_tone_of_its_kind() {
        let warning = TxWarning::new(TxWarningKind::Locked, "a time lock");
        assert_eq!(warning.severity, TxSeverity::Info);
        assert_eq!(
            TxWarning::new(TxWarningKind::Unsigned, "not signed").severity,
            TxSeverity::Alert
        );
    }
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Sequence, TxIn, Txid, WPubkeyHash, Witness, absolute, transaction};

    fn p2wpkh(byte: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([byte; 20]))
    }

    /// A signed-looking transaction: one input with a witness, two
    /// outputs. The witness is not a valid signature, which is fine:
    /// readiness is about presence, validity is the network's call.
    fn signed_tx() -> Transaction {
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: p2wpkh(0x11),
                },
                TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: p2wpkh(0x22),
                },
            ],
        }
    }

    fn unsigned_tx() -> Transaction {
        let mut tx = signed_tx();
        tx.input[0].witness = Witness::new();
        tx
    }

    #[test]
    fn raw_hex_decodes_signed_and_unsigned() {
        let hex = encode::serialize_hex(&signed_tx());
        let decoded = decode_transaction(&hex).unwrap();
        assert_eq!(decoded.source, TxSource::RawTransaction);
        assert!(decoded.ready);
        // Uppercase, whitespace and line breaks are all tolerated.
        let messy = format!("  {}\n", hex.to_uppercase());
        assert!(decode_transaction(&messy).unwrap().ready);

        let unsigned = decode_transaction(&encode::serialize_hex(&unsigned_tx())).unwrap();
        assert!(!unsigned.ready);
        assert!(!unsigned.inputs[0].signed);
    }

    #[test]
    fn psbt_base64_and_hex_decode_alike() {
        let psbt = Psbt::from_unsigned_tx(unsigned_tx()).unwrap();
        let bytes = psbt.serialize();
        let base64 = data_encoding::BASE64.encode(&bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        for text in [base64.as_str(), hex.as_str()] {
            let decoded = decode_transaction(text).unwrap();
            assert_eq!(decoded.source, TxSource::Psbt);
            assert!(!decoded.ready, "an unsigned PSBT is not ready");
            assert!(decoded.tx.input[0].witness.is_empty());
        }
        // Base64 without padding is what some tools print.
        assert!(decode_transaction(base64.trim_end_matches('=')).is_ok());
    }

    #[test]
    fn finalized_psbt_is_ready_and_carries_the_prevout() {
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx()).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: p2wpkh(0x33),
        });
        psbt.inputs[0].final_script_witness = Some(signed_tx().input[0].witness.clone());
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready);
        assert_eq!(
            decoded.inputs[0].prevout.as_ref().unwrap().value.to_sat(),
            100_000
        );
        assert!(
            !decoded.tx.input[0].witness.is_empty(),
            "extracted, not the skeleton"
        );
    }

    #[test]
    fn garbage_is_named_as_such() {
        assert!(decode_transaction("").is_err());
        assert!(decode_transaction("hello world").is_err());
        // Valid hex that is not a transaction says so; text that is
        // neither hex nor base64 says that instead.
        let error = decode_transaction("deadbeef").unwrap_err().to_string();
        assert!(error.contains("not a transaction"), "{error}");
        let error = decode_transaction("wpkh(tpubD6NzVbkrYhZ4X/0/*)")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not hex and not base64"), "{error}");
        assert!(!looks_like_transaction(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        ));
    }

    #[test]
    fn preview_computes_fee_and_warnings() {
        let decoded = decode_transaction(&encode::serialize_hex(&signed_tx())).unwrap();
        let facts = vec![InputFacts {
            prevout: Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: p2wpkh(0x33),
            }),
            wallet: Some(WalletRef {
                id: "w1".into(),
                name: "Cold storage".into(),
            }),
            spent: Some(false),
            unknown: false,
        }];
        let preview = build_preview(
            &decoded,
            Network::Signet,
            &facts,
            &[],
            Some(100),
            1_700_000_000,
        );
        assert_eq!(preview.fee_sats, Some(1_000));
        assert!(preview.fee_rate_sat_vb.unwrap() > 0.0);
        assert!(preview.ready);
        assert!(preview.rbf);
        assert!(preview.hex.is_some());
        assert!(
            preview.inputs[0]
                .address
                .as_deref()
                .unwrap()
                .starts_with("tb1q")
        );
        assert!(preview.outputs[0].address.is_some());
        let kinds: Vec<&TxWarningKind> = preview.warnings.iter().map(|w| &w.kind).collect();
        assert_eq!(kinds, vec![&TxWarningKind::SpendsWatched]);
    }

    #[test]
    fn preview_flags_what_will_go_wrong() {
        let decoded = decode_transaction(&encode::serialize_hex(&unsigned_tx())).unwrap();
        let facts = vec![InputFacts {
            prevout: Some(TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: p2wpkh(0x33),
            }),
            wallet: None,
            spent: Some(true),
            unknown: false,
        }];
        let preview = build_preview(&decoded, Network::Mainnet, &facts, &[], Some(100), 0);
        assert!(!preview.ready);
        assert!(preview.hex.is_none());
        let kinds: Vec<TxWarningKind> = preview.warnings.into_iter().map(|w| w.kind).collect();
        assert!(kinds.contains(&TxWarningKind::Unsigned));
        assert!(kinds.contains(&TxWarningKind::InputSpent));
        // 901 000 sats of fee on a million: both fee warnings fire.
        assert!(kinds.contains(&TxWarningKind::HighFeeRate));
        assert!(kinds.contains(&TxWarningKind::HighFeeShare));

        let unknown = build_preview(
            &decoded,
            Network::Mainnet,
            &[InputFacts {
                unknown: true,
                ..Default::default()
            }],
            &[],
            None,
            0,
        );
        let kinds: Vec<TxWarningKind> = unknown.warnings.into_iter().map(|w| w.kind).collect();
        assert!(kinds.contains(&TxWarningKind::InputUnknown));
        assert!(kinds.contains(&TxWarningKind::FeeUnknown));
    }

    #[test]
    fn locktimes_are_read_against_the_tip_and_the_clock() {
        let mut tx = signed_tx();
        tx.lock_time = absolute::LockTime::from_height(1_000).unwrap();
        let decoded = decode_transaction(&encode::serialize_hex(&tx)).unwrap();
        let locked = build_preview(&decoded, Network::Signet, &[], &[], Some(900), 0);
        assert!(
            locked
                .warnings
                .iter()
                .any(|w| w.kind == TxWarningKind::Locked)
        );
        let free = build_preview(&decoded, Network::Signet, &[], &[], Some(1_000), 0);
        assert!(
            !free
                .warnings
                .iter()
                .any(|w| w.kind == TxWarningKind::Locked)
        );

        tx.lock_time = absolute::LockTime::from_time(1_800_000_000).unwrap();
        let decoded = decode_transaction(&encode::serialize_hex(&tx)).unwrap();
        let later = build_preview(&decoded, Network::Signet, &[], &[], None, 1_700_000_000);
        assert!(
            later
                .warnings
                .iter()
                .any(|w| w.kind == TxWarningKind::Locked)
        );
    }

    // --- a PSBT that lies about the coin it spends ---------------------
    //
    // A finalized PSBT is what every signer hands a broadcaster, and a
    // finalized input never meets the interpreter: whatever it declares
    // about the coin is taken on its word. Regtest, a throwaway key, no
    // network; the coin is worth REAL, the PSBT says CLAIMED.

    use bdk_wallet::bitcoin::secp256k1::{Message, SecretKey};
    use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bdk_wallet::bitcoin::{CompressedPublicKey, PublicKey, ecdsa};

    /// What the coin is really worth, on chain and in the watched wallet.
    const REAL: u64 = 100_000;
    /// What the hostile PSBT claims it is worth.
    const CLAIMED: u64 = 10_200;
    /// What the transaction pays out: a real fee of 90 000 sats, a
    /// claimed one of 200.
    const PAID: u64 = 10_000;

    fn throwaway_key() -> (SecretKey, CompressedPublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = CompressedPublicKey(bdk_wallet::bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &sk,
        ));
        (sk, pk)
    }

    /// The transaction that created the coin, with its true value.
    fn funding(spk: &ScriptBuf) -> Transaction {
        Transaction {
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
        }
    }

    fn spend(prev: OutPoint) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(PAID),
                script_pubkey: p2wpkh(0x11),
            }],
        }
    }

    /// What the manager fills in when a watched wallet holds the coin.
    fn wallet_facts(spk: &ScriptBuf) -> Vec<InputFacts> {
        vec![InputFacts {
            prevout: Some(TxOut {
                value: Amount::from_sat(REAL),
                script_pubkey: spk.clone(),
            }),
            wallet: Some(WalletRef {
                id: "w1".into(),
                name: "Cold storage".into(),
            }),
            spent: Some(false),
            unknown: false,
        }]
    }

    fn kinds(preview: &TxPreview) -> Vec<TxWarningKind> {
        preview.warnings.iter().map(|w| w.kind).collect()
    }

    /// A P2WPKH spend signed over the REAL amount: the network accepts
    /// it, with a 90 000 sat fee.
    fn signed_p2wpkh() -> (
        Transaction,
        ScriptBuf,
        ecdsa::Signature,
        CompressedPublicKey,
    ) {
        let secp = Secp256k1::new();
        let (sk, pk) = throwaway_key();
        let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        let fund = funding(&spk);
        let mut tx = spend(OutPoint::new(fund.compute_txid(), 0));
        let sighash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(0, &spk, Amount::from_sat(REAL), EcdsaSighashType::All)
            .unwrap();
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk),
            sighash_type: EcdsaSighashType::All,
        };
        tx.input[0].witness = Witness::p2wpkh(&sig, &pk.0);
        (tx, spk, sig, pk)
    }

    fn lying_finalized_psbt() -> (Psbt, Transaction, ScriptBuf) {
        let (tx, spk, _, _) = signed_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[0].final_script_witness = Some(tx.input[0].witness.clone());
        (psbt, tx, spk)
    }

    /// The wallet's knowledge wins over the PSBT's word: the real value
    /// is shown, the real fee computed, both fee alerts fire, and the
    /// disagreement itself is the loudest caution of all.
    #[test]
    fn a_finalized_psbt_cannot_talk_the_preview_out_of_what_the_wallet_knows() {
        let (psbt, tx, spk) = lying_finalized_psbt();
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready, "a finalized input is accepted as signed");
        assert_eq!(decoded.tx, tx, "the extracted tx is the network-valid one");

        let preview = build_preview(
            &decoded,
            Network::Regtest,
            &wallet_facts(&spk),
            &[],
            Some(100),
            0,
        );
        assert_eq!(preview.inputs[0].value_sats, Some(REAL));
        assert_eq!(
            preview.inputs[0].wallet.as_ref().unwrap().name,
            "Cold storage"
        );
        assert_eq!(
            preview.fee_sats,
            Some(REAL - PAID),
            "the real fee: 90 000 sats"
        );
        let k = kinds(&preview);
        assert!(k.contains(&TxWarningKind::InputMismatch), "{k:?}");
        assert!(k.contains(&TxWarningKind::HighFeeRate), "{k:?}");
        assert!(k.contains(&TxWarningKind::HighFeeShare), "{k:?}");
        assert!(k.contains(&TxWarningKind::SpendsWatched), "{k:?}");
        let mismatch = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputMismatch)
            .unwrap();
        assert_eq!(mismatch.severity, TxSeverity::Alert);
        assert!(
            mismatch.message.contains("10200 sats"),
            "{}",
            mismatch.message
        );
        assert!(
            mismatch.message.contains("100000 sats"),
            "{}",
            mismatch.message
        );
        assert!(
            mismatch.message.contains("Cold storage"),
            "{}",
            mismatch.message
        );

        // The same bytes as a raw transaction read exactly the same.
        let raw = decode_bytes_as_transaction(&encode::serialize(&tx)).unwrap();
        let from_raw = build_preview(
            &raw,
            Network::Regtest,
            &wallet_facts(&spk),
            &[],
            Some(100),
            0,
        );
        assert_eq!(from_raw.fee_sats, preview.fee_sats);
        assert_eq!(from_raw.inputs[0].value_sats, preview.inputs[0].value_sats);
        assert!(!kinds(&from_raw).contains(&TxWarningKind::InputMismatch));
    }

    /// The signature really commits to the REAL amount: what the PSBT
    /// carries is not garbage a node would refuse, it is a transaction
    /// the network accepts with a 90 000 sat fee.
    #[test]
    fn the_lying_psbt_carries_a_signature_valid_over_the_real_amount() {
        let secp = Secp256k1::verification_only();
        let (tx, spk, sig, pk) = signed_p2wpkh();
        let over = |amount: u64| {
            let h = SighashCache::new(&tx)
                .p2wpkh_signature_hash(0, &spk, Amount::from_sat(amount), EcdsaSighashType::All)
                .unwrap();
            secp.verify_ecdsa(
                &Message::from_digest(h.to_byte_array()),
                &sig.signature,
                &pk.0,
            )
            .is_ok()
        };
        assert!(over(REAL));
        assert!(!over(CLAIMED));
    }

    /// The word of a backend counts the same as a wallet's: a coin the
    /// vault does not hold, that the chain describes otherwise than the
    /// PSBT does, is flagged too, and a script that differs is as much
    /// of a mismatch as a value.
    #[test]
    fn the_backend_word_counts_as_much_as_the_wallets() {
        let (psbt, _, _) = lying_finalized_psbt();
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        let from_chain = vec![InputFacts {
            prevout: Some(TxOut {
                value: Amount::from_sat(CLAIMED),
                script_pubkey: p2wpkh(0x44),
            }),
            wallet: None,
            spent: Some(false),
            unknown: false,
        }];
        let preview = build_preview(&decoded, Network::Regtest, &from_chain, &[], Some(100), 0);
        let mismatch = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputMismatch)
            .expect("a script that differs is a mismatch");
        assert!(
            mismatch.message.contains("the backend"),
            "{}",
            mismatch.message
        );
        assert_eq!(
            preview.inputs[0].address,
            Address::from_script(&p2wpkh(0x44), Network::Regtest.to_bitcoin())
                .ok()
                .map(|a| a.to_string())
        );
    }

    /// The honest path did not move: a PSBT whose word matches what
    /// the wallet knows previews exactly as it always did, and a coin
    /// nobody but the PSBT knows still reads its value from it.
    #[test]
    fn an_honest_psbt_previews_as_before() {
        let (tx, spk, _, _) = signed_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[0].final_script_witness = Some(tx.input[0].witness.clone());
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();

        let known = build_preview(
            &decoded,
            Network::Regtest,
            &wallet_facts(&spk),
            &[],
            Some(100),
            0,
        );
        assert_eq!(known.fee_sats, Some(REAL - PAID));
        assert_eq!(
            kinds(&known),
            vec![
                TxWarningKind::HighFeeRate,
                TxWarningKind::HighFeeShare,
                TxWarningKind::SpendsWatched
            ]
        );

        let alone = build_preview(
            &decoded,
            Network::Regtest,
            &[InputFacts::default()],
            &[],
            Some(100),
            0,
        );
        assert_eq!(alone.inputs[0].value_sats, Some(REAL));
        assert_eq!(alone.fee_sats, Some(REAL - PAID));
        assert!(!kinds(&alone).contains(&TxWarningKind::InputMismatch));
    }

    /// Only a PSBT still carrying partial signatures meets the
    /// interpreter, where a lie about the amount breaks the signature.
    /// No signer hands a broadcaster a PSBT in that state, which is why
    /// the preview cannot rely on it.
    #[test]
    fn an_unfinalized_segwit_psbt_that_lies_does_not_finalize() {
        let (tx, spk, sig, pk) = signed_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[0].partial_sigs.insert(PublicKey::from(pk), sig);
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(!decoded.ready, "the sighash covers the amount");
        assert!(!decoded.inputs[0].signed);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(REAL);
        assert!(
            decode_bytes_as_transaction(&psbt.serialize())
                .unwrap()
                .ready
        );
    }
}
