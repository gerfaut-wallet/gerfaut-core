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

use std::collections::HashMap;

use bdk_wallet::bitcoin::consensus::encode;
use bdk_wallet::bitcoin::script::Instruction;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use bdk_wallet::bitcoin::{
    Address, Amount, OutPoint, Psbt, Script, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
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
    /// knows the coin. Within the PSBT, the previous transaction it
    /// carries counts before its bare witness entry: the outpoint pins
    /// the transaction's txid, and nothing pins the entry.
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
    /// backend holds at that outpoint, or other than the one its own
    /// previous transaction pays: another value, another script.
    InputMismatch,
    /// The fee could not be computed: an input's value is unknown.
    FeeUnknown,
    /// An output below the dust threshold.
    DustOutput,
    /// The transaction spends coins of a watched wallet.
    SpendsWatched,
    /// An input is signed with `SIGHASH_NONE` or `SIGHASH_SINGLE`: its
    /// signature leaves some or all of the outputs open, and whoever
    /// relays or mines the transaction can send that money elsewhere.
    UncommittedOutputs,
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
            // A signature that leaves outputs open hands them to the
            // first node that relays it: the outputs shown are a
            // suggestion, not what will be paid.
            TxWarningKind::UncommittedOutputs => TxSeverity::Alert,
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
    /// Value and script of the coin spent, when the container carried
    /// them. A PSBT input may describe the coin twice: by the previous
    /// transaction, whose txid the outpoint pins, and by a bare witness
    /// entry nothing pins. The transaction is the one read; the entry
    /// stands in only when the transaction is absent.
    pub prevout: Option<TxOut>,
    /// The witness entry, kept only when the same input also carries
    /// the previous transaction and the two disagree. Never the amount
    /// shown: what the PSBT's author declared, for the caution that
    /// names it.
    pub disputed_witness_utxo: Option<TxOut>,
    /// The signature hash type of a signature on this input that does
    /// not cover every output, `SIGHASH_NONE` or `SIGHASH_SINGLE` with
    /// or without `ANYONECANPAY`, spelled that way. `None` when every
    /// signature found covers every output.
    pub loose_sighash: Option<String>,
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
    if let Some((later, earlier)) = repeated_outpoint(&tx.input) {
        return Err(tx_error(format!(
            "input {later} spends the same coin as input {earlier}"
        )));
    }
    let inputs = tx
        .input
        .iter()
        .map(|input| DecodedInput {
            signed: !input.script_sig.is_empty() || !input.witness.is_empty(),
            prevout: None,
            disputed_witness_utxo: None,
            loose_sighash: loose_sighash_in(&input.script_sig, &input.witness),
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
    if let Some((later, earlier)) = repeated_outpoint(&psbt.unsigned_tx.input) {
        return Err(tx_error(format!(
            "invalid PSBT: input {later} spends the same coin as input {earlier}"
        )));
    }
    // Checked before the finalizer runs, which reads the spent output
    // of a previous transaction by index without looking whether it
    // exists. A previous transaction that is not the one this input
    // spends describes some other coin: whatever it says about the
    // value is false by construction, and a legacy signature never
    // covers the amount to contradict it. Refused as the malformed
    // PSBT it is, rather than read for a value nothing vouches for.
    for (index, input) in psbt.inputs.iter().enumerate() {
        let Some(prev) = &input.non_witness_utxo else {
            continue;
        };
        let outpoint = psbt.unsigned_tx.input[index].previous_output;
        if prev.compute_txid() != outpoint.txid {
            return Err(tx_error(format!(
                "invalid PSBT: input {index} carries a previous transaction that is not the \
                 one it spends"
            )));
        }
        if prev.output.len() <= outpoint.vout as usize {
            return Err(tx_error(format!(
                "invalid PSBT: input {index} spends an output its previous transaction does \
                 not have"
            )));
        }
    }
    // The finalizer folds the partial signatures into the final script
    // or witness, where they are read again below; an input it cannot
    // finish keeps them only here.
    let partial_loose: Vec<Option<String>> = psbt
        .inputs
        .iter()
        .map(|input| {
            let ecdsa = input.partial_sigs.values().map(|sig| sig.sighash_type);
            let schnorr = input
                .tap_key_sig
                .iter()
                .chain(input.tap_script_sigs.values())
                .map(|sig| sig.sighash_type);
            ecdsa
                .filter_map(loose_ecdsa)
                .chain(schnorr.filter_map(loose_schnorr))
                .next()
        })
        .collect();
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
    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    for (index, input) in psbt.inputs.iter().enumerate() {
        let outpoint = psbt.unsigned_tx.input[index].previous_output;
        let final_present =
            input.final_script_sig.is_some() || input.final_script_witness.is_some();
        // The previous transaction, checked above to be the one this
        // input spends, is the truth about the coin: its txid commits
        // to every output in it. The witness entry commits to nothing
        // and only stands in when there is no transaction to read;
        // when both are there and disagree, the entry is what the
        // PSBT's author chose to declare, and it is kept for the
        // caution that says so.
        let from_previous = input
            .non_witness_utxo
            .as_ref()
            .and_then(|prev| prev.output.get(outpoint.vout as usize).cloned());
        let disputed_witness_utxo = match (&from_previous, &input.witness_utxo) {
            (Some(known), Some(declared)) if known != declared => Some(declared.clone()),
            _ => None,
        };
        let prevout = from_previous.or_else(|| input.witness_utxo.clone());
        let no_witness = Witness::new();
        let loose_sighash = loose_sighash_in(
            input.final_script_sig.as_deref().unwrap_or(Script::new()),
            input.final_script_witness.as_ref().unwrap_or(&no_witness),
        )
        .or_else(|| partial_loose[index].clone());
        inputs.push(DecodedInput {
            signed: final_present && !unfinished.contains(&index),
            prevout,
            disputed_witness_utxo,
            loose_sighash,
        });
    }
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

/// The first signature hash type found on an input's signatures that
/// leaves outputs open, spelled the way the protocol names it.
///
/// Signatures are recognised by their shape, without the coin they
/// spend: a strict DER signature followed by its type byte, anywhere;
/// and in a witness, a 65-byte Schnorr signature, whose last byte is
/// its type. The script and the control block that end a taproot
/// script-path witness, and its annex, are set aside first, since a
/// control block can be 65 bytes long too; a 65-byte push in a legacy
/// script is an uncompressed public key, and is never read as one.
fn loose_sighash_in(script_sig: &Script, witness: &Witness) -> Option<String> {
    let mut elements: Vec<&[u8]> = witness.iter().collect();
    if elements.len() >= 2 && elements.last().is_some_and(|e| e.first() == Some(&0x50)) {
        elements.pop();
    }
    if elements.len() >= 2 && elements.last().is_some_and(|e| is_control_block(e)) {
        elements.truncate(elements.len() - 2);
    }
    let in_witness = elements.into_iter().find_map(|element| {
        match bdk_wallet::bitcoin::ecdsa::Signature::from_slice(element) {
            Ok(sig) => loose_ecdsa(sig.sighash_type),
            Err(_) if element.len() == 65 => {
                bdk_wallet::bitcoin::taproot::Signature::from_slice(element)
                    .ok()
                    .and_then(|sig| loose_schnorr(sig.sighash_type))
            }
            Err(_) => None,
        }
    });
    in_witness.or_else(|| {
        script_sig
            .instructions()
            .find_map(|instruction| match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    bdk_wallet::bitcoin::ecdsa::Signature::from_slice(bytes.as_bytes())
                        .ok()
                        .and_then(|sig| loose_ecdsa(sig.sighash_type))
                }
                _ => None,
            })
    })
}

/// A taproot control block: a leaf version byte, the internal key, and
/// up to 128 hashes of the path.
fn is_control_block(element: &[u8]) -> bool {
    element.len() >= 33
        && (element.len() - 33).is_multiple_of(32)
        && element.len() <= 33 + 32 * 128
        && element[0] & 0xfe == 0xc0
}

fn loose_ecdsa(kind: EcdsaSighashType) -> Option<String> {
    use EcdsaSighashType as T;
    matches!(
        kind,
        T::None | T::Single | T::NonePlusAnyoneCanPay | T::SinglePlusAnyoneCanPay
    )
    .then(|| kind.to_string())
}

fn loose_schnorr(kind: TapSighashType) -> Option<String> {
    use TapSighashType as T;
    matches!(
        kind,
        T::None | T::Single | T::NonePlusAnyoneCanPay | T::SinglePlusAnyoneCanPay
    )
    .then(|| kind.to_string())
}

/// The first input that spends a coin an earlier one already spends,
/// as `(later, earlier)`. No block takes such a transaction, and a
/// preview that summed its inputs as they come would count the coin
/// twice and show a fee nothing pays.
fn repeated_outpoint(inputs: &[TxIn]) -> Option<(usize, usize)> {
    let mut seen = HashMap::with_capacity(inputs.len());
    inputs.iter().enumerate().find_map(|(index, input)| {
        seen.insert(input.previous_output, index)
            .map(|earlier| (index, earlier))
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
    /// Whether nothing could be asked at all: every endpoint tried
    /// stopped answering before this coin. Different from `unknown`,
    /// which is a backend's answer; this is the absence of one, and it
    /// leaves the PSBT's own declaration unconfronted.
    pub unchecked: bool,
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

    // Checked: the values are the transaction's own word, and those of
    // coins nothing else vouches for are the PSBT author's. Past every
    // bitcoin there is, a sum means nothing.
    let in_total: Option<u64> = inputs
        .iter()
        .map(|i| i.value_sats)
        .try_fold(0u64, |acc, v| v.and_then(|v| acc.checked_add(v)));
    let out_total: Option<u64> = outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value_sats));
    let fee_sats = in_total
        .zip(out_total)
        .and_then(|(total, out)| total.checked_sub(out));
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
    let place = |prevout: &TxOut| {
        address_of(&prevout.script_pubkey)
            .unwrap_or_else(|| format!("script {:x}", prevout.script_pubkey))
    };
    for (i, input) in decoded.inputs.iter().enumerate() {
        if let Some(kind) = &input.loose_sighash {
            warnings.push(TxWarning::new(
                TxWarningKind::UncommittedOutputs,
                format!(
                    "Input {i} is signed with {kind}, which leaves some or all of the outputs \
                     open: whoever relays or mines this transaction can send that money \
                     elsewhere. Have it signed again over every output (SIGHASH_ALL)."
                ),
            ));
        }
        // The PSBT disagrees with itself on the coin: the previous
        // transaction it carries, which the outpoint pins, pays one
        // thing, and its witness entry declares another. The amount
        // and the fee already go by the transaction; this says why.
        if let (Some(known), Some(declared)) = (&input.prevout, &input.disputed_witness_utxo) {
            warnings.push(TxWarning::new(
                TxWarningKind::InputMismatch,
                format!(
                    "Input {i} is not what the PSBT says: its witness entry declares {} sats \
                     on {}, but the previous transaction it carries, the one this input \
                     spends, pays {} sats to {}. The value shown and the fee go by that \
                     transaction; whoever built this PSBT declared a different coin.",
                    declared.value.to_sat(),
                    place(declared),
                    known.value.to_sat(),
                    place(known)
                ),
            ));
        }
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
        } else if facts.unchecked {
            // Saying it "was not found" would be a claim nobody made.
            // Nothing answered, so the value shown for this coin is the
            // transaction's own word, and the fee rests on it.
            warnings.push(TxWarning::new(
                TxWarningKind::InputUnknown,
                format!(
                    "Input {i} could not be checked: no backend answered about this coin. \
                     Its value here, and the fee, are what this transaction claims, not \
                     something confirmed."
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
    // Every input's value known and the sum fine, and still no fee:
    // the outputs pay more than the inputs bring.
    let overspends = inputs.iter().all(|i| i.value_sats.is_some()) && fee_sats.is_none();
    match (fee_sats, fee_rate_sat_vb, in_total) {
        (None, _, _) if overspends => warnings.push(TxWarning::new(
            TxWarningKind::FeeUnknown,
            "The outputs pay more than the inputs bring: the network will refuse this \
             transaction."
                .to_owned(),
        )),
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
    // A lock binds only when an input's sequence leaves it on, and a
    // height lock lets the transaction into the block after the one it
    // names: into the mempool at a tip of `locktime`, not before.
    let locked = tx.is_lock_time_enabled()
        && if tx.lock_time.is_block_height() {
            tip_height.is_some_and(|tip| locktime > tip)
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
            (UncommittedOutputs, TxSeverity::Alert),
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
        assert_eq!(red, 6, "red widened without a decision");
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

    /// A well-formed DER signature with r = s = 1, then its type byte.
    /// Only its shape matters here: nothing checks it against a key.
    fn der_signature(sighash: u8) -> Vec<u8> {
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, sighash]
    }

    fn spending(script_sig: ScriptBuf, witness: Vec<Vec<u8>>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&witness),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: p2wpkh(9),
            }],
        }
    }

    fn loose_of(tx: &Transaction) -> Option<String> {
        let decoded = decode_bytes_as_transaction(&encode::serialize(tx)).unwrap();
        decoded.inputs[0].loose_sighash.clone()
    }

    /// A signature over only some outputs, or none, leaves the rest to
    /// whoever relays the transaction. The preview says so, in red,
    /// whatever the kind of input carries it.
    #[test]
    fn a_signature_that_leaves_outputs_open_is_called_out() {
        let key = vec![0x02; 33];
        // P2WPKH, SIGHASH_NONE.
        let none = spending(ScriptBuf::new(), vec![der_signature(0x02), key.clone()]);
        assert_eq!(loose_of(&none).as_deref(), Some("SIGHASH_NONE"));
        let decoded = decode_bytes_as_transaction(&encode::serialize(&none)).unwrap();
        let preview = build_preview(&decoded, Network::Mainnet, &[], &[], Some(100), 0);
        let warning = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::UncommittedOutputs)
            .expect("the caution");
        assert_eq!(warning.severity, TxSeverity::Alert);
        assert!(warning.message.contains("SIGHASH_NONE"));

        // Legacy, SIGHASH_SINGLE|ANYONECANPAY, in the script.
        let legacy = ScriptBuf::builder()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(&der_signature(0x83)[..])
                    .unwrap(),
            )
            .push_slice([0x02; 33])
            .into_script();
        assert_eq!(
            loose_of(&spending(legacy, Vec::new())).as_deref(),
            Some("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY")
        );

        // Taproot key path: a 65-byte signature ends with its type.
        let mut schnorr = vec![0x11; 64];
        schnorr.push(0x03);
        assert_eq!(
            loose_of(&spending(ScriptBuf::new(), vec![schnorr])).as_deref(),
            Some("SIGHASH_SINGLE")
        );
    }

    /// Output values no transaction can carry neither panic the preview
    /// nor wrap around into a fee; and outputs worth more than known
    /// inputs are called what they are.
    #[test]
    fn preview_sums_never_overflow() {
        let mut tx = signed_tx();
        tx.output = vec![
            TxOut {
                value: Amount::from_sat(u64::MAX / 2 + 1),
                script_pubkey: p2wpkh(9),
            },
            TxOut {
                value: Amount::from_sat(u64::MAX / 2 + 1),
                script_pubkey: p2wpkh(9),
            },
        ];
        let decoded = decode_transaction(&encode::serialize_hex(&tx)).unwrap();
        let facts: Vec<InputFacts> = tx
            .input
            .iter()
            .map(|_| InputFacts {
                prevout: Some(TxOut {
                    value: Amount::from_sat(u64::MAX),
                    script_pubkey: p2wpkh(1),
                }),
                ..Default::default()
            })
            .collect();
        let preview = build_preview(&decoded, Network::Signet, &facts, &[], Some(100), 0);
        assert_eq!(preview.fee_sats, None);

        let mut small = signed_tx();
        small.output[0].value = Amount::from_sat(10_000_000);
        let decoded = decode_transaction(&encode::serialize_hex(&small)).unwrap();
        let facts: Vec<InputFacts> = small
            .input
            .iter()
            .map(|_| InputFacts {
                prevout: Some(TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: p2wpkh(1),
                }),
                ..Default::default()
            })
            .collect();
        let preview = build_preview(&decoded, Network::Signet, &facts, &[], Some(100), 0);
        let fee = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::FeeUnknown)
            .unwrap();
        assert!(
            fee.message.contains("pay more than the inputs bring"),
            "{}",
            fee.message
        );
    }

    /// Signatures over every output, and what only looks like a typed
    /// signature, raise nothing.
    #[test]
    fn signatures_over_every_output_raise_nothing() {
        let key = vec![0x02; 33];
        for sighash in [0x01, 0x81] {
            let tx = spending(ScriptBuf::new(), vec![der_signature(sighash), key.clone()]);
            assert_eq!(loose_of(&tx), None);
            let decoded = decode_bytes_as_transaction(&encode::serialize(&tx)).unwrap();
            let preview = build_preview(&decoded, Network::Mainnet, &[], &[], Some(100), 0);
            assert!(
                preview
                    .warnings
                    .iter()
                    .all(|w| w.kind != TxWarningKind::UncommittedOutputs)
            );
        }
        // Taproot key path, SIGHASH_DEFAULT: 64 bytes.
        assert_eq!(
            loose_of(&spending(ScriptBuf::new(), vec![vec![0x11; 64]])),
            None
        );
        // A script-path spend whose 65-byte control block happens to end
        // in 0x02: the control block is no signature.
        let mut control = vec![0xc0];
        control.extend([0x22; 63]);
        control.push(0x02);
        let script = vec![0x51];
        let path = spending(ScriptBuf::new(), vec![vec![0x11; 64], script, control]);
        assert_eq!(loose_of(&path), None);
        // A legacy spend with an uncompressed key that ends in 0x02.
        let mut uncompressed = [0x04; 65];
        uncompressed[64] = 0x02;
        let legacy = ScriptBuf::builder()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(&der_signature(0x01)[..])
                    .unwrap(),
            )
            .push_slice(uncompressed)
            .into_script();
        assert_eq!(loose_of(&spending(legacy, Vec::new())), None);
    }

    /// A PSBT not finished yet carries its signatures apart, each with
    /// its type: those are read too.
    #[test]
    fn a_partial_signature_that_leaves_outputs_open_is_called_out() {
        use bdk_wallet::bitcoin::{PublicKey, ecdsa, secp256k1};
        let mut unsigned = spending(ScriptBuf::new(), Vec::new());
        unsigned.input[0].witness = Witness::new();
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        // The public key of the BIP-32 test vector 1 master.
        let key: PublicKey = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
            .parse()
            .unwrap();
        psbt.inputs[0].partial_sigs.insert(
            key,
            ecdsa::Signature {
                signature: secp256k1::ecdsa::Signature::from_der(&der_signature(0x02)[..8])
                    .unwrap(),
                sighash_type: EcdsaSighashType::None,
            },
        );
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(!decoded.ready);
        assert_eq!(
            decoded.inputs[0].loose_sighash.as_deref(),
            Some("SIGHASH_NONE")
        );
    }

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

    /// A transaction that spends one coin twice is not one the network
    /// takes, and read as it comes its input total counts the coin
    /// twice: a fee shown that nothing pays. Refused in both containers,
    /// naming the two inputs.
    #[test]
    fn a_coin_spent_twice_is_refused_in_both_containers() {
        let mut tx = unsigned_tx();
        tx.input.push(tx.input[0].clone());
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let error = decode_bytes_as_transaction(&psbt.serialize())
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid transaction: invalid PSBT: input 1 spends the same coin as input 0"
        );

        let mut signed = signed_tx();
        signed.input.push(signed.input[0].clone());
        let error = decode_transaction(&encode::serialize_hex(&signed))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid transaction: input 1 spends the same coin as input 0"
        );

        // Two outputs of the same transaction are two coins.
        let mut tx = unsigned_tx();
        let mut other = tx.input[0].clone();
        other.previous_output.vout = 2;
        tx.input.push(other);
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert!(decode_bytes_as_transaction(&psbt.serialize()).is_ok());
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
            unchecked: false,
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
            unchecked: false,
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
                unchecked: false,
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
        // One block short: the mempool still refuses it.
        let almost = build_preview(&decoded, Network::Signet, &[], &[], Some(999), 0);
        assert!(
            almost
                .warnings
                .iter()
                .any(|w| w.kind == TxWarningKind::Locked)
        );
        // Every sequence final: the lock is off, whatever it says.
        let mut final_tx = tx.clone();
        for input in &mut final_tx.input {
            input.sequence = Sequence::MAX;
        }
        let decoded_final = decode_transaction(&encode::serialize_hex(&final_tx)).unwrap();
        let off = build_preview(&decoded_final, Network::Signet, &[], &[], Some(900), 0);
        assert!(!off.warnings.iter().any(|w| w.kind == TxWarningKind::Locked));

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
    // about the coin is taken on its word. Regtest, no network, and no
    // key: the witnesses below are fixed bytes, which is enough because
    // nothing on the finalized path reads them. The coin is worth REAL,
    // the PSBT says CLAIMED.

    use bdk_wallet::bitcoin::{CompressedPublicKey, PublicKey, ecdsa};

    /// What the coin is really worth, on chain and in the watched wallet.
    const REAL: u64 = 100_000;
    /// What the hostile PSBT claims it is worth.
    const CLAIMED: u64 = 10_200;
    /// What the transaction pays out: a real fee of 90 000 sats, a
    /// claimed one of 200.
    const PAID: u64 = 10_000;

    /// The secp256k1 generator point: the public key of the number one,
    /// which everybody knows and which holds nothing. It only has to
    /// parse as a key and hash into a script; nothing here signs.
    fn fixed_pubkey() -> CompressedPublicKey {
        const G: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        CompressedPublicKey::from_slice(&G).unwrap()
    }

    /// Bytes shaped like a signature and nothing more: strict DER, r
    /// and s in range, SIGHASH_ALL. Computed over nothing, it verifies
    /// over nothing, and no test below needs it to.
    fn fixed_signature() -> ecdsa::Signature {
        let mut bytes = vec![0x30, 0x44, 0x02, 0x20];
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0x02, 0x20]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.push(0x01);
        ecdsa::Signature::from_slice(&bytes).unwrap()
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
            unchecked: false,
        }]
    }

    fn kinds(preview: &TxPreview) -> Vec<TxWarningKind> {
        preview.warnings.iter().map(|w| w.kind).collect()
    }

    /// A P2WPKH spend of the coin with its witness in place: the fixed
    /// signature and key, laid out as a signer would. A finalized input
    /// is taken as signed on presence alone, so these bytes are read
    /// exactly as a genuine witness would be.
    fn finalized_p2wpkh() -> (Transaction, ScriptBuf) {
        let pk = fixed_pubkey();
        let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        let fund = funding(&spk);
        let mut tx = spend(OutPoint::new(fund.compute_txid(), 0));
        tx.input[0].witness = Witness::p2wpkh(&fixed_signature(), &pk.0);
        (tx, spk)
    }

    fn lying_finalized_psbt() -> (Psbt, Transaction, ScriptBuf) {
        let (tx, spk) = finalized_p2wpkh();
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
    /// disagreement itself is the loudest caution of all. Nothing here
    /// looks at the witness, so fixed bytes prove the same thing a
    /// signature would.
    #[test]
    fn a_finalized_psbt_cannot_talk_the_preview_out_of_what_the_wallet_knows() {
        let (psbt, tx, spk) = lying_finalized_psbt();
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready, "a finalized input is accepted as signed");
        assert_eq!(
            decoded.tx, tx,
            "the extracted tx carries the witness as given"
        );

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

    /// Only an unfinalized input meets the interpreter, and there a
    /// signature has to verify: the fixed one verifies over nothing, so
    /// the input stays unsigned even when the PSBT tells the truth
    /// about the coin. The very same bytes as a final witness are never
    /// looked at, and the input counts as signed. That asymmetry is why
    /// the preview cannot lean on the interpreter: no signer hands a
    /// broadcaster an unfinalized PSBT, and a finalized one is not
    /// checked. Whether a genuine signature breaks when the amount is
    /// lied about is the network's business, not proved here.
    #[test]
    fn only_an_unfinalized_input_meets_the_interpreter() {
        use bdk_wallet::miniscript::psbt::{Error, InputError};

        let (tx, spk) = finalized_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[0]
            .partial_sigs
            .insert(PublicKey::from(fixed_pubkey()), fixed_signature());

        // The interpreter is what refuses it, not a missing key: the
        // partial signature is filed under the key the script pays.
        let errors = psbt
            .clone()
            .finalize_mut(&Secp256k1::verification_only())
            .unwrap_err();
        assert!(
            matches!(
                errors[..],
                [Error::InputError(InputError::Interpreter(_), 0)]
            ),
            "{errors:?}"
        );
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(!decoded.ready, "the interpreter ran and refused it");
        assert!(!decoded.inputs[0].signed);

        // The same bytes, final: nobody looks.
        psbt.inputs[0].partial_sigs.clear();
        psbt.inputs[0].final_script_witness = Some(tx.input[0].witness.clone());
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready);
        assert!(decoded.inputs[0].signed);
        assert_eq!(decoded.tx, tx);
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
            unchecked: false,
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
    /// nobody but the PSBT knows still reads its value from it. The
    /// witness is final and so never read; fixed bytes are enough.
    #[test]
    fn an_honest_psbt_previews_as_before() {
        let (tx, spk) = finalized_p2wpkh();
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

    /// A legacy input is described by the whole previous transaction,
    /// and a legacy signature never covers the amount: a forged one, a
    /// copy with the value changed, is a different transaction with a
    /// different txid, and nothing on this path used to compare it with
    /// the outpoint. The comparison runs before the finalizer, so the
    /// signature never comes into it: the fixed one shows the forged
    /// copy refused for the mismatch alone, whether the input still
    /// waits to be finalized or already is. The genuine one, once
    /// final, still reads as before.
    #[test]
    fn a_previous_transaction_that_is_not_the_one_spent_is_refused() {
        let pk = fixed_pubkey();
        let spk = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        let fund = funding(&spk);
        let tx = spend(OutPoint::new(fund.compute_txid(), 0));
        let mut forged = fund.clone();
        forged.output[0].value = Amount::from_sat(CLAIMED);
        assert_ne!(forged.compute_txid(), fund.compute_txid());

        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(forged);
        psbt.inputs[0]
            .partial_sigs
            .insert(PublicKey::from(pk), fixed_signature());
        let error = decode_bytes_as_transaction(&psbt.serialize())
            .unwrap_err()
            .to_string();
        assert!(error.contains("previous transaction"), "{error}");
        assert!(!looks_like_transaction(
            &data_encoding::BASE64.encode(&psbt.serialize())
        ));

        // Already final: refused all the same, before anyone could
        // take the input on its word.
        let script_sig = ScriptBuf::builder()
            .push_slice(fixed_signature().serialize())
            .push_key(&PublicKey::from(pk))
            .into_script();
        psbt.inputs[0].partial_sigs.clear();
        psbt.inputs[0].final_script_sig = Some(script_sig);
        let again = decode_bytes_as_transaction(&psbt.serialize())
            .unwrap_err()
            .to_string();
        assert_eq!(again, error);

        // The genuine previous transaction: the input is accepted, the
        // real value read from the transaction it carries, and the
        // preview agrees with the wallet.
        psbt.inputs[0].non_witness_utxo = Some(fund);
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready);
        assert_eq!(
            decoded.inputs[0].prevout.as_ref().unwrap().value.to_sat(),
            REAL
        );
        let preview = build_preview(
            &decoded,
            Network::Regtest,
            &wallet_facts(&spk),
            &[],
            Some(100),
            0,
        );
        assert_eq!(preview.fee_sats, Some(REAL - PAID));
        assert!(!kinds(&preview).contains(&TxWarningKind::InputMismatch));
    }

    /// The script the coin pays to: what `finalized_p2wpkh` spends.
    fn coin_script() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&fixed_pubkey().wpubkey_hash())
    }

    /// A P2WPKH spend whose PSBT describes the coin twice: by the
    /// previous transaction, the genuine one, and by a witness entry
    /// of the caller's choosing. Final, so nothing reads the witness.
    fn psbt_with_both_descriptions(witness_utxo: TxOut) -> (Psbt, ScriptBuf) {
        let (tx, spk) = finalized_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(funding(&spk));
        psbt.inputs[0].witness_utxo = Some(witness_utxo);
        psbt.inputs[0].final_script_witness = Some(tx.input[0].witness.clone());
        (psbt, spk)
    }

    fn mismatches(preview: &TxPreview) -> Vec<&TxWarning> {
        preview
            .warnings
            .iter()
            .filter(|w| w.kind == TxWarningKind::InputMismatch)
            .collect()
    }

    /// Two descriptions that agree are one description: the coin reads
    /// from the transaction, and nothing is disputed.
    #[test]
    fn a_witness_entry_that_agrees_with_the_previous_transaction_is_silent() {
        let (psbt, spk) = psbt_with_both_descriptions(TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: coin_script(),
        });
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready);
        let prevout = decoded.inputs[0].prevout.as_ref().unwrap();
        assert_eq!(prevout.value.to_sat(), REAL);
        assert_eq!(prevout.script_pubkey, spk);
        assert!(decoded.inputs[0].disputed_witness_utxo.is_none());

        let preview = build_preview(
            &decoded,
            Network::Regtest,
            &[InputFacts::default()],
            &[],
            Some(100),
            0,
        );
        assert_eq!(preview.inputs[0].value_sats, Some(REAL));
        assert_eq!(preview.fee_sats, Some(REAL - PAID));
        assert!(mismatches(&preview).is_empty());
    }

    /// The witness entry says the coin is worth less than the previous
    /// transaction pays: the transaction sets the value and the fee,
    /// the entry never does, and the disagreement is named on the input
    /// with both figures. A wallet that agrees with the transaction adds
    /// nothing to it.
    #[test]
    fn a_witness_entry_that_disagrees_on_the_value_never_sets_the_amount() {
        let (psbt, spk) = psbt_with_both_descriptions(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: coin_script(),
        });
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert!(decoded.ready);
        assert_eq!(
            decoded.inputs[0].prevout.as_ref().unwrap().value.to_sat(),
            REAL
        );
        assert_eq!(
            decoded.inputs[0]
                .disputed_witness_utxo
                .as_ref()
                .unwrap()
                .value
                .to_sat(),
            CLAIMED
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
        let found = mismatches(&alone);
        let [caution] = found.as_slice() else {
            panic!("one mismatch expected, got {:?}", alone.warnings);
        };
        assert_eq!(caution.severity, TxSeverity::Alert);
        assert!(
            caution.message.starts_with("Input 0 "),
            "{}",
            caution.message
        );
        assert!(
            caution.message.contains("10200 sats"),
            "{}",
            caution.message
        );
        assert!(
            caution.message.contains("100000 sats"),
            "{}",
            caution.message
        );
        assert!(
            caution.message.contains("previous transaction"),
            "{}",
            caution.message
        );
        assert!(kinds(&alone).contains(&TxWarningKind::HighFeeRate));

        let with_wallet = build_preview(
            &decoded,
            Network::Regtest,
            &wallet_facts(&spk),
            &[],
            Some(100),
            0,
        );
        assert_eq!(with_wallet.inputs[0].value_sats, Some(REAL));
        assert_eq!(mismatches(&with_wallet).len(), 1);
    }

    /// A different script is as much of a disagreement as a different
    /// value: the address shown is the transaction's, and the caution
    /// names the one the entry declared.
    #[test]
    fn a_witness_entry_that_disagrees_on_the_script_is_reported() {
        let elsewhere = p2wpkh(0x44);
        let (psbt, spk) = psbt_with_both_descriptions(TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: elsewhere.clone(),
        });
        let decoded = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert_eq!(
            decoded.inputs[0].prevout.as_ref().unwrap().script_pubkey,
            spk
        );
        let preview = build_preview(
            &decoded,
            Network::Regtest,
            &[InputFacts::default()],
            &[],
            Some(100),
            0,
        );
        let regtest = |script: &ScriptBuf| {
            Address::from_script(script, Network::Regtest.to_bitcoin())
                .unwrap()
                .to_string()
        };
        assert_eq!(preview.inputs[0].address, Some(regtest(&spk)));
        assert_eq!(preview.fee_sats, Some(REAL - PAID));
        let found = mismatches(&preview);
        let [caution] = found.as_slice() else {
            panic!("one mismatch expected, got {:?}", preview.warnings);
        };
        assert!(
            caution.message.contains(&regtest(&elsewhere)),
            "{}",
            caution.message
        );
        assert!(
            caution.message.contains(&regtest(&spk)),
            "{}",
            caution.message
        );
    }

    /// One description alone is read as it is, whichever it is: the
    /// entry when there is no transaction, the transaction when there
    /// is no entry. Neither leaves anything disputed.
    #[test]
    fn one_description_of_the_coin_is_taken_as_it_is() {
        let (tx, spk) = finalized_p2wpkh();
        let mut psbt = Psbt::from_unsigned_tx(spend(tx.input[0].previous_output)).unwrap();
        psbt.inputs[0].final_script_witness = Some(tx.input[0].witness.clone());

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: spk.clone(),
        });
        let entry_only = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert_eq!(
            entry_only.inputs[0]
                .prevout
                .as_ref()
                .unwrap()
                .value
                .to_sat(),
            CLAIMED,
            "nothing better to read: the entry is the PSBT's word"
        );
        assert!(entry_only.inputs[0].disputed_witness_utxo.is_none());

        psbt.inputs[0].witness_utxo = None;
        psbt.inputs[0].non_witness_utxo = Some(funding(&spk));
        let transaction_only = decode_bytes_as_transaction(&psbt.serialize()).unwrap();
        assert_eq!(
            transaction_only.inputs[0]
                .prevout
                .as_ref()
                .unwrap()
                .value
                .to_sat(),
            REAL
        );
        assert!(transaction_only.inputs[0].disputed_witness_utxo.is_none());
        let preview = build_preview(
            &transaction_only,
            Network::Regtest,
            &[InputFacts::default()],
            &[],
            Some(100),
            0,
        );
        assert!(mismatches(&preview).is_empty());
    }

    /// The finalizer reads the spent output of a previous transaction
    /// by index without looking whether it exists: a PSBT whose input
    /// points past the end of the transaction it carries used to panic
    /// the decoder before any check ran. It is refused like any other
    /// malformed PSBT.
    #[test]
    fn a_previous_transaction_without_the_spent_output_is_refused() {
        let spk = ScriptBuf::new_p2pkh(&fixed_pubkey().pubkey_hash());
        let fund = funding(&spk);
        assert_eq!(fund.output.len(), 1);
        let tx = spend(OutPoint::new(fund.compute_txid(), 1));
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(fund);
        let error = decode_bytes_as_transaction(&psbt.serialize())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not have"), "{error}");
        assert!(!looks_like_transaction(
            &data_encoding::BASE64.encode(&psbt.serialize())
        ));
    }
}
