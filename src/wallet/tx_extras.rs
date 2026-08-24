//! Deep transaction facts shared by every detail view: sizes, feature
//! flags, coinbase attribution, OP_RETURN payloads, raw serialization.
//! Pure functions over a full [`Transaction`], no I/O.

use bdk_wallet::bitcoin::blockdata::script::Instruction;
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::hex::DisplayHex;
use bdk_wallet::bitcoin::{OutPoint, Script, Transaction, TxOut};
use serde::{Deserialize, Serialize};

/// Facts derived from the raw transaction, beyond what the summary
/// carries. Stored for watched addresses, computed on demand for
/// descriptor wallets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxExtras {
    /// Raw serialized size in bytes.
    pub size_bytes: u64,
    /// Virtual size in vbytes (weight / 4, rounded up).
    pub vsize: u64,
    /// Weight in weight units.
    pub weight_wu: u64,
    pub version: i32,
    pub locktime: u32,
    /// At least one input signals opt-in replace-by-fee.
    pub rbf_signaled: bool,
    /// At least one input carries witness data.
    pub segwit: bool,
    /// At least one input spends a P2TR output (known prevouts only).
    pub taproot: bool,
    pub is_coinbase: bool,
    /// Mining pool recognized from the coinbase signature script.
    pub coinbase_pool: Option<String>,
    /// Block height committed in the coinbase input (BIP-34).
    pub coinbase_height: Option<u32>,
    /// Printable text left in the coinbase signature script.
    pub coinbase_tag: Option<String>,
    /// Sigop cost as consensus counts it. Inputs whose previous output
    /// is unknown cannot contribute their P2SH sigops.
    pub sigops: u64,
    /// Full transaction, consensus-serialized, hex.
    pub raw_hex: String,
}

/// A decoded OP_RETURN payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpReturnData {
    /// Payload bytes in hex (pushes concatenated).
    pub hex: String,
    /// The payload as text, when it is printable UTF-8.
    pub text: Option<String>,
    /// Name of a recognized protocol payload, when the prefix says so.
    pub label: Option<String>,
}

/// Recognized OP_RETURN payload prefixes, matched on the hex payload.
const OP_RETURN_TAGS: &[(&str, &str)] = &[
    ("aa21a9ed", "Witness commitment"),
    ("52534b424c4f434b3a", "RSK merge mining"),
    ("6f6d6e69", "Omni Layer"),
    ("444f4350524f4f46", "Proof of existence"),
];

/// Recognizable coinbase tags of the major pools, matched
/// case-insensitively against the coinbase signature script.
const POOL_TAGS: &[(&str, &str)] = &[
    ("foundry", "Foundry USA"),
    ("antpool", "AntPool"),
    ("f2pool", "F2Pool"),
    ("viabtc", "ViaBTC"),
    ("spiderpool", "SpiderPool"),
    ("mara", "MARA Pool"),
    ("luxor", "Luxor"),
    ("braiins", "Braiins Pool"),
    ("slush", "Braiins Pool"),
    ("binance", "Binance Pool"),
    ("btc.com", "BTC.com"),
    ("poolin", "Poolin"),
    ("sbicrypto", "SBI Crypto"),
    ("ocean.xyz", "OCEAN"),
    ("secpool", "SECPOOL"),
    ("emcd", "EMCD"),
    ("carbonnegative", "Carbon Negative"),
    ("ultimus", "ULTIMUSPOOL"),
];

/// Derive every extra fact from a full transaction. `prevout` answers
/// with the spent output when the wallet knows it.
pub fn analyze(tx: &Transaction, mut prevout: impl FnMut(&OutPoint) -> Option<TxOut>) -> TxExtras {
    let is_coinbase = tx.is_coinbase();
    let coinbase_sig = is_coinbase
        .then(|| tx.input.first().map(|vin| vin.script_sig.as_bytes()))
        .flatten();
    let coinbase_pool = coinbase_sig.and_then(pool_of);
    let coinbase_height = coinbase_sig.and_then(bip34_height);
    let coinbase_tag = coinbase_sig.and_then(printable_run);
    let taproot = tx
        .input
        .iter()
        .any(|vin| prevout(&vin.previous_output).is_some_and(|p| p.script_pubkey.is_p2tr()));
    TxExtras {
        size_bytes: tx.total_size() as u64,
        vsize: tx.vsize() as u64,
        weight_wu: tx.weight().to_wu(),
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        rbf_signaled: !is_coinbase && tx.is_explicitly_rbf(),
        segwit: tx.input.iter().any(|vin| !vin.witness.is_empty()),
        taproot,
        is_coinbase,
        coinbase_pool,
        coinbase_height,
        coinbase_tag,
        sigops: tx.total_sigop_cost(|outpoint: &OutPoint| prevout(outpoint)) as u64,
        raw_hex: serialize_hex(tx),
    }
}

/// The OP_RETURN payload of a script, when it is one.
pub fn op_return_of(script: &Script) -> Option<OpReturnData> {
    if !script.is_op_return() {
        return None;
    }
    // Concatenate the data pushes. A payload that does not parse as
    // script (arbitrary bytes happen) falls back to everything after
    // the OP_RETURN opcode, which is what explorers show.
    let mut bytes: Vec<u8> = Vec::new();
    let mut parsed = true;
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::PushBytes(push)) => bytes.extend_from_slice(push.as_bytes()),
            Ok(Instruction::Op(_)) => {}
            Err(_) => {
                parsed = false;
                break;
            }
        }
    }
    if !parsed || bytes.is_empty() {
        bytes = script.as_bytes().get(1..).unwrap_or_default().to_vec();
    }
    let hex = bytes.to_lower_hex_string();
    let label = OP_RETURN_TAGS
        .iter()
        .find(|(prefix, _)| hex.starts_with(prefix))
        .map(|(_, name)| (*name).to_owned());
    let text = String::from_utf8(bytes.clone()).ok().filter(|s| {
        s.chars().count() >= 2
            && s.chars().all(|c| !c.is_control())
            && s.chars().any(|c| c.is_alphanumeric())
    });
    Some(OpReturnData { hex, text, label })
}

/// Block height committed at the start of a coinbase script (BIP-34).
fn bip34_height(script_sig: &[u8]) -> Option<u32> {
    let len = *script_sig.first()? as usize;
    if len == 0 || len > 4 || script_sig.len() < 1 + len {
        return None;
    }
    let mut height = 0u32;
    for (index, byte) in script_sig[1..=len].iter().enumerate() {
        height |= u32::from(*byte) << (8 * index);
    }
    Some(height)
}

/// Longest printable run left in a coinbase script: the miner's tag.
fn printable_run(script_sig: &[u8]) -> Option<String> {
    let mut best = String::new();
    let mut current = String::new();
    for &byte in script_sig {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte as char);
        } else {
            if current.chars().count() > best.chars().count() {
                best = current.clone();
            }
            current.clear();
        }
    }
    if current.chars().count() > best.chars().count() {
        best = current;
    }
    let trimmed = best.trim();
    (trimmed.chars().count() >= 4 && trimmed.chars().any(|c| c.is_alphanumeric()))
        .then(|| trimmed.to_owned())
}

/// Pool name recognized in a coinbase signature script, if any.
fn pool_of(script_sig: &[u8]) -> Option<String> {
    let ascii: String = script_sig
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                ' '
            }
        })
        .collect::<String>()
        .to_lowercase();
    POOL_TAGS
        .iter()
        .find(|(needle, _)| ascii.contains(needle))
        .map(|(_, name)| (*name).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::blockdata::opcodes::all::OP_RETURN;
    use bdk_wallet::bitcoin::blockdata::script::Builder;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness, absolute, transaction};

    fn tx_with(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    fn plain_input(sequence: u32) -> TxIn {
        TxIn {
            // vout 0, not the null outpoint: these are not coinbases.
            previous_output: OutPoint::new(
                bdk_wallet::bitcoin::Txid::from_byte_array([1u8; 32]),
                0,
            ),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }
    }

    #[test]
    fn op_return_text_decodes() {
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"hello gerfaut")
            .into_script();
        let data = op_return_of(&script).expect("op_return");
        assert_eq!(data.text.as_deref(), Some("hello gerfaut"));
        assert_eq!(data.hex, b"hello gerfaut".to_lower_hex_string());
    }

    #[test]
    fn op_return_binary_has_no_text() {
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice([0u8, 159, 146, 150])
            .into_script();
        let data = op_return_of(&script).expect("op_return");
        assert_eq!(data.text, None);
        assert_eq!(data.hex, "009f9296");
    }

    #[test]
    fn regular_script_is_not_op_return() {
        assert!(op_return_of(&ScriptBuf::new()).is_none());
    }

    #[test]
    fn rbf_and_final_sequences() {
        let rbf = tx_with(vec![plain_input(0xFFFF_FFFD)], vec![]);
        assert!(analyze(&rbf, |_| None).rbf_signaled);
        let final_tx = tx_with(vec![plain_input(0xFFFF_FFFF)], vec![]);
        assert!(!analyze(&final_tx, |_| None).rbf_signaled);
    }

    #[test]
    fn segwit_flag_follows_witness() {
        let mut with_witness = plain_input(0xFFFF_FFFF);
        with_witness.witness = Witness::from_slice(&[vec![1u8; 64]]);
        let tx = tx_with(vec![with_witness], vec![]);
        let extras = analyze(&tx, |_| None);
        assert!(extras.segwit);
        assert!(extras.weight_wu > 0);
        assert_eq!(extras.vsize, extras.weight_wu.div_ceil(4));
        assert!(extras.size_bytes >= extras.vsize);
        assert_eq!(extras.version, 2);
        assert!(!extras.raw_hex.is_empty());
    }

    #[test]
    fn taproot_flag_needs_a_known_p2tr_prevout() {
        let tx = tx_with(vec![plain_input(0xFFFF_FFFF)], vec![]);
        let p2tr = TxOut {
            value: Amount::from_sat(1000),
            // 0x51 0x20 <32 bytes>: a taproot output script.
            script_pubkey: ScriptBuf::from_bytes([vec![0x51, 0x20], vec![7u8; 32]].concat()),
        };
        assert!(analyze(&tx, |_| Some(p2tr.clone())).taproot);
        assert!(!analyze(&tx, |_| None).taproot);
    }

    #[test]
    fn coinbase_height_and_tag_are_decoded() {
        // Push of 3 bytes: 0x02446d little endian, then a miner tag.
        let mut script_sig = vec![0x03, 0x6d, 0x44, 0x02];
        script_sig.push(0);
        script_sig.extend_from_slice(b"/Foundry USA Pool #dropgold/");
        script_sig.push(255);
        let mut coinbase = plain_input(0);
        coinbase.previous_output = OutPoint::null();
        coinbase.script_sig = ScriptBuf::from_bytes(script_sig);
        let extras = analyze(&tx_with(vec![coinbase], vec![]), |_| None);
        assert_eq!(extras.coinbase_height, Some(148_589));
        assert_eq!(
            extras.coinbase_tag.as_deref(),
            Some("/Foundry USA Pool #dropgold/")
        );
        assert_eq!(extras.coinbase_pool.as_deref(), Some("Foundry USA"));
    }

    #[test]
    fn non_coinbase_has_no_coinbase_fields() {
        let extras = analyze(&tx_with(vec![plain_input(0xFFFF_FFFF)], vec![]), |_| None);
        assert_eq!(extras.coinbase_height, None);
        assert_eq!(extras.coinbase_tag, None);
        assert_eq!(extras.coinbase_pool, None);
    }

    #[test]
    fn witness_commitment_is_labeled() {
        let mut payload = vec![0xaa, 0x21, 0xa9, 0xed];
        payload.extend_from_slice(&[9u8; 32]);
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice::<&bdk_wallet::bitcoin::script::PushBytes>(
                payload.as_slice().try_into().expect("push"),
            )
            .into_script();
        let data = op_return_of(&script).expect("op_return");
        assert_eq!(data.label.as_deref(), Some("Witness commitment"));
        assert_eq!(data.text, None, "binary commitment is not text");
    }

    #[test]
    fn bare_op_return_yields_an_empty_payload() {
        let script = Builder::new().push_opcode(OP_RETURN).into_script();
        let data = op_return_of(&script).expect("op_return");
        assert_eq!(data.hex, "");
        assert_eq!(data.text, None);
        assert_eq!(data.label, None);
    }

    #[test]
    fn pool_recognition_from_coinbase_tag() {
        let mut sig = vec![0x03u8, 0x89, 0xa2, 0x0c];
        sig.extend_from_slice(b"/Foundry USA Pool #dropgold/");
        assert_eq!(pool_of(&sig), Some("Foundry USA".to_owned()));
        assert_eq!(pool_of(b"/F2Pool/mined"), Some("F2Pool".to_owned()));
        assert_eq!(pool_of(b"nothing recognizable"), None);
    }

    #[test]
    fn coinbase_never_signals_rbf() {
        // Coinbase inputs use sequence values below the RBF threshold by
        // convention; the flag must not fire on them.
        let mut coinbase = plain_input(0);
        coinbase.previous_output = OutPoint::null();
        let tx = tx_with(vec![coinbase], vec![]);
        let extras = analyze(&tx, |_| None);
        assert!(extras.is_coinbase);
        assert!(!extras.rbf_signaled);
    }
}
