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
}

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
    let coinbase_pool = if is_coinbase {
        tx.input
            .first()
            .and_then(|vin| pool_of(vin.script_sig.as_bytes()))
    } else {
        None
    };
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
        sigops: tx.total_sigop_cost(|outpoint: &OutPoint| prevout(outpoint)) as u64,
        raw_hex: serialize_hex(tx),
    }
}

/// The OP_RETURN payload of a script, when it is one.
pub fn op_return_of(script: &Script) -> Option<OpReturnData> {
    if !script.is_op_return() {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new();
    for instruction in script.instructions().flatten() {
        if let Instruction::PushBytes(push) = instruction {
            bytes.extend_from_slice(push.as_bytes());
        }
    }
    let text = String::from_utf8(bytes.clone())
        .ok()
        .filter(|s| !s.is_empty() && s.chars().all(|c| !c.is_control()));
    Some(OpReturnData {
        hex: bytes.to_lower_hex_string(),
        text,
    })
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
    fn pool_recognition_from_coinbase_tag() {
        assert_eq!(
            pool_of(b"\x03\x89\xa2\x0c/Foundry USA Pool #dropgold/"),
            Some("Foundry USA".to_owned()),
        );
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
