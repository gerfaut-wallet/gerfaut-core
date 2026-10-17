//! The status an Electrum server gives a script: the hash of its
//! history, in the order the server lists it.

use bdk_wallet::bitcoin::Txid;

/// The Electrum status of a history: SHA-256 of `txid:height:` for each
/// transaction, in the order given, in hex.
pub(crate) fn history_status(history: &[(Txid, i32)]) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, HashEngine, sha256};
    use bdk_wallet::bitcoin::hex::DisplayHex;
    let mut engine = sha256::Hash::engine();
    for (txid, height) in history {
        engine.input(format!("{txid}:{height}:").as_bytes());
    }
    sha256::Hash::from_engine(engine)
        .to_byte_array()
        .to_lower_hex_string()
}
