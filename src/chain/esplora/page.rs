//! A transaction as an Esplora server lists it, read into about as much
//! memory as it takes on the wire.
//!
//! The crate's own reading keeps each witness item as a vector of its
//! own, two dozen bytes before its first byte: an input that lists a
//! hundred thousand empty items, three bytes each in the answer, took
//! eight times that in memory, and a page of such inputs hundreds of
//! megabytes. Here a witness goes straight into the compact form a
//! transaction keeps it in, and what a sync does not read is skipped as
//! it is parsed.

use std::fmt;

use bdk_esplora::esplora_client::api::TxStatus;
use bdk_wallet::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use serde::Deserialize;
use serde::de::{self, SeqAccess, Visitor};

#[derive(Debug, Deserialize)]
pub(crate) struct PageTx {
    pub txid: Txid,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<PageVin>,
    pub vout: Vec<PageOut>,
    #[serde(default)]
    pub weight: u64,
    #[serde(default)]
    pub fee: u64,
    pub status: TxStatus,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PageVin {
    pub txid: Txid,
    pub vout: u32,
    pub prevout: Option<PageOut>,
    pub scriptsig: ScriptBuf,
    #[serde(default, deserialize_with = "compact_witness")]
    pub witness: Witness,
    pub sequence: u32,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PageOut {
    pub value: u64,
    pub scriptpubkey: ScriptBuf,
}

impl PageTx {
    /// The transaction itself.
    pub(crate) fn to_tx(&self) -> Transaction {
        Transaction {
            version: transaction::Version::non_standard(self.version),
            lock_time: absolute::LockTime::from_consensus(self.locktime),
            input: self
                .vin
                .iter()
                .map(|vin| TxIn {
                    previous_output: OutPoint::new(vin.txid, vin.vout),
                    script_sig: vin.scriptsig.clone(),
                    sequence: Sequence(vin.sequence),
                    witness: vin.witness.clone(),
                })
                .collect(),
            output: self
                .vout
                .iter()
                .map(|vout| TxOut {
                    value: Amount::from_sat(vout.value),
                    script_pubkey: vout.scriptpubkey.clone(),
                })
                .collect(),
        }
    }

    /// The coins it spends, as the server describes them.
    pub(crate) fn prevouts(&self) -> impl Iterator<Item = (OutPoint, TxOut)> + '_ {
        self.vin.iter().filter_map(|vin| {
            vin.prevout.as_ref().map(|prevout| {
                (
                    OutPoint::new(vin.txid, vin.vout),
                    TxOut {
                        value: Amount::from_sat(prevout.value),
                        script_pubkey: prevout.scriptpubkey.clone(),
                    },
                )
            })
        })
    }
}

/// A witness listed as hex items, pushed one at a time into its compact
/// form: each item costs its bytes and a few more, never a vector.
fn compact_witness<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<Witness, D::Error> {
    struct Items;
    impl<'de> Visitor<'de> for Items {
        type Value = Witness;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a list of hex strings")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Witness, A::Error> {
            let mut witness = Witness::new();
            while let Some(item) = items.next_element::<HexItem>()? {
                witness.push(item.0);
            }
            Ok(witness)
        }
    }
    deserializer.deserialize_seq(Items)
}

/// One witness item, decoded from the hex it is listed in.
struct HexItem(Vec<u8>);

impl<'de> Deserialize<'de> for HexItem {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Hex;
        impl Visitor<'_> for Hex {
            type Value = HexItem;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a hex string")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<HexItem, E> {
                Vec::<u8>::from_hex(text)
                    .map(HexItem)
                    .map_err(|_| E::custom("a witness item that is not hex"))
            }
        }
        deserializer.deserialize_str(Hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTED: &str = r#"{
        "txid": "TXID", "version": 2, "locktime": 0, "size": 1, "weight": 437, "fee": 141,
        "vin": [{
            "txid": "0101010101010101010101010101010101010101010101010101010101010101",
            "vout": 1,
            "prevout": {"scriptpubkey": "0014aa", "scriptpubkey_type": "v0_p2wpkh", "value": 5000},
            "scriptsig": "", "scriptsig_asm": "",
            "witness": ["3044", "", "02ff"],
            "is_coinbase": false, "sequence": 4294967293
        }],
        "vout": [{"scriptpubkey": "0014bb", "value": 4859}],
        "status": {"confirmed": true, "block_height": 7, "block_hash": "0202020202020202020202020202020202020202020202020202020202020202", "block_time": 1700000000}
    }"#;

    /// Read the way the crate reads it, and into the same transaction.
    #[test]
    fn a_listed_transaction_reads_as_the_crate_reads_it() {
        use bdk_esplora::esplora_client::api::Tx;
        let theirs: Tx = serde_json::from_str(&LISTED.replace("TXID", &"00".repeat(32))).unwrap();
        let txid = theirs.to_tx().compute_txid().to_string();
        let listed = LISTED.replace("TXID", &txid);
        let theirs: Tx = serde_json::from_str(&listed).unwrap();
        let ours: PageTx = serde_json::from_str(&listed).unwrap();
        assert_eq!(ours.to_tx(), theirs.to_tx());
        assert_eq!(ours.to_tx().compute_txid(), ours.txid);
        assert_eq!(ours.vin[0].witness.len(), 3);
        assert_eq!(ours.prevouts().count(), 1);
        assert_eq!((ours.fee, ours.weight), (141, 437));
        assert_eq!(ours.status.block_height, Some(7));
    }

    /// Two hundred thousand empty witness items take about what they
    /// take in the answer, not eight times as much.
    #[test]
    fn empty_witness_items_cost_their_size() {
        let items = vec!["\"\""; 200_000].join(",");
        let listed = LISTED
            .replace("TXID", &"00".repeat(32))
            .replace(r#"["3044", "", "02ff"]"#, &format!("[{items}]"));
        let ours: PageTx = serde_json::from_str(&listed).unwrap();
        let witness = &ours.vin[0].witness;
        assert_eq!(witness.len(), 200_000);
        // One length byte and a four-byte index per item.
        assert!(witness.size() <= 200_000 * 5 + 9, "{}", witness.size());
        assert!(serde_json::from_str::<PageTx>(&listed.replace("\"\",", "\"0g\",")).is_err());
    }
}
