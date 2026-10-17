//! The proof of a confirmation, against real mainnet headers and a real
//! branch, and against the forgeries each check is there for.

use std::path::Path;

use bdk_wallet::bitcoin::consensus::encode::{deserialize_hex, serialize};
use bdk_wallet::bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

use super::*;

/// The variable that has [`the_target_table`] write the table again, from
/// the `checkpoints.json` of Electrum it names.
const WRITE: &str = "GERFAUT_WRITE_TARGETS";
/// The commit of Electrum that file was read at, written in the table.
const COMMIT: &str = "GERFAUT_TARGETS_COMMIT";

/// Real mainnet headers, each the last block of its period and named by
/// the checkpoints: the first rise of the target's difficulty (period
/// 16), the steepest rise consensus allows (34, four times), the fall
/// after mining left China in 2021 (342), and the last checkpoint.
const REAL: [(u32, &str, &str); 4] = [
    (
        34_271,
        "000000005e36047e39452a7beaaa6721048ac408a3e75bb60a8b0008713653ce",
        "01000000405b203f92ee8012fffad48424cd52827504c06ca717cb7cd7aa69bc00000000a02521744962eccce06cb7187d2451f0dee624a291da2bf9c12ce786d92fa673b2a94b4b6ad8001dc0a41815",
    ),
    (
        70_559,
        "0000000000c169d181d66d242901f70d006f3e088c1ae9cacb88b94b8266e9c3",
        "01000000620655dba3eaa74581d333beab5dfb87d43a61be00bb03cfb7090101000000003208d84e309a7e3f06f66a693ddee7ba6657bf58261916259b6db41dcc7bc6706e414e4cfd68011c476d0d06",
    ),
    (
        691_487,
        "0000000000000000000b964e653343c6ae97d73db7f526cbc3187ff7829b0c42",
        "040000205b9e6a021daea4f45475af25efa728381b81fb05e7ac10000000000000000000344647d50de5ee8584ee25d4b37bee3ed61ba7cca817d919a52a620ad8a789cd7868f360ce981317b3ff321f",
    ),
    (
        963_647,
        "00000000000000000000d29ee44c13e924c37abcaa80c537609ce70b1fea1f33",
        "00000020a9936e1d318143a031b88854ea08e9ba3bd8659ca7b101000000000000000000c971243030a38ed9ad149393c4c4947a82a9622101e9a31a15710f32aeee0184f5388a6a3d35021788eedf2e",
    ),
];

/// The seven mainnet headers under the last checkpoint, 963,640 first:
/// with it, the latest blocks a server of the tests sends as its own.
pub(super) const BELOW_LAST: [&str; 7] = [
    "00e00020866fd623c90f9018dc2710d63edf2a548ab38118d38d01000000000000000000fe861005372174309153521a1817cf76aee6b08fe18c64ca10df7b68f48dd9f8ee2c8a6a3d350217e1417261",
    "0000003872af443cf53f1bb02fb2317c788ce926285d60b16394000000000000000000007d56618d3751912963317855dd101f1aad9b54b7bd2625fffba7d41ddb4cd183482c8a6a3d3502177a87eea3",
    "0080652089bb91fdfc445076635eec0aa545a4377b31641bc31f01000000000000000000b1d6f928ff5b4271d19ace898fc7cab57020b76c5ce5198697f62117630b95962d2e8a6a3d350217c2fc9746",
    "00e000202906fc82c9ccd7fc31f77e8f5aebbb6fc3b8f4434ceb0000000000000000000056bf1829cea467e09a0ca1ff661af5b727c21a404efffdca96cf4a4cfdaf7d8eaa2e8a6a3d3502172ac8c93a",
    "00e04c2b867bc665157ea05777bfd8bebe3f10ba722a05c7698600000000000000000000c0ce5533c3c52b375b9863768f640ef33b0b6b865b28bb94d902635e49ed0b05d12e8a6a3d35021741f11075",
    "0080102957bd0dd9507166fa8128130c385eeadfbd188b3d7fed0000000000000000000089cccdf89dcf26e90b40f2e709fabd07a9431b4748334bf25b1984cb1f456263392f8a6a3d3502175100c1fb",
    "00a02422abdb5a9593e65036a30a25af955753863f6cf3cd472a020000000000000000007597579d980730d6ff23957dfdbcfc22e3ad479ecac0c85160f1c72db5a09b03db318a6a3d350217cd6dc64a",
];

/// A transaction of block 963,647, the sixth, and its branch as servers
/// send it.
pub(super) const REAL_TXID: &str =
    "5aaaa49c7fcf4dd2979ecf4dcd2fabbafc6e39f32a7dbd9fa89b05057b249921";
pub(super) const REAL_TX: &str = "02000000000101ad1b95e50eefb005f6d051bbad71fb079a39ed98fac5af33b47cb7f5e472dc140000000000ffffffff01e2ca04000000000016001437aae28423d24a5afbe1c1a4a9713368a25408ce02473044022050e43923bea910a5afceba2bdbfeaa1caebf53fd884e78fac9cf4fafd49dacc8022041ae65cdc0dda841fa583024999a28d68a8dc3d1215fc3e1b98ceb57c238d37f012103e239381ac542db94c7cc4704d428e6b9e182c670267bd2bdd8131e8e3ec2013f00000000";
/// The transaction it spends from.
pub(super) const REAL_PARENT: &str = "020000000001021c5ead87cc40976d81b3652a99dfe12c6724730c474e56d123bcfef593c377c30000000000ffffffffc3675cc667d8ee765ad9c3d75ba26f2e7b9c8036a6bf5a87bb4d0d9ea2c8bad20100000000ffffffff02e9ec04000000000016001473de7af9ada8a0372f123f98f904a0cc05f26fcf4ef902000000000016001437aae28423d24a5afbe1c1a4a9713368a25408ce0247304402203432685ba596decb19bb01cbf658fa18a5ff31fb9d0666314e5d5bc8959d277d02202ca9a9f9658f007d781925c695cf845f2bd3f6475318869a204ad451d2def75f012103e239381ac542db94c7cc4704d428e6b9e182c670267bd2bdd8131e8e3ec2013f02483045022100c98cd50e8768223ea22dfda1034eded8518e0bed10b29bb0c82f1586b8a4000f02204446ba8a2744aed8c2981c42449104690cb4755efe573c3d9199bd9b7c8131a5012103e239381ac542db94c7cc4704d428e6b9e182c670267bd2bdd8131e8e3ec2013f00000000";
pub(super) const REAL_POS: usize = 5;
pub(super) const REAL_BRANCH: [&str; 13] = [
    "dcd4838c658e6328cc35c676adb00edffb07b4e76c3c0ae782a8b8e13e4182df",
    "bbb83bb88b449c1de7591a12153b21348521697a4b0301431188997faead336d",
    "bf75a91cd4a9761fb75494cb1ce54b786bd30912f41a4557d6c36d80853126b2",
    "dbf2af1a5f16d3a76c36ffb8f8aa1fa711e37f7e182a8fe815f18aa01a39cc34",
    "a24534b2c0ca87bbfcdd21c58e092544f483f7724a9e84b9908e30feb72ca4d8",
    "e8d7d5a94930252541495be1670de3b2416497ef548200ad58ab70218d7a0a40",
    "bd9e0ff9fbc23a1c700d935b1ba570744ce9b7fd684c7f5be5f8da58c51c264b",
    "b4e2793876a20b1ca787234dc5d9c06381a7d1f6ce2d2114cb51d5b804e78152",
    "16664b2f6c885201d6fbf497badae862aff68f947db5e03f7572751c6febfbb8",
    "688e7ce241da4926f795b3d27c742e7bf833d3f478ddb8c16f1c35bd01ed498f",
    "50b9c8ccd353b2e820ddd5e4eb89acfe7713a2192a40bf21a8467bc19e6e0c48",
    "3b0759bdfa37fb832dfa1ecbb1830871a2813c4b70d4ae4d80662674cb71a2c1",
    "b4f5a93b4048a1ef481973403e458a3add170740e66622643144646ad113b4b1",
];

/// Whether a branch proves a confirmation.
pub(super) fn proves_confirmation(
    network: Network,
    height: u32,
    header: &Header,
    txid: Txid,
    branch: &GetMerkleRes,
) -> bool {
    check_confirmation(network, height, header, txid, branch) == Proof::Holds
}

pub(super) fn header(hex: &str) -> Header {
    deserialize_hex(hex).unwrap()
}

/// The last checkpoint's header.
pub(super) fn last_checkpoint() -> Header {
    header(REAL[3].2)
}

/// A branch as a server sends it: its hashes as hex, a txid's way.
pub(super) fn branch(height: u32, pos: usize, hashes: &[&str]) -> GetMerkleRes {
    serde_json::from_value(serde_json::json!({
        "block_height": height, "pos": pos, "merkle": hashes,
    }))
    .unwrap()
}

fn bits(target: Target) -> u32 {
    target.to_compact_lossy().to_consensus()
}

/// The table stands as consensus would have it: the easiest target of
/// mainnet first, each period's target within four times of the one
/// before it, each `bits` in the one spelling consensus writes, and the
/// last checkpoint the last block of the period before the last. With
/// [`WRITE`] set, the table is written again instead:
///
/// ```text
/// curl -sSfLo /tmp/checkpoints.json https://raw.githubusercontent.com/spesmilo/electrum/<commit>/electrum/chains/mainnet/checkpoints.json
/// GERFAUT_WRITE_TARGETS=/tmp/checkpoints.json GERFAUT_TARGETS_COMMIT=<commit> cargo test --lib the_target_table
/// ```
#[test]
fn the_target_table() {
    if let Ok(path) = std::env::var(WRITE) {
        let commit = std::env::var(COMMIT).expect("the commit of Electrum the file was read at");
        write_table(Path::new(&path), &commit);
        return;
    }
    let params = Params::new(Network::Mainnet.to_bitcoin());
    let table = targets::MAINNET_BITS;
    assert_eq!(table[0], bits(params.max_attainable_target));
    let target = |bits: u32| Target::from_compact(CompactTarget::from_consensus(bits));
    for (period, pair) in table.windows(2).enumerate() {
        let (before, after) = (target(pair[0]), target(pair[1]));
        assert!(
            after <= before.max_transition_threshold(&params)
                && after >= before.min_transition_threshold(),
            "period {}",
            period + 1
        );
    }
    for &entry in table {
        assert_eq!(bits(target(entry)), entry, "{entry:#010x}");
    }
    let (height, hash) = targets::LAST_CHECKPOINT;
    assert_eq!(height + 1, (table.len() as u32 - 1) * RETARGET_PERIOD);
    assert_eq!(hash, REAL[3].1);
    assert_eq!(targets::SOURCE.len(), 40);
}

/// Writes `targets.rs` from Electrum's `checkpoints.json` at `path`.
/// Entry `i` of the file names the last block of period `i` and the
/// target of period `i + 1`; period 0 had the easiest target of
/// mainnet. Each target must be one a `bits` spells exactly.
fn write_table(path: &Path, commit: &str) {
    assert!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "a full commit hash"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let entries = read_checkpoints(&text);
    assert!(entries.len() > 400, "{} checkpoints", entries.len());
    let params = Params::new(Network::Mainnet.to_bitcoin());
    let mut table = vec![bits(params.max_attainable_target)];
    for (index, (hash, digits)) in entries.iter().enumerate() {
        assert!(hash.parse::<BlockHash>().is_ok(), "entry {index}: {hash}");
        let target = decimal_target(digits).unwrap_or_else(|| panic!("entry {index}"));
        let entry = bits(target);
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(entry)),
            target,
            "entry {index}: a target no bits spell"
        );
        table.push(entry);
    }
    let (last_hash, _) = entries.last().unwrap();
    let last_height = entries.len() as u32 * RETARGET_PERIOD - 1;
    let mut out = String::new();
    out.push_str(&format!(
        "//! The target of each retarget period of mainnet, as the `bits`
//! every header of the period carries, from period 0 to period {last}:
//! generated, never edited. A release writes it again from the latest
//! checkpoints of Electrum, as `the_target_table` in `tests.rs` says.
//!
//! Read from `electrum/chains/mainnet/checkpoints.json` of Electrum,
//! <https://github.com/spesmilo/electrum>, at the commit `SOURCE`:
//! entry `i` of that file names the last block of period `i` and the
//! target of period `i + 1`. Electrum is under the MIT License:
//!
//! > The MIT License (MIT)
//! >
//! > Copyright (c) 2011-2024 The Electrum developers
//! > Copyright (c) 2011-2024 Thomas Voegtlin
//! >
//! > Permission is hereby granted, free of charge, to any person obtaining
//! > a copy of this software and associated documentation files (the
//! > \"Software\"), to deal in the Software without restriction, including
//! > without limitation the rights to use, copy, modify, merge, publish,
//! > distribute, sublicense, and/or sell copies of the Software, and to
//! > permit persons to whom the Software is furnished to do so, subject to
//! > the following conditions:
//! >
//! > The above copyright notice and this permission notice shall be
//! > included in all copies or substantial portions of the Software.
//! >
//! > THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,
//! > EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! > MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! > NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//! > LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! > OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
//! > WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

/// The commit of Electrum the table was read at.
#[cfg(test)]
pub(super) const SOURCE: &str = \"{commit}\";

/// The last block the checkpoints name: its height, and its hash.
#[cfg(test)]
pub(super) const LAST_CHECKPOINT: (u32, &str) = (
    {last_height},
    \"{last_hash}\",
);

/// The `bits` of each period, period 0 first.
#[rustfmt::skip]
pub(super) const MAINNET_BITS: &[u32] = &[
",
        last = table.len() - 1,
    ));
    for row in table.chunks(8) {
        let row: Vec<String> = row
            .iter()
            .map(|bits| {
                let hex = format!("{bits:08x}");
                format!("0x{}_{}", &hex[..4], &hex[4..])
            })
            .collect();
        out.push_str(&format!("    {},\n", row.join(", ")));
    }
    out.push_str("];\n");
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chain/proof/targets.rs");
    std::fs::write(file, out).unwrap();
}

/// The pairs of `checkpoints.json`, a list of `["<hash>", <target>]`,
/// the target a decimal number too large for any JSON reader of the
/// crate to keep exact: read as text.
fn read_checkpoints(text: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut rest = text.trim();
    assert!(rest.starts_with('[') && rest.ends_with(']'), "a list");
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after.find('"').expect("a string that ends");
        let hash = after[..end].to_owned();
        let after = after[end + 1..]
            .trim_start()
            .strip_prefix(',')
            .expect("a comma after the hash")
            .trim_start();
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        assert!(!digits.is_empty(), "a target after {hash}");
        rest = &after[digits.len()..];
        entries.push((hash, digits));
    }
    entries
}

/// A target written in decimal; `None` past 256 bits.
fn decimal_target(digits: &str) -> Option<Target> {
    let mut bytes = [0u8; 32];
    for digit in digits.bytes() {
        let mut carry = u32::from(digit.checked_sub(b'0').filter(|digit| *digit < 10)?);
        for byte in bytes.iter_mut().rev() {
            let value = u32::from(*byte) * 10 + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(Target::from_be_bytes(bytes))
}

/// The genesis block and four real headers, among them the last
/// checkpoint: each is the block the checkpoints name, mined under its
/// own target, and that target is the table's for its period.
#[test]
fn real_headers_carry_the_target_of_their_period() {
    let genesis = bdk_wallet::bitcoin::constants::genesis_block(Network::Mainnet.to_bitcoin());
    let mut all = vec![(0, genesis.block_hash(), genesis.header)];
    for (height, hash, hex) in REAL {
        all.push((height, hash.parse().unwrap(), header(hex)));
    }
    for (height, hash, header) in all {
        assert_eq!(header.block_hash(), hash, "{height}");
        assert!(header.target().is_met_by(hash), "{height}");
        let period = (height / RETARGET_PERIOD) as usize;
        assert_eq!(
            header.bits.to_consensus(),
            targets::MAINNET_BITS[period],
            "{height}"
        );
        assert!(
            has_proof_of_work(Network::Mainnet, height, &header),
            "{height}"
        );
    }
    // Two of the adjustments everyone remembers, as Bitcoin Core's own
    // tests have them.
    assert_eq!(targets::MAINNET_BITS[16], 0x1d00_d86a);
    assert_eq!(targets::MAINNET_BITS[34], 0x1c01_68fd);
}

/// A header mined in 2009 has the work of 2009: claimed today, it is
/// refused, and so is one whose hash misses its own target, or whose
/// target no mainnet block has.
#[test]
fn a_header_easier_than_its_period_has_no_work() {
    let old = header(REAL[0].2);
    assert!(has_proof_of_work(Network::Mainnet, 34_271, &old));
    assert!(!has_proof_of_work(Network::Mainnet, 963_647, &old));
    assert!(!has_proof_of_work(Network::Mainnet, 980_000, &old));
    // A recent header claimed earlier carries more work than asked.
    assert!(has_proof_of_work(
        Network::Mainnet,
        34_271,
        &last_checkpoint()
    ));
    let unmined = Header {
        nonce: last_checkpoint().nonce.wrapping_add(1),
        ..last_checkpoint()
    };
    assert!(!has_proof_of_work(Network::Mainnet, 963_647, &unmined));
    let easiest = Header {
        bits: CompactTarget::from_consensus(0x207f_ffff),
        ..last_checkpoint()
    };
    assert!(!has_proof_of_work(Network::Mainnet, 963_647, &easiest));
    // Testnet4 and signet keep the check they had.
    assert!(!has_proof_of_work(Network::Testnet4, 0, &easiest));
    assert!(has_proof_of_work(Network::Signet, 963_647, &unmined));
    assert!(has_proof_of_work(Network::Regtest, 963_647, &easiest));
}

/// Past the table, a period's target may be four times easier than the
/// one before, as consensus lets it, for two periods: the height is the
/// server's word, and a header of difficulty one claimed two dozen
/// periods on is refused all the same.
#[test]
fn past_the_table_the_target_grows_four_times_easier_twice() {
    let table = targets::MAINNET_BITS;
    let last = (table.len() - 1) as u32;
    let first_past = (last + 1) * RETARGET_PERIOD;
    let at = |height: u32| easiest_target(Network::Mainnet, height).unwrap();
    let known = Target::from_compact(CompactTarget::from_consensus(table[last as usize]));
    assert_eq!(at(first_past - 1), known);
    let params = Params::new(Network::Mainnet.to_bitcoin());
    let once = known.max_transition_threshold(&params);
    let twice = once.max_transition_threshold(&params);
    assert_eq!(at(first_past), once);
    assert_eq!(at(first_past + RETARGET_PERIOD - 1), once);
    assert_eq!(at(first_past + RETARGET_PERIOD), twice);
    assert_eq!(at(first_past + 2 * RETARGET_PERIOD), twice);
    assert_eq!(at(u32::MAX), twice);
    // A recent header passes beyond the table; neither a header of 2009
    // nor the genesis block passes there, however far the server claims.
    assert!(has_proof_of_work(
        Network::Mainnet,
        first_past + 5_000,
        &last_checkpoint()
    ));
    let genesis = bdk_wallet::bitcoin::constants::genesis_block(Network::Mainnet.to_bitcoin());
    let old = header(REAL[0].2);
    for height in [first_past, 1_012_040, 5_000_000, u32::MAX] {
        assert!(
            !has_proof_of_work(Network::Mainnet, height, &old),
            "{height}"
        );
        assert!(
            !has_proof_of_work(Network::Mainnet, height, &genesis.header),
            "{height}"
        );
    }
}

/// A real transaction of a real block: its branch leads to the block's
/// root, the way servers spell it, and nothing else does.
#[test]
fn a_real_branch_proves_its_transaction() {
    let txid: Txid = REAL_TXID.parse().unwrap();
    let tx: Transaction = deserialize_hex(REAL_TX).unwrap();
    assert_eq!(tx.compute_txid(), txid);
    let block = last_checkpoint();
    let proven = branch(963_647, REAL_POS, &REAL_BRANCH);
    assert!(proves_confirmation(
        Network::Mainnet,
        963_647,
        &block,
        txid,
        &proven
    ));
    // At another height, in another place, through another branch, or
    // for another transaction: nothing.
    assert!(!proves_confirmation(
        Network::Mainnet,
        963_646,
        &block,
        txid,
        &proven
    ));
    let elsewhere = branch(963_647, REAL_POS + 1, &REAL_BRANCH);
    assert!(!proves_confirmation(
        Network::Mainnet,
        963_647,
        &block,
        txid,
        &elsewhere
    ));
    let mut other = REAL_BRANCH;
    other[7] = REAL_BRANCH[8];
    let other = branch(963_647, REAL_POS, &other);
    assert!(!proves_confirmation(
        Network::Mainnet,
        963_647,
        &block,
        txid,
        &other
    ));
    let another: Txid = REAL_BRANCH[0].parse().unwrap();
    assert!(!proves_confirmation(
        Network::Mainnet,
        963_647,
        &block,
        another,
        &proven
    ));
    // The same branch under a header no one mined.
    let unmined = Header {
        nonce: block.nonce.wrapping_add(1),
        ..block
    };
    assert!(!proves_confirmation(
        Network::Mainnet,
        963_647,
        &unmined,
        txid,
        &proven
    ));
}

/// A sound branch that leads to another root than the header read leads
/// to the header read again: a block that moved, and that the branch
/// proves the transaction in, is a reorganisation in between, unsure; the
/// same block again, or a branch that proves nothing in the new one, is a
/// false proof.
#[test]
fn a_branch_into_another_block_is_read_again() {
    let txid: Txid = REAL_TXID.parse().unwrap();
    let proven = branch(963_647, REAL_POS, &REAL_BRANCH);
    let real = last_checkpoint();
    // The block first read: the real one, another root in it.
    let stale = Header {
        merkle_root: TxMerkleNode::from_byte_array([9; 32]),
        ..real
    };
    assert_eq!(
        check_confirmation(Network::Signet, 963_647, &stale, txid, &proven),
        Proof::Elsewhere
    );
    assert_eq!(
        recheck(Network::Signet, 963_647, &stale, &real, txid, &proven),
        Proof::Unsure
    );
    assert_eq!(
        recheck(Network::Signet, 963_647, &stale, &stale, txid, &proven),
        Proof::False
    );
    let other = Header {
        merkle_root: TxMerkleNode::from_byte_array([8; 32]),
        ..real
    };
    assert_eq!(
        recheck(Network::Signet, 963_647, &stale, &other, txid, &proven),
        Proof::False
    );
    // On mainnet, the block read again must carry the work too.
    assert_eq!(
        recheck(Network::Mainnet, 963_647, &stale, &real, txid, &proven),
        Proof::Unsure
    );
    let unmined = Header {
        nonce: real.nonce.wrapping_add(1),
        ..real
    };
    assert_eq!(
        recheck(Network::Mainnet, 963_647, &stale, &unmined, txid, &proven),
        Proof::False
    );
}

/// A confirmation above the tip the server just gave: within three
/// blocks, blocks that came in since, unsure; further, a lie.
#[test]
fn a_confirmation_above_the_tip_is_weighed() {
    assert_eq!(above_the_tip(100, 100), None);
    assert_eq!(above_the_tip(99, 100), None);
    assert_eq!(above_the_tip(101, 100), Some(Proof::Unsure));
    assert_eq!(above_the_tip(103, 100), Some(Proof::Unsure));
    assert_eq!(above_the_tip(104, 100), Some(Proof::False));
    assert_eq!(above_the_tip(u32::MAX, u32::MAX - 1), Some(Proof::Unsure));
}

/// The two halves of a transaction of 64 bytes, as they are hashed: the
/// first one read as a txid, the second as its sibling.
pub(super) fn halves_of_64_bytes(first: [u8; 32]) -> (Txid, [u8; 32], Transaction) {
    // Version, one input, the 27 first bytes of the outpoint's txid: the
    // first half. The rest, chosen: the outpoint's last five bytes, its
    // index, an empty script, the sequence, one output of four bytes of
    // script, the lock time.
    assert_eq!(first[4], 1, "one input");
    let mut outpoint = [0u8; 32];
    outpoint[..27].copy_from_slice(&first[5..]);
    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::non_standard(i32::from_le_bytes(
            first[..4].try_into().unwrap(),
        )),
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(outpoint), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bdk_wallet::bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 4]),
        }],
    };
    let bytes = serialize(&tx);
    assert_eq!(bytes.len(), 64);
    assert_eq!(bytes[..32], first);
    let mut second = [0u8; 32];
    second.copy_from_slice(&bytes[32..]);
    (Txid::from_byte_array(first), second, tx)
}

/// The node above two hashes, left then right.
pub(super) fn root_of(left: [u8; 32], right: [u8; 32]) -> TxMerkleNode {
    let mut inner = [0u8; 64];
    inner[..32].copy_from_slice(&left);
    inner[32..].copy_from_slice(&right);
    TxMerkleNode::from_byte_array(sha256d::Hash::hash(&inner).to_byte_array())
}

/// A hash as a server spells it: reversed, in hex.
pub(super) fn shown(bytes: [u8; 32]) -> String {
    let mut bytes = bytes;
    bytes.reverse();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Branches that lead to the root and prove nothing: through the copy
/// of a node, from a position past the branch, or longer than any block,
/// each a false proof; through a transaction of 64 bytes, or for another
/// height than the one asked, an unsure one.
#[test]
fn a_branch_that_proves_nothing_is_refused() {
    let mut first = [7u8; 32];
    first[4] = 1;
    let (txid, second, _) = halves_of_64_bytes(first);
    let header = |root: TxMerkleNode| Header {
        merkle_root: root,
        ..bdk_wallet::bitcoin::constants::genesis_block(Network::Signet.to_bitcoin()).header
    };
    let at = |pos: usize, hashes: &[String]| {
        let hashes: Vec<&str> = hashes.iter().map(String::as_str).collect();
        branch(1, pos, &hashes)
    };
    let proves = |root, pos, hashes: &[String]| {
        proves_confirmation(Network::Signet, 1, &header(root), txid, &at(pos, hashes))
    };
    let verdict = |root, pos, hashes: &[String]| {
        check_confirmation(Network::Signet, 1, &header(root), txid, &at(pos, hashes))
    };
    // What the client's own validator, used until now, made of it.
    let proved = |root, pos, hashes: &[String]| {
        electrum_client::utils::validate_merkle_proof(&txid, &root, &at(pos, hashes))
    };

    // An inner node that is a transaction of 64 bytes.
    let through_a_transaction = root_of(first, second);
    assert_eq!(
        verdict(through_a_transaction, 0, &[shown(second)]),
        Proof::Unsure
    );
    assert!(proved(through_a_transaction, 0, &[shown(second)]));
    // The same txid beside a hash that makes no transaction of them,
    // its script 171 bytes long: proven.
    let plain = [0xab; 32];
    assert!(proves(root_of(first, plain), 0, &[shown(plain)]));

    // A node paired on its left with a copy of itself.
    let txid_bytes = txid.to_byte_array();
    let copied = root_of(txid_bytes, txid_bytes);
    assert_eq!(verdict(copied, 1, &[shown(txid_bytes)]), Proof::False);
    assert!(proved(copied, 1, &[shown(txid_bytes)]));
    // On its right, the copy an odd row makes: proven.
    assert!(proves(copied, 0, &[shown(txid_bytes)]));

    // A position past what the branch holds.
    let alone = TxMerkleNode::from_byte_array(txid_bytes);
    assert!(proves(alone, 0, &[]));
    assert_eq!(verdict(alone, 1, &[]), Proof::False);
    assert!(proved(alone, 1, &[]));
    assert_eq!(
        verdict(root_of(first, plain), 2, &[shown(plain)]),
        Proof::False
    );

    // A branch the server says is for another height.
    let elsewhere = branch(2, 0, &[]);
    assert_eq!(
        check_confirmation(Network::Signet, 1, &header(alone), txid, &elsewhere),
        Proof::Unsure
    );

    // Longer than any block.
    let mut node = txid_bytes;
    let mut long = Vec::new();
    for _ in 0..=BRANCH_MAX {
        let sibling = [3u8; 32];
        long.push(shown(sibling));
        let mut inner = [0u8; 64];
        inner[..32].copy_from_slice(&node);
        inner[32..].copy_from_slice(&sibling);
        node = sha256d::Hash::hash(&inner).to_byte_array();
    }
    assert_eq!(
        verdict(TxMerkleNode::from_byte_array(node), 0, &long),
        Proof::False
    );
}

// --- servers that prove, and servers that lie --------------------------------

mod servers {
    use std::time::Duration;

    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
    use bdk_wallet::chain::{BlockId, CheckPoint};

    use super::*;
    use crate::chain::electrum::Target;
    use crate::chain::{Held, Plan, Reading, Synced};
    use crate::testkit::{FakeElectrum, header_at, nowhere, script, transaction};

    /// The script the wallet of these tests is paid to.
    fn ours() -> String {
        script(1)
    }

    /// A plan that reads [`ours`] for a wallet of `network` that holds
    /// nothing yet.
    fn plan(network: Network) -> Plan {
        let genesis = bdk_wallet::bitcoin::constants::genesis_block(network.to_bitcoin());
        Plan {
            network,
            tip: CheckPoint::new(BlockId {
                height: 0,
                hash: genesis.block_hash(),
            }),
            start_time: crate::now_secs(),
            scripts: vec![ScriptBuf::from_hex(&ours()).unwrap()],
            scans: Vec::new(),
            stop_gap: 20,
            reading: Reading::Complete,
            held: Held::default(),
        }
    }

    async fn electrum_sync(server: &FakeElectrum, network: Network) -> Result<Synced, String> {
        let target = Target::new(format!("tcp://{}", server.address), None);
        crate::chain::electrum::sync(&target, plan(network), None, Duration::from_secs(30)).await
    }

    /// Where each transaction of an update confirmed.
    fn anchored(synced: &Synced) -> Vec<(Txid, u32, BlockHash)> {
        synced
            .update
            .tx_update
            .anchors
            .iter()
            .map(|(anchor, txid)| (*txid, anchor.block_id.height, anchor.block_id.hash))
            .collect()
    }

    /// The error of a sync that was to fail.
    fn refusal(synced: Result<Synced, String>) -> String {
        match synced {
            Ok(synced) => panic!("confirmed {:?}", anchored(&synced)),
            Err(refused) => refused,
        }
    }

    /// A payment to [`ours`], on the server with the transaction it
    /// spends, whose raw txid satisfies `wanted`: the history lists it at
    /// `height`.
    fn pay(server: &FakeElectrum, height: i64, wanted: impl Fn(&[u8; 32]) -> bool) -> Transaction {
        let parent = transaction(&[nowhere(1, 0)], &[(&script(9), 60_000)]);
        let mut payment = transaction(
            &[OutPoint::new(parent.compute_txid(), 0)],
            &[(&ours(), 50_000)],
        );
        for lock in 0.. {
            payment.lock_time = LockTime::from_consensus(lock);
            if wanted(&payment.compute_txid().to_byte_array()) {
                break;
            }
        }
        server.add_tx(&parent);
        server.add_tx(&payment);
        server.set_history(&ours(), &[(payment.compute_txid(), height)]);
        payment
    }

    /// Serves at `height` a made-up header that commits to `root`.
    fn serve(server: &FakeElectrum, height: u32, root: TxMerkleNode) -> Header {
        let mut header: Header = deserialize_hex(&header_at(height)).unwrap();
        header.merkle_root = root;
        server.state.lock().unwrap().served.insert(height, header);
        header
    }

    /// A signet server at 100.
    async fn signet() -> FakeElectrum {
        let server = FakeElectrum::start().await;
        server.state.lock().unwrap().height = 100;
        server
    }

    /// A mainnet server whose latest blocks are the last checkpoint and
    /// the seven below it, real.
    async fn mainnet() -> FakeElectrum {
        let server = FakeElectrum::start().await;
        let mut state = server.state.lock().unwrap();
        state.genesis = Some(Network::Mainnet.to_bitcoin());
        state.height = 963_647;
        for (at, hex) in (963_640..).zip(BELOW_LAST) {
            state.served.insert(at, header(hex));
        }
        state.served.insert(963_647, last_checkpoint());
        drop(state);
        server
    }

    /// A signet server proves a payment the way a block holds it: proven,
    /// and confirmed where the header says.
    #[tokio::test]
    async fn an_electrum_payment_proven_in_its_block_confirms() {
        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        let synced = electrum_sync(&server, Network::Signet).await.unwrap();
        let header = server.state.lock().unwrap().header_of(90);
        assert_eq!(
            anchored(&synced),
            [(payment.compute_txid(), 90, header.block_hash())]
        );
    }

    /// A branch that does not lead to the root of the block, one through
    /// the copy of a node, and one from a position past it: each refuses
    /// the server, where a wrong branch used to leave the payment
    /// unconfirmed in silence and the others proved it. One through a
    /// transaction of 64 bytes, which the old check proved too, proves
    /// nothing: the payment is left unconfirmed, and the server, which may
    /// only have met such a branch by chance, is not refused.
    #[tokio::test]
    async fn an_electrum_branch_that_proves_nothing_refuses_the_server() {
        // Wrong: the root is the txid, the branch leads elsewhere.
        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        let txid = payment.compute_txid();
        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(txid, (vec!["ab".repeat(32)], 0));
        let refused = refusal(electrum_sync(&server, Network::Signet).await);
        assert!(refused.contains(FALSE_PROOF), "{refused}");

        // Through a transaction of 64 bytes whose first half is the txid.
        let server = signet().await;
        let payment = pay(&server, 90, |txid| txid[4] == 1);
        let (txid, second, _) = halves_of_64_bytes(payment.compute_txid().to_byte_array());
        serve(&server, 90, root_of(txid.to_byte_array(), second));
        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(txid, (vec![shown(second)], 0));
        let synced = electrum_sync(&server, Network::Signet).await.unwrap();
        assert_eq!(anchored(&synced), []);
        assert!(
            synced
                .update
                .tx_update
                .txs
                .iter()
                .any(|tx| tx.compute_txid() == txid)
        );

        // Through the copy of the payment on its left.
        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        let txid = payment.compute_txid();
        let raw = txid.to_byte_array();
        serve(&server, 90, root_of(raw, raw));
        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(txid, (vec![shown(raw)], 1));
        let refused = refusal(electrum_sync(&server, Network::Signet).await);
        assert!(refused.contains(FALSE_PROOF), "{refused}");

        // Alone in its block, at a position past it.
        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(payment.compute_txid(), (Vec::new(), 3));
        let refused = refusal(electrum_sync(&server, Network::Signet).await);
        assert!(refused.contains(FALSE_PROOF), "{refused}");
    }

    /// A block that replaced the one first read, between the header and
    /// the branch: the payment is left unconfirmed, as seen in the
    /// mempool, and the server is not refused, where it used to be taken
    /// for a liar. A branch the server refuses, as one does when the
    /// transaction is no longer in the block it listed, does the same.
    #[tokio::test]
    async fn an_electrum_reorganisation_leaves_a_payment_unsure() {
        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        let txid = payment.compute_txid();
        {
            let mut state = server.state.lock().unwrap();
            let mut stale = state.header_of(90);
            stale.merkle_root = TxMerkleNode::from_byte_array([7; 32]);
            state.stale_once.insert(90, stale);
        }
        let synced = electrum_sync(&server, Network::Signet).await.unwrap();
        assert_eq!(anchored(&synced), []);
        assert!(
            synced
                .update
                .tx_update
                .seen_ats
                .iter()
                .any(|(seen, _)| *seen == txid)
        );

        // The header read again refused, or the header refused at once.
        for stale in [true, false] {
            let server = signet().await;
            let payment = pay(&server, 90, |_| true);
            {
                let mut state = server.state.lock().unwrap();
                if stale {
                    let mut stale = state.header_of(90);
                    stale.merkle_root = TxMerkleNode::from_byte_array([7; 32]);
                    state.stale_once.insert(90, stale);
                }
                state.refused_headers.insert(90);
            }
            let synced = electrum_sync(&server, Network::Signet).await.unwrap();
            assert_eq!(anchored(&synced), []);
            let txid = payment.compute_txid();
            assert!(
                synced
                    .update
                    .tx_update
                    .seen_ats
                    .iter()
                    .any(|(seen, _)| *seen == txid)
            );
        }

        let server = signet().await;
        let payment = pay(&server, 90, |_| true);
        server.state.lock().unwrap().refuse.insert(
            "blockchain.transaction.get_merkle",
            "tx not in block".to_owned(),
        );
        let synced = electrum_sync(&server, Network::Signet).await.unwrap();
        assert_eq!(anchored(&synced), []);
        let txid = payment.compute_txid();
        assert!(
            synced
                .update
                .tx_update
                .seen_ats
                .iter()
                .any(|(seen, _)| *seen == txid)
        );
    }

    /// A confirmation claimed above the tip the server gave: a few blocks
    /// above, unsure, further, the server is refused, on every path.
    #[tokio::test]
    async fn a_confirmation_above_the_tip_is_refused() {
        // A descriptor wallet over Electrum, tip at 100.
        for (height, refused) in [(102, false), (110, true)] {
            let server = signet().await;
            let payment = pay(&server, height, |_| true);
            let synced = electrum_sync(&server, Network::Signet).await;
            match (synced, refused) {
                (Err(error), true) => assert!(error.contains(FALSE_PROOF), "{error}"),
                (Ok(synced), false) => {
                    assert_eq!(anchored(&synced), []);
                    let txid = payment.compute_txid();
                    assert!(
                        synced
                            .update
                            .tx_update
                            .seen_ats
                            .iter()
                            .any(|(seen, _)| *seen == txid)
                    );
                }
                (synced, _) => panic!("{height}: {:?}", synced.map(|synced| anchored(&synced))),
            }
        }
        // A watched address over Electrum.
        let server = signet().await;
        pay_address(&server, 102);
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, None);
        let server = signet().await;
        pay_address(&server, 110);
        let refused = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap_err();
        assert!(refused.contains(FALSE_PROOF), "{refused}");
        // A tip no chain has reached.
        let server = signet().await;
        server.state.lock().unwrap().height = 4_000_000_000;
        let refused = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap_err();
        assert!(refused.contains(crate::chain::IMPOSSIBLE_TIP), "{refused}");
    }

    /// On mainnet, a real transaction of the last checkpoint's block is
    /// proven by its real branch; a payment in a header that commits to
    /// it and that no one mined refuses the server, where it used to
    /// confirm.
    #[tokio::test]
    async fn an_electrum_header_without_work_refuses_the_server() {
        let server = mainnet().await;
        let real: Transaction = deserialize_hex(REAL_TX).unwrap();
        let parent: Transaction = deserialize_hex(REAL_PARENT).unwrap();
        server.add_tx(&real);
        server.add_tx(&parent);
        server.set_history(&ours(), &[(real.compute_txid(), 963_647)]);
        server.state.lock().unwrap().branches.insert(
            real.compute_txid(),
            (
                REAL_BRANCH.iter().map(|hash| hash.to_string()).collect(),
                REAL_POS,
            ),
        );
        let synced = electrum_sync(&server, Network::Mainnet).await.unwrap();
        assert_eq!(
            anchored(&synced),
            [(real.compute_txid(), 963_647, last_checkpoint().block_hash())]
        );

        for height in [900_000, 963_647] {
            let server = mainnet().await;
            let payment = pay(&server, i64::from(height), |_| true);
            let root = TxMerkleNode::from_byte_array(payment.compute_txid().to_byte_array());
            let forged = if height == 963_647 {
                // The real tip's header, made to commit to the payment.
                let forged = Header {
                    merkle_root: root,
                    ..last_checkpoint()
                };
                server.state.lock().unwrap().served.insert(height, forged);
                forged
            } else {
                let mut forged = serve(&server, height, root);
                forged.bits = CompactTarget::from_consensus(targets::MAINNET_BITS[446]);
                server.state.lock().unwrap().served.insert(height, forged);
                forged
            };
            assert!(!forged.target().is_met_by(forged.block_hash()));
            let refused = refusal(electrum_sync(&server, Network::Mainnet).await);
            assert!(
                refused.contains(FALSE_PROOF) || refused.contains("do not chain"),
                "{height}: {refused}"
            );
        }
    }

    /// The BIP-173 address on mainnet and on signet, and its script.
    const MAINNET_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const SIGNET_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const ADDRESS_SCRIPT: &str = "0014751e76e8199196d454941c45d1b3a323f1433bd6";

    async fn address_state(
        server: &FakeElectrum,
        address: &str,
        network: Network,
    ) -> Result<crate::wallet::AddressWatchState, String> {
        let target = Target::new(format!("tcp://{}", server.address), None);
        crate::chain::electrum::address::fetch_state(&target, address, network, None, &[]).await
    }

    /// A payment to the address, with the transaction it spends, listed
    /// at `height`.
    fn pay_address(server: &FakeElectrum, height: i64) -> Transaction {
        let parent = transaction(&[nowhere(2, 0)], &[(&script(9), 60_000)]);
        let payment = transaction(
            &[OutPoint::new(parent.compute_txid(), 0)],
            &[(ADDRESS_SCRIPT, 50_000)],
        );
        server.add_tx(&parent);
        server.add_tx(&payment);
        server.set_history(ADDRESS_SCRIPT, &[(payment.compute_txid(), height)]);
        payment
    }

    /// A watched address: a confirmation proven in its block is taken,
    /// one whose branch leads elsewhere refuses the server, where it used
    /// to be taken on the server's word, proof or none.
    #[tokio::test]
    async fn an_address_confirmation_is_proven_over_electrum() {
        let server = signet().await;
        let payment = pay_address(&server, 90);
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, Some(90));

        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(payment.compute_txid(), (vec!["ab".repeat(32)], 0));
        let refused = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap_err();
        assert!(refused.contains(FALSE_PROOF), "{refused}");
    }

    /// A watched address: a block that replaced the one first read, and a
    /// header the server refuses for one height, leave the payment
    /// unconfirmed, the rest of the address read, where either used to
    /// fail the sync.
    #[tokio::test]
    async fn an_address_reorganisation_leaves_a_payment_unsure() {
        let server = signet().await;
        pay_address(&server, 90);
        {
            let mut state = server.state.lock().unwrap();
            let mut stale = state.header_of(90);
            stale.merkle_root = TxMerkleNode::from_byte_array([7; 32]);
            state.stale_once.insert(90, stale);
        }
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, None);

        let server = signet().await;
        pay_address(&server, 90);
        server.state.lock().unwrap().refused_headers.insert(90);
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, None);
    }

    /// On mainnet, a real confirmation of the last checkpoint's block is
    /// taken, and one in a header no one mined refuses the server.
    #[tokio::test]
    async fn an_address_header_without_work_refuses_the_server() {
        let server = mainnet().await;
        let real: Transaction = deserialize_hex(REAL_TX).unwrap();
        let parent: Transaction = deserialize_hex(REAL_PARENT).unwrap();
        server.add_tx(&real);
        server.add_tx(&parent);
        server.set_history(ADDRESS_SCRIPT, &[(real.compute_txid(), 963_647)]);
        server.state.lock().unwrap().branches.insert(
            real.compute_txid(),
            (
                REAL_BRANCH.iter().map(|hash| hash.to_string()).collect(),
                REAL_POS,
            ),
        );
        let state = address_state(&server, MAINNET_ADDRESS, Network::Mainnet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, Some(963_647));
        assert_eq!(
            state.txs[0].timestamp,
            Some(u64::from(last_checkpoint().time))
        );

        let server = mainnet().await;
        let payment = pay_address(&server, 900_000);
        let mut forged = serve(
            &server,
            900_000,
            TxMerkleNode::from_byte_array(payment.compute_txid().to_byte_array()),
        );
        forged.bits = CompactTarget::from_consensus(targets::MAINNET_BITS[446]);
        server.state.lock().unwrap().served.insert(900_000, forged);
        let refused = address_state(&server, MAINNET_ADDRESS, Network::Mainnet)
            .await
            .unwrap_err();
        assert!(refused.contains(FALSE_PROOF), "{refused}");
    }

    /// A coin is confirmed when its transaction is, in the round: the
    /// height the server gives the coin alone does not confirm it. A coin
    /// of a transaction the history does not list is taken as unconfirmed,
    /// one listed twice counts once, and one its transaction does not pay
    /// refuses the server. Each of them used to count, confirmed, at the
    /// value the server gave.
    #[tokio::test]
    async fn an_address_coin_is_confirmed_as_its_transaction_is() {
        let server = signet().await;
        let payment = pay_address(&server, 0);
        let txid = payment.compute_txid();
        server.set_unspent(ADDRESS_SCRIPT, &[(txid, 0, 90, 50_000)]);
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.txs[0].height, None);
        assert_eq!(state.utxos[0].height, None);
        assert_eq!(crate::wallet::views::address_balance(&state).confirmed, 0);

        // Confirmed, listed twice, beside a coin of nothing the history
        // lists.
        server.set_history(ADDRESS_SCRIPT, &[(txid, 90)]);
        let nobody = nowhere(5, 0).txid;
        server.set_unspent(
            ADDRESS_SCRIPT,
            &[
                (txid, 0, 90, 50_000),
                (txid, 0, 90, 50_000),
                (nobody, 0, 80, 7_000_000),
            ],
        );
        let state = address_state(&server, SIGNET_ADDRESS, Network::Signet)
            .await
            .unwrap();
        assert_eq!(state.utxos.len(), 2);
        let balance = crate::wallet::views::address_balance(&state);
        assert_eq!(balance.confirmed, 50_000);
        assert_eq!(balance.untrusted_pending, 7_000_000);

        // More than the transaction pays, or an output it does not have.
        for (vout, value) in [(0, 60_000), (1, 50_000)] {
            server.set_unspent(ADDRESS_SCRIPT, &[(txid, vout, 90, value)]);
            let refused = address_state(&server, SIGNET_ADDRESS, Network::Signet)
                .await
                .unwrap_err();
            assert!(refused.contains("does not pay"), "{vout}: {refused}");
        }
    }

    // --- Esplora ---------------------------------------------------------

    use crate::testkit::{FakeMempool, esplora_payment};

    /// An instance of `network` whose tip is past the payments of
    /// [`esplora_payment`], at 500.
    async fn mempool(network: Network) -> FakeMempool {
        let server = FakeMempool::start(false, 0).await;
        {
            let mut state = server.state.lock().unwrap();
            state.tip = 600;
            state.genesis = Some(network.to_bitcoin());
        }
        server
    }

    fn esplora(server: &FakeMempool) -> crate::chain::esplora::Client {
        crate::chain::esplora::client_for_run(&format!("http://{}/api", server.address), None)
            .unwrap()
    }

    /// A plan of the script [`esplora_payment`] pays.
    fn address_plan(network: Network, held: Held) -> Plan {
        Plan {
            scripts: vec![ScriptBuf::from_hex(ADDRESS_SCRIPT).unwrap()],
            held,
            ..plan(network)
        }
    }

    /// Lists `payments` as the history of the script [`esplora_payment`]
    /// pays, for a descriptor wallet's sync.
    fn list(server: &FakeMempool, payments: Vec<serde_json::Value>) {
        server
            .state
            .lock()
            .unwrap()
            .scripts
            .insert(FakeMempool::rest_key(ADDRESS_SCRIPT), payments);
    }

    async fn esplora_sync(server: &FakeMempool, plan: Plan) -> Result<Synced, String> {
        crate::chain::esplora::sync::run(&esplora(server), plan).await
    }

    /// The requests asked for so far whose path holds `part`.
    fn asked(server: &FakeMempool, part: &str) -> usize {
        let state = server.state.lock().unwrap();
        state
            .requests
            .iter()
            .filter(|path| path.contains(part))
            .count()
    }

    /// An Esplora server proves a confirmation with the branch of its
    /// block and the block's header: taken, at the time of the header. A
    /// branch that leads elsewhere refuses the server, where the status
    /// used to be taken on its word.
    #[tokio::test]
    async fn an_esplora_confirmation_is_proven() {
        let server = mempool(Network::Signet).await;
        list(&server, vec![esplora_payment(0x31, 0x41, 50_000, true)]);
        let synced = esplora_sync(&server, address_plan(Network::Signet, Held::default()))
            .await
            .unwrap();
        let txid: Txid = crate::testkit::esplora_txid(0x31).parse().unwrap();
        let (anchor, anchored_txid) = synced.update.tx_update.anchors.first().unwrap();
        assert_eq!(*anchored_txid, txid);
        assert_eq!(anchor.block_id.height, 500);
        assert_eq!(
            (asked(&server, "/merkle-proof"), asked(&server, "/header")),
            (1, 1)
        );

        server
            .state
            .lock()
            .unwrap()
            .branches
            .insert(txid.to_string(), (vec!["ab".repeat(32)], 0));
        let refused = esplora_sync(&server, address_plan(Network::Signet, Held::default())).await;
        assert!(refusal(refused).contains(FALSE_PROOF));
    }

    /// A block the server listed and has no header for, as after a
    /// reorganisation, proves nothing and refuses no one: the payment is
    /// left unconfirmed, as seen in the mempool.
    #[tokio::test]
    async fn an_esplora_block_without_its_header_is_left_unconfirmed() {
        let server = mempool(Network::Signet).await;
        list(&server, vec![esplora_payment(0x3d, 0x4d, 50_000, true)]);
        server.state.lock().unwrap().headerless = true;
        let synced = esplora_sync(&server, address_plan(Network::Signet, Held::default()))
            .await
            .unwrap();
        let txid: Txid = crate::testkit::esplora_txid(0x3d).parse().unwrap();
        assert!(synced.update.tx_update.anchors.is_empty());
        assert!(
            synced
                .update
                .tx_update
                .seen_ats
                .iter()
                .any(|(seen, _)| *seen == txid)
        );
    }

    /// A status that names a block a reorganisation replaced, its branch
    /// into the new one: the payment is left unconfirmed and the server is
    /// not refused, where it used to be taken for a liar.
    #[tokio::test]
    async fn an_esplora_reorganisation_leaves_a_payment_unsure() {
        let server = mempool(Network::Signet).await;
        list(&server, vec![esplora_payment(0x3e, 0x4e, 50_000, true)]);
        {
            let mut state = server.state.lock().unwrap();
            let mut stale = crate::testkit::FakeMempool::header_at_height(&state, 500);
            stale.merkle_root = TxMerkleNode::from_byte_array([7; 32]);
            state.stale.insert(500, stale);
        }
        let synced = esplora_sync(&server, address_plan(Network::Signet, Held::default()))
            .await
            .unwrap();
        let txid: Txid = crate::testkit::esplora_txid(0x3e).parse().unwrap();
        assert!(synced.update.tx_update.anchors.is_empty());
        assert!(
            synced
                .update
                .tx_update
                .seen_ats
                .iter()
                .any(|(seen, _)| *seen == txid)
        );
    }

    /// Over Esplora too, a confirmation a few blocks above the tip is
    /// unsure, one further above it refuses the server, and a watched
    /// address on a tip no chain has reached is refused.
    #[tokio::test]
    async fn an_esplora_confirmation_above_the_tip_is_refused() {
        for (height, refused) in [(502, false), (520, true)] {
            let server = mempool(Network::Signet).await;
            server.state.lock().unwrap().tip = 500;
            let mut payment = esplora_payment(0x3f, 0x4f, 50_000, true);
            payment["status"]["block_height"] = serde_json::json!(height);
            list(&server, vec![payment.clone()]);
            let synced =
                esplora_sync(&server, address_plan(Network::Signet, Held::default())).await;
            server.state.lock().unwrap().address_txs = vec![payment];
            let state = esplora_address(&server, Network::Signet).await;
            if refused {
                assert!(refusal(synced).contains(FALSE_PROOF));
                assert!(state.unwrap_err().contains(FALSE_PROOF));
            } else {
                assert!(synced.unwrap().update.tx_update.anchors.is_empty());
                assert_eq!(state.unwrap().txs[0].height, None);
            }
        }
        let server = mempool(Network::Signet).await;
        server.state.lock().unwrap().tip = 4_000_000_000;
        let refused = esplora_address(&server, Network::Signet).await.unwrap_err();
        assert!(refused.contains(crate::chain::IMPOSSIBLE_TIP), "{refused}");
    }

    /// On mainnet, a confirmation in a header no one mined refuses the
    /// server, where it used to be taken.
    #[tokio::test]
    async fn an_esplora_header_without_work_refuses_the_server() {
        let server = mempool(Network::Mainnet).await;
        list(&server, vec![esplora_payment(0x32, 0x42, 50_000, true)]);
        let refused = esplora_sync(&server, address_plan(Network::Mainnet, Held::default())).await;
        assert!(refusal(refused).contains(FALSE_PROOF));
    }

    /// A confirmation the wallet holds in the same block is not proven
    /// again: once a script moves, only what is new on it is.
    #[tokio::test]
    async fn an_esplora_confirmation_held_is_not_proven_again() {
        let server = mempool(Network::Signet).await;
        let first = esplora_payment(0x33, 0x43, 50_000, true);
        list(&server, vec![first.clone()]);
        let synced = esplora_sync(&server, address_plan(Network::Signet, Held::default()))
            .await
            .unwrap();
        let mut held = Held::default();
        for tx in &synced.update.tx_update.txs {
            held.txs.insert(tx.compute_txid(), tx.clone());
        }
        for (anchor, txid) in &synced.update.tx_update.anchors {
            held.anchors.insert(*txid, *anchor);
        }
        let mut second = esplora_payment(0x34, 0x44, 20_000, true);
        second["status"]["block_height"] = serde_json::json!(503);
        list(&server, vec![second, first]);
        let before = (asked(&server, "/merkle-proof"), asked(&server, "/header"));
        let synced = esplora_sync(&server, address_plan(Network::Signet, held))
            .await
            .unwrap();
        assert_eq!(synced.update.tx_update.anchors.len(), 2);
        let after = (asked(&server, "/merkle-proof"), asked(&server, "/header"));
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
    }

    /// What proving costs the first sync of a large wallet: a hundred
    /// used scripts of five confirmations each, two confirmations a block.
    /// One branch per confirmation, one header per block, and nothing for
    /// the rest of the sync; printed with `--nocapture`.
    #[tokio::test]
    async fn what_proving_costs_a_first_esplora_sync() {
        let server = mempool(Network::Signet).await;
        server.state.lock().unwrap().tip = 900;
        let mut scripts = Vec::new();
        let mut label = 0u8;
        for n in 0..100u32 {
            let ours = format!("0014{:040x}", n + 1);
            let payments: Vec<serde_json::Value> = (0..5u32)
                .map(|k| {
                    label = label.wrapping_add(1);
                    let mut payment =
                        esplora_payment(label, (n % 250) as u8, 1_000 + u64::from(k), true);
                    payment["vout"][0]["scriptpubkey"] = serde_json::json!(ours);
                    payment["locktime"] = serde_json::json!(n * 5 + k);
                    let tx = page_tx(&payment);
                    payment["txid"] = serde_json::json!(tx.to_string());
                    payment["status"]["block_height"] = serde_json::json!(300 + (n * 5 + k) / 2);
                    payment
                })
                .collect();
            server
                .state
                .lock()
                .unwrap()
                .scripts
                .insert(FakeMempool::rest_key(&ours), payments);
            scripts.push(ScriptBuf::from_hex(&ours).unwrap());
        }
        let plan = Plan {
            scripts,
            ..plan(Network::Signet)
        };
        let synced = esplora_sync(&server, plan).await.unwrap();
        assert_eq!(synced.update.tx_update.anchors.len(), 500);
        let total = server.state.lock().unwrap().requests.len();
        let (branches, headers) = (asked(&server, "/merkle-proof"), asked(&server, "/header"));
        println!(
            "first sync of 500 confirmations in 250 blocks: {total} requests, of which {branches} \
             branches and {headers} headers, {} without proving",
            total - branches - headers
        );
        assert_eq!((branches, headers), (500, 250));
    }

    /// The txid of a transaction as Esplora lists it.
    fn page_tx(listed: &serde_json::Value) -> Txid {
        let tx: crate::chain::esplora::page::PageTx =
            serde_json::from_value(listed.clone()).unwrap();
        tx.to_tx().compute_txid()
    }

    async fn esplora_address(
        server: &FakeMempool,
        network: Network,
    ) -> Result<crate::wallet::AddressWatchState, String> {
        let address = if network == Network::Mainnet {
            MAINNET_ADDRESS
        } else {
            SIGNET_ADDRESS
        };
        crate::chain::esplora::fetch_address_state(&esplora(server), address, network, &[]).await
    }

    /// A watched address over Esplora: a confirmation is proven, one in a
    /// header no one mined refuses the server, and so does a transaction
    /// that is not the one its txid names, whose confirmation, proven
    /// under that txid, would have been taken for its own.
    #[tokio::test]
    async fn an_address_confirmation_is_proven_over_esplora() {
        let server = mempool(Network::Signet).await;
        server.state.lock().unwrap().address_txs = vec![esplora_payment(0x35, 0x45, 50_000, true)];
        let state = esplora_address(&server, Network::Signet).await.unwrap();
        assert_eq!(state.txs[0].height, Some(500));
        assert_eq!(
            (asked(&server, "/merkle-proof"), asked(&server, "/header")),
            (1, 1)
        );

        let mut passed_off = esplora_payment(0x36, 0x46, 50_000, true);
        passed_off["vout"][0]["value"] = serde_json::json!(5_000_000);
        server.state.lock().unwrap().address_txs = vec![passed_off];
        let refused = esplora_address(&server, Network::Signet).await.unwrap_err();
        assert!(refused.contains("another transaction"), "{refused}");

        let server = mempool(Network::Mainnet).await;
        server.state.lock().unwrap().address_txs = vec![esplora_payment(0x37, 0x47, 50_000, true)];
        let refused = esplora_address(&server, Network::Mainnet)
            .await
            .unwrap_err();
        assert!(refused.contains(FALSE_PROOF), "{refused}");
    }

    /// The coins of an address over Esplora are read as over Electrum.
    #[tokio::test]
    async fn an_address_coin_over_esplora_is_confirmed_as_its_transaction_is() {
        let server = mempool(Network::Signet).await;
        let payment = esplora_payment(0x38, 0x48, 50_000, true);
        let txid = crate::testkit::esplora_txid(0x38);
        let coin = |txid: &str, vout: u32, value: u64| {
            serde_json::json!({
                "txid": txid, "vout": vout, "value": value,
                "status": { "confirmed": true, "block_height": 480, "block_time": 1_700_000_000 },
            })
        };
        let nobody = "55".repeat(32);
        {
            let mut state = server.state.lock().unwrap();
            state.address_txs = vec![payment];
            state.utxos = vec![
                coin(&txid, 0, 50_000),
                coin(&txid, 0, 50_000),
                coin(&nobody, 0, 7_000_000),
            ];
        }
        let state = esplora_address(&server, Network::Signet).await.unwrap();
        assert_eq!(state.utxos.len(), 2);
        assert_eq!(state.utxos[0].height, Some(500));
        let balance = crate::wallet::views::address_balance(&state);
        assert_eq!(balance.confirmed, 50_000);
        assert_eq!(balance.untrusted_pending, 7_000_000);

        server.state.lock().unwrap().utxos = vec![coin(&txid, 0, 60_000)];
        let refused = esplora_address(&server, Network::Signet).await.unwrap_err();
        assert!(refused.contains("does not pay"), "{refused}");
    }

    /// A coin past the round over Esplora counts as confirmed once its
    /// transaction, read again, pays it and is proven where the server
    /// puts it, or once the wallet holds it there. Higher than the round's
    /// oldest confirmation, it is unconfirmed.
    #[tokio::test]
    async fn an_esplora_coin_past_the_round_counts_once_proven() {
        let server = mempool(Network::Signet).await;
        let old = esplora_payment(0x39, 0x49, 50_000, true);
        let txid = crate::testkit::esplora_txid(0x39);
        let mut newer = esplora_payment(0x3a, 0x4a, 1_000, true);
        newer["status"]["block_height"] = serde_json::json!(520);
        server.state.lock().unwrap().address_txs = vec![newer, old];
        let whole = esplora_address(&server, Network::Signet).await.unwrap();
        // The round of the newer one alone, older ones past it.
        let round = crate::chain::esplora::HistoryRound {
            txs: whole.txs[..1].to_vec(),
            cursor: Some(whole.txs[0].txid.clone()),
        };
        let client = esplora(&server);
        // The block the old payment is in, as the server lists it.
        let page: Vec<serde_json::Value> = client.get_json("/address/x/txs").await.unwrap();
        let block = page
            .iter()
            .find(|tx| tx["txid"] == txid)
            .and_then(|tx| tx["status"]["block_hash"].as_str())
            .unwrap()
            .to_owned();
        let coin = |value: u64, height: u32| {
            serde_json::from_value::<crate::chain::esplora::api::Utxo>(serde_json::json!({
                "txid": txid, "vout": 0, "value": value,
                "status": {
                    "confirmed": true, "block_height": height,
                    "block_hash": block, "block_time": 1_700_000_000,
                },
            }))
            .unwrap()
        };
        let ours = ScriptBuf::from_hex(ADDRESS_SCRIPT).unwrap();
        let read = |coins, held: Vec<crate::wallet::AddressTx>| {
            let (client, ours, round) = (&client, &ours, &round);
            async move {
                crate::chain::esplora::coins(
                    client,
                    Network::Signet,
                    600,
                    ours,
                    coins,
                    round,
                    &held,
                )
                .await
            }
        };

        let coins = read(vec![coin(50_000, 500)], Vec::new()).await.unwrap();
        assert_eq!(coins[0].height, Some(500));
        assert_eq!(asked(&server, "/raw"), 1);
        // Proven this session: not read again.
        let again = read(vec![coin(50_000, 500)], Vec::new()).await.unwrap();
        assert_eq!(again, coins);
        assert_eq!(asked(&server, "/raw"), 1);
        // Held there, paying it: at the time the wallet holds, whatever
        // time the server gives the coin.
        let mut held = whole.txs.clone();
        held[1].timestamp = Some(1_234);
        let coins = read(vec![coin(50_000, 500)], held).await.unwrap();
        assert_eq!(coins[0].height, Some(500));
        assert_eq!(coins[0].timestamp, Some(1_234));
        assert_eq!(asked(&server, "/raw"), 1);
        // More than its transaction pays.
        let refused = read(vec![coin(5_000_000, 500)], Vec::new())
            .await
            .unwrap_err();
        assert!(refused.contains("does not pay"), "{refused}");
        // Higher than the round's oldest confirmation: unconfirmed.
        let coins = read(vec![coin(50_000, 530)], Vec::new()).await.unwrap();
        assert_eq!(coins[0].height, None);
    }

    /// A status that says confirmed and names no block confirms nothing,
    /// nor the coin it pays; and a transaction the wallet holds, listed
    /// again with what it pays rewritten, refuses the server. Both used
    /// to count, confirmed, at the server's word.
    #[tokio::test]
    async fn an_esplora_address_takes_no_confirmation_it_cannot_prove() {
        let server = mempool(Network::Signet).await;
        let mut nameless = esplora_payment(0x3b, 0x4b, 50_000, true);
        nameless["status"] = serde_json::json!({ "confirmed": true, "block_height": 480 });
        let txid = crate::testkit::esplora_txid(0x3b);
        {
            let mut state = server.state.lock().unwrap();
            state.address_txs = vec![nameless];
            state.utxos = vec![serde_json::json!({
                "txid": txid, "vout": 0, "value": 50_000,
                "status": { "confirmed": true, "block_height": 480 },
            })];
        }
        let state = esplora_address(&server, Network::Signet).await.unwrap();
        assert_eq!(state.txs[0].height, None);
        assert_eq!(crate::wallet::views::address_balance(&state).confirmed, 0);

        let server = mempool(Network::Signet).await;
        server.state.lock().unwrap().address_txs = vec![esplora_payment(0x3c, 0x4c, 1_000, true)];
        let held = esplora_address(&server, Network::Signet).await.unwrap().txs;
        let mut rewritten = esplora_payment(0x3c, 0x4c, 1_000, true);
        rewritten["vout"][0]["value"] = serde_json::json!(1_000_000_000u64);
        rewritten["txid"] = serde_json::json!(held[0].txid);
        server.state.lock().unwrap().address_txs = vec![rewritten];
        let refused = crate::chain::esplora::fetch_address_state(
            &esplora(&server),
            SIGNET_ADDRESS,
            Network::Signet,
            &held,
        )
        .await
        .unwrap_err();
        assert!(refused.contains("another transaction"), "{refused}");
    }
}
