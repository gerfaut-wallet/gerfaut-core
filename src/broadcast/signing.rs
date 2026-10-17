//! How much a transaction weighs once signed, before it is.
//!
//! A PSBT still waiting for signatures is lighter than the transaction
//! it becomes: every signature, every public key and every script a
//! signer adds is weight the fee rate is paid on. A rate read off the
//! unsigned skeleton is too high, sometimes by a third. What each input
//! still lacks is read here from what the spent coin is and what the
//! PSBT carries about it, the way miniscript counts it for a descriptor:
//! the largest satisfaction, so the estimate errs on the side of a lower
//! rate.

use bdk_wallet::bitcoin::key::TapTweak;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::taproot::{ControlBlock, TapNodeHash};
use bdk_wallet::bitcoin::{
    PublicKey, Script, ScriptBuf, Transaction, VarInt, Weight, XOnlyPublicKey,
};
use bdk_wallet::miniscript::{Descriptor, Legacy, Miniscript, Segwitv0, Tap};

/// The secp256k1 generator, a public constant. Only its size counts: the
/// weight of a signature by any compressed key is the same.
const ANY_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// What signing adds to one input: its weight, counted the way
/// miniscript's `max_weight_to_satisfy` counts it (the input as a segwit
/// transaction serializes it, from an empty script and an empty
/// witness), and whether any of it goes in a witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Satisfaction {
    pub weight: u64,
    pub witness: bool,
}

impl Satisfaction {
    /// The most a descriptor's coin can take to spend, by its own
    /// policy; `None` for a descriptor nothing can satisfy.
    pub fn of_descriptor<Pk: bdk_wallet::miniscript::MiniscriptKey>(
        descriptor: &Descriptor<Pk>,
    ) -> Option<Self> {
        let weight = descriptor.max_weight_to_satisfy().ok()?.to_wu();
        Some(Satisfaction {
            weight,
            witness: descriptor.desc_type().segwit_version().is_some(),
        })
    }

    /// What a finalized input carries: exact.
    pub(crate) fn of_final(
        script_sig: Option<&ScriptBuf>,
        witness: Option<&bdk_wallet::bitcoin::Witness>,
    ) -> Self {
        let script_len = script_sig.map_or(0, |s| s.len());
        let script_growth = script_len + VarInt(script_len as u64).size() - 1;
        let witness_growth = witness.map_or(0, |w| w.size().saturating_sub(1));
        Satisfaction {
            weight: (4 * script_growth + witness_growth) as u64,
            witness: witness.is_some_and(|w| !w.is_empty()),
        }
    }
}

/// What a PSBT input carries that tells how it will be signed: the
/// scripts behind a script hash, the keys, the internal key and the
/// leaves of a taproot output. Its author's word: each is read only
/// once the coin's script is seen to commit to it.
#[derive(Debug, Clone, Default)]
pub struct SigningHints {
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    /// Each leaf script with the control block that reveals it.
    pub tap_leaves: Vec<(ScriptBuf, ControlBlock)>,
    /// The internal key of a taproot output, and the root of its script
    /// tree when it has one.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    pub tap_merkle_root: Option<TapNodeHash>,
    /// The keys the PSBT names for the input: its BIP-32 derivations,
    /// in both encodings, and the keys of its partial signatures.
    pub keys: Vec<PublicKey>,
}

impl SigningHints {
    pub(crate) fn of_psbt_input(input: &bdk_wallet::bitcoin::psbt::Input) -> Self {
        // A derivation names the key without its encoding: both are
        // offered, and the coin's hash picks the one it commits to.
        let derived = input
            .bip32_derivation
            .keys()
            .flat_map(|key| [PublicKey::new(*key), PublicKey::new_uncompressed(*key)]);
        SigningHints {
            redeem_script: input.redeem_script.clone(),
            witness_script: input.witness_script.clone(),
            tap_leaves: input
                .tap_scripts
                .iter()
                .map(|(control, (script, _))| (script.clone(), control.clone()))
                .collect(),
            tap_internal_key: input.tap_internal_key,
            tap_merkle_root: input.tap_merkle_root,
            keys: derived.chain(input.partial_sigs.keys().copied()).collect(),
        }
    }
}

/// What signing will add to an input spending `spent`, judged by the
/// coin's script and what the PSBT says about it. `None` when neither
/// tells, rather than a guess that could weigh less than the signature:
/// a script hash whose script the PSBT does not carry, or carries wrong,
/// a script that is no miniscript, a bare script, a key hash whose key
/// the PSBT does not name (it may be the uncompressed one, 32 bytes
/// more), a taproot output whose key path is not shown to be its only
/// path.
pub fn estimated(spent: &Script, hints: &SigningHints) -> Option<Satisfaction> {
    let key: PublicKey = ANY_KEY.parse().ok()?;
    let of = |descriptor: Result<Descriptor<PublicKey>, _>| {
        descriptor
            .ok()
            .and_then(|d| Satisfaction::of_descriptor(&d))
    };
    if spent.is_p2wpkh() {
        return of(Descriptor::new_wpkh(key));
    }
    if spent.is_p2pkh() {
        let named = hints
            .keys
            .iter()
            .find(|key| ScriptBuf::new_p2pkh(&key.pubkey_hash()) == *spent)?;
        return of(Descriptor::new_pkh(*named));
    }
    if spent.is_p2tr() {
        return taproot(spent, hints);
    }
    // A script the coin's hash does not commit to says nothing of how it
    // will be spent.
    let witness_script = || {
        hints
            .witness_script
            .as_ref()
            .filter(|script| ScriptBuf::new_p2wsh(&script.wscript_hash()) == *spent)
    };
    if spent.is_p2wsh() {
        return of(Descriptor::new_wsh(segwit_ms(witness_script()?)?));
    }
    if spent.is_p2sh() {
        let redeem = hints
            .redeem_script
            .as_ref()
            .filter(|redeem| ScriptBuf::new_p2sh(&redeem.script_hash()) == *spent)?;
        if redeem.is_p2wpkh() {
            return of(Descriptor::new_sh_wpkh(key));
        }
        if redeem.is_p2wsh() {
            let script = hints
                .witness_script
                .as_ref()
                .filter(|script| ScriptBuf::new_p2wsh(&script.wscript_hash()) == *redeem)?;
            return of(Descriptor::new_sh_wsh(segwit_ms(script)?));
        }
        let ms = Miniscript::<PublicKey, Legacy>::parse_insane(redeem).ok()?;
        return of(Descriptor::new_sh(ms));
    }
    None
}

fn segwit_ms(script: &Script) -> Option<Miniscript<PublicKey, Segwitv0>> {
    Miniscript::<PublicKey, Segwitv0>::parse_insane(script).ok()
}

/// A taproot input: the key path, or the heaviest leaf the PSBT
/// reveals, counted as miniscript counts a tree's leaves. A leaf that is
/// no miniscript, or whose control block the output key does not commit
/// to, leaves the weight unknown. With no leaf, the key path is counted
/// only when the PSBT shows it is the only one: its internal key, tweaked
/// with no script tree, is the output key. Otherwise a leaf the PSBT
/// does not show may be the one spent, and its weight is unknown.
fn taproot(spent: &Script, hints: &SigningHints) -> Option<Satisfaction> {
    let output_key = XOnlyPublicKey::from_slice(spent.as_bytes().get(2..34)?).ok()?;
    let secp = Secp256k1::verification_only();
    let leaves = &hints.tap_leaves;
    if leaves.is_empty() {
        let internal = hints
            .tap_internal_key
            .filter(|_| hints.tap_merkle_root.is_none())?;
        let (tweaked, _) = internal.tap_tweak(&secp, None);
        if tweaked.to_x_only_public_key() != output_key {
            return None;
        }
    }
    // One item: a 64-byte signature and its sighash byte, with its length.
    let key_path = VarInt(1).size() - VarInt(0).size() + 1 + 65;
    let mut heaviest = key_path;
    for (script, control) in leaves {
        if !control.verify_taproot_commitment(&secp, output_key, script) {
            return None;
        }
        let control = control.size();
        let ms = Miniscript::<XOnlyPublicKey, Tap>::parse_insane(script).ok()?;
        // The satisfaction's elements and the script, as miniscript
        // counts them (`max_satisfaction_witness_elements` includes the
        // script); one more for the control block.
        let elements = ms.max_satisfaction_witness_elements().ok()?;
        let size = ms.max_satisfaction_size().ok()?;
        let script_size = script.len();
        let weight = VarInt((elements + 1) as u64).size() - VarInt(0).size()
            + size
            + VarInt(script_size as u64).size()
            + script_size
            + VarInt(control as u64).size()
            + control;
        heaviest = heaviest.max(weight);
    }
    Some(Satisfaction {
        weight: heaviest as u64,
        witness: true,
    })
}

/// The weight of `tx` once every input carries what `missing` says it
/// still lacks; `None` in `missing` is an input with nothing to add.
pub fn weight_once_signed(tx: &Transaction, missing: &[Option<Satisfaction>]) -> Weight {
    let segwit = tx.input.iter().any(|input| !input.witness.is_empty())
        || missing.iter().flatten().any(|s| s.witness);
    let base = 4 * tx.base_size() as u64;
    // Marker and flag, then each input's witness, an empty one a single
    // byte that says so.
    let witnesses = if segwit {
        2 + tx
            .input
            .iter()
            .map(|input| input.witness.size() as u64)
            .sum::<u64>()
    } else {
        0
    };
    // Each is the growth of its input from an empty script and an empty
    // witness, which a legacy satisfaction leaves empty: the same count
    // whether the transaction has witnesses or not.
    let added: u64 = missing.iter().flatten().map(|s| s.weight).sum();
    Weight::from_wu(base + witnesses + added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, OutPoint, Sequence, TxIn, TxOut, Txid, WPubkeyHash, Witness, absolute, transaction,
    };

    fn skeleton(inputs: usize, spk: ScriptBuf) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..inputs)
                .map(|n| TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([n as u8 + 1; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spk,
            }],
        }
    }

    fn p2wpkh() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]))
    }

    /// One P2WPKH input, signed for real, against the estimate: the
    /// estimate is the largest signature, so it may be one or two
    /// weight units over and never under.
    #[test]
    fn a_p2wpkh_spend_is_estimated_within_a_signature_byte() {
        let tx = skeleton(1, p2wpkh());
        let missing = estimated(&p2wpkh(), &SigningHints::default()).unwrap();
        assert!(missing.witness);
        let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
        let mut signed = tx.clone();
        let mut witness = Witness::new();
        witness.push([0x30; 72]);
        witness.push([0x02; 33]);
        signed.input[0].witness = witness;
        let real = signed.weight().to_wu();
        assert!(
            estimate >= real && estimate <= real + 2,
            "{estimate} vs {real}"
        );
        // The skeleton, as the preview used to read it, is a quarter
        // lighter: the rate it gave was a third too high.
        assert!(tx.weight().to_wu() * 4 < real * 3 + 4);
    }

    /// The key path of a taproot coin: a 64-byte signature, its sighash
    /// byte at most. Counted only when the PSBT shows it is the only path:
    /// its internal key, tweaked with no script tree, is the output key.
    /// Without that, a leaf it does not show may be the one spent, far
    /// heavier, and the weight is unknown rather than guessed low.
    #[test]
    fn a_taproot_key_path_is_one_signature_when_shown_to_be_the_only_one() {
        let secp = Secp256k1::verification_only();
        let key: PublicKey = ANY_KEY.parse().unwrap();
        let internal = XOnlyPublicKey::from(key.inner);
        let spk = ScriptBuf::new_p2tr(&secp, internal, None);
        assert_eq!(estimated(&spk, &SigningHints::default()), None);
        let shown = SigningHints {
            tap_internal_key: Some(internal),
            ..Default::default()
        };
        // A script tree under it: the key path is one path among others.
        let with_a_tree = SigningHints {
            tap_merkle_root: Some(TapNodeHash::from_byte_array([7; 32])),
            ..shown.clone()
        };
        assert_eq!(estimated(&spk, &with_a_tree), None);
        // An internal key the output does not commit to.
        let other: PublicKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            .parse()
            .unwrap();
        let wrong = SigningHints {
            tap_internal_key: Some(XOnlyPublicKey::from(other.inner)),
            ..Default::default()
        };
        assert_eq!(estimated(&spk, &wrong), None);
        let tx = skeleton(1, p2wpkh());
        let missing = estimated(&spk, &shown).unwrap();
        let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
        let mut signed = tx.clone();
        signed.input[0].witness = Witness::from_slice(&[[0x01; 64]]);
        let real = signed.weight().to_wu();
        assert!(
            estimate >= real && estimate <= real + 1,
            "{estimate} vs {real}"
        );
    }

    /// A 2-of-3 behind a witness script the PSBT carries.
    #[test]
    fn a_multisig_is_read_from_its_witness_script() {
        let keys: Vec<PublicKey> = [
            ANY_KEY,
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ]
        .iter()
        .map(|k| k.parse().unwrap())
        .collect();
        let ms = Miniscript::<PublicKey, Segwitv0>::from_str_insane(&format!(
            "multi(2,{},{},{})",
            keys[0], keys[1], keys[2]
        ))
        .unwrap();
        let script = ms.encode();
        let spk = ScriptBuf::new_p2wsh(&script.wscript_hash());
        let hints = SigningHints {
            witness_script: Some(script.clone()),
            ..Default::default()
        };
        let missing = estimated(&spk, &hints).unwrap();
        let tx = skeleton(1, p2wpkh());
        let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
        let mut signed = tx.clone();
        let mut witness = Witness::new();
        witness.push([]);
        witness.push([0x30; 72]);
        witness.push([0x30; 72]);
        witness.push(script.as_bytes());
        signed.input[0].witness = witness;
        let real = signed.weight().to_wu();
        assert!(
            estimate >= real && estimate <= real + 2,
            "{estimate} vs {real}"
        );
        // Without the script, nothing tells.
        assert_eq!(estimated(&spk, &SigningHints::default()), None);
    }

    /// A legacy spend: the transaction keeps no witness at all, and the
    /// signature goes in the script.
    #[test]
    fn a_legacy_spend_adds_no_witness() {
        let key: PublicKey = ANY_KEY.parse().unwrap();
        let tx = skeleton(1, p2wpkh());
        for (key, length) in [(key, 33), (PublicKey::new_uncompressed(key.inner), 65)] {
            let spk = ScriptBuf::new_p2pkh(&key.pubkey_hash());
            // The key the coin's hash commits to, named by the PSBT: its
            // own length, the uncompressed one 32 bytes longer.
            let named = SigningHints {
                keys: vec![
                    PublicKey::new(key.inner),
                    PublicKey::new_uncompressed(key.inner),
                ],
                ..Default::default()
            };
            let missing = estimated(&spk, &named).unwrap();
            assert!(!missing.witness);
            let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
            let mut signed = tx.clone();
            signed.input[0].script_sig = bdk_wallet::bitcoin::script::Builder::new()
                .push_slice([0x30; 72])
                .push_slice(
                    <&bdk_wallet::bitcoin::script::PushBytes>::try_from(&vec![0x04; length][..])
                        .unwrap(),
                )
                .into_script();
            let real = signed.weight().to_wu();
            assert!(
                estimate >= real && estimate <= real + 4,
                "{length}-byte key: {estimate} vs {real}"
            );
            // A key hash whose key the PSBT does not name may hide either.
            assert_eq!(estimated(&spk, &SigningHints::default()), None);
        }
    }

    /// What a finalized input carries is counted as it is.
    #[test]
    fn a_finalized_input_counts_exactly() {
        let tx = skeleton(2, p2wpkh());
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        let done = Satisfaction::of_final(None, Some(&witness));
        let missing = estimated(&p2wpkh(), &SigningHints::default()).unwrap();
        let estimate = weight_once_signed(&tx, &[Some(done), Some(missing)]).to_wu();
        let mut signed = tx.clone();
        signed.input[0].witness = witness;
        let mut other = Witness::new();
        other.push([0x30; 72]);
        other.push([0x02; 33]);
        signed.input[1].witness = other;
        assert_eq!(estimate, signed.weight().to_wu());
    }

    /// A watched wallet's own descriptor, its keys public and its path
    /// open: the same count as a coin read by its script, and for a
    /// policy with a recovery path, the heaviest of its paths.
    #[test]
    fn a_watched_descriptor_counts_its_heaviest_path() {
        use bdk_wallet::miniscript::DescriptorPublicKey;
        use std::str::FromStr;
        const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";
        let single =
            Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({TPUB}/0/*)")).unwrap();
        assert_eq!(
            Satisfaction::of_descriptor(&single),
            estimated(&p2wpkh(), &SigningHints::default())
        );
        let primary = Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wsh(or_d(pk({TPUB}/0/*),and_v(v:pk({TPUB}/1/*),older(52560))))"
        ))
        .unwrap();
        let recovery = Satisfaction::of_descriptor(&primary).unwrap();
        // Two keys may sign, one at a time: the recovery path, its
        // signature after the empty one that skips the first, is the
        // heavier, and it is the one counted.
        assert!(recovery.witness);
        assert!(recovery.weight > single.max_weight_to_satisfy().unwrap().to_wu());
    }

    /// A coin of a nested segwit address: the redeem script in the
    /// signature script, the signature and key in the witness.
    #[test]
    fn a_nested_segwit_spend_counts_both_halves() {
        let redeem = p2wpkh();
        let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
        let hints = SigningHints {
            redeem_script: Some(redeem.clone()),
            ..Default::default()
        };
        let missing = estimated(&spk, &hints).unwrap();
        let tx = skeleton(1, p2wpkh());
        let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
        let mut signed = tx.clone();
        signed.input[0].script_sig = bdk_wallet::bitcoin::script::Builder::new()
            .push_slice(
                <&bdk_wallet::bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap(),
            )
            .into_script();
        let mut witness = Witness::new();
        witness.push([0x30; 72]);
        witness.push([0x02; 33]);
        signed.input[0].witness = witness;
        let real = signed.weight().to_wu();
        assert_eq!(estimate, real);
        // Without the redeem script, a script hash tells nothing.
        assert_eq!(estimated(&spk, &SigningHints::default()), None);
    }

    /// The scripts a PSBT names are its author's word: one the coin's
    /// hash does not commit to tells nothing, and the rate falls back to
    /// its ceiling rather than to whatever weight that script would give.
    #[test]
    fn a_script_the_coin_does_not_commit_to_is_not_read() {
        let script = p2wpkh();
        let other = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash());
        let hints = SigningHints {
            witness_script: Some(script.clone()),
            redeem_script: Some(script),
            ..Default::default()
        };
        assert_eq!(estimated(&other, &hints), None);
        let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(vec![0x51]).script_hash());
        assert_eq!(estimated(&p2sh, &hints), None);
    }

    /// A taproot leaf counts once its control block shows the output key
    /// commits to it: then its heaviest satisfaction is the weight. A leaf
    /// of another tree is no word about this coin.
    #[test]
    fn a_taproot_leaf_counts_only_when_the_output_commits_to_it() {
        use bdk_wallet::bitcoin::taproot::{LeafVersion, TaprootBuilder};
        let secp = Secp256k1::verification_only();
        let key: PublicKey = ANY_KEY.parse().unwrap();
        let internal = XOnlyPublicKey::from(key.inner);
        let leaf = Miniscript::<XOnlyPublicKey, Tap>::from_str_insane(&format!(
            "and_v(v:pk({internal}),older(144))"
        ))
        .unwrap()
        .encode();
        let tree = |script: &ScriptBuf| {
            TaprootBuilder::new()
                .add_leaf(0, script.clone())
                .unwrap()
                .finalize(&secp, internal)
                .unwrap()
        };
        let info = tree(&leaf);
        let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let hints = SigningHints {
            tap_leaves: vec![(leaf.clone(), control.clone())],
            ..Default::default()
        };
        let missing = estimated(&spk, &hints).unwrap();
        // Heavier than the key path's one signature.
        assert!(missing.weight > 66);
        // Signed through that leaf: a signature, the script, the control
        // block. The estimate is that, at most a byte over.
        let tx = skeleton(1, p2wpkh());
        let estimate = weight_once_signed(&tx, &[Some(missing)]).to_wu();
        let mut signed = tx.clone();
        signed.input[0].witness =
            Witness::from_slice(&[vec![0x01; 64], leaf.to_bytes(), control.serialize()]);
        let real = signed.weight().to_wu();
        assert!(
            estimate >= real && estimate <= real + 1,
            "{estimate} vs {real}"
        );

        // The same leaf, revealed by the control block of another output:
        // the tree of another internal key.
        let other: PublicKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            .parse()
            .unwrap();
        let elsewhere = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, XOnlyPublicKey::from(other.inner))
            .unwrap();
        let foreign = SigningHints {
            tap_leaves: vec![(
                leaf.clone(),
                elsewhere
                    .control_block(&(leaf.clone(), LeafVersion::TapScript))
                    .unwrap(),
            )],
            ..Default::default()
        };
        assert_eq!(estimated(&spk, &foreign), None);
    }

    /// A leaf counted here weighs what miniscript's own count gives for
    /// the same tree: the satisfaction, the script, the control block,
    /// and the number of witness elements, which miniscript already
    /// makes include the script.
    #[test]
    fn a_leaf_weighs_what_miniscript_counts_for_its_tree() {
        use bdk_wallet::bitcoin::taproot::{LeafVersion, TaprootBuilder};
        use std::str::FromStr;
        let secp = Secp256k1::verification_only();
        let key: PublicKey = ANY_KEY.parse().unwrap();
        let internal = XOnlyPublicKey::from(key.inner);
        let policy = format!("and_v(v:pk({internal}),older(144))");
        let leaf = Miniscript::<XOnlyPublicKey, Tap>::from_str_insane(&policy)
            .unwrap()
            .encode();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let ours = estimated(
            &ScriptBuf::new_p2tr_tweaked(info.output_key()),
            &SigningHints {
                tap_leaves: vec![(leaf, control)],
                ..Default::default()
            },
        )
        .unwrap();
        let tree =
            Descriptor::<XOnlyPublicKey>::from_str(&format!("tr({internal},{policy})")).unwrap();
        assert_eq!(ours.weight, tree.max_weight_to_satisfy().unwrap().to_wu());
    }
}
