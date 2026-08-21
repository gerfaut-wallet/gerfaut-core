//! SLIP-132 extended public key handling.
//!
//! Wallets export extended public keys under many version prefixes
//! (`ypub`, `zpub`, `vpub`, ...) that encode a script type on top of the
//! BIP32 payload. Gerfaut normalizes them all back to standard `xpub` /
//! `tpub` and keeps the script type as separate, explicit information.
//!
//! Private prefixes (`xprv` and friends) are recognized here only to be
//! rejected: this crate never accepts private key material.

use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::base58;
use bdk_wallet::bitcoin::bip32::Xpub;

use crate::error::{CoreError, CoreResult};
use crate::input::ScriptKind;

/// Outcome of decoding a SLIP-132 or standard extended public key.
#[derive(Debug, Clone)]
pub struct DecodedXpub {
    /// The key, normalized to standard version bytes.
    pub xpub: Xpub,
    /// Standard-encoded string (`xpub...` / `tpub...`).
    pub normalized: String,
    /// Mainnet or test key.
    pub network_kind: NetworkKind,
    /// Script type implied by the SLIP-132 prefix, when it implies one.
    pub script_hint: Option<ScriptKind>,
    /// True when the input used a non-standard (SLIP-132) prefix.
    pub converted: bool,
    /// True for the multisig prefixes (`Ypub`/`Zpub`/`Upub`/`Vpub`):
    /// a single such key cannot form a wallet on its own.
    pub multisig_only: bool,
}

/// Version bytes: (prefix bytes, mainnet?, script hint, multisig-only).
const PUBLIC_VERSIONS: &[([u8; 4], bool, Option<ScriptKind>, bool)] = &[
    // Standard BIP32. No script hint: a bare xpub does not say how it is used.
    ([0x04, 0x88, 0xB2, 0x1E], true, None, false), // xpub
    ([0x04, 0x35, 0x87, 0xCF], false, None, false), // tpub
    // SLIP-132 single-sig.
    (
        [0x04, 0x9D, 0x7C, 0xB2],
        true,
        Some(ScriptKind::NestedSegwit),
        false,
    ), // ypub
    (
        [0x04, 0xB2, 0x47, 0x46],
        true,
        Some(ScriptKind::Segwit),
        false,
    ), // zpub
    (
        [0x04, 0x4A, 0x52, 0x62],
        false,
        Some(ScriptKind::NestedSegwit),
        false,
    ), // upub
    (
        [0x04, 0x5F, 0x1C, 0xF6],
        false,
        Some(ScriptKind::Segwit),
        false,
    ), // vpub
    // SLIP-132 multisig.
    (
        [0x02, 0x95, 0xB4, 0x3F],
        true,
        Some(ScriptKind::NestedSegwit),
        true,
    ), // Ypub
    (
        [0x02, 0xAA, 0x7E, 0xD3],
        true,
        Some(ScriptKind::Segwit),
        true,
    ), // Zpub
    (
        [0x02, 0x42, 0x89, 0xEF],
        false,
        Some(ScriptKind::NestedSegwit),
        true,
    ), // Upub
    (
        [0x02, 0x57, 0x54, 0x83],
        false,
        Some(ScriptKind::Segwit),
        true,
    ), // Vpub
];

/// All known private version bytes, standard and SLIP-132. Any match is
/// an immediate, unconditional rejection.
const PRIVATE_VERSIONS: &[[u8; 4]] = &[
    [0x04, 0x88, 0xAD, 0xE4], // xprv
    [0x04, 0x35, 0x83, 0x94], // tprv
    [0x04, 0x9D, 0x78, 0x78], // yprv
    [0x04, 0xB2, 0x43, 0x0C], // zprv
    [0x04, 0x4A, 0x4E, 0x28], // uprv
    [0x04, 0x5F, 0x18, 0xBC], // vprv
    [0x02, 0x95, 0xB0, 0x05], // Yprv
    [0x02, 0xAA, 0x7A, 0x99], // Zprv
    [0x02, 0x42, 0x85, 0xB5], // Uprv
    [0x02, 0x57, 0x50, 0x48], // Vprv
];

const STANDARD_PUBLIC_MAINNET: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const STANDARD_PUBLIC_TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

/// Textual prefixes that make a token look like an extended key at all.
/// Used by the classifier to decide whether to attempt a decode.
pub(crate) fn looks_like_extended_key(token: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "xpub", "ypub", "zpub", "Ypub", "Zpub", "tpub", "upub", "vpub", "Upub", "Vpub", "xprv",
        "yprv", "zprv", "Yprv", "Zprv", "tprv", "uprv", "vprv", "Uprv", "Vprv",
    ];
    PREFIXES.iter().any(|p| token.starts_with(p))
}

/// Decodes an extended public key in any known encoding, normalizing it
/// to standard version bytes.
///
/// Rejects private keys ([`CoreError::PrivateMaterialRejected`]) and
/// unknown version bytes.
pub fn decode_extended_key(token: &str) -> CoreResult<DecodedXpub> {
    let data = base58::decode_check(token).map_err(|e| CoreError::InvalidInput {
        kind: "extended key",
        detail: format!("base58 decoding failed: {e}"),
    })?;
    if data.len() != 78 {
        return Err(CoreError::InvalidInput {
            kind: "extended key",
            detail: format!("expected 78 bytes of payload, got {}", data.len()),
        });
    }
    let version: [u8; 4] = data[..4].try_into().expect("length checked above");

    if PRIVATE_VERSIONS.contains(&version) {
        return Err(CoreError::PrivateMaterialRejected);
    }

    let Some((_, mainnet, script_hint, multisig_only)) = PUBLIC_VERSIONS
        .iter()
        .find(|(bytes, ..)| *bytes == version)
        .copied()
    else {
        return Err(CoreError::InvalidInput {
            kind: "extended key",
            detail: "unknown version bytes".to_owned(),
        });
    };

    let standard = if mainnet {
        STANDARD_PUBLIC_MAINNET
    } else {
        STANDARD_PUBLIC_TESTNET
    };
    let converted = version != standard;
    let mut normalized_bytes = data;
    normalized_bytes[..4].copy_from_slice(&standard);
    let normalized = base58::encode_check(&normalized_bytes);

    let xpub = Xpub::decode(&normalized_bytes).map_err(|e| CoreError::InvalidInput {
        kind: "extended key",
        detail: format!("invalid BIP32 payload: {e}"),
    })?;

    Ok(DecodedXpub {
        xpub,
        normalized,
        network_kind: if mainnet {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        },
        script_hint,
        converted,
        multisig_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP32 test vector 1, master public key.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    /// Re-encodes the BIP32 vector under a different version prefix.
    fn with_version(version: [u8; 4]) -> String {
        let mut data = base58::decode_check(XPUB).unwrap();
        data[..4].copy_from_slice(&version);
        base58::encode_check(&data)
    }

    #[test]
    fn standard_xpub_passes_through() {
        let decoded = decode_extended_key(XPUB).unwrap();
        assert_eq!(decoded.normalized, XPUB);
        assert!(!decoded.converted);
        assert!(!decoded.multisig_only);
        assert_eq!(decoded.script_hint, None);
        assert_eq!(decoded.network_kind, NetworkKind::Main);
    }

    #[test]
    fn zpub_converts_back_to_same_xpub() {
        let zpub = with_version([0x04, 0xB2, 0x47, 0x46]);
        assert!(zpub.starts_with("zpub"));
        let decoded = decode_extended_key(&zpub).unwrap();
        assert_eq!(decoded.normalized, XPUB);
        assert!(decoded.converted);
        assert_eq!(decoded.script_hint, Some(ScriptKind::Segwit));
    }

    #[test]
    fn ypub_hints_nested_segwit() {
        let ypub = with_version([0x04, 0x9D, 0x7C, 0xB2]);
        assert!(ypub.starts_with("ypub"));
        let decoded = decode_extended_key(&ypub).unwrap();
        assert_eq!(decoded.script_hint, Some(ScriptKind::NestedSegwit));
        assert!(!decoded.multisig_only);
    }

    #[test]
    fn vpub_is_testnet() {
        let vpub = with_version([0x04, 0x5F, 0x1C, 0xF6]);
        assert!(vpub.starts_with("vpub"));
        let decoded = decode_extended_key(&vpub).unwrap();
        assert_eq!(decoded.network_kind, NetworkKind::Test);
        assert!(decoded.normalized.starts_with("tpub"));
    }

    #[test]
    fn multisig_prefixes_are_flagged() {
        let zpub_multi = with_version([0x02, 0xAA, 0x7E, 0xD3]);
        assert!(zpub_multi.starts_with("Zpub"));
        let decoded = decode_extended_key(&zpub_multi).unwrap();
        assert!(decoded.multisig_only);
    }

    #[test]
    fn every_private_version_is_rejected() {
        for version in PRIVATE_VERSIONS {
            let key = with_version(*version);
            assert!(
                matches!(
                    decode_extended_key(&key),
                    Err(CoreError::PrivateMaterialRejected)
                ),
                "version {version:02x?} must be rejected as private"
            );
        }
    }

    #[test]
    fn garbage_is_invalid_not_private() {
        assert!(matches!(
            decode_extended_key("xpubnotakey"),
            Err(CoreError::InvalidInput { .. })
        ));
    }
}
