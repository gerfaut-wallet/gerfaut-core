//! Automatic recognition of imported wallet material.
//!
//! Whatever the user pastes, scans, or opens as a file ends up here as
//! text. This module decides what it is (descriptor, extended public key,
//! address, wallet export file), normalizes it into canonical output
//! descriptors, and reports what it understood so the app can ask for
//! confirmation. Detection is never silent.
//!
//! Anything that carries private key material — extended private keys,
//! WIF keys, seed phrases — is rejected before any other processing and
//! is never stored or logged.

pub mod xpub;

use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::bitcoin::base58;
use bdk_wallet::miniscript::ForEachKey;
use bdk_wallet::miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorType};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::network::Network;

/// Upper bound on accepted input size. Descriptors are at most a few
/// kilobytes; anything larger is not wallet material.
const MAX_INPUT_LEN: usize = 64 * 1024;

/// Script type of a wallet, kept explicit next to the descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptKind {
    /// P2PKH (`pkh`)
    Legacy,
    /// P2SH-P2WPKH (`sh(wpkh)`)
    NestedSegwit,
    /// P2WPKH (`wpkh`)
    Segwit,
    /// P2TR (`tr`)
    Taproot,
    /// P2WSH or P2SH-P2WSH script (`wsh`, `sh(wsh)`), multisig included
    WitnessScript,
    /// Bare P2SH script (`sh`)
    LegacyScript,
    /// Bare output (`pk`, raw miniscript)
    Bare,
}

/// What the classifier recognized, for the confirmation screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognizedKind {
    /// A single output descriptor.
    Descriptor,
    /// Two descriptors, receive and change.
    DescriptorPair,
    /// A BIP-389 multipath descriptor (`<0;1>`), split into a pair.
    MultipathDescriptor,
    /// An extended public key, standard or SLIP-132.
    ExtendedKey,
    /// A single Bitcoin address.
    Address,
    /// A wallet export file (JSON).
    WalletExport,
}

/// Non-fatal findings the app must surface on the confirmation screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputWarning {
    /// A bare `xpub`/`tpub` carries no script type; BIP84 (`wpkh`) was
    /// assumed. The user should be offered the alternatives.
    AssumedSegwit,
    /// The key used a SLIP-132 prefix and was normalized to `xpub`/`tpub`.
    Slip132Converted,
    /// A single descriptor with a wildcard but no internal path: change
    /// outputs will not be tracked.
    ChangeNotTracked,
    /// The export file contains several account types; the preferred one
    /// was selected.
    MultipleAccountsInFile,
}

/// Normalized wallet material produced by the classifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParsedPayload {
    /// Canonical descriptors, checksummed.
    Descriptors {
        external: String,
        internal: Option<String>,
        script: ScriptKind,
    },
    /// A single address to watch.
    Address { address: String },
}

/// Full classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInput {
    pub kind: RecognizedKind,
    /// Candidate networks, in display order. More than one entry means
    /// the input alone cannot tell (test networks share encodings) and
    /// the active workspace network decides.
    pub networks: Vec<Network>,
    pub payload: ParsedPayload,
    pub warnings: Vec<InputWarning>,
}

/// Classifies raw user input into wallet material.
///
/// The classification order is: private material rejection, JSON export,
/// descriptor(s), extended public key, address. Errors from a recognized
/// but invalid format are reported as such; only inputs matching nothing
/// at all yield [`CoreError::UnrecognizedInput`].
pub fn parse_input(input: &str) -> CoreResult<ParsedInput> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::UnrecognizedInput("empty input".to_owned()));
    }
    if trimmed.len() > MAX_INPUT_LEN {
        return Err(CoreError::UnrecognizedInput("input too large".to_owned()));
    }

    reject_private_material(trimmed)?;

    if trimmed.starts_with('{') {
        return parse_json_export(trimmed);
    }

    let lines: Vec<&str> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if lines.len() == 2 && lines[0].contains('(') && lines[1].contains('(') {
        return parse_descriptor_pair(lines[0], lines[1]);
    }
    if lines.len() != 1 {
        return Err(CoreError::UnrecognizedInput(
            "expected a single value, or two descriptors on two lines".to_owned(),
        ));
    }
    let token = lines[0];

    if token.contains('(') {
        return parse_single_descriptor(token);
    }
    if xpub::looks_like_extended_key(token) {
        return parse_extended_key(token);
    }
    if let Ok(address) = token.parse::<Address<_>>() {
        return classify_address(address);
    }

    Err(CoreError::UnrecognizedInput(
        "not a descriptor, extended public key, address, or wallet export".to_owned(),
    ))
}

// --- private material rejection ---------------------------------------

/// Base58 alphabet, used to delimit key-like tokens.
fn is_base58_char(c: char) -> bool {
    c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l')
}

/// Rejects any input carrying private key material: extended private
/// keys (all SLIP-132 prefixes), WIF keys, and likely seed phrases.
///
/// This runs before any parsing so that a private input fails with a
/// clear, dedicated error instead of a confusing format error — and so
/// that no other code path ever sees the material.
fn reject_private_material(input: &str) -> CoreResult<()> {
    const PRIVATE_PREFIXES: &[&str] = &[
        "xprv", "yprv", "zprv", "Yprv", "Zprv", "tprv", "uprv", "vprv", "Uprv", "Vprv",
    ];

    for token in input.split(|c: char| !is_base58_char(c)) {
        if token.len() < 20 {
            continue;
        }
        if PRIVATE_PREFIXES.iter().any(|p| token.starts_with(p)) {
            return Err(CoreError::PrivateMaterialRejected);
        }
        // WIF: 51-52 base58check chars, version byte 0x80 (mainnet) or
        // 0xEF (testnet), 32-byte key with optional compression flag.
        if matches!(token.len(), 51 | 52)
            && let Ok(decoded) = base58::decode_check(token)
            && matches!(decoded.len(), 33 | 34)
            && matches!(decoded[0], 0x80 | 0xEF)
        {
            return Err(CoreError::PrivateMaterialRejected);
        }
    }

    // Seed phrase heuristic: BIP39 word counts, all plausible words.
    let words: Vec<&str> = input.split_whitespace().collect();
    if matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return Err(CoreError::PrivateMaterialRejected);
    }

    Ok(())
}

// --- descriptors -------------------------------------------------------

fn parse_descriptor_str(s: &str) -> CoreResult<Descriptor<DescriptorPublicKey>> {
    s.parse::<Descriptor<DescriptorPublicKey>>()
        .map_err(|e| CoreError::InvalidInput {
            kind: "descriptor",
            detail: e.to_string(),
        })
}

fn script_kind_of(descriptor: &Descriptor<DescriptorPublicKey>) -> ScriptKind {
    match descriptor.desc_type() {
        DescriptorType::Pkh => ScriptKind::Legacy,
        DescriptorType::Wpkh => ScriptKind::Segwit,
        DescriptorType::ShWpkh => ScriptKind::NestedSegwit,
        DescriptorType::Tr => ScriptKind::Taproot,
        DescriptorType::Wsh | DescriptorType::ShWsh | DescriptorType::ShWshSortedMulti => {
            ScriptKind::WitnessScript
        }
        DescriptorType::Sh | DescriptorType::ShSortedMulti => ScriptKind::LegacyScript,
        _ => ScriptKind::Bare,
    }
}

/// Candidate networks of a descriptor, from the version bytes of the
/// extended keys it contains. A descriptor without extended keys is
/// network-agnostic.
fn descriptor_networks(descriptor: &Descriptor<DescriptorPublicKey>) -> Vec<Network> {
    let mut kind: Option<NetworkKind> = None;
    descriptor.for_each_key(|key| {
        let key_kind = match key {
            DescriptorPublicKey::XPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::MultiXPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::Single(_) => None,
        };
        if kind.is_none() {
            kind = key_kind;
        }
        true
    });
    networks_for_kind(kind)
}

fn networks_for_kind(kind: Option<NetworkKind>) -> Vec<Network> {
    match kind {
        Some(NetworkKind::Main) => vec![Network::Mainnet],
        Some(NetworkKind::Test) => vec![Network::Signet, Network::Testnet4, Network::Regtest],
        None => Network::ALL.to_vec(),
    }
}

fn parse_single_descriptor(s: &str) -> CoreResult<ParsedInput> {
    let descriptor = parse_descriptor_str(s)?;

    if descriptor.is_multipath() {
        let parts =
            descriptor
                .clone()
                .into_single_descriptors()
                .map_err(|e| CoreError::InvalidInput {
                    kind: "descriptor",
                    detail: format!("invalid multipath descriptor: {e}"),
                })?;
        if parts.len() != 2 {
            return Err(CoreError::InvalidInput {
                kind: "descriptor",
                detail: format!(
                    "multipath descriptors must have exactly 2 paths, found {}",
                    parts.len()
                ),
            });
        }
        return Ok(ParsedInput {
            kind: RecognizedKind::MultipathDescriptor,
            networks: descriptor_networks(&parts[0]),
            payload: ParsedPayload::Descriptors {
                external: parts[0].to_string(),
                internal: Some(parts[1].to_string()),
                script: script_kind_of(&parts[0]),
            },
            warnings: vec![],
        });
    }

    let mut warnings = vec![];
    if descriptor.has_wildcard() {
        warnings.push(InputWarning::ChangeNotTracked);
    }
    Ok(ParsedInput {
        kind: RecognizedKind::Descriptor,
        networks: descriptor_networks(&descriptor),
        payload: ParsedPayload::Descriptors {
            external: descriptor.to_string(),
            internal: None,
            script: script_kind_of(&descriptor),
        },
        warnings,
    })
}

fn parse_descriptor_pair(first: &str, second: &str) -> CoreResult<ParsedInput> {
    let external = parse_descriptor_str(first)?;
    let internal = parse_descriptor_str(second)?;
    if external.is_multipath() || internal.is_multipath() {
        return Err(CoreError::InvalidInput {
            kind: "descriptor",
            detail: "cannot combine a multipath descriptor with a second descriptor".to_owned(),
        });
    }
    let external_networks = descriptor_networks(&external);
    if external_networks != descriptor_networks(&internal) {
        return Err(CoreError::InvalidInput {
            kind: "descriptor",
            detail: "the two descriptors belong to different networks".to_owned(),
        });
    }
    Ok(ParsedInput {
        kind: RecognizedKind::DescriptorPair,
        networks: external_networks,
        payload: ParsedPayload::Descriptors {
            external: external.to_string(),
            internal: Some(internal.to_string()),
            script: script_kind_of(&external),
        },
        warnings: vec![],
    })
}

// --- extended keys -----------------------------------------------------

/// Builds the external/internal descriptor pair for a lone extended key.
fn descriptors_for_xpub(
    key: &str,
    origin: Option<&str>,
    script: ScriptKind,
) -> CoreResult<(String, String)> {
    let origin = origin.unwrap_or("");
    let (external, internal) = match script {
        ScriptKind::Legacy => (
            format!("pkh({origin}{key}/0/*)"),
            format!("pkh({origin}{key}/1/*)"),
        ),
        ScriptKind::NestedSegwit => (
            format!("sh(wpkh({origin}{key}/0/*))"),
            format!("sh(wpkh({origin}{key}/1/*))"),
        ),
        ScriptKind::Segwit => (
            format!("wpkh({origin}{key}/0/*)"),
            format!("wpkh({origin}{key}/1/*)"),
        ),
        ScriptKind::Taproot => (
            format!("tr({origin}{key}/0/*)"),
            format!("tr({origin}{key}/1/*)"),
        ),
        other => {
            return Err(CoreError::Internal(format!(
                "no single-key descriptor template for {other:?}"
            )));
        }
    };
    // Canonicalize through the parser: validates and appends checksums.
    Ok((
        parse_descriptor_str(&external)?.to_string(),
        parse_descriptor_str(&internal)?.to_string(),
    ))
}

fn parse_extended_key(token: &str) -> CoreResult<ParsedInput> {
    let decoded = xpub::decode_extended_key(token)?;
    if decoded.multisig_only {
        return Err(CoreError::InvalidInput {
            kind: "extended key",
            detail: "this prefix marks a multisig cosigner key; import the full multisig \
                     descriptor instead"
                .to_owned(),
        });
    }

    let mut warnings = vec![];
    if decoded.converted {
        warnings.push(InputWarning::Slip132Converted);
    }
    let script = match decoded.script_hint {
        Some(script) => script,
        None => {
            warnings.push(InputWarning::AssumedSegwit);
            ScriptKind::Segwit
        }
    };
    let (external, internal) = descriptors_for_xpub(&decoded.normalized, None, script)?;

    Ok(ParsedInput {
        kind: RecognizedKind::ExtendedKey,
        networks: networks_for_kind(Some(decoded.network_kind)),
        payload: ParsedPayload::Descriptors {
            external,
            internal: Some(internal),
            script,
        },
        warnings,
    })
}

// --- addresses ---------------------------------------------------------

fn classify_address(
    address: Address<bdk_wallet::bitcoin::address::NetworkUnchecked>,
) -> CoreResult<ParsedInput> {
    let networks: Vec<Network> = Network::ALL
        .into_iter()
        .filter(|network| address.is_valid_for_network(network.to_bitcoin()))
        .collect();
    if networks.is_empty() {
        return Err(CoreError::InvalidInput {
            kind: "address",
            detail: "address does not belong to any supported network".to_owned(),
        });
    }
    // Canonical form: bech32 lowercased, base58 unchanged. The network
    // itself was validated just above.
    let canonical = address.assume_checked().to_string();
    Ok(ParsedInput {
        kind: RecognizedKind::Address,
        networks,
        payload: ParsedPayload::Address { address: canonical },
        warnings: vec![],
    })
}

// --- wallet export files ----------------------------------------------

/// Parses JSON wallet exports.
///
/// Supported today: a top-level `descriptor` field (with an optional
/// `change_descriptor`), and Coldcard-style exports (`bip44`/`bip49`/
/// `bip84`/`bip86` account objects with `xpub`, `deriv`, and a master
/// fingerprint). Other formats are reported as unrecognized.
fn parse_json_export(input: &str) -> CoreResult<ParsedInput> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| CoreError::InvalidInput {
            kind: "json",
            detail: e.to_string(),
        })?;

    // Generic: { "descriptor": "...", "change_descriptor": "..."? }
    if let Some(descriptor) = value.get("descriptor").and_then(|v| v.as_str()) {
        let mut parsed = match value.get("change_descriptor").and_then(|v| v.as_str()) {
            Some(change) => parse_descriptor_pair(descriptor, change)?,
            None => parse_single_descriptor(descriptor)?,
        };
        parsed.kind = RecognizedKind::WalletExport;
        return Ok(parsed);
    }

    // Coldcard-style: account objects keyed by BIP, modern first.
    const ACCOUNTS: &[(&str, ScriptKind)] = &[
        ("bip84", ScriptKind::Segwit),
        ("bip86", ScriptKind::Taproot),
        ("bip49", ScriptKind::NestedSegwit),
        ("bip44", ScriptKind::Legacy),
    ];
    let present: Vec<&(&str, ScriptKind)> = ACCOUNTS
        .iter()
        .filter(|(key, _)| value.get(*key).map(|v| v.is_object()) == Some(true))
        .collect();
    if let Some((account_key, script)) = present.first() {
        let account = &value[*account_key];
        let key = account
            .get("xpub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::InvalidInput {
                kind: "wallet export",
                detail: format!("`{account_key}` entry has no xpub"),
            })?;
        let decoded = xpub::decode_extended_key(key)?;

        // Origin: master fingerprint (account-level, else top-level) plus
        // the account derivation path.
        let fingerprint = account
            .get("xfp")
            .or_else(|| value.get("xfp"))
            .and_then(|v| v.as_str());
        let derivation = account.get("deriv").and_then(|v| v.as_str());
        let origin = match (fingerprint, derivation) {
            (Some(fp), Some(deriv)) => {
                let path = deriv.trim_start_matches('m').trim_start_matches('/');
                Some(format!("[{}/{}]", fp.to_lowercase(), path))
            }
            _ => None,
        };

        let (external, internal) =
            descriptors_for_xpub(&decoded.normalized, origin.as_deref(), *script)?;
        let mut warnings = vec![];
        if present.len() > 1 {
            warnings.push(InputWarning::MultipleAccountsInFile);
        }
        return Ok(ParsedInput {
            kind: RecognizedKind::WalletExport,
            networks: networks_for_kind(Some(decoded.network_kind)),
            payload: ParsedPayload::Descriptors {
                external,
                internal: Some(internal),
                script: *script,
            },
            warnings,
        });
    }

    Err(CoreError::UnrecognizedInput(
        "JSON file is not a recognized wallet export".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public two-path descriptor from the BDK documentation.
    const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
    const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";

    fn descriptors(parsed: &ParsedInput) -> (&str, Option<&str>, ScriptKind) {
        match &parsed.payload {
            ParsedPayload::Descriptors {
                external,
                internal,
                script,
            } => (external, internal.as_deref(), *script),
            other => panic!("expected descriptors, got {other:?}"),
        }
    }

    #[test]
    fn multipath_descriptor_splits_into_pair() {
        let parsed = parse_input(MULTIPATH).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::MultipathDescriptor);
        let (external, internal, script) = descriptors(&parsed);
        assert!(external.contains("/0/*"));
        assert!(internal.unwrap().contains("/1/*"));
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.contains('#'), "canonical form carries a checksum");
        assert_eq!(
            parsed.networks,
            vec![Network::Signet, Network::Testnet4, Network::Regtest]
        );
    }

    #[test]
    fn single_descriptor_warns_about_change() {
        let single = format!("wpkh({TPUB}/0/*)");
        let parsed = parse_input(&single).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::Descriptor);
        assert!(parsed.warnings.contains(&InputWarning::ChangeNotTracked));
        let (_, internal, _) = descriptors(&parsed);
        assert!(internal.is_none());
    }

    #[test]
    fn two_lines_form_a_pair() {
        let input = format!("wpkh({TPUB}/0/*)\nwpkh({TPUB}/1/*)");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::DescriptorPair);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn bare_tpub_assumes_segwit() {
        let parsed = parse_input(TPUB).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::ExtendedKey);
        assert!(parsed.warnings.contains(&InputWarning::AssumedSegwit));
        let (external, internal, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.starts_with("wpkh("));
        assert!(external.contains("/0/*"));
        assert!(internal.unwrap().contains("/1/*"));
    }

    #[test]
    fn mainnet_bech32_address() {
        let parsed = parse_input("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(parsed.kind, RecognizedKind::Address);
        assert_eq!(parsed.networks, vec![Network::Mainnet]);
    }

    #[test]
    fn testnet_bech32_address_is_ambiguous() {
        let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
        assert_eq!(parsed.networks, vec![Network::Signet, Network::Testnet4]);
    }

    #[test]
    fn legacy_addresses() {
        let mainnet = parse_input("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        assert_eq!(mainnet.networks, vec![Network::Mainnet]);
        let testnet = parse_input("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn").unwrap();
        assert!(testnet.networks.contains(&Network::Testnet4));
        assert!(!testnet.networks.contains(&Network::Mainnet));
    }

    #[test]
    fn uppercase_bech32_is_canonicalized() {
        let parsed = parse_input("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        match parsed.payload {
            ParsedPayload::Address { address } => {
                assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            }
            other => panic!("expected address, got {other:?}"),
        }
    }

    #[test]
    fn descriptor_with_tprv_is_rejected_as_private() {
        let input = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
        assert!(matches!(
            parse_input(input),
            Err(CoreError::PrivateMaterialRejected)
        ));
    }

    #[test]
    fn wif_is_rejected_as_private() {
        assert!(matches!(
            parse_input("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"),
            Err(CoreError::PrivateMaterialRejected)
        ));
    }

    #[test]
    fn seed_phrase_is_rejected_as_private() {
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        assert!(matches!(
            parse_input(phrase),
            Err(CoreError::PrivateMaterialRejected)
        ));
    }

    #[test]
    fn json_descriptor_export() {
        let json = format!("{{\"descriptor\": \"wpkh({TPUB}/0/*)\"}}");
        let parsed = parse_input(&json).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::WalletExport);
    }

    #[test]
    fn coldcard_style_export() {
        let json = format!(
            "{{\"xfp\": \"0F056943\", \"bip84\": {{\"xpub\": \"{TPUB}\", \
             \"deriv\": \"m/84'/1'/0'\", \"name\": \"p2wpkh\"}}}}"
        );
        let parsed = parse_input(&json).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::WalletExport);
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.contains("[0f056943/84'/1'/0']"));
    }

    #[test]
    fn garbage_is_unrecognized() {
        assert!(matches!(
            parse_input("hello world, this is not wallet material at all"),
            Err(CoreError::UnrecognizedInput(_))
        ));
        assert!(matches!(
            parse_input(""),
            Err(CoreError::UnrecognizedInput(_))
        ));
    }

    #[test]
    fn txid_like_hex_is_unrecognized() {
        assert!(matches!(
            parse_input("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
            Err(CoreError::UnrecognizedInput(_))
        ));
    }
}
