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

pub mod bsms;
pub mod qr;
pub mod xpub;

use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::bitcoin::base58;
use bdk_wallet::miniscript::ForEachKey;
use bdk_wallet::miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorType};
use serde::{Deserialize, Serialize};

use crate::backup::BACKUP_PREFIX;
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
    /// A BSMS descriptor record (BIP-129).
    Bsms,
}

/// Non-fatal findings the app must surface on the confirmation screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputWarning {
    /// A bare `xpub`/`tpub` carries no script type; BIP84 (`wpkh`) was
    /// assumed. The alternatives are listed in `script_options`.
    AssumedSegwit,
    /// The key used a SLIP-132 prefix and was normalized to `xpub`/`tpub`.
    Slip132Converted,
    /// A single descriptor with a wildcard but no internal path: change
    /// outputs will not be tracked.
    ChangeNotTracked,
    /// The export file contains several account types; the preferred one
    /// was selected.
    MultipleAccountsInFile,
    /// The branches differ from the BIP32 convention (`0/*` receive,
    /// `1/*` change): a wallet that follows it shows other addresses.
    NonStandardDerivation,
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
    /// Script types the user may pick instead of the one in `payload`.
    /// Non-empty only when the input does not fix the script type by
    /// itself (a lone extended key). Re-run [`parse_input_with_options`]
    /// with the choice to rebuild the descriptors.
    #[serde(default)]
    pub script_options: Vec<ScriptKind>,
    /// Branches and origin behind `payload` for a lone extended key,
    /// defaults filled in. `None` when the input spells out its own.
    #[serde(default)]
    pub derivation: Option<DerivationChoice>,
    /// True when `derivation` may still be changed; only a lone extended
    /// key leaves it open. Re-run [`parse_input_with_options`] with the
    /// new choice to rebuild the descriptors.
    #[serde(default)]
    pub derivation_editable: bool,
    /// First receive address, derived for the first candidate network,
    /// so the user can compare it with the wallet they are importing.
    /// `None` for single addresses and for descriptors that cannot
    /// derive one.
    #[serde(default)]
    pub preview_address: Option<String>,
}

/// Script types a lone extended key can be imported as.
pub const SINGLE_KEY_SCRIPTS: [ScriptKind; 4] = [
    ScriptKind::Legacy,
    ScriptKind::NestedSegwit,
    ScriptKind::Segwit,
    ScriptKind::Taproot,
];

/// Receive branch every single-key wallet uses, BIP44 through BIP86.
const RECEIVE_BRANCH: &str = "0/*";
/// Change branch of the same convention.
const CHANGE_BRANCH: &str = "1/*";

/// Where a lone extended key derives its addresses from.
///
/// Wallets agree on `0/*` for receive and `1/*` for change, so the
/// defaults cover almost every import. The fields exist for the rest: a
/// key exported one level up, an odd branch, an origin the signer will
/// need in the descriptor later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationChoice {
    /// Receive branch, relative to the key, unhardened, wildcard last
    /// (`0/*`, `*`, `2/0/*`).
    pub receive: String,
    /// Change branch in the same form; `None` leaves change untracked.
    pub change: Option<String>,
    /// Key origin, `[fingerprint/path]`; `None` keeps the one the input
    /// carries, if any.
    pub origin: Option<String>,
}

impl Default for DerivationChoice {
    fn default() -> Self {
        Self {
            receive: RECEIVE_BRANCH.to_owned(),
            change: Some(CHANGE_BRANCH.to_owned()),
            origin: None,
        }
    }
}

/// What the user picked on the confirmation screen. Each choice only
/// applies to inputs that leave it open, which is a lone extended key;
/// the others fix their own and ignore it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportOptions {
    pub script: Option<ScriptKind>,
    pub derivation: Option<DerivationChoice>,
}

/// Classifies raw user input into wallet material.
///
/// The classification order is: private material rejection, JSON export,
/// descriptor(s), extended public key, address. Errors from a recognized
/// but invalid format are reported as such; only inputs matching nothing
/// at all yield [`CoreError::UnrecognizedInput`].
pub fn parse_input(input: &str) -> CoreResult<ParsedInput> {
    parse_input_with_options(input, &ImportOptions::default())
}

/// Same as [`parse_input`], with the script type the user picked for a
/// lone extended key.
pub fn parse_input_with(input: &str, script: Option<ScriptKind>) -> CoreResult<ParsedInput> {
    parse_input_with_options(
        input,
        &ImportOptions {
            script,
            derivation: None,
        },
    )
}

/// Same as [`parse_input`], with everything the user may pick for a
/// lone extended key. Inputs that fix their own script type and paths
/// (`script_options` empty, `derivation_editable` false) ignore the
/// options.
pub fn parse_input_with_options(input: &str, options: &ImportOptions) -> CoreResult<ParsedInput> {
    if bsms::is_bsms(input) {
        return parse_bsms_record(input);
    }
    let mut parsed = classify(input, options)?;
    if parsed.preview_address.is_none() {
        parsed.preview_address = preview_address(&parsed);
    }
    Ok(parsed)
}

/// A BSMS record is its descriptor plus a promise: the first address the
/// coordinator derived. Gerfaut derives it too and refuses the record
/// when the two differ, the same check every signer makes.
fn parse_bsms_record(input: &str) -> CoreResult<ParsedInput> {
    reject_private_material(input.trim())?;
    let record = bsms::parse_bsms(input)?;
    let mut parsed = classify(&record.descriptor, &ImportOptions::default())?;
    parsed.preview_address = preview_address(&parsed);
    match parsed.preview_address.as_deref() {
        Some(derived) if derived.eq_ignore_ascii_case(&record.first_address) => {}
        Some(derived) => {
            return Err(CoreError::InvalidInput {
                kind: "bsms",
                detail: format!(
                    "the first address in the record ({}) is not the one this descriptor derives ({derived}); the file may be altered or belong to another network",
                    record.first_address
                ),
            });
        }
        None => {
            return Err(CoreError::InvalidInput {
                kind: "bsms",
                detail: "the descriptor in the record derives no address".to_owned(),
            });
        }
    }
    parsed.kind = RecognizedKind::Bsms;
    Ok(parsed)
}

fn classify(input: &str, options: &ImportOptions) -> CoreResult<ParsedInput> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::UnrecognizedInput("empty input".to_owned()));
    }
    if trimmed.len() > MAX_INPUT_LEN {
        return Err(CoreError::UnrecognizedInput("input too large".to_owned()));
    }

    reject_private_material(trimmed)?;

    // A backup is restored from the settings, not watched as a wallet.
    if trimmed.starts_with(BACKUP_PREFIX) {
        return Err(CoreError::InvalidInput {
            kind: "backup",
            detail: "this is a Gerfaut backup, not a wallet to watch: restore it from Settings"
                .to_owned(),
        });
    }

    // A pasted QR payload (UR, BBQr) is opened first; a multi-part one
    // cannot be typed in, it has to be scanned frame by frame.
    if qr::is_envelope(trimmed) {
        let progress = qr::assemble(&[trimmed.to_owned()])?;
        return match progress.text {
            Some(text) => classify(&text, options),
            None => Err(CoreError::InvalidInput {
                kind: "qr",
                detail: format!(
                    "this is part 1 of a {}-part QR code: scan it with the camera",
                    progress.total
                ),
            }),
        };
    }

    if trimmed.starts_with('{') {
        return parse_json_export(trimmed);
    }

    // A signed transaction or a PSBT is a thing to broadcast, not a
    // thing to watch: say so instead of "unrecognized".
    if crate::broadcast::looks_like_transaction(trimmed) {
        return Err(CoreError::InvalidInput {
            kind: "transaction",
            detail: "this is a transaction, not a wallet to watch: the Broadcast page sends it"
                .to_owned(),
        });
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
    if let Some((origin, key)) = split_key_origin(token) {
        return parse_extended_key(key, Some(origin), options);
    }
    if xpub::looks_like_extended_key(token) {
        return parse_extended_key(token, None, options);
    }
    if let Ok(address) = token.parse::<Address<_>>() {
        return classify_address(address);
    }

    Err(CoreError::UnrecognizedInput(
        "not a descriptor, extended public key, address, or wallet export".to_owned(),
    ))
}

// --- private material rejection ---------------------------------------

/// Rejects any input carrying private key material: extended private
/// keys (all SLIP-132 prefixes), WIF keys, and likely seed phrases.
///
/// This runs before any parsing so that a private input fails with a
/// clear, dedicated error instead of a confusing format error — and so
/// that no other code path ever sees the material.
pub(crate) fn reject_private_material(input: &str) -> CoreResult<()> {
    for token in input.split(|c: char| !xpub::is_base58_char(c)) {
        if token.len() < 20 {
            continue;
        }
        if xpub::PRIVATE_PREFIXES.iter().any(|p| token.starts_with(p)) {
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
        DescriptorType::Wsh
        | DescriptorType::WshSortedMulti
        | DescriptorType::ShWsh
        | DescriptorType::ShWshSortedMulti => ScriptKind::WitnessScript,
        DescriptorType::Sh | DescriptorType::ShSortedMulti => ScriptKind::LegacyScript,
        _ => ScriptKind::Bare,
    }
}

/// Candidate networks of a descriptor, from the version bytes of the
/// extended keys it contains. A descriptor without extended keys is
/// network-agnostic; one mixing mainnet and test keys is rejected.
fn descriptor_networks(descriptor: &Descriptor<DescriptorPublicKey>) -> CoreResult<Vec<Network>> {
    let mut kinds: Vec<NetworkKind> = Vec::new();
    descriptor.for_each_key(|key| {
        let key_kind = match key {
            DescriptorPublicKey::XPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::MultiXPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::Single(_) => None,
        };
        if let Some(key_kind) = key_kind
            && !kinds.contains(&key_kind)
        {
            kinds.push(key_kind);
        }
        true
    });
    if kinds.len() > 1 {
        return Err(CoreError::InvalidInput {
            kind: "descriptor",
            detail: "the descriptor mixes mainnet and test network keys".to_owned(),
        });
    }
    Ok(networks_for_kind(kinds.first().copied()))
}

fn networks_for_kind(kind: Option<NetworkKind>) -> Vec<Network> {
    match kind {
        Some(NetworkKind::Main) => vec![Network::Mainnet],
        Some(NetworkKind::Test) => vec![Network::Signet, Network::Testnet4, Network::Regtest],
        None => Network::ALL.to_vec(),
    }
}

/// A SLIP-132 key is read the same inside a descriptor as on its own:
/// rewritten to the standard prefix, and said so once.
fn slip132_warning(converted: bool) -> Vec<InputWarning> {
    if converted {
        vec![InputWarning::Slip132Converted]
    } else {
        vec![]
    }
}

/// The prefix of a SLIP-132 key names the script the wallet exported
/// it for: `zpub` a P2WPKH key, `ypub` one under P2SH, `Zpub` a P2WSH
/// cosigner and `Ypub` one under P2SH, `vpub` and the rest the same on
/// a test network. A descriptor that wraps the key in anything else
/// was not written by the wallet that exported the key, or not for
/// it, and the addresses it derives are not the ones that wallet
/// shows. Refused naming both, the prefix and the function, rather
/// than imported as the descriptor says with a notice beside it.
fn check_slip132_hints(
    hints: &[xpub::Slip132Hint],
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> CoreResult<()> {
    use DescriptorType::{ShWpkh, ShWsh, ShWshSortedMulti, Wpkh, Wsh, WshSortedMulti};
    let kind = descriptor.desc_type();
    for hint in hints {
        let (says, agrees) = match (hint.multisig_only, hint.script) {
            (false, Some(ScriptKind::Segwit)) => ("Native SegWit", kind == Wpkh),
            (false, Some(ScriptKind::NestedSegwit)) => ("Nested SegWit", kind == ShWpkh),
            (true, Some(ScriptKind::Segwit)) => (
                "Native SegWit multisig",
                matches!(kind, Wsh | WshSortedMulti),
            ),
            (true, Some(ScriptKind::NestedSegwit)) => (
                "Nested SegWit multisig",
                matches!(kind, ShWsh | ShWshSortedMulti),
            ),
            _ => continue,
        };
        if !agrees {
            return Err(CoreError::InvalidInput {
                kind: "descriptor",
                detail: format!(
                    "the key's {} prefix says {says}, but the descriptor wraps it in {}: \
                     check the export",
                    hint.prefix,
                    descriptor_function(kind)
                ),
            });
        }
    }
    Ok(())
}

/// The outer function of a descriptor, the way it is written.
fn descriptor_function(kind: DescriptorType) -> &'static str {
    match kind {
        DescriptorType::Pkh => "pkh()",
        DescriptorType::Wpkh => "wpkh()",
        DescriptorType::ShWpkh => "sh(wpkh())",
        DescriptorType::Tr => "tr()",
        DescriptorType::Wsh | DescriptorType::WshSortedMulti => "wsh()",
        DescriptorType::ShWsh | DescriptorType::ShWshSortedMulti => "sh(wsh())",
        DescriptorType::Sh | DescriptorType::ShSortedMulti => "sh()",
        _ => "a bare script",
    }
}

fn parse_single_descriptor(s: &str) -> CoreResult<ParsedInput> {
    let (s, hints) = xpub::normalize_descriptor_keys(s)?;
    let descriptor = parse_descriptor_str(&s)?;
    check_slip132_hints(&hints, &descriptor)?;
    let mut warnings = slip132_warning(!hints.is_empty());

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
            networks: descriptor_networks(&parts[0])?,
            payload: ParsedPayload::Descriptors {
                external: parts[0].to_string(),
                internal: Some(parts[1].to_string()),
                script: script_kind_of(&parts[0]),
            },
            warnings,
            script_options: vec![],
            derivation: None,
            derivation_editable: false,
            preview_address: None,
        });
    }

    if descriptor.has_wildcard() {
        warnings.push(InputWarning::ChangeNotTracked);
    }
    Ok(ParsedInput {
        kind: RecognizedKind::Descriptor,
        networks: descriptor_networks(&descriptor)?,
        payload: ParsedPayload::Descriptors {
            external: descriptor.to_string(),
            internal: None,
            script: script_kind_of(&descriptor),
        },
        warnings,
        script_options: vec![],
        derivation: None,
        derivation_editable: false,
        preview_address: None,
    })
}

fn parse_descriptor_pair(first: &str, second: &str) -> CoreResult<ParsedInput> {
    let (first, first_hints) = xpub::normalize_descriptor_keys(first)?;
    let (second, second_hints) = xpub::normalize_descriptor_keys(second)?;
    let external = parse_descriptor_str(&first)?;
    let internal = parse_descriptor_str(&second)?;
    check_slip132_hints(&first_hints, &external)?;
    check_slip132_hints(&second_hints, &internal)?;
    if external.is_multipath() || internal.is_multipath() {
        return Err(CoreError::InvalidInput {
            kind: "descriptor",
            detail: "cannot combine a multipath descriptor with a second descriptor".to_owned(),
        });
    }
    let external_networks = descriptor_networks(&external)?;
    if external_networks != descriptor_networks(&internal)? {
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
        warnings: slip132_warning(!first_hints.is_empty() || !second_hints.is_empty()),
        script_options: vec![],
        derivation: None,
        derivation_editable: false,
        preview_address: None,
    })
}

// --- extended keys -----------------------------------------------------

/// Builds the descriptors of a lone extended key: external on the
/// receive branch, internal on the change branch when there is one.
fn descriptors_for_xpub(
    key: &str,
    script: ScriptKind,
    derivation: &DerivationChoice,
) -> CoreResult<(String, Option<String>)> {
    let origin = derivation.origin.as_deref().unwrap_or("");
    let build = |branch: &str| -> CoreResult<String> {
        let key = format!("{origin}{key}/{branch}");
        let descriptor = match script {
            ScriptKind::Legacy => format!("pkh({key})"),
            ScriptKind::NestedSegwit => format!("sh(wpkh({key}))"),
            ScriptKind::Segwit => format!("wpkh({key})"),
            ScriptKind::Taproot => format!("tr({key})"),
            other => {
                return Err(CoreError::Internal(format!(
                    "no single-key descriptor template for {other:?}"
                )));
            }
        };
        // Canonicalize through the parser: validates and appends checksums.
        Ok(parse_descriptor_str(&descriptor)?.to_string())
    };
    let external = build(&derivation.receive)?;
    let internal = derivation.change.as_deref().map(build).transpose()?;
    Ok((external, internal))
}

/// Splits a key-origin prefixed extended key, `[fingerprint/path]xpub…`,
/// into its origin (brackets included) and the key. Returns `None` for
/// anything else.
fn split_key_origin(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix('[')?;
    let close = rest.find(']')?;
    let origin = &token[..close + 2];
    let key = &rest[close + 1..];
    (key.len() > 20 && xpub::looks_like_extended_key(key)).then_some((origin, key))
}

/// Script type implied by the purpose level of a key origin path
/// (`[fp/84'/0'/0']`): BIP44, BIP49, BIP84, BIP86. `None` when the path
/// starts elsewhere.
fn script_from_origin(origin: &str) -> Option<ScriptKind> {
    let path = origin.trim_start_matches('[').trim_end_matches(']');
    let purpose = path.split('/').nth(1)?;
    match purpose.trim_end_matches(['\'', 'h', 'H']) {
        "44" => Some(ScriptKind::Legacy),
        "49" => Some(ScriptKind::NestedSegwit),
        "84" => Some(ScriptKind::Segwit),
        "86" => Some(ScriptKind::Taproot),
        _ => None,
    }
}

/// First hardened index; a public key stops deriving right below it.
const HARDENED_INDEX: u32 = 1 << 31;

fn derivation_error(detail: String) -> CoreError {
    CoreError::InvalidInput {
        kind: "derivation path",
        detail,
    }
}

/// One step of a path: its index and whether it is hardened. The error
/// is a sentence tail to hang after the path's name.
fn parse_step(step: &str) -> Result<(u32, bool), String> {
    if step.is_empty() {
        return Err("has an empty step".to_owned());
    }
    let (digits, hardened) = match step.strip_suffix(['\'', 'h', 'H']) {
        Some(digits) => (digits, true),
        None => (step, false),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("has a step that is not a number (`{step}`)"));
    }
    let index = digits
        .parse::<u32>()
        .ok()
        .filter(|index| *index < HARDENED_INDEX)
        .ok_or_else(|| format!("has an index above {} (`{step}`)", HARDENED_INDEX - 1))?;
    Ok((index, hardened))
}

/// Checks a receive or change branch and returns it in canonical form.
/// An extended public key only derives unhardened children, and the
/// wildcard has to come last so that every address gets its own index.
fn canonical_branch(path: &str, which: &str) -> CoreResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(derivation_error(format!(
            "the {which} path is empty; wallets use `0/*` for receive and `1/*` for change"
        )));
    }
    let refuse = |reason: String| derivation_error(format!("the {which} path `{path}` {reason}"));
    let steps = match path.strip_suffix('*') {
        Some("") => "",
        Some(steps) => steps
            .strip_suffix('/')
            .ok_or_else(|| refuse("must end with `/*`".to_owned()))?,
        None => {
            return Err(refuse(
                "must end with `*`, the placeholder for the address index".to_owned(),
            ));
        }
    };
    let steps = steps.strip_prefix('/').unwrap_or(steps);
    let mut canonical = Vec::new();
    if !steps.is_empty() {
        for step in steps.split('/') {
            if step == "*" {
                return Err(refuse(
                    "has `*` before the end; it can only be the last step".to_owned(),
                ));
            }
            let (index, hardened) = parse_step(step).map_err(&refuse)?;
            if hardened {
                return Err(refuse(format!(
                    "has a hardened step (`{step}`): an extended public key cannot derive \
                     hardened children"
                )));
            }
            canonical.push(index.to_string());
        }
    }
    canonical.push("*".to_owned());
    Ok(canonical.join("/"))
}

/// Checks a key origin and returns it in canonical form,
/// `[fingerprint/path]` with `'` on hardened steps, the way the
/// descriptor prints it. Hardened steps are fine here: the origin
/// records what the signer derived, not what this key will.
fn canonical_origin(origin: &str) -> CoreResult<String> {
    let origin = origin.trim();
    let refuse = |reason: String| derivation_error(format!("the key origin `{origin}` {reason}"));
    let inner = match origin
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        Some(inner) => inner,
        None if origin.starts_with('[') || origin.ends_with(']') => {
            return Err(refuse(
                "must be written between brackets, `[fingerprint/path]`".to_owned(),
            ));
        }
        None => origin,
    };
    let mut steps = inner.split('/');
    let fingerprint = steps.next().unwrap_or_default();
    if fingerprint.len() != 8 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refuse(format!(
            "must start with the master key fingerprint, 8 hexadecimal characters, not \
             `{fingerprint}`"
        )));
    }
    let mut canonical = fingerprint.to_ascii_lowercase();
    for step in steps {
        if step.contains('*') {
            return Err(refuse(
                "cannot contain a wildcard; `*` belongs to the receive and change paths".to_owned(),
            ));
        }
        let (index, hardened) = parse_step(step).map_err(&refuse)?;
        canonical.push('/');
        canonical.push_str(&index.to_string());
        if hardened {
            canonical.push('\'');
        }
    }
    Ok(format!("[{canonical}]"))
}

/// The derivation in effect for a lone extended key: the user's choice
/// when there is one, the BIP32 convention otherwise, and the origin
/// the input carries unless the choice names another.
fn effective_derivation(
    input_origin: Option<&str>,
    choice: Option<&DerivationChoice>,
) -> CoreResult<DerivationChoice> {
    let default = DerivationChoice::default();
    let choice = choice.unwrap_or(&default);
    let receive = canonical_branch(&choice.receive, "receive")?;
    let change = choice
        .change
        .as_deref()
        .map(|change| canonical_branch(change, "change"))
        .transpose()?;
    if change.as_deref() == Some(receive.as_str()) {
        return Err(derivation_error(format!(
            "the receive and change paths are both `{receive}`; change needs its own branch"
        )));
    }
    let origin = choice
        .origin
        .as_deref()
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .or(input_origin)
        .map(canonical_origin)
        .transpose()?;
    Ok(DerivationChoice {
        receive,
        change,
        origin,
    })
}

/// A lone extended key, with or without a key origin.
///
/// The script type comes, in order, from the user's explicit choice,
/// the SLIP-132 prefix (`ypub`, `zpub`, …), the purpose of the origin
/// path, and finally the BIP84 default with a warning. The branches
/// come from the user's choice or the BIP32 convention. In every case
/// the user may still switch: `script_options` lists the alternatives
/// and `derivation_editable` opens the paths.
fn parse_extended_key(
    token: &str,
    origin: Option<&str>,
    options: &ImportOptions,
) -> CoreResult<ParsedInput> {
    let decoded = xpub::decode_extended_key(token)?;
    if decoded.multisig_only {
        return Err(CoreError::InvalidInput {
            kind: "extended key",
            detail: "this prefix marks a multisig cosigner key; import the full multisig \
                     descriptor instead"
                .to_owned(),
        });
    }
    if let Some(choice) = options.script
        && !SINGLE_KEY_SCRIPTS.contains(&choice)
    {
        return Err(CoreError::InvalidInput {
            kind: "script type",
            detail: format!("{choice:?} cannot be built from a single key"),
        });
    }
    let derivation = effective_derivation(origin, options.derivation.as_ref())?;

    let mut warnings = vec![];
    if decoded.converted {
        warnings.push(InputWarning::Slip132Converted);
    }
    let script = match (
        options.script,
        decoded.script_hint,
        derivation.origin.as_deref().and_then(script_from_origin),
    ) {
        (Some(choice), ..) => choice,
        (None, Some(hint), _) | (None, None, Some(hint)) => hint,
        (None, None, None) => {
            warnings.push(InputWarning::AssumedSegwit);
            ScriptKind::Segwit
        }
    };
    let (external, internal) = descriptors_for_xpub(&decoded.normalized, script, &derivation)?;
    if derivation.receive != RECEIVE_BRANCH || derivation.change.as_deref() != Some(CHANGE_BRANCH) {
        warnings.push(InputWarning::NonStandardDerivation);
    }
    if internal.is_none() {
        warnings.push(InputWarning::ChangeNotTracked);
    }

    Ok(ParsedInput {
        kind: RecognizedKind::ExtendedKey,
        networks: networks_for_kind(Some(decoded.network_kind)),
        payload: ParsedPayload::Descriptors {
            external,
            internal,
            script,
        },
        warnings,
        script_options: SINGLE_KEY_SCRIPTS.to_vec(),
        derivation: Some(derivation),
        derivation_editable: true,
        preview_address: None,
    })
}

/// First receive address of a descriptor payload, on the first
/// candidate network. Best effort: a descriptor that cannot derive
/// (bare miniscript, no wildcard on a script we cannot address) yields
/// `None` rather than an error, the import itself is unaffected.
fn preview_address(parsed: &ParsedInput) -> Option<String> {
    let ParsedPayload::Descriptors { external, .. } = &parsed.payload else {
        return None;
    };
    let network = parsed.networks.first()?.to_bitcoin();
    let descriptor = external.parse::<Descriptor<DescriptorPublicKey>>().ok()?;
    let definite = descriptor.at_derivation_index(0).ok()?;
    definite.address(network).ok().map(|a| a.to_string())
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
        script_options: vec![],
        derivation: None,
        derivation_editable: false,
        preview_address: None,
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

        let derivation = DerivationChoice {
            origin,
            ..DerivationChoice::default()
        };
        let (external, internal) = descriptors_for_xpub(&decoded.normalized, *script, &derivation)?;
        let mut warnings = vec![];
        if present.len() > 1 {
            warnings.push(InputWarning::MultipleAccountsInFile);
        }
        return Ok(ParsedInput {
            kind: RecognizedKind::WalletExport,
            networks: networks_for_kind(Some(decoded.network_kind)),
            payload: ParsedPayload::Descriptors {
                external,
                internal,
                script: *script,
            },
            warnings,
            script_options: vec![],
            derivation: None,
            derivation_editable: false,
            preview_address: None,
        });
    }

    Err(CoreError::UnrecognizedInput(
        "JSON file is not a recognized wallet export".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use bdk_wallet::miniscript::descriptor::checksum::desc_checksum;

    use super::*;

    /// Public two-path descriptor from the BDK documentation.
    const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
    const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";
    /// BIP32 test vector 1, master public key.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    /// First receive address of `TPUB` on the default derivation.
    const DEFAULT_PREVIEW: &str = "tb1qh9ruph54tnfveh7dtve3nrfx26p56rx4q4l0zx";
    /// BIP32 test vector 1, master private key: the one private key
    /// these tests may spell, because everybody already knows it.
    const TPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";

    /// SLIP-132 version bytes: public single-sig test, native (`vpub`)
    /// and nested (`upub`); public multisig test, native (`Vpub`) and
    /// nested (`Upub`); public main, single-sig (`zpub`) and multisig
    /// (`Zpub`); and private single-sig test (`vprv`).
    const VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
    const UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
    const VPUB_MULTI: [u8; 4] = [0x02, 0x57, 0x54, 0x83];
    const UPUB_MULTI: [u8; 4] = [0x02, 0x42, 0x89, 0xEF];
    const ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
    const ZPUB_MULTI: [u8; 4] = [0x02, 0xAA, 0x7E, 0xD3];
    const VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];

    /// `key` re-encoded under other version bytes, the way a wallet
    /// exporting SLIP-132 spells the very same key.
    fn slip132(key: &str, version: [u8; 4]) -> String {
        let mut data = base58::decode_check(key).unwrap();
        data[..4].copy_from_slice(&version);
        base58::encode_check(&data)
    }

    fn with_derivation(receive: &str, change: Option<&str>, origin: Option<&str>) -> ImportOptions {
        ImportOptions {
            script: None,
            derivation: Some(DerivationChoice {
                receive: receive.to_owned(),
                change: change.map(str::to_owned),
                origin: origin.map(str::to_owned),
            }),
        }
    }

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

    /// A descriptor written with a SLIP-132 key reads exactly as the
    /// same descriptor written with the standard key, plus the notice
    /// that the key was rewritten, when the prefix and the function
    /// agree, as an export's do.
    #[test]
    fn a_slip132_key_inside_a_descriptor_is_read_as_the_standard_one() {
        let vpub = slip132(TPUB, VPUB);
        assert!(vpub.starts_with("vpub"));
        let parsed = parse_input(&MULTIPATH.replace(TPUB, &vpub)).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::MultipathDescriptor);
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        assert_eq!(
            parsed.networks,
            vec![Network::Signet, Network::Testnet4, Network::Regtest]
        );
        let (external, internal, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.starts_with("wpkh([9a6a2580/84'/1'/0']tpub"));
        assert!(!external.contains(&vpub));
        assert!(internal.unwrap().contains("/1/*"));

        let standard = parse_input(MULTIPATH).unwrap();
        assert_eq!(descriptors(&parsed), descriptors(&standard));
        assert_eq!(parsed.preview_address, standard.preview_address);
        assert!(parsed.script_options.is_empty());
        assert!(!parsed.derivation_editable);
    }

    /// The checksum covers the text as written: rewriting a key inside
    /// it makes it stale, so it is recomputed. One that was wrong to
    /// begin with is still refused, before any key is looked at.
    #[test]
    fn a_checksummed_slip132_descriptor_is_accepted() {
        let vpub = slip132(TPUB, VPUB);
        let body = format!("wpkh({vpub}/0/*)");
        let input = format!("{body}#{}", desc_checksum(&body).unwrap());
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::Descriptor);
        assert!(parsed.warnings.contains(&InputWarning::Slip132Converted));
        let (external, _, _) = descriptors(&parsed);
        assert_eq!(external, format!("wpkh({TPUB}/0/*)#dmh8w44d"));

        let error = parse_input(&format!("{body}#00000000"))
            .unwrap_err()
            .to_string();
        assert!(error.to_lowercase().contains("checksum"), "{error}");
    }

    #[test]
    fn a_pair_of_slip132_descriptors_is_said_to_be_converted_once() {
        let vpub = slip132(TPUB, VPUB);
        let input = format!("wpkh({vpub}/0/*)\nwpkh({vpub}/1/*)");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::DescriptorPair);
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        let (external, internal, _) = descriptors(&parsed);
        assert_eq!(external, format!("wpkh({TPUB}/0/*)#dmh8w44d"));
        assert_eq!(internal.unwrap(), format!("wpkh({TPUB}/1/*)#u0jxnq94"));

        // One converted line is enough to say so.
        let input = format!("wpkh({TPUB}/0/*)\nwpkh({vpub}/1/*)");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
    }

    #[test]
    fn a_descriptor_may_spell_its_keys_both_ways() {
        let cosigner = slip132(XPUB, ZPUB_MULTI);
        let input = format!("wsh(multi(1,{XPUB}/<0;1>/*,{cosigner}/<2;3>/*))");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::MultipathDescriptor);
        assert_eq!(parsed.networks, vec![Network::Mainnet]);
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::WitnessScript);
        assert_eq!(external.matches(XPUB).count(), 2, "{external}");
    }

    /// The multisig prefixes are refused on their own, since a lone
    /// cosigner key makes no wallet; inside the multisig descriptor
    /// they were exported for, they read as the keys they are.
    #[test]
    fn multisig_prefixes_are_read_inside_a_multisig_descriptor() {
        let cosigner = slip132(TPUB, VPUB_MULTI);
        assert!(cosigner.starts_with("Vpub"));
        let input = format!(
            "wsh(sortedmulti(1,[9a6a2580/48'/1'/0'/2']{cosigner}/<0;1>/*,[00000000/48'/1'/0'/2']{cosigner}/<2;3>/*))"
        );
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::MultipathDescriptor);
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::WitnessScript);
        assert!(external.starts_with("wsh(sortedmulti(1,[9a6a2580/48'/1'/0'/2']tpub"));
        assert!(parsed.preview_address.unwrap().starts_with("tb1q"));

        let error = parse_input(&cosigner).unwrap_err().to_string();
        assert!(error.contains("multisig"), "{error}");
    }

    /// A rewritten key keeps its network: a mainnet `zpub` next to a
    /// test `tpub` is the same mix it was, and refused the same way.
    #[test]
    fn a_slip132_key_keeps_its_network_inside_a_descriptor() {
        let cosigner = slip132(XPUB, ZPUB_MULTI);
        let error = parse_input(&format!("wsh(multi(1,{cosigner}/0/*,{TPUB}/0/*))"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("mixes mainnet and test"), "{error}");
    }

    /// The prefix names the script the key was exported for, and the
    /// descriptor has to agree: a `zpub` under `pkh()`, `tr()` or a
    /// multisig, a `upub` under `wpkh()`, is a descriptor written for
    /// another key, and the addresses it derives are not the exporting
    /// wallet's. Refused naming both, on either line of a pair.
    #[test]
    fn a_slip132_prefix_the_descriptor_contradicts_is_refused() {
        let zpub = slip132(XPUB, ZPUB);
        let error = parse_input(&format!("pkh({zpub}/0/*)"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid descriptor: the key's zpub prefix says Native SegWit, but the descriptor \
             wraps it in pkh(): check the export"
        );
        let error = parse_input(&format!("tr({zpub}/0/*)"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("wraps it in tr()"), "{error}");
        let error = parse_input(&format!("wsh(multi(1,{zpub}/0/*,{XPUB}/0/*))"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("says Native SegWit, but the descriptor wraps it in wsh()"),
            "{error}"
        );

        let upub = slip132(TPUB, UPUB);
        let error = parse_input(&format!("wpkh({upub}/0/*)"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid descriptor: the key's upub prefix says Nested SegWit, but the descriptor \
             wraps it in wpkh(): check the export"
        );

        let vpub = slip132(TPUB, VPUB);
        let error = parse_input(&format!("wpkh({vpub}/0/*)\nsh(wpkh({vpub}/1/*))"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("wraps it in sh(wpkh())"), "{error}");
    }

    /// A prefix that agrees with the function passes with the notice
    /// that the key was rewritten, and nothing else: `upub` under
    /// `sh(wpkh())`, `Upub` under `sh(wsh())`.
    #[test]
    fn a_slip132_prefix_the_descriptor_agrees_with_is_read() {
        let upub = slip132(TPUB, UPUB);
        let parsed = parse_input(&format!("sh(wpkh({upub}/<0;1>/*))")).unwrap();
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::NestedSegwit);
        assert!(external.starts_with("sh(wpkh(tpub"), "{external}");

        let cosigner = slip132(TPUB, UPUB_MULTI);
        let parsed = parse_input(&format!(
            "sh(wsh(sortedmulti(1,{cosigner}/<0;1>/*,{TPUB}/<0;1>/*)))"
        ))
        .unwrap();
        assert_eq!(parsed.warnings, vec![InputWarning::Slip132Converted]);
        assert_eq!(descriptors(&parsed).2, ScriptKind::WitnessScript);
    }

    /// A multisig prefix marks a cosigner key: under a single-key
    /// function it was pasted where it does not belong, and under the
    /// other multisig wrapper it was exported for another setup.
    #[test]
    fn a_multisig_prefix_in_a_single_key_descriptor_is_refused() {
        let cosigner = slip132(TPUB, VPUB_MULTI);
        let error = parse_input(&format!("wpkh({cosigner}/0/*)"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "invalid descriptor: the key's Vpub prefix says Native SegWit multisig, but the \
             descriptor wraps it in wpkh(): check the export"
        );
        let error = parse_input(&format!("sh(wsh(multi(1,{cosigner}/0/*,{TPUB}/0/*)))"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("says Native SegWit multisig, but the descriptor wraps it in sh(wsh())"),
            "{error}"
        );
    }

    /// The rewrite only touches descriptors: an address is not scanned
    /// for keys, a JSON export is read field by field, and a field that
    /// holds a descriptor is read like a pasted one.
    #[test]
    fn the_rewrite_reaches_descriptors_and_nothing_else() {
        let address = parse_input("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert!(address.warnings.is_empty());

        let standard = parse_input(&format!("{{\"descriptor\": \"wpkh({TPUB}/0/*)\"}}")).unwrap();
        assert!(!standard.warnings.contains(&InputWarning::Slip132Converted));

        let vpub = slip132(TPUB, VPUB);
        let export = parse_input(&format!("{{\"descriptor\": \"wpkh({vpub}/0/*)\"}}")).unwrap();
        assert_eq!(export.kind, RecognizedKind::WalletExport);
        assert!(export.warnings.contains(&InputWarning::Slip132Converted));
        let (external, _, _) = descriptors(&export);
        assert_eq!(external, format!("wpkh({TPUB}/0/*)#dmh8w44d"));

        // A Coldcard-style export names its script by account, and its
        // key is decoded as a key, not rewritten as text.
        let zpub = slip132(XPUB, ZPUB);
        let coldcard = parse_input(&format!(
            "{{\"xfp\": \"0F056943\", \"bip84\": {{\"xpub\": \"{zpub}\", \"deriv\": \"m/84'/0'/0'\"}}}}"
        ))
        .unwrap();
        assert_eq!(coldcard.kind, RecognizedKind::WalletExport);
        let (external, _, script) = descriptors(&coldcard);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.contains(XPUB));
    }

    #[test]
    fn a_slip132_private_key_inside_a_descriptor_is_rejected() {
        let vprv = slip132(TPRV, VPRV);
        assert!(vprv.starts_with("vprv"));
        assert!(matches!(
            parse_input(&format!("wpkh({vprv}/0/*)")),
            Err(CoreError::PrivateMaterialRejected)
        ));
        assert!(matches!(
            parse_input(&format!("wpkh({vprv}/0/*)\nwpkh({vprv}/1/*)")),
            Err(CoreError::PrivateMaterialRejected)
        ));
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
    fn a_backup_is_refused_by_name() {
        let refused = |input: &str| {
            let error = parse_input(input).unwrap_err();
            assert!(
                matches!(error, CoreError::InvalidInput { kind: "backup", .. }),
                "{error}"
            );
            assert!(error.to_string().contains("restore it"), "{error}");
        };
        refused("gerfaut-backup:R0ZCQUNLVVAAAQ==");
        // The same backup scanned as a single ur:bytes frame.
        let mut bytes = crate::store::cipher::BACKUP_MAGIC.to_vec();
        bytes.extend([1u8; 20]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&ciborium::Value::Bytes(bytes), &mut cbor).unwrap();
        refused(&ur::ur::encode(&cbor, &ur::ur::Type::Bytes));
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
        assert_eq!(parsed.script_options, SINGLE_KEY_SCRIPTS.to_vec());
        let preview = parsed.preview_address.as_deref().unwrap();
        assert!(preview.starts_with("tb1q"), "{preview}");
    }

    #[test]
    fn chosen_script_rebuilds_the_descriptors() {
        let taproot = parse_input_with(TPUB, Some(ScriptKind::Taproot)).unwrap();
        let (external, _, script) = descriptors(&taproot);
        assert_eq!(script, ScriptKind::Taproot);
        assert!(external.starts_with("tr("));
        assert!(!taproot.warnings.contains(&InputWarning::AssumedSegwit));
        assert!(taproot.preview_address.unwrap().starts_with("tb1p"));

        let legacy = parse_input_with(TPUB, Some(ScriptKind::Legacy)).unwrap();
        let (external, _, _) = descriptors(&legacy);
        assert!(external.starts_with("pkh("));
        let preview = legacy.preview_address.unwrap();
        assert!(
            preview.starts_with('m') || preview.starts_with('n'),
            "{preview}"
        );

        let nested = parse_input_with(TPUB, Some(ScriptKind::NestedSegwit)).unwrap();
        assert!(nested.preview_address.unwrap().starts_with('2'));
    }

    #[test]
    fn choice_is_ignored_for_fixed_inputs() {
        let single = format!("wpkh({TPUB}/0/*)");
        let parsed = parse_input_with(&single, Some(ScriptKind::Taproot)).unwrap();
        let (_, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(parsed.script_options.is_empty());
        assert!(parsed.preview_address.unwrap().starts_with("tb1q"));
    }

    #[test]
    fn multisig_scripts_cannot_be_chosen_for_a_key() {
        assert!(matches!(
            parse_input_with(TPUB, Some(ScriptKind::WitnessScript)),
            Err(CoreError::InvalidInput {
                kind: "script type",
                ..
            })
        ));
    }

    #[test]
    fn key_origin_sets_the_script_type() {
        let input = format!("[9a6a2580/86'/1'/0']{TPUB}");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::ExtendedKey);
        assert!(parsed.warnings.is_empty());
        let (external, internal, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Taproot);
        assert!(external.starts_with("tr([9a6a2580/86'/1'/0']"));
        assert!(internal.unwrap().contains("/1/*"));

        let hardened_h = format!("[9a6a2580/49h/1h/0h]{TPUB}");
        let (_, _, script) = descriptors(&parse_input(&hardened_h).unwrap());
        assert_eq!(script, ScriptKind::NestedSegwit);

        let unknown_purpose = format!("[9a6a2580/0'/1'/0']{TPUB}");
        let parsed = parse_input(&unknown_purpose).unwrap();
        assert!(parsed.warnings.contains(&InputWarning::AssumedSegwit));
    }

    #[test]
    fn bsms_record_is_checked_against_its_first_address() {
        let template = format!(
            "wsh(sortedmulti(1,[9a6a2580/48'/1'/0'/2']{TPUB}/**,[00000000/48'/1'/0'/2']{TPUB}/**))"
        );
        // Derive the truth once through the classifier itself.
        let truth = parse_input(&template.replace("/**", "/<0;1>/*")).unwrap();
        let first = truth.preview_address.clone().unwrap();

        let record = format!("BSMS 1.0\n{template}\n/0/*,/1/*\n{first}\n");
        let parsed = parse_input(&record).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::Bsms);
        let (external, internal, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::WitnessScript);
        assert!(external.contains("/0/*") && internal.unwrap().contains("/1/*"));
        assert_eq!(parsed.preview_address.as_deref(), Some(first.as_str()));

        let tampered = format!(
            "BSMS 1.0\n{template}\n/0/*,/1/*\ntb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx\n"
        );
        let error = parse_input(&tampered).unwrap_err().to_string();
        assert!(error.contains("first address"), "{error}");

        let private = format!("BSMS 1.0\nwsh(pk({TPRV}/**))\n/0/*,/1/*\n{first}\n");
        assert!(matches!(
            parse_input(&private),
            Err(CoreError::PrivateMaterialRejected)
        ));
    }

    #[test]
    fn sorted_multisig_is_a_witness_script() {
        let input = format!("wsh(sortedmulti(1,{TPUB}/<0;1>/*,{TPUB}/<2;3>/*))");
        let parsed = parse_input(&input).unwrap();
        assert_eq!(parsed.kind, RecognizedKind::MultipathDescriptor);
        let (_, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::WitnessScript);
        assert!(parsed.preview_address.unwrap().starts_with("tb1q"));
    }

    #[test]
    fn address_has_no_preview() {
        let parsed = parse_input("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert!(parsed.preview_address.is_none());
        assert!(parsed.script_options.is_empty());
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
        let input = format!("wpkh({TPRV}/84'/1'/0'/0/*)");
        assert!(matches!(
            parse_input(&input),
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

    #[test]
    fn default_derivation_matches_the_plain_import() {
        let parsed = parse_input_with_options(TPUB, &ImportOptions::default()).unwrap();
        let (external, internal, _) = descriptors(&parsed);
        assert_eq!(external, format!("wpkh({TPUB}/0/*)#dmh8w44d"));
        assert_eq!(internal.unwrap(), format!("wpkh({TPUB}/1/*)#u0jxnq94"));
        assert!(parsed.derivation_editable);
        assert_eq!(parsed.derivation, Some(DerivationChoice::default()));
        assert!(
            !parsed
                .warnings
                .contains(&InputWarning::NonStandardDerivation)
        );
        assert_eq!(parsed.preview_address.as_deref(), Some(DEFAULT_PREVIEW));
    }

    #[test]
    fn key_origin_fills_the_derivation() {
        let parsed = parse_input(&format!("[9a6a2580/84h/1h/0h]{TPUB}")).unwrap();
        assert!(parsed.derivation_editable);
        assert!(parsed.warnings.is_empty());
        let derivation = parsed.derivation.as_ref().unwrap();
        assert_eq!(derivation.origin.as_deref(), Some("[9a6a2580/84'/1'/0']"));
        assert_eq!(derivation.receive, "0/*");
        assert_eq!(derivation.change.as_deref(), Some("1/*"));
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.starts_with("wpkh([9a6a2580/84'/1'/0']"));
    }

    #[test]
    fn untracked_change_is_a_single_descriptor() {
        let options = with_derivation("0/*", None, None);
        let parsed = parse_input_with_options(TPUB, &options).unwrap();
        let (external, internal, _) = descriptors(&parsed);
        assert_eq!(external, format!("wpkh({TPUB}/0/*)#dmh8w44d"));
        assert!(internal.is_none());
        assert!(parsed.warnings.contains(&InputWarning::ChangeNotTracked));
        assert!(
            parsed
                .warnings
                .contains(&InputWarning::NonStandardDerivation)
        );
        assert_eq!(parsed.derivation.unwrap().change, None);
    }

    #[test]
    fn custom_branches_rebuild_both_descriptors() {
        let options = with_derivation("5/*", Some("6/*"), None);
        let parsed = parse_input_with_options(TPUB, &options).unwrap();
        let (external, internal, _) = descriptors(&parsed);
        assert!(external.contains(&format!("{TPUB}/5/*")), "{external}");
        assert!(internal.unwrap().contains(&format!("{TPUB}/6/*")));
        assert!(
            parsed
                .warnings
                .contains(&InputWarning::NonStandardDerivation)
        );
        assert!(!parsed.warnings.contains(&InputWarning::ChangeNotTracked));
        let preview = parsed.preview_address.unwrap();
        assert!(preview.starts_with("tb1q"), "{preview}");
        assert_ne!(preview, DEFAULT_PREVIEW);
    }

    #[test]
    fn branches_are_canonicalized() {
        let options = with_derivation(" 007/* ", Some("/*"), None);
        let parsed = parse_input_with_options(TPUB, &options).unwrap();
        let derivation = parsed.derivation.as_ref().unwrap();
        assert_eq!(derivation.receive, "7/*");
        assert_eq!(derivation.change.as_deref(), Some("*"));
        let (external, internal, _) = descriptors(&parsed);
        assert!(external.contains(&format!("{TPUB}/7/*")));
        assert!(internal.unwrap().contains(&format!("{TPUB}/*)")));
    }

    #[test]
    fn bad_branches_are_refused_as_derivation_paths() {
        let rejected = |receive: &str, change: Option<&str>| {
            let options = with_derivation(receive, change, None);
            match parse_input_with_options(TPUB, &options) {
                Err(CoreError::InvalidInput {
                    kind: "derivation path",
                    detail,
                }) => detail,
                other => panic!("{receive:?}/{change:?} should be refused, got {other:?}"),
            }
        };
        assert!(rejected("0'/*", Some("1/*")).contains("hardened"));
        assert!(rejected("0h/*", Some("1/*")).contains("hardened"));
        assert!(rejected("0/*", Some("1H/*")).contains("hardened"));
        assert!(rejected("0", Some("1/*")).contains('*'));
        assert!(rejected("0*", Some("1/*")).contains("/*"));
        assert!(rejected("0/*", Some("0/*")).contains("both"));
        assert!(rejected("", Some("1/*")).contains("empty"));
        assert!(rejected("0//*", Some("1/*")).contains("empty step"));
        assert!(rejected("a/*", Some("1/*")).contains("not a number"));
        assert!(rejected("2147483648/*", Some("1/*")).contains("above"));
        assert!(rejected("*/0/*", Some("1/*")).contains("last"));
    }

    #[test]
    fn bad_origins_are_refused_as_derivation_paths() {
        let rejected = |origin: &str| {
            let options = with_derivation("0/*", Some("1/*"), Some(origin));
            match parse_input_with_options(TPUB, &options) {
                Err(CoreError::InvalidInput {
                    kind: "derivation path",
                    detail,
                }) => detail,
                other => panic!("{origin:?} should be refused, got {other:?}"),
            }
        };
        assert!(rejected("[zz]").contains("fingerprint"));
        assert!(rejected("[deadbeef0/84']").contains("fingerprint"));
        assert!(rejected("[deadbeef/84'/*]").contains("wildcard"));
        assert!(rejected("[deadbeef/84'/x]").contains("not a number"));
        assert!(rejected("[deadbeef/84'/]").contains("empty step"));
        assert!(rejected("[deadbeef/84'").contains("brackets"));
    }

    #[test]
    fn chosen_origin_overrides_the_input() {
        let options = with_derivation("0/*", Some("1/*"), Some("[DEADBEEF/84h/0h/0h]"));
        let parsed = parse_input_with_options(XPUB, &options).unwrap();
        let (external, internal, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Segwit);
        assert!(external.starts_with("wpkh([deadbeef/84'/0'/0']xpub"));
        assert!(
            internal
                .unwrap()
                .starts_with("wpkh([deadbeef/84'/0'/0']xpub")
        );
        assert!(!parsed.warnings.contains(&InputWarning::AssumedSegwit));
        assert_eq!(parsed.networks, vec![Network::Mainnet]);
        assert_eq!(
            parsed.derivation.unwrap().origin.as_deref(),
            Some("[deadbeef/84'/0'/0']")
        );

        let input = format!("[9a6a2580/86'/1'/0']{TPUB}");
        let options = with_derivation("0/*", Some("1/*"), Some("[deadbeef/44'/1'/0']"));
        let parsed = parse_input_with_options(&input, &options).unwrap();
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Legacy);
        assert!(external.starts_with("pkh([deadbeef/44'/1'/0']"));

        // A blank choice keeps the input's origin.
        let options = with_derivation("0/*", Some("1/*"), Some(" "));
        let parsed = parse_input_with_options(&input, &options).unwrap();
        assert_eq!(
            parsed.derivation.unwrap().origin.as_deref(),
            Some("[9a6a2580/86'/1'/0']")
        );
    }

    #[test]
    fn fingerprint_only_origin_is_accepted() {
        let options = with_derivation("0/*", Some("1/*"), Some("deadbeef"));
        let parsed = parse_input_with_options(TPUB, &options).unwrap();
        assert_eq!(
            parsed.derivation.as_ref().unwrap().origin.as_deref(),
            Some("[deadbeef]")
        );
        assert!(parsed.warnings.contains(&InputWarning::AssumedSegwit));
        let (external, _, _) = descriptors(&parsed);
        assert!(external.starts_with("wpkh([deadbeef]tpub"));
    }

    #[test]
    fn explicit_script_wins_over_the_chosen_origin() {
        let options = ImportOptions {
            script: Some(ScriptKind::Taproot),
            derivation: Some(DerivationChoice {
                origin: Some("[deadbeef/84'/1'/0']".to_owned()),
                ..DerivationChoice::default()
            }),
        };
        let parsed = parse_input_with_options(TPUB, &options).unwrap();
        let (external, _, script) = descriptors(&parsed);
        assert_eq!(script, ScriptKind::Taproot);
        assert!(external.starts_with("tr([deadbeef/84'/1'/0']"));
        assert!(
            !parsed
                .warnings
                .contains(&InputWarning::NonStandardDerivation)
        );
    }

    #[test]
    fn fixed_inputs_ignore_the_derivation() {
        let options = with_derivation("5/*", None, Some("[deadbeef]"));

        let single = format!("wpkh({TPUB}/0/*)");
        let parsed = parse_input_with_options(&single, &options).unwrap();
        assert!(!parsed.derivation_editable);
        assert!(parsed.derivation.is_none());
        let (external, _, _) = descriptors(&parsed);
        assert!(external.contains("/0/*") && !external.contains("deadbeef"));

        let address =
            parse_input_with_options("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &options)
                .unwrap();
        assert!(!address.derivation_editable && address.derivation.is_none());

        let template = format!(
            "wsh(sortedmulti(1,[9a6a2580/48'/1'/0'/2']{TPUB}/**,[00000000/48'/1'/0'/2']{TPUB}/**))"
        );
        let truth = parse_input(&template.replace("/**", "/<0;1>/*")).unwrap();
        let first = truth.preview_address.unwrap();
        let record = format!("BSMS 1.0\n{template}\n/0/*,/1/*\n{first}\n");
        let bsms = parse_input_with_options(&record, &options).unwrap();
        assert_eq!(bsms.kind, RecognizedKind::Bsms);
        assert!(!bsms.derivation_editable && bsms.derivation.is_none());
    }

    #[test]
    fn parsed_input_without_derivation_fields_still_loads() {
        let json = format!(
            "{{\"kind\":\"extended_key\",\"networks\":[\"signet\"],\"payload\":{{\"type\":\
             \"descriptors\",\"external\":\"wpkh({TPUB}/0/*)\",\"internal\":null,\
             \"script\":\"segwit\"}},\"warnings\":[\"assumed_segwit\"]}}"
        );
        let parsed: ParsedInput = serde_json::from_str(&json).unwrap();
        assert!(parsed.derivation.is_none());
        assert!(!parsed.derivation_editable);

        let options = with_derivation("5/*", Some("6/*"), Some("[deadbeef/84'/1'/0']"));
        let original = parse_input_with_options(TPUB, &options).unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"non_standard_derivation\""), "{json}");
        assert!(json.contains("\"derivation_editable\":true"), "{json}");
        let restored: ParsedInput = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.derivation, original.derivation);
        assert!(restored.derivation_editable);
    }
}
