//! QR envelopes around wallet material.
//!
//! Hardware wallets and coordinators do not put a descriptor in a QR
//! code as plain text: Sparrow, Keystone, Passport and others wrap it
//! in a Uniform Resource (`ur:crypto-output/…`, BCR-2020-010, animated
//! over several frames with fountain codes), Coldcard and Sparrow in a
//! BBQr (`B$…`, compressed and split into numbered parts). This module
//! turns any of these back into the text the classifier understands.
//!
//! The decoders here only ever see public material: a `crypto-output`
//! carries extended *public* keys, a BBQr text part is parsed as text.
//! A PSBT or a transaction (`ur:crypto-psbt`, BBQr `P` and `T`) comes
//! out in its text form for the broadcast page; the wallet import
//! refuses it there, by name.

use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use ciborium::Value;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::backup::BACKUP_PREFIX;
use crate::error::{CoreError, CoreResult};
use crate::store::cipher::BACKUP_MAGIC;

/// Envelope recognized around a scanned frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrFormat {
    /// The frame is the material itself.
    Plain,
    /// Uniform Resource, single or multi-part.
    Ur,
    /// BBQr, single or multi-part.
    Bbqr,
}

/// Where a scan stands after the frames seen so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrProgress {
    pub format: QrFormat,
    /// Distinct parts received (for a UR: fragments resolved).
    pub received: u32,
    /// Parts announced by the envelope; 1 for plain frames.
    pub total: u32,
    pub complete: bool,
    /// The assembled text, once complete.
    pub text: Option<String>,
}

fn qr_error(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidInput {
        kind: "qr",
        detail: detail.into(),
    }
}

/// True when a frame is an envelope this module can open.
pub fn is_envelope(frame: &str) -> bool {
    let frame = frame.trim();
    is_ur(frame) || frame.starts_with("B$")
}

/// Whether a frame opens a UR, in either case. Read on bytes: a frame
/// is whatever a camera decoded or a person pasted, and a byte index
/// that lands inside a character would panic.
fn is_ur(frame: &str) -> bool {
    frame
        .as_bytes()
        .get(..3)
        .is_some_and(|head| head.eq_ignore_ascii_case(b"ur:"))
}

/// Assembles the frames scanned so far. Frames may repeat and arrive in
/// any order; the caller keeps feeding the growing list until
/// `complete` is true, then hands `text` to the classifier.
pub fn assemble(frames: &[String]) -> CoreResult<QrProgress> {
    let frames: Vec<&str> = frames
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .collect();
    let Some(first) = frames.first() else {
        return Err(qr_error("no frame scanned yet"));
    };
    if is_ur(first) {
        assemble_ur(&frames)
    } else if first.starts_with("B$") {
        assemble_bbqr(&frames)
    } else {
        Ok(QrProgress {
            format: QrFormat::Plain,
            received: 1,
            total: 1,
            complete: true,
            text: Some((*first).to_owned()),
        })
    }
}

// --- Uniform Resources ------------------------------------------------

/// `ur:TYPE/SEQ-TOTAL/PAYLOAD` → (type, Some(total)) or `ur:TYPE/PAYLOAD`
/// → (type, None).
fn ur_header(frame: &str) -> CoreResult<(String, Option<u32>)> {
    let lower = frame.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("ur:")
        .ok_or_else(|| qr_error("not a UR"))?;
    let (ur_type, rest) = rest
        .split_once('/')
        .ok_or_else(|| qr_error("UR without a type"))?;
    let total = match rest.split_once('/') {
        Some((seq, _)) => Some(
            seq.split_once('-')
                .and_then(|(_, total)| total.parse::<u32>().ok())
                .ok_or_else(|| qr_error("malformed UR sequence"))?,
        ),
        None => None,
    };
    Ok((ur_type.to_owned(), total))
}

/// Most parts a multi-part UR may announce: a 4 MB message in the
/// smallest fragments any encoder uses, far past anything a wallet
/// shows as a QR code. The decoder sizes its tables by the announced
/// count before a single fragment is checked, and a count near four
/// billion, in one frame anyone can print, asks for tens of gigabytes:
/// the process dies there, beyond the reach of any error.
const MAX_UR_PARTS: u32 = 100_000;

/// True when a multi-part frame announces a count the decoder can take.
fn ur_part_count_is_sane(frame: &str) -> bool {
    matches!(ur_header(frame), Ok((_, Some(total))) if (1..=MAX_UR_PARTS).contains(&total))
}

fn assemble_ur(frames: &[&str]) -> CoreResult<QrProgress> {
    let (ur_type, total) = ur_header(frames[0])?;
    if total.is_some() && !ur_part_count_is_sane(frames[0]) {
        return Err(qr_error(
            "this QR code announces an impossible number of parts",
        ));
    }
    let progress =
        |received: u32, total: u32, message: Option<Vec<u8>>| -> CoreResult<QrProgress> {
            let text = message
                .map(|bytes| ur_message_to_text(&ur_type, &bytes))
                .transpose()?;
            Ok(QrProgress {
                format: QrFormat::Ur,
                received,
                total,
                complete: text.is_some(),
                text,
            })
        };

    let Some(total) = total else {
        let (_, bytes) =
            ur::ur::decode(frames[0]).map_err(|e| qr_error(format!("invalid UR: {e}")))?;
        return progress(1, 1, Some(bytes));
    };

    let mut decoder = ur::ur::Decoder::default();
    for frame in frames {
        // Frames of another type or a damaged one do not abort the scan:
        // the camera will see them again. One announcing an impossible
        // count never reaches the decoder.
        if !ur_part_count_is_sane(frame) {
            continue;
        }
        let _ = decoder.receive(frame);
        if decoder.complete() {
            break;
        }
    }
    let received = decoder.resolved_fragment_count().unwrap_or(0) as u32;
    let message = if decoder.complete() {
        decoder
            .message()
            .map_err(|e| qr_error(format!("invalid UR: {e}")))?
    } else {
        None
    };
    progress(received.min(total), total, message)
}

/// Turns the CBOR payload of a UR into classifier text.
fn ur_message_to_text(ur_type: &str, bytes: &[u8]) -> CoreResult<String> {
    match ur_type {
        "bytes" => {
            let value: Value = ciborium::from_reader(bytes)
                .map_err(|e| qr_error(format!("invalid ur:bytes payload: {e}")))?;
            let Value::Bytes(raw) = value else {
                return Err(qr_error("ur:bytes does not hold a byte string"));
            };
            // A Gerfaut backup travels as raw file bytes; it comes out in
            // the text form the restore screen accepts.
            if raw.starts_with(BACKUP_MAGIC) {
                return Ok(format!(
                    "{BACKUP_PREFIX}{}",
                    data_encoding::BASE64.encode(&raw)
                ));
            }
            String::from_utf8(raw).map_err(|_| qr_error("ur:bytes is not text"))
        }
        "crypto-output" => {
            let value: Value = ciborium::from_reader(bytes)
                .map_err(|e| qr_error(format!("invalid crypto-output: {e}")))?;
            crypto_output_to_descriptor(&value)
        }
        "crypto-hdkey" => {
            let value: Value = ciborium::from_reader(bytes)
                .map_err(|e| qr_error(format!("invalid crypto-hdkey: {e}")))?;
            hdkey_expression(&value)
        }
        // A PSBT rides as a CBOR byte string (BCR-2020-006). It comes
        // out as base64, the text every other PSBT path accepts.
        "crypto-psbt" | "psbt" => {
            let value: Value = ciborium::from_reader(bytes)
                .map_err(|e| qr_error(format!("invalid crypto-psbt: {e}")))?;
            let Value::Bytes(raw) = value else {
                return Err(qr_error("crypto-psbt does not hold a byte string"));
            };
            Ok(data_encoding::BASE64.encode(&raw))
        }
        other => Err(qr_error(format!("unsupported UR type `{other}`"))),
    }
}

// CBOR tags of BCR-2020-010 (crypto-output) and BCR-2020-007 (hdkey).
const TAG_SH: u64 = 400;
const TAG_WSH: u64 = 401;
const TAG_PK: u64 = 402;
const TAG_PKH: u64 = 403;
const TAG_WPKH: u64 = 404;
const TAG_MULTI: u64 = 406;
const TAG_SORTED_MULTI: u64 = 407;
const TAG_TR: u64 = 409;
const TAG_HDKEY: u64 = 303;
const TAG_KEYPATH: u64 = 304;
const TAG_ECKEY: u64 = 306;

/// Renders a `crypto-output` tree as a descriptor string. Checksums are
/// left to the classifier, which canonicalizes the result.
fn crypto_output_to_descriptor(value: &Value) -> CoreResult<String> {
    let Value::Tag(tag, inner) = value else {
        return Err(qr_error("crypto-output must start with a script tag"));
    };
    let wrap = |name: &str| -> CoreResult<String> {
        Ok(format!("{name}({})", crypto_output_to_descriptor(inner)?))
    };
    match *tag {
        TAG_SH => wrap("sh"),
        TAG_WSH => wrap("wsh"),
        TAG_PK => Ok(format!("pk({})", key_expression(inner)?)),
        TAG_PKH => Ok(format!("pkh({})", key_expression(inner)?)),
        TAG_WPKH => Ok(format!("wpkh({})", key_expression(inner)?)),
        TAG_TR => Ok(format!("tr({})", key_expression(inner)?)),
        TAG_MULTI | TAG_SORTED_MULTI => {
            let name = if *tag == TAG_MULTI {
                "multi"
            } else {
                "sortedmulti"
            };
            let threshold = map_get(inner, 1)
                .and_then(as_u64)
                .ok_or_else(|| qr_error("multisig without a threshold"))?;
            let keys = match map_get(inner, 2) {
                Some(Value::Array(keys)) => keys,
                _ => return Err(qr_error("multisig without keys")),
            };
            let keys = keys
                .iter()
                .map(key_expression)
                .collect::<CoreResult<Vec<_>>>()?;
            Ok(format!("{name}({threshold},{})", keys.join(",")))
        }
        other => Err(qr_error(format!("unsupported crypto-output tag {other}"))),
    }
}

/// A key inside a crypto-output: an hdkey (with origin and children) or
/// a bare EC public key.
fn key_expression(value: &Value) -> CoreResult<String> {
    match value {
        Value::Tag(TAG_HDKEY, inner) => hdkey_expression(inner),
        Value::Tag(TAG_ECKEY, inner) => {
            if map_get(inner, 2).and_then(as_bool) == Some(true) {
                return Err(CoreError::PrivateMaterialRejected);
            }
            match map_get(inner, 3) {
                Some(Value::Bytes(data)) => Ok(hex(data)),
                _ => Err(qr_error("EC key without data")),
            }
        }
        _ => Err(qr_error("unsupported key in crypto-output")),
    }
}

/// `[fingerprint/origin]xpub/children` from a `crypto-hdkey` map.
///
/// Without a children path, both branches are watched (`/<0;1>/*`):
/// coordinators that omit it mean the whole account, and a lone
/// receive branch would silently miss change.
fn hdkey_expression(map: &Value) -> CoreResult<String> {
    if map_get(map, 2).and_then(as_bool) == Some(true) {
        return Err(CoreError::PrivateMaterialRejected);
    }
    let key_data = match map_get(map, 3) {
        Some(Value::Bytes(data)) => data,
        _ => return Err(qr_error("hdkey without key data")),
    };
    let chain_code = match map_get(map, 4) {
        Some(Value::Bytes(data)) => data,
        _ => return Err(qr_error("hdkey without chain code")),
    };
    let public_key =
        PublicKey::from_slice(key_data).map_err(|e| qr_error(format!("invalid key data: {e}")))?;
    let chain_code: [u8; 32] = chain_code
        .as_slice()
        .try_into()
        .map_err(|_| qr_error("chain code must be 32 bytes"))?;

    // Network from use-info (2: network, 0 mainnet / 1 testnet); mainnet
    // when absent, as the spec says.
    let network = match map_get(map, 5)
        .and_then(|info| map_get(tagged(info), 2))
        .and_then(as_u64)
    {
        Some(1) => NetworkKind::Test,
        _ => NetworkKind::Main,
    };

    let origin = map_get(map, 6).map(tagged);
    let components = origin
        .and_then(|o| map_get(o, 1))
        .and_then(keypath_components)
        .transpose()?;
    let source_fingerprint = origin.and_then(|o| map_get(o, 2)).and_then(as_u64);
    let depth = origin
        .and_then(|o| map_get(o, 3))
        .and_then(as_u64)
        .or_else(|| components.as_ref().map(|c| c.len() as u64))
        .unwrap_or(0);
    let child_number = match components.as_deref().and_then(|c| c.last()) {
        Some(Component::Index {
            index,
            hardened: true,
        }) => ChildNumber::from_hardened_idx(*index),
        Some(Component::Index {
            index,
            hardened: false,
        }) => ChildNumber::from_normal_idx(*index),
        _ => Ok(ChildNumber::from_normal_idx(0).expect("0 is a valid index")),
    }
    .map_err(|e| qr_error(format!("invalid child number: {e}")))?;
    let parent_fingerprint = map_get(map, 8)
        .and_then(as_u64)
        .map(|fp| Fingerprint::from((fp as u32).to_be_bytes()))
        .unwrap_or_default();

    let xpub = Xpub {
        network,
        depth: depth as u8,
        parent_fingerprint,
        child_number,
        public_key,
        chain_code: ChainCode::from(chain_code),
    };

    let origin_text = match (source_fingerprint, &components) {
        (Some(fp), Some(components)) if !components.is_empty() => {
            format!("[{:08x}/{}]", fp as u32, render_components(components))
        }
        (Some(fp), _) => format!("[{:08x}]", fp as u32),
        (None, _) => String::new(),
    };
    let children = match map_get(map, 7).map(tagged).and_then(|c| map_get(c, 1)) {
        Some(components) => {
            let components = keypath_components(components)
                .transpose()?
                .unwrap_or_default();
            if components.is_empty() {
                "/<0;1>/*".to_owned()
            } else {
                format!("/{}", render_components(&components))
            }
        }
        None => "/<0;1>/*".to_owned(),
    };
    Ok(format!("{origin_text}{xpub}{children}"))
}

/// One step of a BCR-2020-007 key path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    Index { index: u32, hardened: bool },
    Wildcard { hardened: bool },
    Pair { low: u32, high: u32, hardened: bool },
}

/// Parses `[index-or-wildcard-or-pair, hardened, …]` pairs.
fn keypath_components(value: &Value) -> Option<CoreResult<Vec<Component>>> {
    let Value::Array(items) = value else {
        return Some(Err(qr_error("key path is not an array")));
    };
    let mut components = Vec::new();
    for pair in items.chunks(2) {
        let [item, hardened] = pair else {
            return Some(Err(qr_error("key path with a dangling component")));
        };
        let hardened = as_bool(hardened).unwrap_or(false);
        let component = match item {
            Value::Integer(_) => Component::Index {
                index: as_u64(item).unwrap_or(0) as u32,
                hardened,
            },
            Value::Array(inner) if inner.is_empty() => Component::Wildcard { hardened },
            Value::Array(inner) if inner.len() == 2 => Component::Pair {
                low: as_u64(&inner[0]).unwrap_or(0) as u32,
                high: as_u64(&inner[1]).unwrap_or(0) as u32,
                hardened,
            },
            _ => return Some(Err(qr_error("unsupported key path component"))),
        };
        components.push(component);
    }
    Some(Ok(components))
}

fn render_components(components: &[Component]) -> String {
    components
        .iter()
        .map(|component| match component {
            Component::Index { index, hardened } => format!("{index}{}", tick(*hardened)),
            Component::Wildcard { hardened } => format!("*{}", tick(*hardened)),
            Component::Pair {
                low,
                high,
                hardened,
            } => format!("<{low}{h};{high}{h}>", h = tick(*hardened)),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn tick(hardened: bool) -> &'static str {
    if hardened { "'" } else { "" }
}

fn tagged(value: &Value) -> &Value {
    match value {
        Value::Tag(TAG_KEYPATH, inner) | Value::Tag(_, inner) => inner,
        other => other,
    }
}

fn map_get(map: &Value, key: u64) -> Option<&Value> {
    let Value::Map(entries) = map else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| as_u64(k) == Some(key))
        .map(|(_, v)| v)
}

fn as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(i) => u64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- BBQr ----------------------------------------------------------------

/// Largest payload a compressed BBQr may inflate to: the cap of the
/// broadcast page, the largest consumer of an assembled frame. Deflate
/// reaches a thousand to one, so a frame of a few hundred kilobytes
/// used to come out as hundreds of megabytes before the same cap
/// refused it one step later. Nothing past it could ever be read, and
/// every file type comes out at least as long as the bytes it holds:
/// stopping the inflation here loses nothing.
const MAX_INFLATED_LEN: usize = 4_000_000;

/// Header of a BBQr frame: `B$` + encoding + file type + total + index.
struct BbqrHeader {
    encoding: char,
    file_type: char,
    total: u32,
    index: u32,
}

fn bbqr_header(frame: &str) -> CoreResult<(BbqrHeader, &str)> {
    // A BBQr frame is ASCII by specification. The header is read by
    // byte offsets, and one that lands inside a character would panic:
    // anything else is refused here, before an offset is taken.
    if !frame.is_ascii() {
        return Err(qr_error(
            "not a BBQr frame: it carries characters outside ASCII",
        ));
    }
    let bytes = frame.as_bytes();
    if !frame.starts_with("B$") || bytes.len() < 8 {
        return Err(qr_error("not a BBQr frame"));
    }
    let base36 = |s: &str| -> CoreResult<u32> {
        u32::from_str_radix(s, 36).map_err(|_| qr_error("malformed BBQr header"))
    };
    let header = BbqrHeader {
        encoding: bytes[2] as char,
        file_type: bytes[3] as char,
        total: base36(&frame[4..6])?,
        index: base36(&frame[6..8])?,
    };
    if header.total == 0 || header.index >= header.total {
        return Err(qr_error("malformed BBQr header"));
    }
    Ok((header, &frame[8..]))
}

fn assemble_bbqr(frames: &[&str]) -> CoreResult<QrProgress> {
    let (first, _) = bbqr_header(frames[0])?;
    let total = first.total;
    let mut parts: Vec<Option<&str>> = vec![None; total as usize];
    for frame in frames {
        let Ok((header, payload)) = bbqr_header(frame) else {
            continue;
        };
        if header.total != total
            || header.encoding != first.encoding
            || header.file_type != first.file_type
        {
            continue;
        }
        parts[header.index as usize] = Some(payload);
    }
    let received = parts.iter().filter(|p| p.is_some()).count() as u32;
    if received < total {
        return Ok(QrProgress {
            format: QrFormat::Bbqr,
            received,
            total,
            complete: false,
            text: None,
        });
    }

    if !matches!(first.file_type, 'U' | 'J' | 'P' | 'T') {
        return Err(qr_error(format!(
            "unsupported BBQr file type `{}`",
            first.file_type
        )));
    }
    let joined: String = parts.iter().map(|p| p.unwrap_or_default()).collect();
    let bytes = match first.encoding {
        'H' => data_encoding::HEXUPPER_PERMISSIVE
            .decode(joined.as_bytes())
            .map_err(|_| qr_error("invalid BBQr hex payload"))?,
        '2' => decode_base32(&joined)?,
        'Z' => {
            let compressed = decode_base32(&joined)?;
            let mut text = Vec::new();
            // Bounded: one byte past the cap is enough to know the
            // payload is over it, and the rest is never inflated.
            flate2::read::DeflateDecoder::new(&compressed[..])
                .take(MAX_INFLATED_LEN as u64 + 1)
                .read_to_end(&mut text)
                .map_err(|e| qr_error(format!("invalid BBQr compressed payload: {e}")))?;
            if text.len() > MAX_INFLATED_LEN {
                return Err(qr_error(
                    "this BBQr code expands to far more than any transaction or wallet",
                ));
            }
            text
        }
        other => return Err(qr_error(format!("unsupported BBQr encoding `{other}`"))),
    };
    // Binary file types come out as the text form every other path
    // accepts: a PSBT as base64, a transaction as hex.
    let text = match first.file_type {
        'P' => data_encoding::BASE64.encode(&bytes),
        'T' => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        _ => String::from_utf8(bytes).map_err(|_| qr_error("BBQr payload is not text"))?,
    };
    Ok(QrProgress {
        format: QrFormat::Bbqr,
        received,
        total,
        complete: true,
        text: Some(text.trim().to_owned()),
    })
}

fn decode_base32(payload: &str) -> CoreResult<Vec<u8>> {
    data_encoding::BASE32_NOPAD
        .decode(payload.trim_end_matches('=').as_bytes())
        .map_err(|_| qr_error("invalid BBQr base32 payload"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Public two-path key from the BDK documentation.
    const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";

    fn map(entries: Vec<(u64, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Integer(k.into()), v))
                .collect(),
        )
    }

    fn tag(tag: u64, inner: Value) -> Value {
        Value::Tag(tag, Box::new(inner))
    }

    /// An hdkey map for TPUB with an account origin, optionally with a
    /// children path.
    fn hdkey(children: Option<Value>) -> Value {
        let xpub: Xpub = TPUB.parse().unwrap();
        let mut entries = vec![
            (2, Value::Bool(false)),
            (3, Value::Bytes(xpub.public_key.serialize().to_vec())),
            (4, Value::Bytes(xpub.chain_code.as_bytes().to_vec())),
            (
                5,
                tag(
                    305,
                    map(vec![
                        (1, Value::Integer(0.into())),
                        (2, Value::Integer(1.into())),
                    ]),
                ),
            ),
            (
                6,
                tag(
                    304,
                    map(vec![
                        (
                            1,
                            Value::Array(vec![
                                Value::Integer(84.into()),
                                Value::Bool(true),
                                Value::Integer(1.into()),
                                Value::Bool(true),
                                Value::Integer(0.into()),
                                Value::Bool(true),
                            ]),
                        ),
                        (2, Value::Integer(0x9a6a2580u64.into())),
                        (3, Value::Integer(3.into())),
                    ]),
                ),
            ),
            (
                8,
                Value::Integer(u32::from_be_bytes(*xpub.parent_fingerprint.as_bytes()).into()),
            ),
        ];
        if let Some(children) = children {
            entries.push((7, tag(304, map(vec![(1, children)]))));
        }
        tag(303, map(entries))
    }

    fn encode_ur(ur_type: &str, value: &Value) -> String {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        ur::ur::encode(&bytes, &ur::ur::Type::Custom(ur_type))
    }

    #[test]
    fn plain_frames_pass_through() {
        let progress = assemble(&[format!("wpkh({TPUB}/0/*)")]).unwrap();
        assert_eq!(progress.format, QrFormat::Plain);
        assert!(progress.complete);
        assert_eq!(progress.text.unwrap(), format!("wpkh({TPUB}/0/*)"));
    }

    #[test]
    fn crypto_output_single_key_without_children_watches_both_branches() {
        let ur_text = encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(None)));
        assert!(is_envelope(&ur_text));
        let progress = assemble(&[ur_text]).unwrap();
        assert_eq!(progress.format, QrFormat::Ur);
        assert!(progress.complete);
        assert_eq!(
            progress.text.unwrap(),
            format!("wpkh([9a6a2580/84'/1'/0']{TPUB}/<0;1>/*)")
        );
    }

    #[test]
    fn crypto_output_children_paths_are_kept() {
        let children = Value::Array(vec![
            Value::Integer(0.into()),
            Value::Bool(false),
            Value::Array(vec![]),
            Value::Bool(false),
        ]);
        let ur_text = encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(Some(children))));
        let text = assemble(&[ur_text]).unwrap().text.unwrap();
        assert!(text.ends_with(&format!("{TPUB}/0/*)")), "{text}");

        let pair = Value::Array(vec![
            Value::Array(vec![Value::Integer(0.into()), Value::Integer(1.into())]),
            Value::Bool(false),
            Value::Array(vec![]),
            Value::Bool(false),
        ]);
        let ur_text = encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(Some(pair))));
        let text = assemble(&[ur_text]).unwrap().text.unwrap();
        assert!(text.ends_with(&format!("{TPUB}/<0;1>/*)")), "{text}");
    }

    #[test]
    fn crypto_output_sorted_multisig() {
        let multi = tag(
            TAG_WSH,
            tag(
                TAG_SORTED_MULTI,
                map(vec![
                    (1, Value::Integer(2.into())),
                    (2, Value::Array(vec![hdkey(None), hdkey(None)])),
                ]),
            ),
        );
        let text = assemble(&[encode_ur("crypto-output", &multi)])
            .unwrap()
            .text
            .unwrap();
        assert!(
            text.starts_with("wsh(sortedmulti(2,[9a6a2580/84'/1'/0']"),
            "{text}"
        );
        assert_eq!(text.matches(TPUB).count(), 2);
        // The classifier accepts what came out.
        let parsed = crate::input::parse_input(&text).unwrap();
        assert_eq!(
            parsed.kind,
            crate::input::RecognizedKind::MultipathDescriptor
        );
    }

    #[test]
    fn multi_part_ur_reports_progress_then_completes() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&tag(TAG_WPKH, hdkey(None)), &mut bytes).unwrap();
        let mut encoder = ur::ur::Encoder::new(&bytes, 40, "crypto-output").unwrap();
        let mut frames: Vec<String> = Vec::new();
        let first = encoder.next_part().unwrap();
        frames.push(first.clone());
        frames.push(first); // a repeated frame is harmless
        let progress = assemble(&frames).unwrap();
        assert_eq!(progress.format, QrFormat::Ur);
        assert!(!progress.complete);
        assert!(progress.total > 1);
        assert!(progress.received < progress.total);
        for _ in 0..40 {
            frames.push(encoder.next_part().unwrap());
            let progress = assemble(&frames).unwrap();
            if progress.complete {
                assert!(progress.text.unwrap().starts_with("wpkh([9a6a2580"));
                return;
            }
        }
        panic!("the fountain never completed");
    }

    /// One multi-part frame announcing about four billion parts, as its
    /// header and its fountain part both say.
    fn frame_announcing_billions(ur_type: &str) -> String {
        let part = Value::Array(vec![
            Value::Integer(4_294_967_295u32.into()),
            Value::Integer(4_294_967_294u32.into()),
            Value::Integer(1.into()),
            Value::Integer(0.into()),
            Value::Bytes(vec![0]),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&part, &mut cbor).unwrap();
        let words = ur::bytewords::encode(&cbor, ur::bytewords::Style::Minimal);
        format!("ur:{ur_type}/4294967295-4294967294/{words}")
    }

    /// Such a frame is refused before the decoder sizes anything by it,
    /// alone or among the frames of an honest scan.
    #[test]
    fn a_ur_announcing_billions_of_parts_is_refused() {
        let hostile = frame_announcing_billions("bytes");
        assert!(matches!(
            assemble(std::slice::from_ref(&hostile)),
            Err(CoreError::InvalidInput { kind: "qr", .. })
        ));
        assert!(crate::input::parse_input(&hostile).is_err());

        let mut bytes = Vec::new();
        ciborium::into_writer(&tag(TAG_WPKH, hdkey(None)), &mut bytes).unwrap();
        let mut encoder = ur::ur::Encoder::new(&bytes, 40, "crypto-output").unwrap();
        let hostile = frame_announcing_billions("crypto-output");
        let mut frames = vec![encoder.next_part().unwrap(), hostile];
        for _ in 0..40 {
            frames.push(encoder.next_part().unwrap());
            if assemble(&frames).unwrap().complete {
                return;
            }
        }
        panic!("the fountain never completed");
    }

    #[test]
    fn private_hdkey_is_rejected() {
        let Value::Tag(_, inner) = hdkey(None) else {
            unreachable!()
        };
        let Value::Map(mut entries) = *inner else {
            unreachable!()
        };
        entries[0].1 = Value::Bool(true);
        let ur_text = encode_ur(
            "crypto-output",
            &tag(TAG_WPKH, tag(303, Value::Map(entries))),
        );
        assert!(matches!(
            assemble(&[ur_text]),
            Err(CoreError::PrivateMaterialRejected)
        ));
    }

    /// A `crypto-psbt` comes out as base64: the text the broadcast page
    /// and every PSBT tool accept.
    #[test]
    fn psbt_urs_open_as_base64() {
        let payload = b"psbt\xff\x01\x00";
        let ur_text = encode_ur("crypto-psbt", &Value::Bytes(payload.to_vec()));
        let progress = assemble(&[ur_text]).unwrap();
        assert!(progress.complete);
        assert_eq!(
            progress.text.as_deref(),
            Some(data_encoding::BASE64.encode(payload).as_str())
        );
    }

    fn bbqr_frames(text: &str, parts: usize) -> Vec<String> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(text.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = data_encoding::BASE32_NOPAD.encode(&compressed);
        let chunk = encoded.len().div_ceil(parts);
        encoded
            .as_bytes()
            .chunks(chunk)
            .enumerate()
            .map(|(index, payload)| {
                format!(
                    "B$ZU{:02}{:02}{}",
                    parts,
                    index,
                    std::str::from_utf8(payload).unwrap()
                )
            })
            .collect()
    }

    #[test]
    fn bbqr_compressed_text_in_parts() {
        let descriptor = format!("wpkh({TPUB}/<0;1>/*)");
        let frames = bbqr_frames(&descriptor, 3);
        assert!(is_envelope(&frames[0]));
        // Out of order, with a repeat, one missing: not complete yet.
        let partial = assemble(&[frames[2].clone(), frames[0].clone(), frames[2].clone()]).unwrap();
        assert_eq!(partial.format, QrFormat::Bbqr);
        assert_eq!(
            (partial.received, partial.total, partial.complete),
            (2, 3, false)
        );
        let full = assemble(&[frames[2].clone(), frames[0].clone(), frames[1].clone()]).unwrap();
        assert!(full.complete);
        assert_eq!(full.text.unwrap(), descriptor);
    }

    /// A frame is whatever a camera decoded or a person typed. Two
    /// accented letters in the import field used to close the desktop
    /// application: the envelope checks indexed bytes without looking
    /// for a character boundary.
    #[test]
    fn text_that_is_not_ascii_is_refused_not_a_panic() {
        let plain = [
            "\u{e9}\u{e9}",
            "\u{e9}\u{e9}\u{e9}",
            "\u{e9} \u{e9}",
            "\u{1f642}\u{1f642}",
        ];
        for text in plain {
            assert!(!is_envelope(text), "{text:?}");
            // Not an envelope: the frame is the material itself, and
            // the classifier says what it makes of it.
            let progress = assemble(&[text.to_owned()]).unwrap();
            assert_eq!(progress.format, QrFormat::Plain);
            assert_eq!(progress.text.as_deref(), Some(text));
            assert!(crate::input::parse_input(text).is_err(), "{text:?}");
            assert!(
                crate::broadcast::decode_transaction(text).is_err(),
                "{text:?}"
            );
        }
        // An envelope whose header lands a byte offset inside a
        // character: refused by name, on every path that opens one.
        let envelopes = [
            "B$ZUa\u{e9}000",
            "B$ZU01a\u{e9}0",
            "B$ZU0100\u{e9}",
            "B$\u{e9}",
            "ur:\u{e9}/\u{e9}",
        ];
        for text in envelopes {
            assert!(is_envelope(text), "{text:?}");
            let error = assemble(&[text.to_owned()]).unwrap_err();
            assert!(
                matches!(error, CoreError::InvalidInput { kind: "qr", .. }),
                "{text:?}: {error}"
            );
            assert!(crate::input::parse_input(text).is_err(), "{text:?}");
            assert!(
                crate::broadcast::decode_transaction(text).is_err(),
                "{text:?}"
            );
        }
        // A damaged frame of an animated code is skipped, like any
        // other: the camera will see the real one again.
        let progress = assemble(&["UR:bytes/1-2/\u{e9}".to_owned()]).unwrap();
        assert!(!progress.complete);
        let descriptor = format!("wpkh({TPUB}/<0;1>/*)");
        let mut frames = bbqr_frames(&descriptor, 2);
        frames.insert(1, "B$ZU0201\u{e9}".to_owned());
        assert_eq!(assemble(&frames).unwrap().text.unwrap(), descriptor);
    }

    /// Two hundred megabytes of zeroes deflate to a frame of a few
    /// hundred kilobytes, small enough for the broadcast page to accept
    /// it. It used to inflate whole before that page refused the
    /// result; now the inflation stops one byte past the cap.
    #[test]
    fn a_bbqr_that_inflates_without_end_is_refused_before_it_does() {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        let zeroes = vec![b'0'; 1 << 20];
        for _ in 0..200 {
            encoder.write_all(&zeroes).unwrap();
        }
        let compressed = encoder.finish().unwrap();
        let frame = format!(
            "B$ZU0100{}",
            data_encoding::BASE32_NOPAD.encode(&compressed)
        );
        assert!(frame.len() < 4_000_000, "{} bytes", frame.len());

        let refused = assemble(std::slice::from_ref(&frame)).unwrap_err();
        assert!(
            refused.to_string().contains("expands to far more"),
            "{refused}"
        );
        let refused = crate::broadcast::decode_transaction(&frame).unwrap_err();
        assert!(
            refused.to_string().contains("expands to far more"),
            "{refused}"
        );

        // Right under the cap, the same encoding still opens.
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![b'0'; MAX_INFLATED_LEN]).unwrap();
        let frame = format!(
            "B$ZU0100{}",
            data_encoding::BASE32_NOPAD.encode(&encoder.finish().unwrap())
        );
        let opened = assemble(&[frame]).unwrap();
        assert_eq!(opened.text.unwrap().len(), MAX_INFLATED_LEN);
    }

    /// BBQr binary types come out in their text form: a PSBT as base64,
    /// a transaction as hex.
    #[test]
    fn bbqr_binary_types_open_as_text() {
        let psbt = assemble(&["B$HP01007073627400".to_owned()]).unwrap();
        assert_eq!(psbt.text.as_deref(), Some("cHNidAA="));
        let tx = assemble(&["B$HT0100DEADBEEF".to_owned()]).unwrap();
        assert_eq!(tx.text.as_deref(), Some("deadbeef"));
        let error = assemble(&["B$HX010000".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("file type"), "{error}");
    }
}
