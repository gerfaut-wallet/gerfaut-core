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
//! A BBQr holding a PSBT or a transaction is refused as such.

use bdk_wallet::bitcoin::NetworkKind;
use bdk_wallet::bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use ciborium::Value;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::{CoreError, CoreResult};

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
    frame.len() >= 3 && (frame[..3].eq_ignore_ascii_case("ur:") || frame.starts_with("B$"))
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
    if first[..first.len().min(3)].eq_ignore_ascii_case("ur:") {
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

fn assemble_ur(frames: &[&str]) -> CoreResult<QrProgress> {
    let (ur_type, total) = ur_header(frames[0])?;
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
        // the camera will see them again.
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
        "crypto-psbt" | "psbt" => Err(qr_error("this QR code holds a PSBT, not a wallet to watch")),
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

/// Header of a BBQr frame: `B$` + encoding + file type + total + index.
struct BbqrHeader {
    encoding: char,
    file_type: char,
    total: u32,
    index: u32,
}

fn bbqr_header(frame: &str) -> CoreResult<(BbqrHeader, &str)> {
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

    match first.file_type {
        'U' | 'J' => {}
        'P' => return Err(qr_error("this QR code holds a PSBT, not a wallet to watch")),
        'T' => {
            return Err(qr_error(
                "this QR code holds a transaction, not a wallet to watch",
            ));
        }
        other => return Err(qr_error(format!("unsupported BBQr file type `{other}`"))),
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
            flate2::read::DeflateDecoder::new(&compressed[..])
                .read_to_end(&mut text)
                .map_err(|e| qr_error(format!("invalid BBQr compressed payload: {e}")))?;
            text
        }
        other => return Err(qr_error(format!("unsupported BBQr encoding `{other}`"))),
    };
    let text = String::from_utf8(bytes).map_err(|_| qr_error("BBQr payload is not text"))?;
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

    #[test]
    fn psbt_urs_are_refused_as_such() {
        let ur_text = ur::ur::encode(b"psbt", &ur::ur::Type::Custom("crypto-psbt"));
        let error = assemble(&[ur_text]).unwrap_err().to_string();
        assert!(error.contains("PSBT"), "{error}");
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

    #[test]
    fn bbqr_psbt_is_refused() {
        let frame = format!("B$HP0100{}", "00");
        let error = assemble(&[frame]).unwrap_err().to_string();
        assert!(error.contains("PSBT"), "{error}");
    }
}
