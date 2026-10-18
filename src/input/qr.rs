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

use super::InputWarning;
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
    /// What was assumed reading the envelope, which the text no longer
    /// shows: show them with the classifier's own warnings for `text`.
    #[serde(default)]
    pub warnings: Vec<InputWarning>,
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

/// The text an envelope held, refused when it is an envelope itself. No
/// wallet puts one QR code inside another, and each level opened costs
/// the stack a frame: a level of compressed BBQr fits in a hundred
/// characters, so a pasted text holds hundreds of them and a file
/// dropped on the broadcast page tens of thousands, past what the stack
/// of the thread reading them takes.
pub(crate) fn opened_once(text: String) -> CoreResult<String> {
    if is_envelope(&text) {
        return Err(qr_error(
            "this QR code holds another QR code, which no wallet makes",
        ));
    }
    Ok(text)
}

/// The fewest distinct frames a scan may bring before a code is refused
/// as more than Gerfaut reads, whatever it announces.
pub const MIN_SCAN_FRAMES: usize = 2_000;
/// The most distinct frames any scan may bring.
pub const MAX_SCAN_FRAMES: usize = 10_000;

/// The distinct frames a scan of a code that announces `total` parts
/// may bring: three times as many, within [`MIN_SCAN_FRAMES`] and
/// [`MAX_SCAN_FRAMES`]. A camera that misses half the frames of a
/// fountain code needs about twice as many as it has parts, and a large
/// PSBT shown at low density runs to well over a thousand. Past that,
/// the scan is refused: a fountain code never runs out of new frames,
/// and every one of them the decoder takes it keeps.
pub fn scan_frame_limit(total: u32) -> usize {
    (total as usize)
        .saturating_mul(3)
        .clamp(MIN_SCAN_FRAMES, MAX_SCAN_FRAMES)
}

/// The parts the first frame of a multi-part code announces; 0 when it
/// announces none.
fn announced_parts(first: &str) -> u32 {
    if is_ur(first) {
        return ur_header(first)
            .ok()
            .and_then(|(_, total)| total)
            .unwrap_or(0);
    }
    bbqr_header(first)
        .map(|(header, _)| header.total)
        .unwrap_or(0)
}

/// Assembles the frames scanned so far. Frames may repeat and arrive in
/// any order; the caller keeps feeding the growing list until
/// `complete` is true, then hands `text` to the classifier. More frames
/// than [`scan_frame_limit`] allows, repeats counted, blanks not, are
/// refused with [`CoreError::TooManyFrames`], and the frames past the
/// bound are not decoded: the scan is over. The apps send each frame
/// once, so the bound is the distinct frames a scan may bring; whoever
/// sends repeats reaches it sooner, never later. The parts it is
/// reckoned from are those of the first frame, the one both assemblers
/// read the count from; whatever it announces, the bound stays between
/// [`MIN_SCAN_FRAMES`] and [`MAX_SCAN_FRAMES`].
///
/// The frames go through a [`QrScan`] one after the other: a scan in
/// progress keeps one of those and gives it each new frame, rather
/// than handing the whole list here again at every frame.
pub fn assemble(frames: &[String]) -> CoreResult<QrProgress> {
    let mut scan = QrScan::new();
    for frame in frames {
        scan.take(frame);
    }
    scan.progress()
}

/// A scan read one frame at a time: what [`assemble`] says of the
/// frames seen so far, without reading them all again at each frame.
/// [`QrScan::push`] after each frame answers exactly what [`assemble`]
/// answers for the list of them, progress, warnings and refusals alike,
/// and never reads an earlier frame again: a scan of 10,000 frames
/// costs a second, where the list handed over at each frame cost three
/// quarters of an hour (a 5,000-part UR that never comes together).
///
/// A refusal stands for every frame after it, as it does for a longer
/// list: the scan that refuses its first frame, or meets two codes at
/// once, has nothing more to read. Only the frame bound still counts
/// them. What the scan keeps is what the decoder needs and no more: the
/// fountain of a UR, the parts of a BBQr, the answer once it is known.
#[derive(Default)]
pub struct QrScan {
    /// Frames taken, blanks aside, repeats counted.
    frames: usize,
    /// The frames this scan may bring, set by its first frame.
    limit: usize,
    fold: Fold,
}

/// What a scan holds of the frames it took.
#[derive(Default)]
enum Fold {
    /// No frame yet.
    #[default]
    Empty,
    /// The answer no later frame changes: a plain frame, a single-part
    /// UR, a first frame refused, a fountain come together, two BBQr
    /// codes met at once.
    Settled(CoreResult<QrProgress>),
    /// A multi-part UR on its way.
    Ur(UrFold),
    /// A BBQr on its way, or complete and still watched for the parts
    /// of another code.
    Bbqr(BbqrFold),
    /// Past the frame bound: nothing is kept, the count goes on.
    Over,
}

impl QrScan {
    /// A scan with no frame yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one more frame and says where the scan stands, as
    /// [`assemble`] would of every frame taken so far.
    pub fn push(&mut self, frame: &str) -> CoreResult<QrProgress> {
        self.take(frame);
        self.progress()
    }

    /// The frames taken so far, blanks aside.
    pub fn frames(&self) -> usize {
        self.frames
    }

    fn take(&mut self, frame: &str) {
        let frame = frame.trim();
        if frame.is_empty() {
            return;
        }
        self.frames += 1;
        if matches!(self.fold, Fold::Empty) {
            self.limit = scan_frame_limit(announced_parts(frame));
            self.fold = Fold::first(frame);
            return;
        }
        if self.frames > self.limit {
            // Refused from here on, whatever comes: what was kept goes.
            self.fold = Fold::Over;
            return;
        }
        let settled = match &mut self.fold {
            Fold::Ur(ur) => ur.take(frame),
            Fold::Bbqr(bbqr) => bbqr.take(frame),
            Fold::Empty | Fold::Settled(_) | Fold::Over => None,
        };
        if let Some(outcome) = settled {
            self.fold = Fold::Settled(outcome);
        }
    }

    /// Where the scan stands after the frames taken so far.
    pub fn progress(&self) -> CoreResult<QrProgress> {
        if self.frames == 0 {
            return Err(qr_error("no frame scanned yet"));
        }
        if self.frames > self.limit {
            return Err(CoreError::TooManyFrames(self.frames as u32));
        }
        match &self.fold {
            Fold::Settled(outcome) => replay(outcome),
            Fold::Ur(ur) => Ok(ur.partial()),
            Fold::Bbqr(bbqr) => bbqr.progress(),
            // Both are ruled out by the counts above.
            Fold::Empty | Fold::Over => Err(qr_error("no frame scanned yet")),
        }
    }
}

impl Fold {
    /// What the first frame of a scan opens.
    fn first(frame: &str) -> Self {
        if is_ur(frame) {
            return UrFold::open(frame);
        }
        if frame.starts_with("B$") {
            return BbqrFold::open(frame);
        }
        Fold::Settled(Ok(QrProgress {
            format: QrFormat::Plain,
            received: 1,
            total: 1,
            complete: true,
            text: Some(frame.to_owned()),
            warnings: Vec::new(),
        }))
    }
}

/// The same answer again. Nothing in this module refuses a frame with
/// any other error than these four; another one, should it ever come,
/// is said in its own words under the code of a QR code refused.
fn replay(outcome: &CoreResult<QrProgress>) -> CoreResult<QrProgress> {
    match outcome {
        Ok(progress) => Ok(progress.clone()),
        Err(CoreError::InvalidInput { kind, detail }) => Err(CoreError::InvalidInput {
            kind,
            detail: detail.clone(),
        }),
        Err(CoreError::TooManyParts(total)) => Err(CoreError::TooManyParts(*total)),
        Err(CoreError::TooManyFrames(count)) => Err(CoreError::TooManyFrames(*count)),
        Err(CoreError::PrivateMaterialRejected) => Err(CoreError::PrivateMaterialRejected),
        Err(other) => Err(qr_error(other.to_string())),
    }
}

// --- Scans held by an app ----------------------------------------------

/// Most scans an app holds open at once. A screen opens one when its
/// camera starts and closes it when it goes; one left open by a screen
/// that never closed it is dropped when a new one would pass the bound.
pub const MAX_OPEN_SCANS: usize = 4;

/// Longest frame a scan takes, in bytes: what the largest QR code holds
/// once decoded, 7,089 digits. Whatever is longer did not come from a
/// camera, and the frames of a scan are kept until it ends.
pub const MAX_FRAME_LEN: usize = 7_089;

/// Most bytes of frames one scan takes before it is refused as a code
/// larger than Gerfaut reads: past what [`MAX_SCAN_FRAMES`] frames of a
/// large PSBT bring, far short of what they could at [`MAX_FRAME_LEN`].
pub const MAX_SCAN_BYTES: usize = 16 << 20;

/// The scans an app holds for its screens, each read one frame at a
/// time: the apps keep one of these in their state and send each frame
/// once, under the number [`QrScans::open`] gave the scan.
///
/// A scan ends with its answer: once a frame completes it or has it
/// refused, what it held is dropped and the next frame starts a new
/// one, which is what both screens do on a refusal. Bounded in number
/// ([`MAX_OPEN_SCANS`]) and in the frames each takes: frames past
/// [`MAX_FRAME_LEN`] are refused, and a scan past [`MAX_SCAN_BYTES`] or
/// past its frame bound ([`scan_frame_limit`]) too.
///
/// Left unbounded by bytes: the fountain decoder of the `ur` crate
/// keeps, for each mixed part it takes, the list of the fragments mixed
/// in it, twice, 16 bytes a fragment. An honest scan of a 5,000-part
/// code holds some 550 a part, about 40 MB at worst; a code drawn so
/// that every part mixes thousands of fragments holds up to 700 MB at
/// the frame bound, shown frame after frame for twenty minutes. The
/// list handed whole to [`assemble`] at each frame reached the same
/// peak. Counting it would take the degree of each part before the
/// decoder does, which the crate only gives through `minicbor`, one
/// more dependency, and a sampler call that underflows on a part
/// numbered 0: left for a release after 0.1.0, or for a part bound
/// smaller than the 5,000 parts a UR may announce.
#[derive(Default)]
pub struct QrScans {
    open: std::sync::Mutex<OpenScans>,
}

#[derive(Default)]
struct OpenScans {
    /// The number the last scan opened was given.
    last: u32,
    /// Open scans, oldest first.
    scans: std::collections::VecDeque<(u32, std::sync::Arc<std::sync::Mutex<HeldScan>>)>,
}

/// One scan an app holds, and the bytes of frames it took.
#[derive(Default)]
struct HeldScan {
    scan: QrScan,
    bytes: usize,
}

impl HeldScan {
    fn push(&mut self, frame: &str) -> CoreResult<QrProgress> {
        let taken = frame.trim().len();
        if taken > MAX_FRAME_LEN {
            return Err(qr_error("this frame is longer than any QR code holds"));
        }
        self.bytes += taken;
        if self.bytes > MAX_SCAN_BYTES {
            return Err(CoreError::TooManyFrames(self.scan.frames() as u32 + 1));
        }
        self.scan.push(frame)
    }
}

/// The lock, taken back from a thread that panicked holding it.
fn held<T>(lock: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl QrScans {
    /// Opens a scan and gives the number its frames go under. The oldest
    /// open scan is dropped when there are already [`MAX_OPEN_SCANS`].
    pub fn open(&self) -> u32 {
        let mut open = held(&self.open);
        open.last = open.last.wrapping_add(1);
        let id = open.last;
        while open.scans.len() >= MAX_OPEN_SCANS {
            open.scans.pop_front();
        }
        open.scans.push_back((id, Default::default()));
        id
    }

    /// Gives one frame to an open scan: where it stands, as [`assemble`]
    /// says of every frame it took. A scan that answers with its text or
    /// a refusal starts again empty.
    pub fn push(&self, id: u32, frame: &str) -> CoreResult<QrProgress> {
        let scan = held(&self.open)
            .scans
            .iter()
            .find(|(open, _)| *open == id)
            .map(|(_, scan)| scan.clone())
            .ok_or_else(|| qr_error("this scan was closed: open the scanner again"))?;
        let mut scan = match scan.lock() {
            Ok(scan) => scan,
            // A frame that panicked the decoder left it halfway: the
            // scan starts over rather than read on from there.
            Err(poisoned) => {
                scan.clear_poison();
                let mut scan = poisoned.into_inner();
                *scan = HeldScan::default();
                scan
            }
        };
        let outcome = scan.push(frame);
        if !matches!(&outcome, Ok(progress) if !progress.complete) {
            *scan = HeldScan::default();
        }
        outcome
    }

    /// Closes a scan and lets go of what it held; a scan already closed
    /// is left as it is.
    pub fn close(&self, id: u32) {
        held(&self.open).scans.retain(|(open, _)| *open != id);
    }

    /// How many scans are open.
    pub fn open_count(&self) -> usize {
        held(&self.open).scans.len()
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

/// Most parts a multi-part UR may announce: a PSBT of a few hundred
/// kilobytes in the fragments wallets use, far past anything a person
/// scans. The decoder sizes its tables by the announced count before a
/// single fragment is checked, and a count near four billion, in one
/// frame anyone can print, asks for tens of gigabytes: the process dies
/// there, beyond the reach of any error. The count also prices every
/// mixed fragment: the decoder draws which parts it mixes out of a list
/// of them all, and one frame of a few bytes that names half of a
/// hundred thousand parts cost seconds, paid again for each frame
/// scanned after it.
const MAX_UR_PARTS: u32 = 5_000;

/// True when a multi-part frame announces a count the decoder can take.
fn ur_part_count_is_sane(frame: &str) -> bool {
    matches!(ur_header(frame), Ok((_, Some(total))) if (1..=MAX_UR_PARTS).contains(&total))
}

/// A multi-part UR on its way: the fountain decoder, fed one frame at
/// a time in the order they came.
struct UrFold {
    /// The type the first frame named, used until a part says its own.
    ur_type: String,
    /// The parts the first frame announced.
    total: u32,
    decoder: ur::ur::Decoder,
}

impl UrFold {
    /// What the first frame of a UR opens: a single-part UR is read on
    /// the spot, a count no decoder takes is refused on the count.
    fn open(first: &str) -> Fold {
        let (ur_type, total) = match ur_header(first) {
            Ok(header) => header,
            Err(e) => return Fold::Settled(Err(e)),
        };
        let total = match total {
            Some(0) => {
                return Fold::Settled(Err(qr_error(
                    "this QR code announces an impossible number of parts",
                )));
            }
            // A code of its own: the screens say this one in their words.
            Some(total) if total > MAX_UR_PARTS => {
                return Fold::Settled(Err(CoreError::TooManyParts(total)));
            }
            Some(total) => total,
            None => {
                let outcome = ur::ur::decode(first)
                    .map_err(|e| qr_error(format!("invalid UR: {e}")))
                    .and_then(|(_, bytes)| ur_progress(&ur_type, 1, 1, Some(bytes)));
                return Fold::Settled(outcome);
            }
        };
        let mut fold = UrFold {
            ur_type,
            total,
            decoder: ur::ur::Decoder::default(),
        };
        match fold.take(first) {
            Some(outcome) => Fold::Settled(outcome),
            None => Fold::Ur(fold),
        }
    }

    /// Takes one frame; the answer once the fountain comes together.
    fn take(&mut self, frame: &str) -> Option<CoreResult<QrProgress>> {
        // Frames of another type or a damaged one do not abort the scan:
        // the camera will see them again. One announcing an impossible
        // count never reaches the decoder.
        if ur_part_count_is_sane(frame) {
            let _ = self.decoder.receive(frame);
        }
        self.decoder.complete().then(|| self.finish())
    }

    /// The parts resolved so far, nothing decoded yet.
    fn partial(&self) -> QrProgress {
        QrProgress {
            format: QrFormat::Ur,
            received: self.received(),
            total: self.total,
            complete: false,
            text: None,
            warnings: Vec::new(),
        }
    }

    fn received(&self) -> u32 {
        (self.decoder.resolved_fragment_count().unwrap_or(0) as u32).min(self.total)
    }

    /// The message the fountain came together into, read as text.
    fn finish(&self) -> CoreResult<QrProgress> {
        let message = self
            .decoder
            .message()
            .map_err(|e| qr_error(format!("invalid UR: {e}")))?;
        // The type the parts carried, not the first frame's: that one may
        // be a damaged frame of another code, skipped above.
        let ur_type = self.decoder.ur_type().unwrap_or(&self.ur_type);
        ur_progress(ur_type, self.received(), self.total, message)
    }
}

/// Where a UR stands, its message read as text when there is one.
fn ur_progress(
    ur_type: &str,
    received: u32,
    total: u32,
    message: Option<Vec<u8>>,
) -> CoreResult<QrProgress> {
    let mut warnings = Vec::new();
    let text = message
        .map(|bytes| ur_message_to_text(ur_type, &bytes, &mut warnings))
        .transpose()?;
    Ok(QrProgress {
        format: QrFormat::Ur,
        received,
        total,
        complete: text.is_some(),
        text,
        warnings,
    })
}

/// Turns the CBOR payload of a UR into classifier text, noting in
/// `warnings` what it had to assume.
fn ur_message_to_text(
    ur_type: &str,
    bytes: &[u8],
    warnings: &mut Vec<InputWarning>,
) -> CoreResult<String> {
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
            crypto_output_to_descriptor(&value, warnings)
        }
        // A key alone is an account key, as pasted: `[origin]xpub`, the
        // branches left to the confirmation screen, which reads the
        // script from the origin. With its children path glued on, the
        // classifier took the whole for one key and refused it.
        "crypto-hdkey" => {
            let value: Value = ciborium::from_reader(bytes)
                .map_err(|e| qr_error(format!("invalid crypto-hdkey: {e}")))?;
            hdkey_parts(&value).map(|(key, _)| key)
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
const TAG_ECKEY: u64 = 306;

/// Renders a `crypto-output` tree as a descriptor string. Checksums are
/// left to the classifier, which canonicalizes the result.
fn crypto_output_to_descriptor(
    value: &Value,
    warnings: &mut Vec<InputWarning>,
) -> CoreResult<String> {
    let Value::Tag(tag, inner) = value else {
        return Err(qr_error("crypto-output must start with a script tag"));
    };
    let mut wrap = |name: &str| -> CoreResult<String> {
        Ok(format!(
            "{name}({})",
            crypto_output_to_descriptor(inner, warnings)?
        ))
    };
    match *tag {
        TAG_SH => wrap("sh"),
        TAG_WSH => wrap("wsh"),
        TAG_PK => Ok(format!("pk({})", key_expression(inner, warnings)?)),
        TAG_PKH => Ok(format!("pkh({})", key_expression(inner, warnings)?)),
        TAG_WPKH => Ok(format!("wpkh({})", key_expression(inner, warnings)?)),
        TAG_TR => Ok(format!("tr({})", key_expression(inner, warnings)?)),
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
                .map(|key| key_expression(key, warnings))
                .collect::<CoreResult<Vec<_>>>()?;
            Ok(format!("{name}({threshold},{})", keys.join(",")))
        }
        other => Err(qr_error(format!("unsupported crypto-output tag {other}"))),
    }
}

/// A key inside a crypto-output: an hdkey (with origin and children) or
/// a bare EC public key.
///
/// An hdkey without a children path watches both branches (`/<0;1>/*`):
/// coordinators that omit it mean the whole account, and a lone receive
/// branch would silently miss change. The addresses rest on that guess,
/// so it is said ([`InputWarning::AssumedBranches`]).
fn key_expression(value: &Value, warnings: &mut Vec<InputWarning>) -> CoreResult<String> {
    match value {
        Value::Tag(TAG_HDKEY, inner) => {
            let (key, children) = hdkey_parts(inner)?;
            let children = children.unwrap_or_else(|| {
                if !warnings.contains(&InputWarning::AssumedBranches) {
                    warnings.push(InputWarning::AssumedBranches);
                }
                "/<0;1>/*".to_owned()
            });
            Ok(format!("{key}{children}"))
        }
        Value::Tag(TAG_ECKEY, inner) => {
            if map_get(inner, 2).and_then(as_bool) == Some(true) {
                return Err(CoreError::PrivateMaterialRejected);
            }
            // A public key is 33 bytes, or 65 uncompressed; 32 is the
            // length of a private key in this format, flag or not.
            match map_get(inner, 3) {
                Some(Value::Bytes(data)) if matches!(data.len(), 33 | 65) => Ok(hex(data)),
                Some(Value::Bytes(data)) if data.len() == 32 => {
                    Err(CoreError::PrivateMaterialRejected)
                }
                Some(Value::Bytes(_)) => Err(qr_error("EC key of a length no public key has")),
                _ => Err(qr_error("EC key without data")),
            }
        }
        _ => Err(qr_error("unsupported key in crypto-output")),
    }
}

/// `[fingerprint/origin]xpub` and `/children` from a `crypto-hdkey`
/// map, `None` for the children when the map names no step of them.
fn hdkey_parts(map: &Value) -> CoreResult<(String, Option<String>)> {
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
    // when absent, as the spec says. Any other value is no network.
    let network = match map_get(map, 5).and_then(|info| map_get(tagged(info), 2)) {
        None => NetworkKind::Main,
        Some(code) => match as_u64(code) {
            Some(0) => NetworkKind::Main,
            Some(1) => NetworkKind::Test,
            _ => return Err(qr_error("hdkey for a network this format does not name")),
        },
    };

    let origin = map_get(map, 6).map(tagged);
    let components = origin
        .and_then(|o| map_get(o, 1))
        .map(keypath_components)
        .transpose()?;
    let source_fingerprint = origin
        .and_then(|o| map_get(o, 2))
        .map(fingerprint)
        .transpose()?;
    let depth = match origin.and_then(|o| map_get(o, 3)) {
        Some(depth) => as_u64(depth),
        None => Some(components.as_ref().map_or(0, |c| c.len() as u64)),
    }
    .and_then(|depth| u8::try_from(depth).ok())
    .ok_or_else(|| qr_error("hdkey deeper than a key can be"))?;
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
        .map(fingerprint)
        .transpose()?
        .map(|fp| Fingerprint::from(fp.to_be_bytes()))
        .unwrap_or_default();

    let xpub = Xpub {
        network,
        depth,
        parent_fingerprint,
        child_number,
        public_key,
        chain_code: ChainCode::from(chain_code),
    };

    let origin_text = match (source_fingerprint, &components) {
        (Some(fp), Some(components)) if !components.is_empty() => {
            format!("[{fp:08x}/{}]", render_components(components))
        }
        (Some(fp), _) => format!("[{fp:08x}]"),
        (None, _) => String::new(),
    };
    let children = match map_get(map, 7).map(tagged).and_then(|c| map_get(c, 1)) {
        Some(components) => {
            let components = keypath_components(components)?;
            (!components.is_empty()).then(|| format!("/{}", render_components(&components)))
        }
        None => None,
    };
    Ok((format!("{origin_text}{xpub}"), children))
}

/// One step of a BCR-2020-007 key path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    Index { index: u32, hardened: bool },
    Wildcard { hardened: bool },
    Pair { low: u32, high: u32, hardened: bool },
}

/// Parses `[index-or-wildcard-or-pair, hardened, …]` pairs.
fn keypath_components(value: &Value) -> CoreResult<Vec<Component>> {
    let Value::Array(items) = value else {
        return Err(qr_error("key path is not an array"));
    };
    let mut components = Vec::new();
    for pair in items.chunks(2) {
        let [item, hardened] = pair else {
            return Err(qr_error("key path with a dangling component"));
        };
        let hardened =
            as_bool(hardened).ok_or_else(|| qr_error("key path step without its hardened flag"))?;
        let component = match item {
            Value::Integer(_) => Component::Index {
                index: child_index(item)?,
                hardened,
            },
            Value::Array(inner) if inner.is_empty() => Component::Wildcard { hardened },
            Value::Array(inner) if inner.len() == 2 => Component::Pair {
                low: child_index(&inner[0])?,
                high: child_index(&inner[1])?,
                hardened,
            },
            _ => return Err(qr_error("unsupported key path component")),
        };
        components.push(component);
    }
    Ok(components)
}

/// A step of a key path: an index below 2³¹, the hardened flag beside
/// it. Anything else, negative, larger or not a number, is refused
/// rather than read as another step.
fn child_index(value: &Value) -> CoreResult<u32> {
    as_u64(value)
        .and_then(|index| u32::try_from(index).ok())
        .filter(|index| *index < 1 << 31)
        .ok_or_else(|| qr_error("key path step out of range"))
}

/// A key fingerprint, four bytes as one integer.
fn fingerprint(value: &Value) -> CoreResult<u32> {
    as_u64(value)
        .and_then(|fp| u32::try_from(fp).ok())
        .ok_or_else(|| qr_error("key fingerprint out of range"))
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

/// What a tag wraps, whichever tag it is: a keypath (304) or a
/// use-info (305) is read by its place in the map, not by its tag.
fn tagged(value: &Value) -> &Value {
    match value {
        Value::Tag(_, inner) => inner,
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
    data_encoding::HEXLOWER.encode(bytes)
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

/// A BBQr on its way: the parts of the code its first frame belongs to,
/// by index.
struct BbqrFold {
    encoding: char,
    file_type: char,
    total: u32,
    parts: Vec<Option<String>>,
    received: u32,
    /// The text the parts make, read once the last one arrives. The
    /// parts stay: a part of another code may still come and refuse it.
    outcome: Option<CoreResult<QrProgress>>,
}

impl BbqrFold {
    fn open(first: &str) -> Fold {
        let header = match bbqr_header(first) {
            Ok((header, _)) => header,
            Err(e) => return Fold::Settled(Err(e)),
        };
        let mut fold = BbqrFold {
            encoding: header.encoding,
            file_type: header.file_type,
            total: header.total,
            parts: vec![None; header.total as usize],
            received: 0,
            outcome: None,
        };
        match fold.take(first) {
            Some(outcome) => Fold::Settled(outcome),
            None => Fold::Bbqr(fold),
        }
    }

    /// Takes one frame; a refusal when it is a part of another code.
    fn take(&mut self, frame: &str) -> Option<CoreResult<QrProgress>> {
        let Ok((header, payload)) = bbqr_header(frame) else {
            return None;
        };
        if header.total != self.total
            || header.encoding != self.encoding
            || header.file_type != self.file_type
        {
            return None;
        }
        // Two codes in front of the camera at once, the same kind and
        // length: their parts would be glued together into a text
        // neither holds.
        match &mut self.parts[header.index as usize] {
            Some(seen) if *seen != payload => {
                return Some(Err(qr_error(
                    "two different QR codes were scanned together: scan one at a time",
                )));
            }
            Some(_) => {}
            slot => {
                *slot = Some(payload.to_owned());
                self.received += 1;
                if self.received == self.total {
                    self.outcome = Some(self.decode());
                }
            }
        }
        None
    }

    fn progress(&self) -> CoreResult<QrProgress> {
        match &self.outcome {
            Some(outcome) => replay(outcome),
            None => Ok(QrProgress {
                format: QrFormat::Bbqr,
                received: self.received,
                total: self.total,
                complete: false,
                text: None,
                warnings: Vec::new(),
            }),
        }
    }

    /// The text every part together makes.
    fn decode(&self) -> CoreResult<QrProgress> {
        if !matches!(self.file_type, 'U' | 'J' | 'P' | 'T') {
            return Err(qr_error(format!(
                "unsupported BBQr file type `{}`",
                self.file_type
            )));
        }
        let joined: String = self.parts.iter().flatten().map(String::as_str).collect();
        let bytes = match self.encoding {
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
        let text = match self.file_type {
            'P' => data_encoding::BASE64.encode(&bytes),
            'T' => hex(&bytes),
            _ => String::from_utf8(bytes).map_err(|_| qr_error("BBQr payload is not text"))?,
        };
        Ok(QrProgress {
            format: QrFormat::Bbqr,
            received: self.received,
            total: self.total,
            complete: true,
            text: Some(text.trim().to_owned()),
            warnings: Vec::new(),
        })
    }
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

    /// A key without a children path is read as the whole account,
    /// receive and change, and that guess is said, once however many
    /// keys share it: the addresses rest on it. A path given, `<0;1>`
    /// included, is no guess, and neither is a lone key, whose branches
    /// the confirmation screen shows.
    #[test]
    fn an_assumed_children_path_is_said() {
        let assumed = vec![InputWarning::AssumedBranches];
        let ur_text = encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(None)));
        let progress = assemble(std::slice::from_ref(&ur_text)).unwrap();
        assert_eq!(progress.warnings, assumed);

        let empty = hdkey(Some(Value::Array(vec![])));
        let progress = assemble(&[encode_ur("crypto-output", &tag(TAG_WPKH, empty))]).unwrap();
        assert!(progress.text.unwrap().ends_with("/<0;1>/*)"));
        assert_eq!(progress.warnings, assumed);

        let multi = tag(
            TAG_WSH,
            tag(
                TAG_SORTED_MULTI,
                map(vec![
                    (1, Value::Integer(1.into())),
                    (2, Value::Array(vec![hdkey(None), hdkey(None)])),
                ]),
            ),
        );
        let progress = assemble(&[encode_ur("crypto-output", &multi)]).unwrap();
        assert_eq!(progress.warnings, assumed);

        let pair = Value::Array(vec![
            Value::Array(vec![Value::Integer(0.into()), Value::Integer(1.into())]),
            Value::Bool(false),
            Value::Array(vec![]),
            Value::Bool(false),
        ]);
        let given = encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(Some(pair))));
        let given = assemble(&[given]).unwrap();
        assert!(given.warnings.is_empty());
        let Value::Tag(_, lone) = hdkey(None) else {
            unreachable!()
        };
        let lone = assemble(&[encode_ur("crypto-hdkey", &lone)]).unwrap();
        assert!(lone.warnings.is_empty());

        // Pasted, the code is opened by the classifier, which says it
        // with its own findings; the descriptor it held, typed, is no
        // guess.
        let pasted = crate::input::parse_input(&ur_text).unwrap();
        assert!(pasted.warnings.contains(&InputWarning::AssumedBranches));
        let typed = crate::input::parse_input(&given.text.unwrap()).unwrap();
        assert!(!typed.warnings.contains(&InputWarning::AssumedBranches));
        assert_eq!(pasted.payload, typed.payload);
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
        frame_announcing(ur_type, 4_294_967_295, 4_294_967_294)
    }

    /// One multi-part frame, fragment `seq` of `total`, as its header
    /// and its fountain part both say.
    fn frame_announcing(ur_type: &str, seq: u32, total: u32) -> String {
        let part = Value::Array(vec![
            Value::Integer(seq.into()),
            Value::Integer(total.into()),
            Value::Integer(1.into()),
            Value::Integer(0.into()),
            Value::Bytes(vec![0]),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&part, &mut cbor).unwrap();
        let words = ur::bytewords::encode(&cbor, ur::bytewords::Style::Minimal);
        format!("ur:{ur_type}/{seq}-{total}/{words}")
    }

    /// A scan brings three times the parts its code announces at most,
    /// two thousand whatever it announces and ten thousand whatever it
    /// does: past that, a fountain code that never comes together is
    /// refused, under the code of a code too large to read.
    #[test]
    fn a_scan_past_its_frames_is_refused() {
        assert_eq!(scan_frame_limit(0), MIN_SCAN_FRAMES);
        assert_eq!(scan_frame_limit(3), MIN_SCAN_FRAMES);
        assert_eq!(scan_frame_limit(1_000), 3_000);
        assert_eq!(scan_frame_limit(5_000), MAX_SCAN_FRAMES);

        // Frames of a 600-part code the decoder cannot read: the scan
        // never comes together.
        let frames: Vec<String> = (1..=MIN_SCAN_FRAMES + 1)
            .map(|seq| format!("ur:bytes/{seq}-600/damaged"))
            .collect();
        let kept = assemble(&frames[..MIN_SCAN_FRAMES]).unwrap();
        assert!(!kept.complete);
        // Repeats count: a list past the bound is refused whatever it
        // holds, before a frame of it is read. Blanks do not, and the
        // refusal counts frames scanned.
        let repeated = vec![frames[0].clone(); MIN_SCAN_FRAMES + 1];
        assert!(matches!(
            assemble(&repeated),
            Err(CoreError::TooManyFrames(2_001))
        ));
        let mut padded = vec![String::new(); 5_000];
        padded.extend(frames[..MIN_SCAN_FRAMES].iter().cloned());
        assert!(assemble(&padded).is_ok());
        padded.push(frames[MIN_SCAN_FRAMES].clone());
        assert!(matches!(
            assemble(&padded),
            Err(CoreError::TooManyFrames(2_001))
        ));
        let refused = assemble(&frames).unwrap_err();
        assert!(
            matches!(refused, CoreError::TooManyFrames(2_001)),
            "{refused:?}"
        );
        assert_eq!(refused.code(), crate::error::ErrorCode::TooManyParts);
    }

    /// A count past what anyone scans is refused before the decoder
    /// draws a single mix from it; up to the cap, the scan goes on.
    #[test]
    fn a_ur_announcing_more_parts_than_anyone_scans_is_refused() {
        let hostile = frame_announcing("bytes", 7_000, MAX_UR_PARTS + 1);
        let refused = assemble(&[hostile]).unwrap_err();
        assert!(
            matches!(refused, CoreError::TooManyParts(5_001)),
            "{refused}"
        );
        assert_eq!(refused.code(), crate::error::ErrorCode::TooManyParts);
        assert_eq!(
            refused.to_string(),
            "invalid qr: this QR code announces 5001 parts, more than Gerfaut reads"
        );
        // A count of none is no count at all, not one too large.
        assert!(matches!(
            assemble(&[frame_announcing("bytes", 1, 0)]),
            Err(CoreError::InvalidInput { kind: "qr", .. })
        ));
        let progress = assemble(&[frame_announcing("bytes", 1, MAX_UR_PARTS)]).unwrap();
        assert!(!progress.complete);
        assert_eq!(progress.total, MAX_UR_PARTS);
    }

    /// Such a frame is refused before the decoder sizes anything by it,
    /// alone or among the frames of an honest scan.
    #[test]
    fn a_ur_announcing_billions_of_parts_is_refused() {
        let hostile = frame_announcing_billions("bytes");
        assert!(matches!(
            assemble(std::slice::from_ref(&hostile)),
            Err(CoreError::TooManyParts(4_294_967_294))
        ));
        // Pasted, as a wallet or as a transaction, it meets the same
        // refusal.
        assert!(matches!(
            crate::input::parse_input(&hostile),
            Err(CoreError::TooManyParts(_))
        ));
        assert!(matches!(
            crate::broadcast::decode_transaction(&hostile),
            Err(CoreError::TooManyParts(_))
        ));

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

    /// A key scanned alone opens as the account key a person would
    /// paste, and the classifier takes it, script read from its origin.
    #[test]
    fn a_lone_hdkey_opens_as_an_account_key() {
        let Value::Tag(_, map) = hdkey(None) else {
            unreachable!()
        };
        let text = assemble(&[encode_ur("crypto-hdkey", &map)])
            .unwrap()
            .text
            .unwrap();
        assert_eq!(text, format!("[9a6a2580/84'/1'/0']{TPUB}"));
        let parsed = crate::input::parse_input(&text).unwrap();
        assert_eq!(parsed.kind, crate::input::RecognizedKind::ExtendedKey);
        let crate::input::ParsedPayload::Descriptors {
            external, internal, ..
        } = parsed.payload
        else {
            panic!("an extended key makes descriptors");
        };
        assert!(
            external.starts_with(&format!("wpkh([9a6a2580/84'/1'/0']{TPUB}/0/*)")),
            "{external}"
        );
        assert!(internal.is_some());
    }

    /// [`hdkey`] with one entry of its map set to `value`.
    fn hdkey_with(key: u64, value: Value) -> Value {
        let Value::Tag(_, inner) = hdkey(None) else {
            unreachable!()
        };
        let Value::Map(mut entries) = *inner else {
            unreachable!()
        };
        entries.retain(|(k, _)| as_u64(k) != Some(key));
        entries.push((Value::Integer(key.into()), value));
        tag(TAG_HDKEY, Value::Map(entries))
    }

    /// An account origin of three hardened steps, the first one given.
    fn origin_from(first: Value, hardened: Value, depth: u64, fingerprint: u64) -> Value {
        tag(
            304,
            map(vec![
                (
                    1,
                    Value::Array(vec![
                        first,
                        hardened,
                        Value::Integer(1.into()),
                        Value::Bool(true),
                        Value::Integer(0.into()),
                        Value::Bool(true),
                    ]),
                ),
                (2, Value::Integer(fingerprint.into())),
                (3, Value::Integer(depth.into())),
            ]),
        )
    }

    /// What the format cannot say is refused, not read as something
    /// else: a step out of range or without its hardened flag, a
    /// network it does not name, a depth or a fingerprint that does not
    /// fit. Each used to come out as another key, without a word.
    #[test]
    fn a_malformed_hdkey_is_refused_not_guessed() {
        let index = |i: i64| Value::Integer(i.into());
        let hardened = Value::Bool(true);
        let fp = 0x9a6a_2580;
        let malformed = [
            hdkey_with(6, origin_from(index(1 << 31), hardened.clone(), 3, fp)),
            hdkey_with(6, origin_from(index(-1), hardened.clone(), 3, fp)),
            hdkey_with(6, origin_from(index(84), Value::Integer(1.into()), 3, fp)),
            hdkey_with(6, origin_from(index(84), hardened.clone(), 300, fp)),
            hdkey_with(6, origin_from(index(84), hardened.clone(), 3, 1 << 32)),
            hdkey_with(8, Value::Integer((1u64 << 32).into())),
            hdkey_with(5, tag(305, map(vec![(1, index(0)), (2, index(2))]))),
        ];
        for key in malformed {
            let frame = encode_ur("crypto-output", &tag(TAG_WPKH, key));
            let refused = assemble(&[frame]).unwrap_err();
            assert!(
                matches!(refused, CoreError::InvalidInput { kind: "qr", .. }),
                "{refused}"
            );
        }
        // The same origin, well formed, still opens.
        let key = hdkey_with(6, origin_from(index(84), hardened, 3, fp));
        let text = assemble(&[encode_ur("crypto-output", &tag(TAG_WPKH, key))])
            .unwrap()
            .text
            .unwrap();
        assert!(text.starts_with("wpkh([9a6a2580/84'/1'/0']"), "{text}");
    }

    /// A bare key is a public key of 33 bytes, or 65; 32 is a private
    /// key in this format, with or without the flag that says so.
    #[test]
    fn an_ec_key_of_a_private_length_is_refused_as_one() {
        let eckey = |data: Vec<u8>| tag(TAG_PK, tag(TAG_ECKEY, map(vec![(3, Value::Bytes(data))])));
        assert!(matches!(
            assemble(&[encode_ur("crypto-output", &eckey(vec![7; 32]))]),
            Err(CoreError::PrivateMaterialRejected)
        ));
        assert!(matches!(
            assemble(&[encode_ur("crypto-output", &eckey(vec![2; 20]))]),
            Err(CoreError::InvalidInput { kind: "qr", .. })
        ));
        let xpub: Xpub = TPUB.parse().unwrap();
        let public = xpub.public_key.serialize().to_vec();
        let text = assemble(&[encode_ur("crypto-output", &eckey(public.clone()))])
            .unwrap()
            .text
            .unwrap();
        assert_eq!(text, format!("pk({})", hex(&public)));
    }

    /// A damaged frame of another code seen first does not decide what
    /// the parts that follow are.
    #[test]
    fn a_ur_is_read_by_the_type_its_parts_carry() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&tag(TAG_WPKH, hdkey(None)), &mut bytes).unwrap();
        let mut encoder = ur::ur::Encoder::new(&bytes, 40, "crypto-output").unwrap();
        let mut frames = vec!["ur:crypto-psbt/1-3/lpadaxcfaxhl".to_owned()];
        for _ in 0..60 {
            frames.push(encoder.next_part().unwrap());
            let progress = assemble(&frames).unwrap();
            if progress.complete {
                let text = progress.text.unwrap();
                assert!(text.starts_with("wpkh([9a6a2580"), "{text}");
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

    /// Two codes of the same kind and length in front of the camera:
    /// their parts are not glued into a text neither holds. The same
    /// frame seen twice is only the camera seeing it again.
    #[test]
    fn two_bbqr_codes_scanned_together_are_refused() {
        let one = bbqr_frames(&format!("wpkh({TPUB}/<0;1>/*)"), 2);
        let other = bbqr_frames(&format!("pkh({TPUB}/<0;1>/*)"), 2);
        let refused = assemble(&[one[0].clone(), other[0].clone(), one[1].clone()]).unwrap_err();
        assert!(refused.to_string().contains("one at a time"), "{refused}");
        let again = assemble(&[one[0].clone(), one[0].clone(), one[1].clone()]).unwrap();
        assert!(again.complete);
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

    /// The same answer, error included: same variant, same words.
    fn same(left: &CoreResult<QrProgress>, right: &CoreResult<QrProgress>) -> bool {
        match (left, right) {
            (Ok(left), Ok(right)) => left == right,
            (Err(left), Err(right)) => format!("{left:?}") == format!("{right:?}"),
            _ => false,
        }
    }

    /// The frames of a multi-part UR of `ur_type` around `bytes`, in the
    /// order the encoder shows them, fountain parts after the plain ones.
    fn ur_parts(ur_type: &str, bytes: &[u8], fragment: usize, count: usize) -> Vec<String> {
        let mut encoder = ur::ur::Encoder::new(bytes, fragment, ur_type).unwrap();
        (0..count).map(|_| encoder.next_part().unwrap()).collect()
    }

    /// A pseudo-random draw, the same at every run.
    struct Draw(u64);

    impl Draw {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }
    }

    /// Frame after frame, a scan answers what [`assemble`] answers for
    /// the list of frames so far: suites of frames of one code out of
    /// order and repeated, frames of another code among them, of
    /// another kind, damaged, blank, and every kind of first frame.
    #[test]
    fn a_scan_answers_what_assemble_answers() {
        let mut descriptor = Vec::new();
        ciborium::into_writer(&tag(TAG_WPKH, hdkey(None)), &mut descriptor).unwrap();
        let mut other = Vec::new();
        ciborium::into_writer(&tag(TAG_PKH, hdkey(None)), &mut other).unwrap();
        let mut unsupported = Vec::new();
        ciborium::into_writer(&Value::Bytes(vec![1, 2, 3]), &mut unsupported).unwrap();
        let mut private = Vec::new();
        let Value::Tag(_, key) = hdkey(None) else {
            unreachable!()
        };
        let Value::Map(mut entries) = *key else {
            unreachable!()
        };
        entries[0].1 = Value::Bool(true);
        ciborium::into_writer(&tag(TAG_WPKH, tag(303, Value::Map(entries))), &mut private).unwrap();

        let main = ur_parts("crypto-output", &descriptor, 20, 60);
        let groups: Vec<Vec<String>> = vec![
            main.clone(),
            ur_parts("crypto-output", &other, 20, 30),
            ur_parts("crypto-psbt", &unsupported, 2, 6),
            ur_parts("crypto-output", &private, 30, 30),
            bbqr_frames(&format!("wpkh({TPUB}/<0;1>/*)"), 5),
            bbqr_frames(&format!("pkh({TPUB}/<0;1>/*)"), 5),
            bbqr_frames(&format!("tr({TPUB}/<0;1>/*)"), 3),
            vec![
                "B$HP01007073627400".to_owned(),
                "B$HX010000".to_owned(),
                "B$ZU0201\u{e9}".to_owned(),
                "B$ZU0100".to_owned(),
                "B$ZUa\u{e9}000".to_owned(),
            ],
            vec![
                format!("wpkh({TPUB}/0/*)"),
                "\u{e9}\u{e9}".to_owned(),
                encode_ur("crypto-output", &tag(TAG_WPKH, hdkey(None))),
                encode_ur("crypto-psbt", &Value::Bytes(b"psbt\xff".to_vec())),
            ],
            vec![
                "ur:bytes/1-3/garbage".to_owned(),
                "UR:bytes/1-2/\u{e9}".to_owned(),
                "ur:crypto-psbt/1-3/lpadaxcfaxhl".to_owned(),
                "ur:".to_owned(),
                "ur:bytes/x-y/z".to_owned(),
                frame_announcing("bytes", 1, 0),
                frame_announcing("crypto-output", 7_000, MAX_UR_PARTS + 1),
                frame_announcing_billions("crypto-output"),
            ],
            vec![String::new(), "  ".to_owned(), "\n".to_owned()],
        ];

        let mut draw = Draw(0x5eed_cafe);
        let mut suites: Vec<Vec<String>> = Vec::new();
        // The code in order, then with frames of every group among it.
        suites.push(main.clone());
        for group in &groups {
            let mut suite = group.clone();
            suite.extend(main.iter().cloned());
            suites.push(suite);
        }
        for _ in 0..240 {
            let lead = draw.below(groups.len());
            let mut suite = vec![groups[lead][draw.below(groups[lead].len())].clone()];
            for _ in 0..draw.below(45) {
                // Mostly the code of the first frame, out of order and
                // repeated; else any frame of any group.
                let group = if draw.below(3) == 0 {
                    draw.below(groups.len())
                } else {
                    lead
                };
                suite.push(groups[group][draw.below(groups[group].len())].clone());
            }
            suites.push(suite);
        }

        let mut answers = std::collections::BTreeSet::new();
        for suite in &suites {
            let mut scan = QrScan::new();
            assert!(same(&scan.progress(), &assemble(&[])));
            for seen in 1..=suite.len() {
                let pushed = scan.push(&suite[seen - 1]);
                let assembled = assemble(&suite[..seen]);
                assert!(
                    same(&pushed, &assembled),
                    "after {seen} frames of {suite:?}: {pushed:?} != {assembled:?}"
                );
                answers.insert(match &pushed {
                    Ok(progress) => format!("{:?} {}", progress.format, progress.complete),
                    Err(e) => e.code().to_string(),
                });
            }
        }
        // The suites went through every kind of answer.
        for kind in [
            "Ur true",
            "Ur false",
            "Bbqr true",
            "Bbqr false",
            "Plain true",
        ] {
            assert!(answers.contains(kind), "{kind} never came: {answers:?}");
        }
        for code in ["invalid_input", "too_many_parts", "private_material"] {
            assert!(answers.contains(code), "{code} never came: {answers:?}");
        }
    }

    /// Past its frame bound a scan is refused as the list is, by the
    /// count it reached, whatever it holds; blanks do not count.
    #[test]
    fn a_scan_past_its_frames_answers_what_assemble_answers() {
        let mut frames: Vec<String> = (1..=MIN_SCAN_FRAMES + 3)
            .map(|seq| format!("ur:bytes/{seq}-600/damaged"))
            .collect();
        frames.insert(10, String::new());
        let mut scan = QrScan::new();
        for seen in 1..=frames.len() {
            let pushed = scan.push(&frames[seen - 1]);
            if seen < 5 || seen + 6 > frames.len() {
                assert!(same(&pushed, &assemble(&frames[..seen])), "{seen}");
            }
        }
        assert!(matches!(
            scan.progress(),
            Err(CoreError::TooManyFrames(2_003))
        ));
        assert_eq!(scan.frames(), MIN_SCAN_FRAMES + 3);
    }

    /// The scans an app holds: one frame at a time under its number,
    /// started again after its answer, closed, bounded in number and in
    /// what they take.
    #[test]
    fn the_scans_an_app_holds_are_bounded() {
        let scans = QrScans::default();
        let frames = bbqr_frames(&format!("wpkh({TPUB}/<0;1>/*)"), 3);
        let id = scans.open();
        assert!(!scans.push(id, &frames[0]).unwrap().complete);
        assert_eq!(scans.push(id, &frames[2]).unwrap().received, 2);
        let done = scans.push(id, &frames[1]).unwrap();
        assert!(done.complete);
        // The answer given, the scan starts again empty.
        assert_eq!(scans.push(id, &frames[1]).unwrap().received, 1);

        // A refusal starts it again too, as both screens do.
        let other = bbqr_frames(&format!("pkh({TPUB}/<0;1>/*)"), 3);
        let refused = scans.push(id, &other[1]).unwrap_err();
        assert!(refused.to_string().contains("one at a time"), "{refused}");
        assert_eq!(scans.push(id, &other[1]).unwrap().received, 1);

        // A frame longer than any QR code holds is refused.
        let long = format!("B$ZU0300{}", "A".repeat(MAX_FRAME_LEN));
        assert!(matches!(
            scans.push(id, &long),
            Err(CoreError::InvalidInput { kind: "qr", .. })
        ));

        // So is a scan past its bytes, as a code larger than Gerfaut
        // reads.
        let wide = |seq: usize| format!("ur:bytes/{seq}-4000/{}", "a".repeat(MAX_FRAME_LEN - 20));
        let mut bytes = 0;
        let mut seq = 1;
        let refused = loop {
            let frame = wide(seq);
            bytes += frame.len();
            match scans.push(id, &frame) {
                Ok(progress) => assert!(!progress.complete),
                Err(e) => break e,
            }
            seq += 1;
        };
        assert!(bytes > MAX_SCAN_BYTES);
        assert!(bytes - MAX_SCAN_BYTES <= MAX_FRAME_LEN);
        assert!(matches!(refused, CoreError::TooManyFrames(n) if n as usize == seq));
        assert_eq!(refused.code(), crate::error::ErrorCode::TooManyParts);

        // Closed, a scan takes no more frames.
        scans.close(id);
        scans.close(id);
        assert_eq!(scans.open_count(), 0);
        assert!(matches!(
            scans.push(id, &frames[0]),
            Err(CoreError::InvalidInput { kind: "qr", .. })
        ));

        // The oldest goes past the bound.
        let opened: Vec<u32> = (0..MAX_OPEN_SCANS + 2).map(|_| scans.open()).collect();
        assert_eq!(scans.open_count(), MAX_OPEN_SCANS);
        assert!(scans.push(opened[0], &frames[0]).is_err());
        assert!(scans.push(opened[1], &frames[0]).is_err());
        for id in &opened[2..] {
            assert!(scans.push(*id, &frames[0]).is_ok());
        }
    }
}
