//! Account keys, licence certificates and the signed heartbeat.
//!
//! A key is sixteen symbols from an alphabet of thirty-two, shown and
//! typed as `xxxx-xxxx-xxxx-xxxx`; case and dashes carry nothing. A
//! certificate is `base64url(claims).base64url(signature)`, the
//! signature Ed25519 over the claims bytes, made by the server and
//! checked here with the public key below. The heartbeat is the same
//! key signing a small JSON text with the server's clock and tip, so an
//! app can tell a live server from a stale cache or a captive portal.
//!
//! Verification says whether the server wrote something, never whether
//! it still holds: an expired certificate verifies, and the caller reads
//! its dates through [`licence_state`]. Expiry is a matter of clocks
//! and grace periods the screen decides about; a bad signature is not.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER_PERMISSIVE};
use serde::{Deserialize, Serialize};

use crate::error::{CoreResult, PremiumError};

/// Hex of the Ed25519 key the production server signs with.
pub const LICENCE_PUBLIC_KEY_HEX: &str =
    "59c82605df28daf026ca6bc0d88a2cbb30037c0bc0b0a277028a3821e7d86a8e";

/// No `l`, `o`, `0` or `1`: nothing to misread from a screen. The
/// alphabet the server draws keys from, and the one ntfy topics use.
pub const KEY_ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
/// Symbols in a key, dashes not counted.
pub const KEY_SYMBOLS: usize = 16;
/// How far the server's clock may sit from this device's, in seconds,
/// for a heartbeat to count as fresh.
pub const HEARTBEAT_MAX_SKEW: i64 = 300;

/// The certificate format this build reads.
const CLAIMS_VERSION: u8 = 1;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Lowercase, dashes and spaces dropped: what a user typed, made
/// canonical. What goes in the `Authorization` header.
pub fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// `abcd-efgh-ijkm-npqr`, the way a key is shown.
pub fn format_key(key: &str) -> String {
    let compact = normalize_key(key);
    compact
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// A fresh account key, drawn from the operating system's generator:
/// sixteen symbols of [`KEY_ALPHABET`], each from five random bits, so
/// every symbol is as likely as the next. What the server would draw
/// for a key change, drawn here so that the vault holds it before the
/// request leaves. A random name for an account, nothing that holds or
/// could spend a coin.
pub(crate) fn draw_account_key() -> CoreResult<String> {
    use rand::TryRngCore;
    let mut bytes = [0u8; KEY_SYMBOLS];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|e| {
        crate::error::CoreError::Internal(format!("no randomness to draw a key: {e}"))
    })?;
    Ok(bytes
        .iter()
        .map(|b| KEY_ALPHABET[usize::from(*b & 31)] as char)
        .collect())
}

/// Whether a typed key has the shape of one; not whether it exists.
pub fn is_well_formed_key(key: &str) -> bool {
    let compact = normalize_key(key);
    compact.len() == KEY_SYMBOLS && compact.bytes().all(|b| KEY_ALPHABET.contains(&b))
}

/// The signed part of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Format version.
    pub v: u8,
    /// Hex of the key hash the certificate is about. The apps cannot
    /// recompute it (the server's pepper is not theirs): it is a stable
    /// name for the account, nothing more.
    pub sub: String,
    /// Unix seconds: when the paid time ends.
    pub exp: i64,
    /// Unix seconds: when the certificate was issued.
    pub iat: i64,
}

impl Claims {
    /// Whether the paid time covers `now_unix`, the way the server
    /// judges it: active up to the second the paid time ends.
    pub fn is_active(&self, now_unix: i64) -> bool {
        now_unix < self.exp
    }

    /// The certificate read against a clock.
    pub fn state(&self, now_unix: i64) -> LicenceState {
        licence_state(self, now_unix)
    }
}

/// What a certificate says at a given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LicenceState {
    /// Paid time left, until this unix second.
    Active { until: i64 },
    /// The paid time ended at this unix second. Deliveries go on for a
    /// week after it; whether to say so is the screen's call.
    Expired { since: i64 },
}

/// The certificate read against a clock: the signature was already
/// checked by [`verify_certificate`], this only compares dates.
pub fn licence_state(claims: &Claims, now_unix: i64) -> LicenceState {
    if claims.is_active(now_unix) {
        LicenceState::Active { until: claims.exp }
    } else {
        LicenceState::Expired { since: claims.exp }
    }
}

/// Checks a certificate against the licence key and returns its claims.
///
/// Only authenticity is judged here: a certificate whose paid time has
/// ended still verifies, and comes back with its dates for the caller
/// to read. Anything malformed, signed by another key, or in a format
/// this build does not know is refused.
pub fn verify_certificate(certificate: &str, public_key_hex: &str) -> CoreResult<Claims> {
    let invalid = |detail: &str| PremiumError::InvalidCertificate(detail.to_owned());
    let (payload, signature) = certificate
        .trim()
        .split_once('.')
        .ok_or_else(|| invalid("expected two base64url parts separated by a dot"))?;
    let payload = BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .map_err(|_| invalid("the claims are not base64url"))?;
    let signature = BASE64URL_NOPAD
        .decode(signature.as_bytes())
        .map_err(|_| invalid("the signature is not base64url"))?;
    verify_signature(public_key_hex, &payload, &signature)
        .map_err(PremiumError::InvalidCertificate)?;
    let claims: Claims = serde_json::from_slice(&payload)
        .map_err(|e| PremiumError::InvalidCertificate(format!("the claims do not parse: {e}")))?;
    if claims.v != CLAIMS_VERSION {
        return Err(PremiumError::InvalidCertificate(format!(
            "certificate version {} is not one this build reads",
            claims.v
        ))
        .into());
    }
    Ok(claims)
}

/// What the server signs to prove it is up: its clock, and the chain
/// tip it watches from (`None` before its first block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Unix seconds on the server.
    pub now: i64,
    pub tip_height: Option<u32>,
}

/// Checks a heartbeat: the signature over the exact JSON text, then the
/// server's clock against `now_unix`. A heartbeat more than
/// [`HEARTBEAT_MAX_SKEW`] seconds off is genuine but not fresh, which
/// for the "watch is offline" banner is the same as no heartbeat.
pub fn verify_heartbeat(
    payload_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
    now_unix: i64,
) -> CoreResult<Heartbeat> {
    let signature = HEXLOWER_PERMISSIVE
        .decode(signature_hex.trim().as_bytes())
        .map_err(|_| PremiumError::InvalidHeartbeat("the signature is not hex".to_owned()))?;
    verify_signature(public_key_hex, payload_json.as_bytes(), &signature)
        .map_err(PremiumError::InvalidHeartbeat)?;
    let heartbeat: Heartbeat = serde_json::from_str(payload_json)
        .map_err(|e| PremiumError::InvalidHeartbeat(format!("the payload does not parse: {e}")))?;
    let skew = now_unix - heartbeat.now;
    if skew.abs() > HEARTBEAT_MAX_SKEW {
        return Err(PremiumError::StaleHeartbeat { skew }.into());
    }
    Ok(heartbeat)
}

/// Ed25519 over `message`, with the key given as hex. The error is a
/// sentence for the variant the caller wraps it in.
fn verify_signature(public_key_hex: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = HEXLOWER_PERMISSIVE
        .decode(public_key_hex.trim().as_bytes())
        .map_err(|_| "the public key is not hex".to_owned())?;
    if key.len() != PUBLIC_KEY_BYTES {
        return Err(format!(
            "the public key is {} bytes, not {PUBLIC_KEY_BYTES}",
            key.len()
        ));
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(format!(
            "the signature is {} bytes, not {SIGNATURE_BYTES}",
            signature.len()
        ));
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(message, signature)
        .map_err(|_| "the signature does not match".to_owned())
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! The server's side of the protocol, done once and offline: two
    //! throwaway Ed25519 keys, drawn at random and discarded the moment
    //! the constants below were printed, signed the certificates and
    //! heartbeats the tests verify. Nothing in this crate signs, not
    //! even a test; whoever audits that promise with a grep should
    //! find no signer here to explain away.
    //!
    //! To produce a new set, in a scratch project outside the
    //! repository with `ed25519-dalek`, `data-encoding` and `rand`:
    //! draw two 32-byte seeds, make a signing key of each, and with
    //! the server's key sign the exact text named above each constant.
    //! A certificate is `base64url(text).base64url(signature)`, both
    //! without padding; a heartbeat signature is the lower-case hex of
    //! the signature over the exact text. The other key signs the valid
    //! claims and the `tip_height` 1 heartbeat once each, so a test can
    //! hand the verifier the right text under the wrong key. Replace
    //! the whole set at once: the keys that made this one are gone.

    /// The unix second every fixture is dated against.
    pub const NOW: i64 = 1_790_000_000;

    /// The server's verifying key, hex.
    pub const SERVER_PUBLIC_KEY_HEX: &str =
        "4c506fd45f58d9ba24b9526fba8dac4021648531d3dd08a131aa1acca9d3cacd";
    /// A second verifying key, hex: another server, or whoever
    /// pretends to be one.
    pub const OTHER_PUBLIC_KEY_HEX: &str =
        "f40d3c96a47ccc48c29dd01102f3e3858c56c1a02974ff8c099a554d74381a6f";

    /// Over `{"v":1,"sub":"<ab × 32>","exp":1790086400,"iat":1789999940}`:
    /// a day of paid time left at [`NOW`].
    pub const VALID_CERTIFICATE: &str = "eyJ2IjoxLCJzdWIiOiJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiZXhwIjoxNzkwMDg2NDAwLCJpYXQiOjE3ODk5OTk5NDB9.agV86zDZGD4sf_rRL2bF1J19z_9somd00AiFZ-OKrd5rlmBjc5el5obcZbH06P5xXisCmGJR50VK1YONErH_Aw";
    /// The same claims as [`VALID_CERTIFICATE`], under the other key.
    pub const OTHER_KEY_CERTIFICATE: &str = "eyJ2IjoxLCJzdWIiOiJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiZXhwIjoxNzkwMDg2NDAwLCJpYXQiOjE3ODk5OTk5NDB9.rK_XjHUg2YYWikvyfpPQiA_mHUtzPBAf6RyJBen-3UuFUporQRD1T7ERJfmYyW6ZrfIpqw8RsXEHYMPFjlSvCA";
    /// Over `{"v":1,"sub":"<ab × 32>","exp":1789996400,"iat":1789999940}`:
    /// paid time that ended an hour before [`NOW`].
    pub const EXPIRED_CERTIFICATE: &str = "eyJ2IjoxLCJzdWIiOiJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiZXhwIjoxNzg5OTk2NDAwLCJpYXQiOjE3ODk5OTk5NDB9.wHO7bYAQ4KzyCqi5UmnpUhrus-Jhhe6rdE9-xMWnJegedn7XZ7mcOypRtxnmBVCB9LXB0BNJbpw6KCvrPso4Bg";
    /// Over `{"v":2,"sub":"<ab × 32>","exp":1790086400,"iat":1789999940}`:
    /// a format this build does not read.
    pub const VERSION_2_CERTIFICATE: &str = "eyJ2IjoyLCJzdWIiOiJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiZXhwIjoxNzkwMDg2NDAwLCJpYXQiOjE3ODk5OTk5NDB9.nvXqaGMGcMhjvrEvYOj2cuew1rGZSdGrHRMt3D5uWAJTDEEST1odtVY1X4ue6lfka7sk96YGSYVphl7EXug5CA";
    /// Over the five bytes `hello`: genuine, and not claims.
    pub const NOT_JSON_CERTIFICATE: &str = "aGVsbG8.bITsEGQQAfyTRSxxBq5ZMCGoQ_t3MV254F0jsQvLmx6QOxcgBnTQZHdawxRIGHohshE1xGVgY0q4JI0UdTrNBg";
    /// Over `{"v":1,"sub":"<cd × 32>","exp":1792592000,"iat":1790000000}`:
    /// thirty days of paid time on another account, issued at [`NOW`].
    pub const ACCOUNT_CERTIFICATE: &str = "eyJ2IjoxLCJzdWIiOiJjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkY2RjZGNkIiwiZXhwIjoxNzkyNTkyMDAwLCJpYXQiOjE3OTAwMDAwMDB9.40dcvoUVC3xvZQPjOeoxeI2-IEhn2CsCKY7DnS11zqsrH3u-blK4F7UHQcUUb9LRS1r-KCOlYbaf46RbkeYhAQ";

    /// A heartbeat: the exact text the server signed, and its
    /// signature in hex.
    pub type SignedText = (&'static str, &'static str);

    pub const HEARTBEAT_AT_900000: SignedText = (
        r#"{"now":1790000000,"tip_height":900000}"#,
        "f739acee9837abaab25189ad65f1ecf0e29b1f69ea8fb8bce15d8d71779d6727be2a29342dcfee6dffd4d5935ce3ce2c2a4edccc995653a3b0603b534d4e420f",
    );
    pub const HEARTBEAT_BEFORE_FIRST_BLOCK: SignedText = (
        r#"{"now":1790000000,"tip_height":null}"#,
        "b3993262d46fcaf25571dcfc1e9a9fe1c404b23e361c89d784c18daaaff0cb8d4abd443ec57acfb71ad88f14fea1058e2f6eeae0ffff3d6acf2fc0038d3fce01",
    );
    pub const HEARTBEAT_AT_1: SignedText = (
        r#"{"now":1790000000,"tip_height":1}"#,
        "39b0c66f457f6aff8aee9a84da4494ef7a0a05add364f7459a797d787fb7ea0a3afe41ad1444a32a44dd76e5bfa6e7b695ff83c1aaff3b93fc1b15690f012f0f",
    );
    pub const HEARTBEAT_AT_910000: SignedText = (
        r#"{"now":1790000000,"tip_height":910000}"#,
        "6e0a468ac8d73796563eee08fe93a70e2f55c166d17e09ff39709598da423ca1e074ff9ace97e6533f01feecfe69a68ff3b3c107171623836bbb9c9351949d0a",
    );
    /// Genuine, and not a heartbeat.
    pub const NOT_A_HEARTBEAT: SignedText = (
        r#"{"hello":"world"}"#,
        "777711416a55dd1cfb000ce0d015a558145558dc44c43e95b3ec2cbca2e9434ee5c0f860bc0d56cabd8db523110e6c85ec37b6a068de3c9388a7cc506f849708",
    );
    /// The other key's signature over the text of [`HEARTBEAT_AT_1`].
    pub const OTHER_KEY_HEARTBEAT_AT_1_SIGNATURE_HEX: &str = "4bff0264c6d3e1c7b31a6fe0a849e08dd92500a20c98ec2c0bfbf8cce4efa7b574c52c52d2ae7cc192ed7a128492edcf4ab8498ce0a7b514a5303d7d2a7fd40c";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::error::CoreError;

    fn claims(exp: i64) -> Claims {
        Claims {
            v: 1,
            sub: "ab".repeat(32),
            exp,
            iat: NOW - 60,
        }
    }

    fn premium_error(error: CoreError) -> PremiumError {
        match error {
            CoreError::Premium(error) => error,
            other => panic!("not a premium error: {other}"),
        }
    }

    #[test]
    fn a_key_is_read_however_it_was_typed() {
        let key = "abcd-efgh-ijkm-npqr";
        assert_eq!(normalize_key(key), "abcdefghijkmnpqr");
        assert_eq!(normalize_key(" ABCD EFGH\tijkm-NPQR "), "abcdefghijkmnpqr");
        assert_eq!(format_key("ABCDEFGHIJKMNPQR"), key);
        assert_eq!(format_key(key), key);
        // A partial key formats as far as it goes: the field shows the
        // groups while they are typed.
        assert_eq!(format_key("abcdef"), "abcd-ef");
    }

    #[test]
    fn a_well_formed_key_is_sixteen_symbols_of_the_alphabet() {
        assert!(is_well_formed_key("abcd-efgh-ijkm-npqr"));
        assert!(is_well_formed_key("ABCDEFGHIJKMNPQR"));
        assert!(is_well_formed_key("2345 6789 abcd efgh"));
        // Too short, too long, and the four symbols the alphabet leaves
        // out because a screen misreads them.
        assert!(!is_well_formed_key("abcd-efgh-ijkm-npq"));
        assert!(!is_well_formed_key("abcd-efgh-ijkm-npqrs"));
        assert!(!is_well_formed_key("abcd-efgh-ijkl-npqr"));
        assert!(!is_well_formed_key("abcd-efgh-ijkm-npqo"));
        assert!(!is_well_formed_key("abcd-efgh-ijkm-npq0"));
        assert!(!is_well_formed_key("abcd-efgh-ijkm-npq1"));
        assert!(!is_well_formed_key(""));
    }

    #[test]
    fn a_drawn_account_key_is_well_formed_and_new_each_time() {
        let key = draw_account_key().unwrap();
        assert!(is_well_formed_key(&key), "{key}");
        assert_eq!(key, normalize_key(&key));
        assert_ne!(key, draw_account_key().unwrap());
    }

    #[test]
    fn the_production_key_is_thirty_two_bytes_of_hex() {
        let key = HEXLOWER_PERMISSIVE
            .decode(LICENCE_PUBLIC_KEY_HEX.as_bytes())
            .unwrap();
        assert_eq!(key.len(), PUBLIC_KEY_BYTES);
    }

    #[test]
    fn a_certificate_verifies_and_reads_its_claims() {
        let read = verify_certificate(VALID_CERTIFICATE, SERVER_PUBLIC_KEY_HEX).unwrap();
        assert_eq!(read, claims(NOW + 86_400));
        assert!(read.is_active(NOW));
        assert_eq!(
            read.state(NOW),
            LicenceState::Active {
                until: NOW + 86_400
            }
        );
        // Whitespace around a pasted certificate is nobody's fault.
        assert!(
            verify_certificate(&format!(" {VALID_CERTIFICATE}\n"), SERVER_PUBLIC_KEY_HEX).is_ok()
        );
    }

    /// Verification is about who wrote the certificate, not whether it
    /// still holds: the screen decides what an ended paid time means.
    #[test]
    fn an_expired_certificate_verifies_and_says_so() {
        let read = verify_certificate(EXPIRED_CERTIFICATE, SERVER_PUBLIC_KEY_HEX).unwrap();
        assert_eq!(read, claims(NOW - 3_600));
        assert!(!read.is_active(NOW));
        assert_eq!(
            read.state(NOW),
            LicenceState::Expired { since: NOW - 3_600 }
        );
        // The boundary belongs to the past: at the very second the paid
        // time ends, it has ended, as the server sees it.
        assert!(!claims(NOW).is_active(NOW));
        assert!(claims(NOW + 1).is_active(NOW));
    }

    #[test]
    fn another_key_or_a_changed_claim_is_refused() {
        let refused =
            premium_error(verify_certificate(VALID_CERTIFICATE, OTHER_PUBLIC_KEY_HEX).unwrap_err());
        assert_eq!(
            refused,
            PremiumError::InvalidCertificate("the signature does not match".to_owned())
        );
        // A later expiry pasted over the signed one.
        let (payload, signature) = VALID_CERTIFICATE.split_once('.').unwrap();
        let mut forged = claims(NOW + 86_400);
        forged.exp = NOW + 10 * 365 * 86_400;
        let forged = format!(
            "{}.{signature}",
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&forged).unwrap())
        );
        assert!(verify_certificate(&forged, SERVER_PUBLIC_KEY_HEX).is_err());
        // The right claims under another key's signature: the other
        // key's certificate holds the very same claims, and is good
        // under its own key alone.
        let (other_payload, other_signature) = OTHER_KEY_CERTIFICATE.split_once('.').unwrap();
        assert_eq!(other_payload, payload);
        assert!(verify_certificate(OTHER_KEY_CERTIFICATE, OTHER_PUBLIC_KEY_HEX).is_ok());
        let swapped = format!("{payload}.{other_signature}");
        assert!(verify_certificate(&swapped, SERVER_PUBLIC_KEY_HEX).is_err());
    }

    #[test]
    fn a_malformed_certificate_is_named_not_guessed_at() {
        let detail = |certificate: &str| match premium_error(
            verify_certificate(certificate, SERVER_PUBLIC_KEY_HEX).unwrap_err(),
        ) {
            PremiumError::InvalidCertificate(detail) => detail,
            other => panic!("{other}"),
        };
        assert!(detail("").contains("two base64url parts"));
        assert!(detail("onlyonepart").contains("two base64url parts"));
        assert!(detail("not*base64.AAAA").contains("claims are not base64url"));
        assert!(detail("AAAA.not*base64").contains("signature is not base64url"));
        // Standard base64 with padding is not the url-safe alphabet the
        // server writes.
        assert!(detail("AAA=.AAAA").contains("not base64url"));
        assert!(detail("AAAA.AAAA").contains("bytes, not 64"));
        // Signed by the right key, but not JSON claims.
        assert!(detail(NOT_JSON_CERTIFICATE).contains("do not parse"));
        // Signed by the right key, in a format this build does not read.
        assert!(detail(VERSION_2_CERTIFICATE).contains("version 2"));
    }

    #[test]
    fn a_bad_public_key_is_refused_before_anything_else() {
        assert!(verify_certificate(VALID_CERTIFICATE, "zz").is_err());
        assert!(verify_certificate(VALID_CERTIFICATE, "abcd").is_err());
        assert!(verify_certificate(VALID_CERTIFICATE, "").is_err());
    }

    #[test]
    fn a_fresh_heartbeat_verifies() {
        let (payload, signature) = HEARTBEAT_AT_900000;
        assert_eq!(payload, format!(r#"{{"now":{NOW},"tip_height":900000}}"#));
        let heartbeat =
            verify_heartbeat(payload, signature, SERVER_PUBLIC_KEY_HEX, NOW + 30).unwrap();
        assert_eq!(
            heartbeat,
            Heartbeat {
                now: NOW,
                tip_height: Some(900_000),
            }
        );
        // Before the first block the tip is null; the hex may be upper
        // case.
        let (payload, signature) = HEARTBEAT_BEFORE_FIRST_BLOCK;
        let heartbeat = verify_heartbeat(
            payload,
            &signature.to_uppercase(),
            SERVER_PUBLIC_KEY_HEX,
            NOW - 299,
        )
        .unwrap();
        assert_eq!(heartbeat.tip_height, None);
    }

    #[test]
    fn a_heartbeat_off_by_more_than_five_minutes_is_stale() {
        let (payload, signature) = HEARTBEAT_AT_1;
        let key = SERVER_PUBLIC_KEY_HEX;
        assert!(verify_heartbeat(payload, signature, key, NOW + 300).is_ok());
        assert!(verify_heartbeat(payload, signature, key, NOW - 300).is_ok());
        assert_eq!(
            premium_error(verify_heartbeat(payload, signature, key, NOW + 301).unwrap_err()),
            PremiumError::StaleHeartbeat { skew: 301 }
        );
        assert_eq!(
            premium_error(verify_heartbeat(payload, signature, key, NOW - 301).unwrap_err()),
            PremiumError::StaleHeartbeat { skew: -301 }
        );
    }

    #[test]
    fn a_heartbeat_is_the_exact_text_that_was_signed() {
        let (payload, signature) = HEARTBEAT_AT_1;
        let key = SERVER_PUBLIC_KEY_HEX;
        // The same value, spelled with a space: not what was signed.
        let respaced = payload.replace(',', ", ");
        assert!(verify_heartbeat(&respaced, signature, key, NOW).is_err());
        // A later clock pasted in, to look fresh.
        let advanced = payload.replace(&NOW.to_string(), &(NOW + 1000).to_string());
        assert!(verify_heartbeat(&advanced, signature, key, NOW + 1000).is_err());
        // Another server's signature, good under its own key and no
        // other, and no signature at all.
        let elsewhere = OTHER_KEY_HEARTBEAT_AT_1_SIGNATURE_HEX;
        assert!(verify_heartbeat(payload, elsewhere, key, NOW).is_err());
        assert!(verify_heartbeat(payload, elsewhere, OTHER_PUBLIC_KEY_HEX, NOW).is_ok());
        assert_eq!(
            premium_error(verify_heartbeat(payload, "not hex", key, NOW).unwrap_err()),
            PremiumError::InvalidHeartbeat("the signature is not hex".to_owned())
        );
        assert!(verify_heartbeat(payload, "abcd", key, NOW).is_err());
        // Signed, but not a heartbeat.
        let (text, signature) = NOT_A_HEARTBEAT;
        assert!(matches!(
            premium_error(verify_heartbeat(text, signature, key, NOW).unwrap_err()),
            PremiumError::InvalidHeartbeat(detail) if detail.contains("does not parse")
        ));
    }

    #[test]
    fn licence_states_serialize_for_the_apps() {
        assert_eq!(
            serde_json::to_string(&LicenceState::Active { until: 5 }).unwrap(),
            r#"{"status":"active","until":5}"#
        );
        assert_eq!(
            serde_json::to_string(&LicenceState::Expired { since: 5 }).unwrap(),
            r#"{"status":"expired","since":5}"#
        );
    }
}
