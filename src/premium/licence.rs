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
pub(crate) mod testing {
    //! A signer for the tests only: the server's side of the protocol,
    //! so what is verified here was produced the way the server does it.

    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use ed25519_dalek::{Signer, SigningKey};

    use super::Claims;

    pub struct Issuer {
        signing: SigningKey,
    }

    impl Issuer {
        pub fn from_seed(seed: u8) -> Self {
            Issuer {
                signing: SigningKey::from_bytes(&[seed; 32]),
            }
        }

        pub fn public_key_hex(&self) -> String {
            HEXLOWER.encode(&self.signing.verifying_key().to_bytes())
        }

        pub fn sign_hex(&self, message: &[u8]) -> String {
            HEXLOWER.encode(&self.signing.sign(message).to_bytes())
        }

        /// `base64url(claims).base64url(signature)`, as the server
        /// issues it.
        pub fn issue(&self, claims: &Claims) -> String {
            let payload = serde_json::to_vec(claims).expect("claims serialize");
            self.issue_bytes(&payload)
        }

        pub fn issue_bytes(&self, payload: &[u8]) -> String {
            let signature = self.signing.sign(payload);
            format!(
                "{}.{}",
                BASE64URL_NOPAD.encode(payload),
                BASE64URL_NOPAD.encode(&signature.to_bytes())
            )
        }

        /// The `{"now":..,"tip_height":..}` text and its hex signature.
        pub fn heartbeat(&self, now: i64, tip_height: Option<u32>) -> (String, String) {
            let payload = serde_json::json!({ "now": now, "tip_height": tip_height }).to_string();
            let signature = self.sign_hex(payload.as_bytes());
            (payload, signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Issuer;
    use super::*;
    use crate::error::CoreError;

    const NOW: i64 = 1_790_000_000;

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
    fn the_production_key_is_thirty_two_bytes_of_hex() {
        let key = HEXLOWER_PERMISSIVE
            .decode(LICENCE_PUBLIC_KEY_HEX.as_bytes())
            .unwrap();
        assert_eq!(key.len(), PUBLIC_KEY_BYTES);
    }

    #[test]
    fn a_certificate_verifies_and_reads_its_claims() {
        let issuer = Issuer::from_seed(7);
        let issued = claims(NOW + 86_400);
        let certificate = issuer.issue(&issued);
        let read = verify_certificate(&certificate, &issuer.public_key_hex()).unwrap();
        assert_eq!(read, issued);
        assert!(read.is_active(NOW));
        assert_eq!(
            read.state(NOW),
            LicenceState::Active {
                until: NOW + 86_400
            }
        );
        // Whitespace around a pasted certificate is nobody's fault.
        assert!(verify_certificate(&format!(" {certificate}\n"), &issuer.public_key_hex()).is_ok());
    }

    /// Verification is about who wrote the certificate, not whether it
    /// still holds: the screen decides what an ended paid time means.
    #[test]
    fn an_expired_certificate_verifies_and_says_so() {
        let issuer = Issuer::from_seed(7);
        let certificate = issuer.issue(&claims(NOW - 3_600));
        let read = verify_certificate(&certificate, &issuer.public_key_hex()).unwrap();
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
        let issuer = Issuer::from_seed(7);
        let certificate = issuer.issue(&claims(NOW + 86_400));
        let other = Issuer::from_seed(8);
        let refused =
            premium_error(verify_certificate(&certificate, &other.public_key_hex()).unwrap_err());
        assert_eq!(
            refused,
            PremiumError::InvalidCertificate("the signature does not match".to_owned())
        );
        // A later expiry pasted over the signed one.
        let (payload, signature) = certificate.split_once('.').unwrap();
        let mut forged = claims(NOW + 86_400);
        forged.exp = NOW + 10 * 365 * 86_400;
        let forged = format!(
            "{}.{signature}",
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&forged).unwrap())
        );
        assert!(verify_certificate(&forged, &issuer.public_key_hex()).is_err());
        // The right claims under another certificate's signature.
        let swapped = format!(
            "{payload}.{}",
            other
                .issue(&claims(NOW + 86_400))
                .split_once('.')
                .unwrap()
                .1
        );
        assert!(verify_certificate(&swapped, &issuer.public_key_hex()).is_err());
    }

    #[test]
    fn a_malformed_certificate_is_named_not_guessed_at() {
        let issuer = Issuer::from_seed(7);
        let key = issuer.public_key_hex();
        let detail = |certificate: &str| match premium_error(
            verify_certificate(certificate, &key).unwrap_err(),
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
        assert!(detail(&issuer.issue_bytes(b"hello")).contains("do not parse"));
        // Signed by the right key, in a format this build does not read.
        let mut future = claims(NOW + 86_400);
        future.v = 2;
        assert!(detail(&issuer.issue(&future)).contains("version 2"));
    }

    #[test]
    fn a_bad_public_key_is_refused_before_anything_else() {
        let issuer = Issuer::from_seed(7);
        let certificate = issuer.issue(&claims(NOW + 86_400));
        assert!(verify_certificate(&certificate, "zz").is_err());
        assert!(verify_certificate(&certificate, "abcd").is_err());
        assert!(verify_certificate(&certificate, "").is_err());
    }

    #[test]
    fn a_fresh_heartbeat_verifies() {
        let issuer = Issuer::from_seed(7);
        let (payload, signature) = issuer.heartbeat(NOW, Some(900_000));
        assert_eq!(payload, format!(r#"{{"now":{NOW},"tip_height":900000}}"#));
        let heartbeat =
            verify_heartbeat(&payload, &signature, &issuer.public_key_hex(), NOW + 30).unwrap();
        assert_eq!(
            heartbeat,
            Heartbeat {
                now: NOW,
                tip_height: Some(900_000),
            }
        );
        // Before the first block the tip is null; the hex may be upper
        // case.
        let (payload, signature) = issuer.heartbeat(NOW, None);
        let heartbeat = verify_heartbeat(
            &payload,
            &signature.to_uppercase(),
            &issuer.public_key_hex(),
            NOW - 299,
        )
        .unwrap();
        assert_eq!(heartbeat.tip_height, None);
    }

    #[test]
    fn a_heartbeat_off_by_more_than_five_minutes_is_stale() {
        let issuer = Issuer::from_seed(7);
        let (payload, signature) = issuer.heartbeat(NOW, Some(1));
        let key = issuer.public_key_hex();
        assert!(verify_heartbeat(&payload, &signature, &key, NOW + 300).is_ok());
        assert!(verify_heartbeat(&payload, &signature, &key, NOW - 300).is_ok());
        assert_eq!(
            premium_error(verify_heartbeat(&payload, &signature, &key, NOW + 301).unwrap_err()),
            PremiumError::StaleHeartbeat { skew: 301 }
        );
        assert_eq!(
            premium_error(verify_heartbeat(&payload, &signature, &key, NOW - 301).unwrap_err()),
            PremiumError::StaleHeartbeat { skew: -301 }
        );
    }

    #[test]
    fn a_heartbeat_is_the_exact_text_that_was_signed() {
        let issuer = Issuer::from_seed(7);
        let (payload, signature) = issuer.heartbeat(NOW, Some(1));
        let key = issuer.public_key_hex();
        // The same value, spelled with a space: not what was signed.
        let respaced = payload.replace(',', ", ");
        assert!(verify_heartbeat(&respaced, &signature, &key, NOW).is_err());
        // A later clock pasted in, to look fresh.
        let advanced = payload.replace(&NOW.to_string(), &(NOW + 1000).to_string());
        assert!(verify_heartbeat(&advanced, &signature, &key, NOW + 1000).is_err());
        // Another server's signature, and no signature at all.
        let other = Issuer::from_seed(8);
        assert!(
            verify_heartbeat(&payload, &other.sign_hex(payload.as_bytes()), &key, NOW).is_err()
        );
        assert_eq!(
            premium_error(verify_heartbeat(&payload, "not hex", &key, NOW).unwrap_err()),
            PremiumError::InvalidHeartbeat("the signature is not hex".to_owned())
        );
        assert!(verify_heartbeat(&payload, "abcd", &key, NOW).is_err());
        // Signed, but not a heartbeat.
        let text = r#"{"hello":"world"}"#;
        assert!(matches!(
            premium_error(
                verify_heartbeat(text, &issuer.sign_hex(text.as_bytes()), &key, NOW).unwrap_err()
            ),
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
