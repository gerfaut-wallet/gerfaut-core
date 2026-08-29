//! Encrypted backup of the wallets: the file a user keeps somewhere
//! safe, and the animated QR that carries the same bytes from one
//! device to the other.
//!
//! A backup holds wallet identities (descriptors or addresses, names,
//! labels) and, on request, the settings worth carrying over: backends,
//! accepted Electrum certificates, gap limit. Never chain state: the
//! receiving device syncs on its own. The payload is JSON, compressed,
//! then sealed with the vault cipher under a password-derived key and a
//! magic of its own ([`BACKUP_MAGIC`]), so a backup and a vault can never
//! be mistaken for one another. A backup only ever carries what the
//! vault does, and the vault never holds a private key.
//!
//! Over QR the sealed bytes ride in `ur:bytes` frames (BCR-2020-005),
//! the envelope the scanners around already speak. The frame list loops
//! on screen, and a receiver may join at any frame.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::chain::BackendConfig;
use crate::error::{CoreError, CoreResult, VaultError};
use crate::network::Network;
use crate::store::VaultKey;
use crate::store::cipher::{self, BACKUP_MAGIC};
use crate::wallet::meta::{WalletKind, WalletMeta};

/// Payload schema version written by this build.
pub const BACKUP_VERSION: u32 = 1;

/// Prefix of a backup in text form: what a scanned QR yields, and one
/// of the forms the restore screen accepts.
pub const BACKUP_PREFIX: &str = "gerfaut-backup:";

/// Shortest accepted password, after trimming.
const MIN_PASSWORD_CHARS: usize = 8;

/// Longest fragment of an animated QR, in bytes: small enough for a
/// phone camera to catch every frame at arm's length.
const MAX_FRAGMENT_LEN: usize = 100;

/// One wallet as a backup carries it: identity and labels, no chain
/// state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupWallet {
    pub name: String,
    pub network: Network,
    pub kind: WalletKind,
    pub gap_limit: u32,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub created_at: u64,
}

/// Everything a backup decrypts to. The settings fields are present
/// only when the export included them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupPayload {
    pub version: u32,
    pub created_at: u64,
    pub wallets: Vec<BackupWallet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backends: Option<BTreeMap<Network, BackendConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub electrum_certs: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_limit: Option<u32>,
}

impl BackupPayload {
    /// True when the export carried settings.
    pub fn has_settings(&self) -> bool {
        self.backends.is_some() || self.electrum_certs.is_some() || self.gap_limit.is_some()
    }
}

/// What to put in a backup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupOptions {
    /// Wallets to include; `None` means every wallet on every network.
    #[serde(default)]
    pub wallet_ids: Option<Vec<String>>,
    /// Whether backends, accepted certificates and the gap limit ride
    /// along.
    #[serde(default)]
    pub include_settings: bool,
}

/// A sealed backup in both transport forms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBundle {
    /// The sealed file bytes, base64.
    pub data: String,
    /// The frames of the animated QR, to loop on screen.
    pub frames: Vec<String>,
    pub wallet_count: u32,
    pub size_bytes: u32,
}

/// What a backup holds, before anything is restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPreview {
    pub created_at: u64,
    pub wallets: Vec<BackupWalletPreview>,
    pub has_settings: bool,
}

/// One wallet of a backup, as the restore screen lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupWalletPreview {
    /// Position in the backup, the handle [`ImportChoices`] uses.
    pub index: u32,
    pub name: String,
    pub network: Network,
    pub kind: WalletKind,
    /// A wallet watching the same thing on the same network exists
    /// already; restoring it would be skipped.
    pub already_watched: bool,
}

/// What to restore out of a backup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportChoices {
    /// Wallets to restore, by index in the preview; `None` means all.
    #[serde(default)]
    pub indexes: Option<Vec<u32>>,
    /// Whether the settings the backup carries replace the current ones.
    #[serde(default)]
    pub apply_settings: bool,
}

/// Outcome of a restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub added: Vec<WalletMeta>,
    /// Wallets left out: not chosen, or already watched.
    pub skipped: u32,
    pub settings_applied: bool,
}

fn backup_error(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidInput {
        kind: "backup",
        detail: detail.into(),
    }
}

/// The key a password derives to, after the checks both sides share.
///
/// The password is trimmed first: a stray space typed on one device
/// must not lock the other one out.
fn password_key(password: &str) -> CoreResult<VaultKey> {
    let password = password.trim();
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(CoreError::InvalidInput {
            kind: "backup password",
            detail: format!("at least {MIN_PASSWORD_CHARS} characters"),
        });
    }
    Ok(VaultKey::Password(password.to_owned()))
}

/// Serializes, compresses and seals a payload under a password.
pub fn seal(payload: &BackupPayload, password: &str) -> CoreResult<Vec<u8>> {
    let key = password_key(password)?;
    let json = serde_json::to_vec(payload)
        .map_err(|e| CoreError::Internal(format!("backup serialization failed: {e}")))?;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let compressed = encoder
        .write_all(&json)
        .and_then(|_| encoder.finish())
        .map_err(|e| CoreError::Internal(format!("backup compression failed: {e}")))?;
    Ok(cipher::seal_with(BACKUP_MAGIC, &compressed, &key)?)
}

/// Opens a sealed backup. A wrong password and a tampered file are one
/// and the same failure; a file that is not a backup is said to be so;
/// a payload written by a newer schema is refused by name rather than
/// half-read.
pub fn open(bytes: &[u8], password: &str) -> CoreResult<BackupPayload> {
    let key = password_key(password)?;
    let compressed = cipher::unseal_with(BACKUP_MAGIC, bytes, &key)?;
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(&compressed[..])
        .read_to_end(&mut json)
        .map_err(|e| VaultError::CorruptedPayload(e.to_string()))?;

    #[derive(Deserialize)]
    struct Versioned {
        version: u32,
    }
    let Versioned { version } =
        serde_json::from_slice(&json).map_err(|e| VaultError::CorruptedPayload(e.to_string()))?;
    if version > BACKUP_VERSION {
        return Err(backup_error(format!(
            "backup version {version} needs a newer Gerfaut"
        )));
    }
    serde_json::from_slice(&json).map_err(|e| VaultError::CorruptedPayload(e.to_string()).into())
}

/// Bytes of a backup handed over as text: bare base64 of the file, or
/// the `gerfaut-backup:` form a scanned QR yields. Whitespace and line
/// breaks are ignored either way, so a pasted file survives wrapping.
pub fn decode_source(source: &str) -> CoreResult<Vec<u8>> {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    let body = if compact.len() >= BACKUP_PREFIX.len()
        && compact[..BACKUP_PREFIX.len()].eq_ignore_ascii_case(BACKUP_PREFIX)
    {
        &compact[BACKUP_PREFIX.len()..]
    } else {
        compact.as_str()
    };
    if body.is_empty() {
        return Err(backup_error("nothing to restore"));
    }
    let padded = match body.len() % 4 {
        0 => body.to_owned(),
        rem => format!("{body}{}", "=".repeat(4 - rem)),
    };
    let bytes = data_encoding::BASE64
        .decode(padded.as_bytes())
        .map_err(|_| backup_error("expected the text of a backup file or a scanned backup"))?;
    if !bytes.starts_with(BACKUP_MAGIC) {
        return Err(backup_error("this is not a Gerfaut backup"));
    }
    Ok(bytes)
}

/// Frames of the animated QR carrying `bytes`: `ur:bytes` parts, the
/// pure fragments first, then as many fountain mixes, so a receiver
/// joining the loop at any frame still completes. Bytes that fit one
/// fragment make a single, static frame.
pub fn frames(bytes: &[u8]) -> Vec<String> {
    let mut message = Vec::with_capacity(bytes.len() + 8);
    ciborium::into_writer(&Value::Bytes(bytes.to_vec()), &mut message)
        .expect("writing CBOR to a vec cannot fail");
    if message.len() <= MAX_FRAGMENT_LEN {
        return vec![ur::ur::encode(&message, &ur::ur::Type::Bytes)];
    }
    let mut encoder = ur::ur::Encoder::bytes(&message, MAX_FRAGMENT_LEN)
        .expect("the message is not empty and the fragment length is not zero");
    (0..2 * encoder.fragment_count())
        .map(|_| {
            encoder
                .next_part()
                .expect("encoding a fountain part to CBOR cannot fail")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::ScriptKind;
    use crate::input::qr::assemble;

    const PASSWORD: &str = "correct horse battery staple";
    /// Public two-path key from the BDK documentation.
    const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";

    fn payload() -> BackupPayload {
        BackupPayload {
            version: BACKUP_VERSION,
            created_at: 1_755_000_000,
            wallets: vec![
                BackupWallet {
                    name: "Cold storage".to_owned(),
                    network: Network::Signet,
                    kind: WalletKind::Descriptors {
                        external: format!("wpkh({TPUB}/0/*)#checksum"),
                        internal: Some(format!("wpkh({TPUB}/1/*)#checksum")),
                        script: ScriptKind::Segwit,
                    },
                    gap_limit: 20,
                    labels: BTreeMap::from([("addr:tb1q".to_owned(), "rent".to_owned())]),
                    created_at: 1_754_000_000,
                },
                BackupWallet {
                    name: "Watched".to_owned(),
                    network: Network::Mainnet,
                    kind: WalletKind::SingleAddress {
                        address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned(),
                    },
                    gap_limit: 20,
                    labels: BTreeMap::new(),
                    created_at: 1_754_000_001,
                },
            ],
            backends: Some(BTreeMap::from([(
                Network::Signet,
                BackendConfig::CustomEsplora {
                    url: "https://esplora.example.org/api".to_owned(),
                },
            )])),
            electrum_certs: Some(BTreeMap::from([(
                "electrum.example.org:50002".to_owned(),
                "AB:CD".to_owned(),
            )])),
            gap_limit: Some(50),
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let sealed = seal(&payload(), PASSWORD).unwrap();
        assert_eq!(&sealed[..8], BACKUP_MAGIC);
        let opened = open(&sealed, PASSWORD).unwrap();
        assert_eq!(opened, payload());
        assert!(opened.has_settings());
        // Whitespace around the password is not part of it.
        assert_eq!(
            open(&sealed, &format!("  {PASSWORD}\n")).unwrap(),
            payload()
        );
    }

    #[test]
    fn settings_are_absent_when_not_exported() {
        let bare = BackupPayload {
            backends: None,
            electrum_certs: None,
            gap_limit: None,
            ..payload()
        };
        assert!(!bare.has_settings());
        let json = serde_json::to_string(&bare).unwrap();
        assert!(!json.contains("backends"), "{json}");
        let opened = open(&seal(&bare, PASSWORD).unwrap(), PASSWORD).unwrap();
        assert_eq!(opened, bare);
    }

    #[test]
    fn wrong_password_fails_closed() {
        let sealed = seal(&payload(), PASSWORD).unwrap();
        assert!(matches!(
            open(&sealed, "correct horse battery stapler"),
            Err(CoreError::Vault(VaultError::WrongKeyOrCorrupted))
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal(&payload(), PASSWORD).unwrap();
        let middle = sealed.len() / 2;
        sealed[middle] ^= 0x01;
        assert!(matches!(
            open(&sealed, PASSWORD),
            Err(CoreError::Vault(VaultError::WrongKeyOrCorrupted))
        ));
    }

    #[test]
    fn short_passwords_are_refused() {
        let error = seal(&payload(), "  short ").unwrap_err();
        assert!(
            matches!(
                error,
                CoreError::InvalidInput {
                    kind: "backup password",
                    ..
                }
            ),
            "{error}"
        );
        let sealed = seal(&payload(), PASSWORD).unwrap();
        assert!(matches!(
            open(&sealed, "short"),
            Err(CoreError::InvalidInput {
                kind: "backup password",
                ..
            })
        ));
    }

    #[test]
    fn newer_versions_are_refused_by_name() {
        let future = BackupPayload {
            version: BACKUP_VERSION + 1,
            ..payload()
        };
        let sealed = seal(&future, PASSWORD).unwrap();
        let error = open(&sealed, PASSWORD).unwrap_err();
        assert!(
            matches!(error, CoreError::InvalidInput { kind: "backup", .. }),
            "{error}"
        );
        assert!(error.to_string().contains("version 2"), "{error}");
    }

    #[test]
    fn a_vault_is_not_a_backup() {
        let key = VaultKey::Password(PASSWORD.to_owned());
        let vault = cipher::seal(b"{}", &key).unwrap();
        assert!(matches!(
            open(&vault, PASSWORD),
            Err(CoreError::Vault(VaultError::NotAVault))
        ));
        assert!(matches!(
            open(b"garbage", PASSWORD),
            Err(CoreError::Vault(VaultError::NotAVault))
        ));
    }

    #[test]
    fn decode_source_tolerates_every_text_form() {
        let sealed = seal(&payload(), PASSWORD).unwrap();
        let base64 = data_encoding::BASE64.encode(&sealed);

        assert_eq!(decode_source(&base64).unwrap(), sealed);
        assert_eq!(
            decode_source(&format!("{BACKUP_PREFIX}{base64}")).unwrap(),
            sealed
        );
        assert_eq!(
            decode_source(&format!("Gerfaut-Backup:{base64}")).unwrap(),
            sealed
        );
        let wrapped: String = base64
            .as_bytes()
            .chunks(64)
            .map(|line| format!("{}\r\n", std::str::from_utf8(line).unwrap()))
            .collect();
        assert_eq!(decode_source(&format!("\n  {wrapped} \t")).unwrap(), sealed);
        let unpadded = base64.trim_end_matches('=');
        assert_eq!(decode_source(unpadded).unwrap(), sealed);
    }

    #[test]
    fn decode_source_rejects_what_is_not_a_backup() {
        for garbage in ["", "   ", "not base64 at all!", "wpkh(abc)", BACKUP_PREFIX] {
            let error = decode_source(garbage).unwrap_err();
            assert!(
                matches!(error, CoreError::InvalidInput { kind: "backup", .. }),
                "{garbage:?}: {error}"
            );
        }
        // Valid base64 of something else, a vault file included.
        let key = VaultKey::Password(PASSWORD.to_owned());
        let vault = data_encoding::BASE64.encode(&cipher::seal(b"{}", &key).unwrap());
        let error = decode_source(&vault).unwrap_err();
        assert!(
            error.to_string().contains("not a Gerfaut backup"),
            "{error}"
        );
    }

    #[test]
    fn frames_assemble_from_any_starting_point() {
        let sealed = seal(&payload(), PASSWORD).unwrap();
        let frames = frames(&sealed);
        let expected = format!("{BACKUP_PREFIX}{}", data_encoding::BASE64.encode(&sealed));

        let parts = frames[0]
            .split('/')
            .nth(1)
            .and_then(|seq| seq.split_once('-'))
            .and_then(|(_, total)| total.parse::<usize>().ok())
            .expect("multi-part header");
        assert!(parts > 1, "the sealed bytes span several fragments");
        assert_eq!(frames.len(), 2 * parts, "pure fragments, then mixes");
        assert!(frames.iter().all(|f| f.starts_with("ur:bytes/")));

        let progress = assemble(&frames).unwrap();
        assert!(progress.complete);
        assert_eq!(progress.text.as_deref(), Some(expected.as_str()));
        assert_eq!(decode_source(&expected).unwrap(), sealed);

        // Joining the loop midway: mixes first, pure fragments last.
        let offset = parts / 2 + 1;
        let rotated: Vec<String> = frames[offset..]
            .iter()
            .chain(&frames[..offset])
            .cloned()
            .collect();
        let progress = assemble(&rotated).unwrap();
        assert!(progress.complete);
        assert_eq!(progress.text.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn a_small_backup_is_one_static_frame() {
        let mut bytes = BACKUP_MAGIC.to_vec();
        bytes.extend([7u8; 30]);
        let frames = frames(&bytes);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].matches('/').count(), 1, "no sequence header");
        let progress = assemble(&frames).unwrap();
        assert!(progress.complete);
        assert_eq!(
            progress.text.unwrap(),
            format!("{BACKUP_PREFIX}{}", data_encoding::BASE64.encode(&bytes))
        );
    }
}
