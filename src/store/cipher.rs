//! Authenticated encryption of the vault file, and of the backups that
//! share its format.
//!
//! Format, all fields fixed-size before the ciphertext:
//!
//! ```text
//! magic (8) | version (1) | kdf (1) | salt (16) | nonce (24) | ciphertext
//! ```
//!
//! The magic names the file: `GFVAULT1` for the vault, `GFBACKUP` for a
//! backup. It is bound with the rest of the header, so a backup can never
//! be opened as a vault or the reverse. XChaCha20-Poly1305 with a random
//! 24-byte nonce per write; the whole header is bound as associated data
//! (since version 2). The key is either provided raw by the platform (32
//! bytes out of the OS keystore) or derived from a password with Argon2id
//! (pinned parameters). A fresh salt and nonce are drawn on every save.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::VaultError;

const MAGIC: &[u8; 8] = b"GFVAULT1";
/// Magic of a backup file: same envelope, different name, so the two
/// can never be mistaken for one another.
pub const BACKUP_MAGIC: &[u8; 8] = b"GFBACKUP";
const VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + 1 + SALT_LEN + NONCE_LEN;

/// The KDF byte names a profile, and the code fixes the parameters of
/// each profile for good: a dependency bump changing library defaults
/// must never lock existing files out.
const KDF_RAW: u8 = 0;
/// Argon2id, the OWASP profile: m=19456 KiB, t=2, p=1. Every vault
/// sealed under a password, and every backup written before the
/// heavier profile existed.
const KDF_ARGON2ID: u8 = 1;
/// Argon2id, the RFC 9106 profile: m=65536 KiB, t=3, p=1. What a backup
/// is sealed under now. A backup is a file that travels and can be
/// guessed at offline for as long as it exists, so its password gets
/// the profile that costs a guess five times more; the vault, opened
/// and saved at every change, keeps the lighter one.
const KDF_ARGON2ID_64M: u8 = 2;

/// Key material for the vault. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum VaultKey {
    /// A 32-byte key supplied by the platform layer, typically held in
    /// the OS keystore (Android Keystore, Windows DPAPI, keyring).
    Raw([u8; 32]),
    /// A user password; the key is derived with Argon2id.
    Password(String),
}

impl VaultKey {
    /// The profile a file of this `magic` is sealed under with this
    /// key.
    fn kdf_id(&self, magic: &[u8; 8]) -> u8 {
        match self {
            VaultKey::Raw(_) => KDF_RAW,
            VaultKey::Password(_) if magic == BACKUP_MAGIC => KDF_ARGON2ID_64M,
            VaultKey::Password(_) => KDF_ARGON2ID,
        }
    }

    /// Derives the 32-byte encryption key for a given salt, under the
    /// profile the file's KDF byte names.
    /// Wiped when dropped, on every path out, an error included.
    fn derive(&self, kdf: u8, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        match self {
            VaultKey::Raw(key) => Ok(Zeroizing::new(*key)),
            VaultKey::Password(password) => {
                let (m_cost, t_cost) = match kdf {
                    KDF_ARGON2ID_64M => (65_536, 3),
                    _ => (19_456, 2),
                };
                let params = argon2::Params::new(m_cost, t_cost, 1, Some(32))
                    .map_err(|e| VaultError::Kdf(e.to_string()))?;
                let argon =
                    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
                let mut out = Zeroizing::new([0u8; 32]);
                argon
                    .hash_password_into(password.as_bytes(), salt, &mut out[..])
                    .map_err(|e| VaultError::Kdf(e.to_string()))?;
                Ok(out)
            }
        }
    }
}

/// Encrypts a serialized payload into the vault file format.
///
/// The whole header (magic, version, KDF id, salt, nonce) is bound as
/// associated data: flipping any header byte fails authentication.
pub fn seal(plaintext: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    seal_with(MAGIC, plaintext, key)
}

/// [`seal`] under another magic, for files that share the envelope
/// without being vaults.
pub fn seal_with(magic: &[u8; 8], plaintext: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let kdf = key.kdf_id(magic);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(magic);
    header.push(VERSION);
    header.push(kdf);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let derived = key.derive(kdf, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived[..]));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Kdf("encryption failure".to_owned()))?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a vault file back into the serialized payload.
///
/// Fails with [`VaultError::WrongKeyOrCorrupted`] when authentication
/// fails — a wrong key and a tampered file are indistinguishable by
/// design. Version 1 files (no header binding) are still readable; they
/// are rewritten as version 2 at the next save.
pub fn unseal(file: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    unseal_with(MAGIC, file, key)
}

/// [`unseal`] under another magic. A file carrying a different magic is
/// [`VaultError::NotAVault`], whichever way round.
pub fn unseal_with(magic: &[u8; 8], file: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    if file.len() < HEADER_LEN || &file[..8] != magic {
        return Err(VaultError::NotAVault);
    }
    let version = file[8];
    if version != 1 && version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    // The KDF byte names the profile a password is derived under, and
    // lets an app prompt for the right credential kind. Decryption still
    // trusts the provided key: the byte is bound as associated data, so
    // rewriting it to a lighter profile fails authentication rather than
    // yielding a key to guess at. A profile this build does not know is
    // one a newer build added: the file is refused as such, before any
    // key is derived, never reported as a wrong key.
    let kdf = file[9];
    if !matches!(kdf, KDF_RAW | KDF_ARGON2ID | KDF_ARGON2ID_64M) {
        return Err(VaultError::UnsupportedKdf(kdf));
    }
    let salt = &file[10..10 + SALT_LEN];
    let nonce = &file[10 + SALT_LEN..HEADER_LEN];
    let ciphertext = &file[HEADER_LEN..];

    let derived = key.derive(kdf, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived[..]));
    let payload = Payload {
        msg: ciphertext,
        // Version 1 sealed without associated data.
        aad: if version == 1 {
            &[]
        } else {
            &file[..HEADER_LEN]
        },
    };
    cipher
        .decrypt(XNonce::from_slice(nonce), payload)
        .map_err(|_| VaultError::WrongKeyOrCorrupted)
}

/// Reads the KDF kind of a vault file, so the app knows whether to ask
/// for a password or fetch the platform key.
pub fn kdf_kind(file: &[u8]) -> Result<VaultKdf, VaultError> {
    if file.len() < HEADER_LEN || &file[..8] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    match file[9] {
        KDF_RAW => Ok(VaultKdf::PlatformKey),
        KDF_ARGON2ID | KDF_ARGON2ID_64M => Ok(VaultKdf::Password),
        other => Err(VaultError::UnsupportedKdf(other)),
    }
}

/// Credential kind a vault file expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultKdf {
    PlatformKey,
    Password,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_key(byte: u8) -> VaultKey {
        VaultKey::Raw([byte; 32])
    }

    #[test]
    fn roundtrip_raw_key() {
        let sealed = seal(b"payload", &raw_key(7)).unwrap();
        assert_eq!(unseal(&sealed, &raw_key(7)).unwrap(), b"payload");
    }

    #[test]
    fn roundtrip_password() {
        let key = VaultKey::Password("correct horse".to_owned());
        let sealed = seal(b"payload", &key).unwrap();
        assert_eq!(unseal(&sealed, &key).unwrap(), b"payload");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal(b"payload", &raw_key(7)).unwrap();
        assert!(matches!(
            unseal(&sealed, &raw_key(8)),
            Err(VaultError::WrongKeyOrCorrupted)
        ));
        let sealed = seal(b"payload", &VaultKey::Password("a".to_owned())).unwrap();
        assert!(matches!(
            unseal(&sealed, &VaultKey::Password("b".to_owned())),
            Err(VaultError::WrongKeyOrCorrupted)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal(b"payload", &raw_key(7)).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            unseal(&sealed, &raw_key(7)),
            Err(VaultError::WrongKeyOrCorrupted)
        ));
    }

    #[test]
    fn header_tampering_is_detected() {
        let mut sealed = seal(b"payload", &raw_key(7)).unwrap();
        // Flip the KDF id byte: the header is bound as associated data.
        sealed[9] ^= 0x01;
        assert!(matches!(
            unseal(&sealed, &raw_key(7)),
            Err(VaultError::WrongKeyOrCorrupted)
        ));
    }

    #[test]
    fn version_1_files_stay_readable() {
        // Reproduce the version 1 layout: same header, no associated data.
        let key = raw_key(7);
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let derived = key.derive(KDF_RAW, &salt).unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived[..]));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), b"legacy payload".as_slice())
            .unwrap();
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.push(1);
        file.push(KDF_RAW);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);

        assert_eq!(unseal(&file, &key).unwrap(), b"legacy payload");
    }

    /// A file sealed under `kdf` with `key`, the way this build writes
    /// one, whatever profile it would choose itself.
    fn sealed_under(magic: &[u8; 8], kdf: u8, key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let mut header = Vec::new();
        header.extend_from_slice(magic);
        header.push(VERSION);
        header.push(kdf);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        let derived = key.derive(kdf, &salt).unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived[..]));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        header.extend_from_slice(&ciphertext);
        header
    }

    /// A backup is sealed under the heavier profile, a vault under the
    /// one every password vault was written with, and each opens under
    /// the profile its own byte names.
    #[test]
    fn a_backup_gets_the_heavier_profile_and_a_vault_keeps_its_own() {
        let key = VaultKey::Password("correct horse".to_owned());
        let backup = seal_with(BACKUP_MAGIC, b"payload", &key).unwrap();
        assert_eq!(backup[9], KDF_ARGON2ID_64M);
        assert_eq!(
            unseal_with(BACKUP_MAGIC, &backup, &key).unwrap(),
            b"payload"
        );
        let vault = seal(b"payload", &key).unwrap();
        assert_eq!(vault[9], KDF_ARGON2ID);
        assert_eq!(unseal(&vault, &key).unwrap(), b"payload");
        assert_eq!(kdf_kind(&vault).unwrap(), VaultKdf::Password);
        // The platform key derives nothing, under either magic.
        assert_eq!(
            seal_with(BACKUP_MAGIC, b"p", &raw_key(7)).unwrap()[9],
            KDF_RAW
        );
    }

    /// Every backup written before the heavier profile existed carries
    /// the first Argon2id byte, and must go on opening under the first
    /// Argon2id parameters.
    #[test]
    fn a_backup_under_the_first_profile_still_opens() {
        let key = VaultKey::Password("correct horse".to_owned());
        let older = sealed_under(BACKUP_MAGIC, KDF_ARGON2ID, &key, b"older backup");
        assert_eq!(
            unseal_with(BACKUP_MAGIC, &older, &key).unwrap(),
            b"older backup"
        );
        // And a vault written under the heavier byte, should one ever
        // be, reads under it as well: the byte decides, not the magic.
        let heavier = sealed_under(MAGIC, KDF_ARGON2ID_64M, &key, b"heavier vault");
        assert_eq!(unseal(&heavier, &key).unwrap(), b"heavier vault");
        assert_eq!(kdf_kind(&heavier).unwrap(), VaultKdf::Password);
    }

    /// The byte is bound as associated data: rewriting a backup to the
    /// lighter profile does not hand out a lighter key to guess at, and
    /// a profile this build does not know is named as a newer one
    /// rather than tried, or blamed on the key.
    #[test]
    fn the_kdf_byte_cannot_be_downgraded_and_an_unknown_one_is_named() {
        let key = VaultKey::Password("correct horse".to_owned());
        let mut backup = seal_with(BACKUP_MAGIC, b"payload", &key).unwrap();
        backup[9] = KDF_ARGON2ID;
        assert!(matches!(
            unseal_with(BACKUP_MAGIC, &backup, &key),
            Err(VaultError::WrongKeyOrCorrupted)
        ));
        backup[9] = 9;
        assert!(matches!(
            unseal_with(BACKUP_MAGIC, &backup, &key),
            Err(VaultError::UnsupportedKdf(9))
        ));
        let mut vault = seal(b"payload", &key).unwrap();
        vault[9] = 9;
        assert!(matches!(
            kdf_kind(&vault),
            Err(VaultError::UnsupportedKdf(9))
        ));
    }

    #[test]
    fn nonce_and_salt_are_fresh_per_seal() {
        let key = raw_key(7);
        let a = seal(b"payload", &key).unwrap();
        let b = seal(b"payload", &key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn garbage_is_not_a_vault() {
        assert!(matches!(
            unseal(
                b"not a vault at all, way too short anyway padding",
                &raw_key(7)
            ),
            Err(VaultError::NotAVault)
        ));
        assert!(matches!(
            unseal(b"", &raw_key(7)),
            Err(VaultError::NotAVault)
        ));
    }

    #[test]
    fn future_version_is_refused() {
        let mut sealed = seal(b"payload", &raw_key(7)).unwrap();
        sealed[8] = 99;
        assert!(matches!(
            unseal(&sealed, &raw_key(7)),
            Err(VaultError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn backup_and_vault_magics_refuse_each_other() {
        let key = VaultKey::Password("correct horse".to_owned());
        let backup = seal_with(BACKUP_MAGIC, b"payload", &key).unwrap();
        assert_eq!(&backup[..8], BACKUP_MAGIC);
        assert_eq!(
            unseal_with(BACKUP_MAGIC, &backup, &key).unwrap(),
            b"payload"
        );
        assert!(matches!(unseal(&backup, &key), Err(VaultError::NotAVault)));
        assert!(matches!(kdf_kind(&backup), Err(VaultError::NotAVault)));

        let vault = seal(b"payload", &key).unwrap();
        assert!(matches!(
            unseal_with(BACKUP_MAGIC, &vault, &key),
            Err(VaultError::NotAVault)
        ));
    }

    #[test]
    fn kdf_kind_is_readable_without_key() {
        let sealed = seal(b"p", &raw_key(7)).unwrap();
        assert_eq!(kdf_kind(&sealed).unwrap(), VaultKdf::PlatformKey);
        let sealed = seal(b"p", &VaultKey::Password("x".to_owned())).unwrap();
        assert_eq!(kdf_kind(&sealed).unwrap(), VaultKdf::Password);
    }
}
