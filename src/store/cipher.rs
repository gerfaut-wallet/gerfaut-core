//! Authenticated encryption of the vault file.
//!
//! Format, all fields fixed-size before the ciphertext:
//!
//! ```text
//! magic "GFVAULT1" (8) | version (1) | kdf (1) | salt (16) | nonce (24) | ciphertext
//! ```
//!
//! XChaCha20-Poly1305 with a random 24-byte nonce per write. The key is
//! either provided raw by the platform (32 bytes out of the OS keystore)
//! or derived from a password with Argon2id. A fresh salt and nonce are
//! drawn on every save.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;

const MAGIC: &[u8; 8] = b"GFVAULT1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + 1 + SALT_LEN + NONCE_LEN;

const KDF_RAW: u8 = 0;
const KDF_ARGON2ID: u8 = 1;

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
    fn kdf_id(&self) -> u8 {
        match self {
            VaultKey::Raw(_) => KDF_RAW,
            VaultKey::Password(_) => KDF_ARGON2ID,
        }
    }

    /// Derives the 32-byte encryption key for a given salt.
    fn derive(&self, salt: &[u8]) -> Result<[u8; 32], VaultError> {
        match self {
            VaultKey::Raw(key) => Ok(*key),
            VaultKey::Password(password) => {
                let mut out = [0u8; 32];
                Argon2::default()
                    .hash_password_into(password.as_bytes(), salt, &mut out)
                    .map_err(|e| VaultError::Kdf(e.to_string()))?;
                Ok(out)
            }
        }
    }
}

/// Encrypts a serialized payload into the vault file format.
pub fn seal(plaintext: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let mut derived = key.derive(&salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| VaultError::Kdf("encryption failure".to_owned()))?;
    derived.zeroize();

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(key.kdf_id());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a vault file back into the serialized payload.
///
/// Fails with [`VaultError::WrongKeyOrCorrupted`] when authentication
/// fails — a wrong key and a tampered file are indistinguishable by
/// design.
pub fn unseal(file: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    if file.len() < HEADER_LEN || &file[..8] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    let version = file[8];
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    // The KDF byte is informative (it lets an app prompt for the right
    // credential kind); decryption trusts the provided key.
    let salt = &file[10..10 + SALT_LEN];
    let nonce = &file[10 + SALT_LEN..HEADER_LEN];
    let ciphertext = &file[HEADER_LEN..];

    let mut derived = key.derive(salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::WrongKeyOrCorrupted);
    derived.zeroize();
    plaintext
}

/// Reads the KDF kind of a vault file, so the app knows whether to ask
/// for a password or fetch the platform key.
pub fn kdf_kind(file: &[u8]) -> Result<VaultKdf, VaultError> {
    if file.len() < HEADER_LEN || &file[..8] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    match file[9] {
        KDF_RAW => Ok(VaultKdf::PlatformKey),
        KDF_ARGON2ID => Ok(VaultKdf::Password),
        _ => Err(VaultError::UnsupportedVersion(file[8])),
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
    fn kdf_kind_is_readable_without_key() {
        let sealed = seal(b"p", &raw_key(7)).unwrap();
        assert_eq!(kdf_kind(&sealed).unwrap(), VaultKdf::PlatformKey);
        let sealed = seal(b"p", &VaultKey::Password("x".to_owned())).unwrap();
        assert_eq!(kdf_kind(&sealed).unwrap(), VaultKdf::Password);
    }
}
