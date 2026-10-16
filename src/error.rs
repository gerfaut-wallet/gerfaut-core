//! Error types shared across the crate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result alias used by the public API.
pub type CoreResult<T> = Result<T, CoreError>;

/// The stable name of a failure, the one the apps decide on.
///
/// Every [`CoreError`] has one, given by [`CoreError::code`]. Both
/// bridges send it unchanged as the `kind` of a failure, beside the
/// error's own words, and a screen picks its sentence on the code
/// alone: the words are for logs, and for the screens that have no
/// sentence of their own for a failure.
///
/// Serialized in snake_case, the form [`ErrorCode::as_str`] gives. A
/// code keeps its name and its meaning: a failure the apps must tell
/// apart gets a code of its own, and a code no longer raised is not
/// handed to another failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Nothing in the input reads as a format Gerfaut watches.
    UnrecognizedInput,
    /// The input holds a private key, refused before anything is kept.
    PrivateMaterial,
    /// A recognized format, invalid in itself: a bad checksum, a
    /// malformed path, a QR code no wallet makes, a choice out of range.
    InvalidInput,
    /// An animated QR code announces more parts than Gerfaut reads.
    TooManyParts,
    /// The input belongs to another network than the one asked for.
    NetworkMismatch,
    /// No wallet of that id in the vault.
    WalletNotFound,
    /// The wallet is watched already.
    DuplicateWallet,
    /// The key or password given does not open the vault or the
    /// backup. To the cipher a file altered after it was sealed is the
    /// same failure, so a screen names both. Never raised for anything
    /// else: a file of another kind, or from a newer Gerfaut, has a
    /// code of its own.
    WrongKey,
    /// Another open holds the vault: a healthy vault, nothing read.
    VaultInUse,
    /// The vault could not be read or written: the disk, a damaged
    /// file, a key derivation that failed.
    Vault,
    /// What was handed over as a backup cannot be read as one: not a
    /// Gerfaut backup at all (another file, a vault, a QR code of
    /// something else), or one damaged outside what the password
    /// guards. The password is not in question.
    UnreadableBackup,
    /// A vault or a backup written by a newer Gerfaut, in a format this
    /// build does not know: updating Gerfaut opens it. The password is
    /// not in question either.
    NewerFormat,
    /// A chain backend failed during a sync.
    Sync,
    /// The network refused a transaction, or no backend took it.
    Broadcast,
    /// The configured backend cannot serve this request.
    BackendUnavailable,
    /// Tor is required, and no way through it could be found.
    Tor,
    /// The wallet engine refused a descriptor.
    Descriptor,
    /// A bug in the core.
    Internal,
}

impl ErrorCode {
    /// Every code, in declaration order.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::UnrecognizedInput,
        ErrorCode::PrivateMaterial,
        ErrorCode::InvalidInput,
        ErrorCode::TooManyParts,
        ErrorCode::NetworkMismatch,
        ErrorCode::WalletNotFound,
        ErrorCode::DuplicateWallet,
        ErrorCode::WrongKey,
        ErrorCode::VaultInUse,
        ErrorCode::Vault,
        ErrorCode::UnreadableBackup,
        ErrorCode::NewerFormat,
        ErrorCode::Sync,
        ErrorCode::Broadcast,
        ErrorCode::BackendUnavailable,
        ErrorCode::Tor,
        ErrorCode::Descriptor,
        ErrorCode::Internal,
    ];

    /// The code as it crosses the bridges: its serialized name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnrecognizedInput => "unrecognized_input",
            ErrorCode::PrivateMaterial => "private_material",
            ErrorCode::InvalidInput => "invalid_input",
            ErrorCode::TooManyParts => "too_many_parts",
            ErrorCode::NetworkMismatch => "network_mismatch",
            ErrorCode::WalletNotFound => "wallet_not_found",
            ErrorCode::DuplicateWallet => "duplicate_wallet",
            ErrorCode::WrongKey => "wrong_key",
            ErrorCode::VaultInUse => "vault_in_use",
            ErrorCode::Vault => "vault",
            ErrorCode::UnreadableBackup => "unreadable_backup",
            ErrorCode::NewerFormat => "newer_format",
            ErrorCode::Sync => "sync",
            ErrorCode::Broadcast => "broadcast",
            ErrorCode::BackendUnavailable => "backend_unavailable",
            ErrorCode::Tor => "tor",
            ErrorCode::Descriptor => "descriptor",
            ErrorCode::Internal => "internal",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level error of the crate.
///
/// The apps tell failures apart by [`CoreError::code`], never by
/// variant or by message; the inner strings carry technical detail for
/// logs.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The pasted or scanned input could not be recognized as any
    /// supported watch-only format.
    #[error("unrecognized input: {0}")]
    UnrecognizedInput(String),

    /// The input contains private key material. Gerfaut is watch-only:
    /// such inputs are refused outright and never stored.
    #[error("input contains private key material and was rejected")]
    PrivateMaterialRejected,

    /// The input is a recognized format but invalid in itself
    /// (bad checksum, malformed derivation path, ...).
    #[error("invalid {kind}: {detail}")]
    InvalidInput { kind: &'static str, detail: String },

    /// A multi-part UR announces more parts than the 5,000 Gerfaut
    /// reads, the count it gives. Refused on the count alone, before
    /// any part is decoded.
    #[error("invalid qr: this QR code announces {0} parts, more than Gerfaut reads")]
    TooManyParts(u32),

    /// The input belongs to a different network than the requested one.
    #[error("network mismatch: input is for {found}, expected {expected}")]
    NetworkMismatch { expected: String, found: String },

    /// No wallet with this id exists in the vault.
    #[error("wallet not found: {0}")]
    WalletNotFound(String),

    /// A wallet with the same content already exists.
    #[error("wallet already exists: {0}")]
    DuplicateWallet(String),

    /// Vault file errors: I/O, corruption, or wrong decryption key.
    #[error(transparent)]
    Vault(#[from] VaultError),

    /// What was handed over as a backup is not one this build can read:
    /// not a Gerfaut backup, or a backup damaged outside its seal. A
    /// wrong password is never this: it is
    /// [`VaultError::WrongKeyOrCorrupted`].
    #[error("invalid backup: {0}")]
    UnreadableBackup(String),

    /// A backup written by a newer Gerfaut, at any layer of its format.
    #[error("invalid backup: {0}")]
    NewerBackup(String),

    /// Chain backend errors during sync.
    #[error("sync failed via {backend}: {detail}")]
    Sync { backend: String, detail: String },

    /// The network refused a transaction handed to it, or no backend
    /// could be reached to try. `detail` is the node's own words.
    #[error("{backend} refused the transaction: {detail}")]
    Broadcast { backend: String, detail: String },

    /// The configured backend cannot serve this request
    /// (e.g. no public backend exists for regtest).
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    /// An onion backend could not be given a way through Tor: no proxy
    /// answers, or the embedded client could not start.
    #[error("tor: {0}")]
    Tor(String),

    /// Descriptor-level error surfaced by the wallet engine.
    #[error("descriptor error: {0}")]
    Descriptor(String),

    /// Internal invariant violation. Indicates a bug in this crate.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// The stable code the apps decide on.
    pub fn code(&self) -> ErrorCode {
        match self {
            CoreError::UnrecognizedInput(_) => ErrorCode::UnrecognizedInput,
            CoreError::PrivateMaterialRejected => ErrorCode::PrivateMaterial,
            CoreError::InvalidInput { .. } => ErrorCode::InvalidInput,
            CoreError::TooManyParts(_) => ErrorCode::TooManyParts,
            CoreError::NetworkMismatch { .. } => ErrorCode::NetworkMismatch,
            CoreError::WalletNotFound(_) => ErrorCode::WalletNotFound,
            CoreError::DuplicateWallet(_) => ErrorCode::DuplicateWallet,
            CoreError::Vault(error) => error.code(),
            CoreError::UnreadableBackup(_) => ErrorCode::UnreadableBackup,
            CoreError::NewerBackup(_) => ErrorCode::NewerFormat,
            CoreError::Sync { .. } => ErrorCode::Sync,
            CoreError::Broadcast { .. } => ErrorCode::Broadcast,
            CoreError::BackendUnavailable(_) => ErrorCode::BackendUnavailable,
            CoreError::Tor(_) => ErrorCode::Tor,
            CoreError::Descriptor(_) => ErrorCode::Descriptor,
            CoreError::Internal(_) => ErrorCode::Internal,
        }
    }
}

/// Errors specific to the encrypted vault store.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Another open holds this vault: a second copy of the app running
    /// on the same data directory, or a second manager opened in the
    /// same process. Nothing was read or written. The holder keeps the
    /// vault until it closes it or exits, and a crash releases it too.
    #[error("the vault is already open in another Gerfaut process")]
    AlreadyOpen,

    /// The file does not start with the expected magic bytes.
    #[error("not a vault file")]
    NotAVault,

    /// The file version is newer than what this build understands.
    #[error("vault version {0} is not supported by this build")]
    UnsupportedVersion(u8),

    /// The file names a key derivation profile this build does not
    /// know: it was written by a newer build, not damaged.
    #[error("vault key profile {0} is not supported by this build")]
    UnsupportedKdf(u8),

    /// Decryption failed: wrong key/password, or the file was tampered with.
    #[error("vault decryption failed: wrong key or corrupted file")]
    WrongKeyOrCorrupted,

    /// The decrypted payload could not be deserialized.
    #[error("vault payload is corrupted: {0}")]
    CorruptedPayload(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),
}

impl VaultError {
    /// The code a vault failure reaches the apps under. A wrong key, a
    /// vault held elsewhere and a file from a newer Gerfaut are named
    /// apart: the first is what a password explains, the second a
    /// healthy vault, the third an update away.
    pub fn code(&self) -> ErrorCode {
        match self {
            VaultError::WrongKeyOrCorrupted => ErrorCode::WrongKey,
            VaultError::AlreadyOpen => ErrorCode::VaultInUse,
            VaultError::UnsupportedVersion(_) | VaultError::UnsupportedKdf(_) => {
                ErrorCode::NewerFormat
            }
            VaultError::Io(_)
            | VaultError::NotAVault
            | VaultError::CorruptedPayload(_)
            | VaultError::Kdf(_) => ErrorCode::Vault,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names the apps match on. Renaming one breaks a screen in
    /// both apps without a compiler to say so: this list is the
    /// contract, and changes only by adding to it.
    #[test]
    fn the_codes_keep_their_names() {
        let names: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(
            names,
            [
                "unrecognized_input",
                "private_material",
                "invalid_input",
                "too_many_parts",
                "network_mismatch",
                "wallet_not_found",
                "duplicate_wallet",
                "wrong_key",
                "vault_in_use",
                "vault",
                "unreadable_backup",
                "newer_format",
                "sync",
                "broadcast",
                "backend_unavailable",
                "tor",
                "descriptor",
                "internal",
            ]
        );
    }

    /// What serde writes is what `as_str` gives, both ways, and no two
    /// codes share a name.
    #[test]
    fn a_code_serializes_to_its_name() {
        let mut seen = std::collections::HashSet::new();
        for &code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(code.to_string(), code.as_str());
            assert_eq!(serde_json::from_str::<ErrorCode>(&json).unwrap(), code);
            assert!(seen.insert(code.as_str()), "{code} named twice");
        }
    }

    /// A wrong key is the only vault failure under `wrong_key`, a vault
    /// held elsewhere the only one under `vault_in_use`, and a file
    /// from a newer Gerfaut is under `newer_format`.
    #[test]
    fn a_wrong_key_is_told_apart_from_other_vault_failures() {
        let code = |error: VaultError| CoreError::Vault(error).code();
        assert_eq!(code(VaultError::WrongKeyOrCorrupted), ErrorCode::WrongKey);
        assert_eq!(code(VaultError::AlreadyOpen), ErrorCode::VaultInUse);
        assert_eq!(
            code(VaultError::UnsupportedVersion(9)),
            ErrorCode::NewerFormat
        );
        assert_eq!(code(VaultError::UnsupportedKdf(9)), ErrorCode::NewerFormat);
        for other in [
            VaultError::Io(std::io::Error::other("disk gone")),
            VaultError::NotAVault,
            VaultError::CorruptedPayload("truncated".to_owned()),
            VaultError::Kdf("out of memory".to_owned()),
        ] {
            assert_eq!(code(other), ErrorCode::Vault);
        }
    }

    /// Each variant reaches the apps under its own code.
    #[test]
    fn every_error_has_its_code() {
        let text = || "detail".to_owned();
        let cases = [
            (
                CoreError::UnrecognizedInput(text()),
                ErrorCode::UnrecognizedInput,
            ),
            (
                CoreError::PrivateMaterialRejected,
                ErrorCode::PrivateMaterial,
            ),
            (
                CoreError::InvalidInput {
                    kind: "qr",
                    detail: text(),
                },
                ErrorCode::InvalidInput,
            ),
            (CoreError::TooManyParts(5_001), ErrorCode::TooManyParts),
            (
                CoreError::NetworkMismatch {
                    expected: "signet".to_owned(),
                    found: "bitcoin".to_owned(),
                },
                ErrorCode::NetworkMismatch,
            ),
            (CoreError::WalletNotFound(text()), ErrorCode::WalletNotFound),
            (
                CoreError::DuplicateWallet(text()),
                ErrorCode::DuplicateWallet,
            ),
            (
                CoreError::UnreadableBackup(text()),
                ErrorCode::UnreadableBackup,
            ),
            (CoreError::NewerBackup(text()), ErrorCode::NewerFormat),
            (
                CoreError::Sync {
                    backend: text(),
                    detail: text(),
                },
                ErrorCode::Sync,
            ),
            (
                CoreError::Broadcast {
                    backend: text(),
                    detail: text(),
                },
                ErrorCode::Broadcast,
            ),
            (
                CoreError::BackendUnavailable(text()),
                ErrorCode::BackendUnavailable,
            ),
            (CoreError::Tor(text()), ErrorCode::Tor),
            (CoreError::Descriptor(text()), ErrorCode::Descriptor),
            (CoreError::Internal(text()), ErrorCode::Internal),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "{error}");
        }
    }
}
