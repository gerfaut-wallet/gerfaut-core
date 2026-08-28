//! Error types shared across the crate.

use thiserror::Error;

/// Result alias used by the public API.
pub type CoreResult<T> = Result<T, CoreError>;

/// Top-level error of the crate.
///
/// Variants are stable identifiers the UIs can match on to pick a
/// user-facing message; the inner strings carry technical detail for logs.
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

    /// Descriptor-level error surfaced by the wallet engine.
    #[error("descriptor error: {0}")]
    Descriptor(String),

    /// Internal invariant violation. Indicates a bug in this crate.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Errors specific to the encrypted vault store.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The file does not start with the expected magic bytes.
    #[error("not a vault file")]
    NotAVault,

    /// The file version is newer than what this build understands.
    #[error("vault version {0} is not supported by this build")]
    UnsupportedVersion(u8),

    /// Decryption failed: wrong key/password, or the file was tampered with.
    #[error("vault decryption failed: wrong key or corrupted file")]
    WrongKeyOrCorrupted,

    /// The decrypted payload could not be deserialized.
    #[error("vault payload is corrupted: {0}")]
    CorruptedPayload(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),
}
