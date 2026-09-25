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

    /// An onion backend could not be given a way through Tor: no proxy
    /// answers, or the embedded client could not start.
    #[error("tor: {0}")]
    Tor(String),

    /// Descriptor-level error surfaced by the wallet engine.
    #[error("descriptor error: {0}")]
    Descriptor(String),

    /// The premium server, or what it signed, said no.
    #[error(transparent)]
    Premium(#[from] PremiumError),

    /// Internal invariant violation. Indicates a bug in this crate.
    #[error("internal error: {0}")]
    Internal(String),
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

/// Errors of the premium client and the licence checks, sorted by what
/// the screen does about them.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PremiumError {
    /// The client has no account key, and the route needs one: the
    /// connection of a device, the one request the key goes with.
    #[error("no premium key")]
    NoKey,

    /// This device holds no token, and the route needs one: it was
    /// never connected with the key, or the server disowned it. Nothing
    /// was sent.
    #[error("this device is not connected to the Premium account")]
    NoDevice,

    /// The server does not know this key (HTTP 401 on the connection
    /// of a device, said in the server's own error body; a bare 401 is
    /// a refusal instead).
    #[error("the premium server does not know this key")]
    UnknownKey,

    /// This device is connected and waits: for another device of the
    /// account to approve it, or for `until`, unix seconds, when it gets
    /// full access on its own. Until then the server shows it nothing
    /// and lets it change nothing (HTTP 403 `device_pending`).
    #[error("this device is waiting for approval")]
    DevicePending { until: i64 },

    /// The server no longer knows this device's token: another device
    /// disconnected it, the key was changed, or the account is gone
    /// (HTTP 401 `device_disconnected`). The manager drops the token
    /// and keeps the key; connecting again is the user's call.
    #[error("this device was disconnected from the Premium account")]
    DeviceDisconnected,

    /// The key went where a device token was due (HTTP 401
    /// `device_required`): connect the device first.
    #[error("connect this device with the Premium key first")]
    DeviceRequired,

    /// The key already has as many devices as the server takes (HTTP
    /// 409 `too_many_devices`); the sentence is the server's own.
    #[error("{0}")]
    TooManyDevices(String),

    /// A key change was sent and not answered, and what was asked would
    /// lose the new key: the server may already hold it, and nothing
    /// else does. Trying the change again completes it. Nothing was
    /// sent.
    #[error("the key change did not finish; try again to complete it")]
    KeyChangePending,

    /// The key exists but has no paid time left, and the route changes
    /// what is watched (HTTP 403, said in the server's own error body
    /// with no code of a device refusal; a bare 403 is a refusal
    /// instead).
    #[error("this key has no paid time left")]
    NoPaidTime,

    /// The server has no resource under the id the route named (HTTP
    /// 404 and 410, said in the server's own error body): a wallet or
    /// a channel already gone from it. For a route that removes
    /// something, the state that was wanted. A bare 404, the answer of
    /// a captive portal or a proxy without a route, is a refusal
    /// instead.
    #[error("the server has nothing under that id")]
    NotFound,

    /// The server refused the request; the sentence is its own.
    #[error("the premium server refused: {0}")]
    Rejected(String),

    /// The server asks this client to slow down (HTTP 429 with
    /// `Retry-After`, or a bare 429 from something on the path). Not a
    /// word about the request itself: the same one may pass later, and
    /// whatever follows it now would be turned away too. `retry_after`
    /// is the wait that was named, in seconds, 3,600 at most. A 429 the
    /// server words itself and gives no wait for, five wrong codes on a
    /// channel, is [`PremiumError::Rejected`]: waiting settles nothing.
    #[error("the premium server asks to wait before trying again")]
    RateLimited { retry_after: Option<u64> },

    /// The server could not be reached, or answered with a failure of
    /// its own (HTTP 5xx).
    #[error("the premium server is unreachable: {0}")]
    Unreachable(String),

    /// The server answered, with something other than what the route
    /// promises.
    #[error("unexpected answer from the premium server: {0}")]
    UnexpectedResponse(String),

    /// The certificate is malformed, or not signed by the licence key.
    #[error("invalid licence certificate: {0}")]
    InvalidCertificate(String),

    /// The heartbeat is malformed, or not signed by the licence key.
    #[error("invalid heartbeat: {0}")]
    InvalidHeartbeat(String),

    /// The heartbeat is genuine but its clock sits too far from this
    /// device's: a replay, a stale cache, or a clock to fix.
    #[error("the heartbeat is {skew} seconds off this device's clock")]
    StaleHeartbeat { skew: i64 },
}
