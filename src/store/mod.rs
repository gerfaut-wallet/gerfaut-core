//! Encrypted persistence: one vault file holding everything.
//!
//! The vault is a single encrypted file (see [`cipher`]) containing the
//! wallet list, per-wallet chain state (BDK change sets, address-watch
//! state), and settings. Wallet-scale data is small, so the whole
//! payload is rewritten atomically on each save — no partial-write
//! states to reason about, and the file is unreadable at rest without
//! the key.

pub mod cipher;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::chain::BackendConfig;
use crate::chain::tor::TorSettings;
use crate::error::VaultError;
use crate::lock::AppLock;
use crate::network::Network;
use crate::premium::PremiumState;
use crate::wallet::AddressWatchState;
use crate::wallet::meta::WalletMeta;

pub use cipher::{VaultKdf, VaultKey};

/// Current payload schema version. Bump on breaking changes and migrate
/// in [`Vault::load`].
const PAYLOAD_VERSION: u32 = 1;

/// One wallet and its chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRecord {
    pub meta: WalletMeta,
    /// Aggregate BDK change set for descriptor wallets. The full wallet
    /// state reloads from this alone.
    #[serde(default)]
    pub changeset: Option<bdk_wallet::ChangeSet>,
    /// State of single-address wallets.
    #[serde(default)]
    pub address_state: Option<AddressWatchState>,
}

/// Global settings stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// The workspace network: which wallets are shown and what network
    /// new imports default to.
    pub active_network: Network,
    /// Backend configuration, per network.
    #[serde(default)]
    pub backends: BTreeMap<Network, BackendConfig>,
    /// Gap limit shared by every wallet: how far past the last used
    /// address syncs scan, and where the apps warn on Receive.
    #[serde(default = "default_gap_limit")]
    pub gap_limit: u32,
    /// Small app-side preferences (theme, hidden balances, ...) kept in
    /// the same encrypted file so nothing leaks in plain preference
    /// stores. Keys are namespaced by the apps.
    #[serde(default)]
    pub app_prefs: BTreeMap<String, String>,
    /// Electrum certificates the user accepted, by `host:port`. An
    /// entry is added only by an explicit acceptance, and a server whose
    /// certificate stops matching its entry is refused, never trusted
    /// again silently.
    #[serde(default)]
    pub electrum_certs: BTreeMap<String, String>,
    /// The PIN or password asked before the interface shows, when the
    /// user set one. Its hash lives here, in the encrypted file, so a
    /// plain preference store never learns it exists.
    #[serde(default)]
    pub app_lock: Option<AppLock>,
    /// How `.onion` backends are reached. Vaults written before it
    /// existed read as the default, the system Tor first.
    #[serde(default)]
    pub tor: TorSettings,
    /// The premium account: its key, its last certificate, and which
    /// wallets the user agreed to send to the server. In the encrypted
    /// file because the key is the account. Empty until one is entered.
    #[serde(default)]
    pub premium: PremiumState,
}

fn default_gap_limit() -> u32 {
    crate::wallet::meta::DEFAULT_GAP_LIMIT
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            active_network: Network::Mainnet,
            backends: BTreeMap::new(),
            gap_limit: default_gap_limit(),
            app_prefs: BTreeMap::new(),
            electrum_certs: BTreeMap::new(),
            app_lock: None,
            tor: TorSettings::default(),
            premium: PremiumState::default(),
        }
    }
}

impl Settings {
    /// Backend for a network, falling back to the public default.
    pub fn backend_for(&self, network: Network) -> BackendConfig {
        self.backends.get(&network).cloned().unwrap_or_default()
    }
}

/// How far a transaction had come when it was announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxStage {
    /// Seen, not yet in a block.
    Mempool,
    /// In a block.
    Confirmed,
    /// An incoming payment announced at the [`TxStage::Mempool`] stage
    /// left the mempool, and nothing the wallet holds pays nearly as
    /// much in its place: the sender replaced it with a transaction
    /// that pays elsewhere, or pays the wallet much less, or it was
    /// evicted. The money it announced is not coming, unless it is
    /// broadcast again, in which case its confirmation is announced as
    /// usual.
    Dropped,
}

/// One announcement already made: see
/// [`crate::WalletManager::claim_announcements`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announced {
    /// The wallet it was made for: a transaction between two watched
    /// wallets is news for each. Empty in a record written before
    /// announcements were kept by wallet, which then stands for every
    /// wallet, so that nothing it covered is said again.
    #[serde(default)]
    pub wallet_id: String,
    pub txid: String,
    pub stage: TxStage,
    /// The transaction announced first for the same payment, when this
    /// one is a fee bump of it, however many bumps lie between: see
    /// [`crate::live::LiveTx::replaces`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
}

impl Announced {
    /// Whether this record covers an announcement for this wallet.
    pub(crate) fn covers(&self, wallet_id: &str) -> bool {
        self.wallet_id.is_empty() || self.wallet_id == wallet_id
    }
}

/// A transaction a sync found worth announcing, kept until a caller
/// claims it: see [`crate::WalletManager::claim_announcements`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unclaimed {
    pub wallet_id: String,
    pub txid: String,
    /// Net effect on the wallet, in satoshis.
    pub net_sats: i64,
    pub stage: TxStage,
    /// When the sync found it, unix seconds.
    pub found_at: u64,
    /// The transaction announced first for the same payment: see
    /// [`crate::live::LiveTx::replaces`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
}

/// Everything the vault persists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub version: u32,
    pub settings: Settings,
    pub wallets: Vec<WalletRecord>,
    /// What was announced, oldest first, so that no transaction is
    /// announced twice at the same stage by two callers or after a
    /// restart. Absent from vaults written before live alerts.
    #[serde(default)]
    pub announced: Vec<Announced>,
    /// What syncs found worth announcing and nobody has claimed yet,
    /// oldest first. Written with the sync that found it, whoever ran
    /// that sync, so nothing found is lost when that caller announces
    /// nothing.
    #[serde(default)]
    pub unclaimed: Vec<Unclaimed>,
}

impl Default for VaultPayload {
    fn default() -> Self {
        VaultPayload {
            version: PAYLOAD_VERSION,
            settings: Settings::default(),
            wallets: Vec::new(),
            announced: Vec::new(),
            unclaimed: Vec::new(),
        }
    }
}

/// Handle on the vault file. Owns the key material, and the exclusive
/// lock that keeps every other opener out while it lives.
pub struct Vault {
    path: PathBuf,
    key: VaultKey,
    /// The open lock file, locked. Dropping it releases the lock, and
    /// so does the death of the process, however it dies. `None` when
    /// the file system cannot lock at all.
    _lock: Option<std::fs::File>,
    /// Makes every save fail, so a test can meet a full disk.
    #[cfg(test)]
    fail_saves: std::sync::atomic::AtomicBool,
}

impl Vault {
    /// Opens an existing vault or creates an empty one at `path`.
    ///
    /// The vault is locked first, so no other process, and no other
    /// open in this one, can read or write it until this handle is
    /// dropped. A vault already open elsewhere is refused with
    /// [`VaultError::AlreadyOpen`] before anything is read.
    ///
    /// Creation writes the file immediately so that a wrong permission
    /// or path fails now, not at the first save.
    pub fn open_or_create(
        path: impl Into<PathBuf>,
        key: VaultKey,
    ) -> Result<(Self, VaultPayload), VaultError> {
        let path = path.into();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let lock = acquire_lock(&lock_path(&path))?;
        let vault = Vault {
            path,
            key,
            _lock: lock,
            #[cfg(test)]
            fail_saves: std::sync::atomic::AtomicBool::new(false),
        };
        // Nobody else writes here now: whatever temporary file is left
        // was abandoned by a save that never finished.
        vault.remove_stale_temporaries();
        // Only a vault that is certainly absent is created: one that
        // cannot be looked at (a permission, a storage error) fails the
        // open rather than being replaced by an empty one.
        if vault.path.try_exists()? {
            let payload = vault.load()?;
            Ok((vault, payload))
        } else {
            let payload = VaultPayload::default();
            vault.save(&payload)?;
            Ok((vault, payload))
        }
    }

    /// Reads and decrypts the whole payload.
    pub fn load(&self) -> Result<VaultPayload, VaultError> {
        let file = std::fs::read(&self.path)?;
        let plaintext = cipher::unseal(&file, &self.key)?;
        let payload: VaultPayload = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::CorruptedPayload(e.to_string()))?;
        if payload.version > PAYLOAD_VERSION {
            return Err(VaultError::UnsupportedVersion(
                payload.version.min(255) as u8
            ));
        }
        Ok(payload)
    }

    /// Encrypts and writes the whole payload, atomically: the new file
    /// is written and flushed to disk next to the old one, then swapped
    /// in with a rename, so neither a crash mid-write nor a power loss
    /// right after the rename can leave a truncated vault. Each save
    /// writes to a temporary file of its own, removed if the save fails.
    pub fn save(&self, payload: &VaultPayload) -> Result<(), VaultError> {
        #[cfg(test)]
        if self.fail_saves.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(VaultError::Io(std::io::Error::other("saves fail")));
        }
        let plaintext =
            serde_json::to_vec(payload).map_err(|e| VaultError::CorruptedPayload(e.to_string()))?;
        let sealed = cipher::seal(&plaintext, &self.key)?;
        let tmp = self.temporary_path();
        let written = write_then_swap(&tmp, &sealed, &self.path);
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        // Persist the rename itself where the platform allows it.
        #[cfg(unix)]
        if let Some(parent) = self.path.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// The vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Makes every later save fail, or succeed again.
    #[cfg(test)]
    pub(crate) fn fail_saves(&self, fail: bool) {
        self.fail_saves
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// `gerfaut.vault.<random>.tmp` beside `gerfaut.vault`: a name no
    /// other save picks.
    fn temporary_path(&self) -> PathBuf {
        let mut name = self.file_name();
        name.push(format!(".{:016x}{TEMP_SUFFIX}", rand::random::<u64>()));
        self.path.with_file_name(name)
    }

    fn file_name(&self) -> std::ffi::OsString {
        self.path.file_name().unwrap_or_default().to_owned()
    }

    /// Removes the temporary files of saves that never finished: those
    /// named after this vault, and the one fixed name older builds used.
    /// Only files, and never the vault or its lock.
    fn remove_stale_temporaries(&self) {
        let prefix = {
            let mut prefix = self.file_name();
            prefix.push(".");
            prefix.to_string_lossy().into_owned()
        };
        let legacy = self.path.with_extension("tmp");
        let dir = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let ours = name.starts_with(&prefix) && name.ends_with(TEMP_SUFFIX);
            let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
            if is_file && (ours || entry.path() == legacy) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// What ends the name of a vault's temporary file.
const TEMP_SUFFIX: &str = ".tmp";

/// `gerfaut.vault.lock` beside `gerfaut.vault`. It stays on disk after
/// the vault is closed: the lock lives in the open file, not in the
/// file's existence, and removing it would only let two openers lock
/// two different files.
fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault.file_name().unwrap_or_default().to_owned();
    name.push(".lock");
    vault.with_file_name(name)
}

/// Takes the exclusive lock on the lock file, without waiting.
///
/// The lock is advisory and belongs to the open file: flock on Unix and
/// Android, where a second open of the same file conflicts even within
/// one process, and LockFileEx on Windows, which behaves the same. The
/// system drops it when the file is closed or the process dies, so a
/// crash never leaves a vault that cannot be opened again.
///
/// A file system that cannot lock at all (some network and FUSE mounts)
/// gets the vault unlocked, as every earlier build had it, rather than
/// no vault: that is logged, and one copy of the app per data directory
/// is then up to the user.
fn acquire_lock(path: &Path) -> Result<Option<std::fs::File>, VaultError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(file)),
        Err(fs4::TryLockError::WouldBlock) => Err(VaultError::AlreadyOpen),
        Err(fs4::TryLockError::Error(error)) => {
            log::warn!("the vault cannot be locked here, opening it unlocked: {error}");
            Ok(None)
        }
    }
}

/// Writes `bytes` to the new file `tmp`, flushes them to disk, and
/// renames `tmp` over `target`.
fn write_then_swap(tmp: &Path, bytes: &[u8], target: &Path) -> std::io::Result<()> {
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    rename_over(tmp, target)
}

/// Renames `from` over `to`. On Windows a rename onto a file something
/// else holds open without delete sharing (a virus scanner, a backup or
/// indexing tool reading the vault) fails for as long as it holds it, so
/// it is tried again a few times, 310 ms in all, before giving up.
fn rename_over(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut delay = std::time::Duration::from_millis(10);
        for _ in 0..5 {
            match std::fs::rename(from, to) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    std::thread::sleep(delay);
                    delay *= 2;
                }
                other => return other,
            }
        }
    }
    std::fs::rename(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{RecognizedKind, ScriptKind};
    use crate::wallet::meta::{CachedTotals, DEFAULT_GAP_LIMIT, WalletIcon, WalletKind};

    fn key() -> VaultKey {
        VaultKey::Raw([42u8; 32])
    }

    fn sample_meta() -> WalletMeta {
        WalletMeta {
            id: "0000-test".to_owned(),
            name: "Cold storage".to_owned(),
            icon: WalletIcon::default(),
            network: Network::Signet,
            kind: WalletKind::Descriptors {
                external: "wpkh(xpub.../0/*)#checksum".to_owned(),
                internal: None,
                script: ScriptKind::Segwit,
            },
            recognized_as: RecognizedKind::Descriptor,
            created_at: 1_755_000_000,
            gap_limit: DEFAULT_GAP_LIMIT,
            scan_gap: DEFAULT_GAP_LIMIT,
            labels: Default::default(),
            last_sync: None,
            cached: CachedTotals::default(),
        }
    }

    #[test]
    fn create_load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");

        let (vault, mut payload) = Vault::open_or_create(&path, key()).unwrap();
        assert!(path.exists(), "creation writes the file immediately");
        assert!(payload.wallets.is_empty());

        payload.wallets.push(WalletRecord {
            meta: sample_meta(),
            changeset: None,
            address_state: None,
        });
        payload.settings.active_network = Network::Signet;
        vault.save(&payload).unwrap();
        drop(vault);

        let (_, reloaded) = Vault::open_or_create(&path, key()).unwrap();
        assert_eq!(reloaded.wallets.len(), 1);
        assert_eq!(reloaded.wallets[0].meta.name, "Cold storage");
        assert_eq!(reloaded.settings.active_network, Network::Signet);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        Vault::open_or_create(&path, key()).unwrap();

        let result = Vault::open_or_create(&path, VaultKey::Raw([1u8; 32]));
        assert!(matches!(result, Err(VaultError::WrongKeyOrCorrupted)));
    }

    #[test]
    fn no_tmp_file_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        let (vault, payload) = Vault::open_or_create(&path, key()).unwrap();
        vault.save(&payload).unwrap();
        vault.save(&payload).unwrap();
        assert_eq!(
            names_in(dir.path()),
            ["gerfaut.vault", "gerfaut.vault.lock"]
        );
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Two opens of one vault would each save their own copy over the
    /// other's. The second is refused before it reads anything, in this
    /// process as in another, and the vault opens again once the first
    /// handle is gone.
    #[test]
    fn a_vault_opens_once_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        let (vault, mut payload) = Vault::open_or_create(&path, key()).unwrap();

        let second = Vault::open_or_create(&path, key());
        assert!(matches!(second, Err(VaultError::AlreadyOpen)));
        // Even with the wrong key: nothing was read to find out.
        let wrong = Vault::open_or_create(&path, VaultKey::Raw([1u8; 32]));
        assert!(matches!(wrong, Err(VaultError::AlreadyOpen)));

        payload.settings.gap_limit = 42;
        vault.save(&payload).unwrap();
        drop(vault);

        let (_, reloaded) = Vault::open_or_create(&path, key()).unwrap();
        assert_eq!(reloaded.settings.gap_limit, 42);
        // The lock file stays: the lock is in the open file, not in its
        // existence.
        assert!(dir.path().join("gerfaut.vault.lock").exists());
    }

    /// An open that fails, on a wrong key here, lets go of the lock:
    /// the app can set that vault aside and try again.
    #[test]
    fn a_failed_open_releases_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        drop(Vault::open_or_create(&path, key()).unwrap());

        let wrong = Vault::open_or_create(&path, VaultKey::Raw([1u8; 32]));
        assert!(matches!(wrong, Err(VaultError::WrongKeyOrCorrupted)));
        assert!(Vault::open_or_create(&path, key()).is_ok());
    }

    /// A save cut short by a crash leaves its temporary file behind; the
    /// next open clears it, and the name older builds used, and nothing
    /// else.
    #[test]
    fn an_open_clears_abandoned_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        drop(Vault::open_or_create(&path, key()).unwrap());
        for name in [
            "gerfaut.vault.00000000deadbeef.tmp",
            "gerfaut.tmp",
            "gerfaut.attempts.tmp",
            "notes.tmp",
        ] {
            std::fs::write(dir.path().join(name), b"half a vault").unwrap();
        }
        std::fs::create_dir(dir.path().join("gerfaut.vault.dir.tmp")).unwrap();

        let (_, payload) = Vault::open_or_create(&path, key()).unwrap();
        assert!(payload.wallets.is_empty());
        assert_eq!(
            names_in(dir.path()),
            [
                "gerfaut.attempts.tmp",
                "gerfaut.vault",
                "gerfaut.vault.dir.tmp",
                "gerfaut.vault.lock",
                "notes.tmp",
            ]
        );
    }

    /// A vault whose presence cannot be checked is not taken for a
    /// first launch and replaced with an empty one. A link that loops
    /// stands for any such error here, a permission or a storage fault.
    #[cfg(unix)]
    #[test]
    fn a_vault_that_cannot_be_checked_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        std::os::unix::fs::symlink(&path, &path).unwrap();

        let opened = Vault::open_or_create(&path, key());
        assert!(matches!(opened, Err(VaultError::Io(_))));
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
    }

    /// A save that fails removes what it wrote, and the vault on disk is
    /// the one before it.
    #[test]
    fn a_failed_save_leaves_the_previous_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        let (vault, mut payload) = Vault::open_or_create(&path, key()).unwrap();
        let before = std::fs::read(&path).unwrap();

        // A directory where the vault should be: the rename fails after
        // the temporary file was written.
        let elsewhere = dir.path().join("moved.vault");
        std::fs::rename(&path, &elsewhere).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), b"x").unwrap();
        payload.settings.gap_limit = 42;
        assert!(vault.save(&payload).is_err());
        assert_eq!(
            names_in(dir.path()),
            ["gerfaut.vault", "gerfaut.vault.lock", "moved.vault"]
        );
        assert_eq!(std::fs::read(&elsewhere).unwrap(), before);
    }

    #[test]
    fn file_is_actually_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.vault");
        let (vault, mut payload) = Vault::open_or_create(&path, key()).unwrap();
        payload.wallets.push(WalletRecord {
            meta: sample_meta(),
            changeset: None,
            address_state: None,
        });
        vault.save(&payload).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let haystack = String::from_utf8_lossy(&raw);
        assert!(!haystack.contains("Cold storage"));
        assert!(!haystack.contains("wpkh"));
    }

    #[test]
    fn settings_fall_back_to_public_backend() {
        let settings = Settings::default();
        assert_eq!(
            settings.backend_for(Network::Mainnet),
            BackendConfig::default()
        );
    }

    /// A vault written before Tor had settings must open as it always
    /// did, with Tor in its default mode, and write those settings back
    /// in the shape the apps read.
    #[test]
    fn a_vault_without_tor_settings_reads_as_auto() {
        use crate::chain::tor::TorMode;
        let stored: Settings =
            serde_json::from_str(r#"{"active_network":"mainnet","gap_limit":20}"#).unwrap();
        assert_eq!(stored.tor, TorSettings::default());
        assert_eq!(stored.tor.mode, TorMode::Auto);
        assert_eq!(stored.tor.socks_proxy, None);

        let mut settings = stored;
        settings.tor = TorSettings {
            mode: TorMode::System,
            socks_proxy: Some("127.0.0.1:9150".to_owned()),
        };
        let json = serde_json::to_string(&settings).unwrap();
        assert!(json.contains(r#""tor":{"mode":"system","socks_proxy":"127.0.0.1:9150"}"#));
        let again: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(again.tor, settings.tor);
    }
}
