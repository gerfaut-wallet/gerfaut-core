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
        }
    }
}

impl Settings {
    /// Backend for a network, falling back to the public default.
    pub fn backend_for(&self, network: Network) -> BackendConfig {
        self.backends.get(&network).cloned().unwrap_or_default()
    }
}

/// Everything the vault persists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub version: u32,
    pub settings: Settings,
    pub wallets: Vec<WalletRecord>,
}

impl Default for VaultPayload {
    fn default() -> Self {
        VaultPayload {
            version: PAYLOAD_VERSION,
            settings: Settings::default(),
            wallets: Vec::new(),
        }
    }
}

/// Handle on the vault file. Owns the key material.
pub struct Vault {
    path: PathBuf,
    key: VaultKey,
}

impl Vault {
    /// Opens an existing vault or creates an empty one at `path`.
    ///
    /// Creation writes the file immediately so that a wrong permission
    /// or path fails now, not at the first save.
    pub fn open_or_create(
        path: impl Into<PathBuf>,
        key: VaultKey,
    ) -> Result<(Self, VaultPayload), VaultError> {
        let vault = Vault {
            path: path.into(),
            key,
        };
        if vault.path.exists() {
            let payload = vault.load()?;
            Ok((vault, payload))
        } else {
            if let Some(parent) = vault.path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
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
    /// right after the rename can leave a truncated vault.
    pub fn save(&self, payload: &VaultPayload) -> Result<(), VaultError> {
        let plaintext =
            serde_json::to_vec(payload).map_err(|e| VaultError::CorruptedPayload(e.to_string()))?;
        let sealed = cipher::seal(&plaintext, &self.key)?;
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&sealed)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{RecognizedKind, ScriptKind};
    use crate::wallet::meta::{CachedTotals, DEFAULT_GAP_LIMIT, WalletKind};

    fn key() -> VaultKey {
        VaultKey::Raw([42u8; 32])
    }

    fn sample_meta() -> WalletMeta {
        WalletMeta {
            id: "0000-test".to_owned(),
            name: "Cold storage".to_owned(),
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
        assert!(!path.with_extension("tmp").exists());
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
