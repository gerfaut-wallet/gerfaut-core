//! The wallet manager: the single facade every consumer talks to.
//!
//! Desktop (Tauri commands), mobile (FFI bridge), and later the server
//! all drive this type. It owns the encrypted vault, keeps loaded BDK
//! engines in memory, and coordinates syncs so that network I/O never
//! blocks reads: requests are built under the lock, executed outside it,
//! and applied back under the lock.
//!
//! The facade spans three files: this one, `manager/devices.rs` for the
//! Premium devices (connecting, logging out, changing the key), and
//! `live.rs` for the live watch and the alerts it hands out.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use tokio::sync::Mutex;

use std::str::FromStr;

use bdk_wallet::bitcoin::Address;

use crate::backup::{
    self, BACKUP_VERSION, BackupBackendPreview, BackupBundle, BackupOptions, BackupPayload,
    BackupPreview, BackupWallet, BackupWalletPreview, ImportChoices, ImportReport,
};
use crate::chain::tor;
use crate::chain::{self, BackendConfig};
use crate::error::PremiumError;
use crate::error::{CoreError, CoreResult};
use crate::input::RecognizedKind;
use crate::lock::{self, AppLock, LockAttempts, LockKind, LockVerdict};
use crate::network::Network;
use crate::premium::{Channel, PremiumClient, PremiumState};
use crate::store::{Vault, VaultKey, VaultPayload, WalletRecord};
use crate::wallet::meta::{CachedTotals, WalletIcon, WalletKind, WalletMeta};
use crate::wallet::snapshot::SyncReport;
use crate::wallet::views;

mod broadcast;
mod devices;
mod settings;
mod sync;
mod wallets;

pub(crate) use sync::{Reach, complete_lately};
pub use sync::{SyncAllReport, SyncFailure};

/// Vault file name inside the data directory.
const VAULT_FILE: &str = "gerfaut.vault";
/// The failed unlock attempts, beside the vault: a count and a time,
/// nothing secret, kept so a restart does not reset the delays.
const ATTEMPTS_FILE: &str = "gerfaut.attempts";

pub(crate) struct ManagerState {
    vault: Vault,
    pub(crate) payload: VaultPayload,
    /// Loaded BDK engines, keyed by wallet id. Lazily populated.
    engines: HashMap<String, bdk_wallet::Wallet>,
    /// Where the vault lives, and where the embedded Tor client keeps
    /// its state.
    pub(crate) data_dir: PathBuf,
    /// The order an Electrum server listed each script's history in, as
    /// the syncs read it: what the statuses handed to the watch hash.
    orders: views::HistoryOrders,
}

impl ManagerState {
    /// Everything a connection needs from the settings: which backend,
    /// and the certificates the user accepted for it.
    fn chain_setup(&self, network: Network) -> (BackendConfig, chain::TrustedCerts) {
        (
            self.payload.settings.backend_for(network),
            self.payload.settings.electrum_certs.clone(),
        )
    }

    /// Applies `change` to a copy of the payload, saves that copy, and
    /// only then makes it the state. A save that fails leaves memory as
    /// it was: the error the caller reports is then the whole truth, and
    /// no later save, made for something else, quietly commits a change
    /// nobody was told about.
    ///
    /// What the user decides goes through here. Chain state does not:
    /// a sync, more history, an address revealed are written in place,
    /// engine and payload alike, and saved after. That state is a cache
    /// of the chain, which the next sync reads again, so a save that
    /// fails there keeps it in memory, and a later save writes it.
    pub(crate) fn commit<T>(
        &mut self,
        change: impl FnOnce(&mut VaultPayload) -> CoreResult<T>,
    ) -> CoreResult<T> {
        let mut next = self.payload.clone();
        let value = change(&mut next)?;
        self.vault.save(&next)?;
        self.payload = next;
        Ok(value)
    }
}

/// The facade. A handle: cloning it is cheap and every clone is the
/// same manager, which is how a task that outlives a call, the live
/// watch for one, keeps it.
#[derive(Clone)]
pub struct WalletManager {
    shared: std::sync::Arc<Shared>,
}

/// What every clone of the manager shares.
pub struct Shared {
    pub(crate) state: Mutex<ManagerState>,
    /// Recent failed unlock attempts, kept apart from the vault lock so
    /// an unlock never waits on a sync.
    attempts: Mutex<LockAttempts>,
    /// The live watch, while one runs. Held for a few instructions,
    /// never across an await: stopping the watch never waits on
    /// anything.
    pub(crate) live: std::sync::Mutex<Option<crate::live::Running>>,
    /// Counts the readings of what the watch should follow, so an older
    /// one never replaces a newer one on the running watch.
    pub(crate) watch_setups: std::sync::atomic::AtomicU64,
    /// One sync at a time per wallet, and when the last one ended.
    syncing: std::sync::Mutex<HashMap<String, SyncSlot>>,
    /// The wallets a complete sync has read since the vault was opened:
    /// see [`WalletManager::sync_wallet`].
    complete_here: std::sync::Mutex<HashSet<String>>,
    /// Held across a change of this device's premium connection, the
    /// network call included: two connections made at once would leave
    /// the server with a device nobody holds, and a log out racing a
    /// connection could bring back the key it removed.
    premium_changes: Mutex<()>,
    /// Until when the server asked not to be sent a connection of a key
    /// again, and that key: a rate limit
    /// [`Self::premium_ensure_device`] waits out rather than meet again
    /// at every poll. The server counts connections by key, so the wait
    /// holds back a connection of that key and no other.
    premium_connect_after: std::sync::Mutex<Option<(Instant, String)>>,
    /// The key the premium clients built here check signed answers
    /// against, in place of the one [`crate::premium::endpoint`] names.
    #[cfg(test)]
    premium_public_key: std::sync::Mutex<Option<String>>,
}

/// The last sync of a wallet to finish, when it started and how far it
/// read, behind the lock a sync of that wallet holds while it runs.
type SyncSlot = std::sync::Arc<Mutex<Option<(Instant, SyncReport, Reach)>>>;

impl std::ops::Deref for WalletManager {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.shared
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether two premium keys are the same account key, however each was
/// typed; two absent keys are the same absence.
fn same_key(a: Option<&str>, b: Option<&str>) -> bool {
    a.map(crate::premium::licence::normalize_key) == b.map(crate::premium::licence::normalize_key)
}

impl WalletManager {
    /// Opens (or creates) the vault at `data_dir/gerfaut.vault`, and
    /// reads back the unlock attempts recorded beside it.
    pub fn open(data_dir: impl Into<PathBuf>, key: VaultKey) -> CoreResult<Self> {
        // Before anything here can open a socket. Two rustls backends
        // are compiled in and the first one installed serves the whole
        // process, so the choice is made in the open rather than won by
        // whichever connection happens to go first. See
        // `chain::tls::provider`.
        crate::chain::tls::provider();
        let data_dir = data_dir.into();
        let (vault, payload) = Vault::open_or_create(data_dir.join(VAULT_FILE), key)?;
        let attempts = LockAttempts::load(data_dir.join(ATTEMPTS_FILE));
        Ok(WalletManager {
            shared: std::sync::Arc::new(Shared {
                state: Mutex::new(ManagerState {
                    vault,
                    payload,
                    engines: HashMap::new(),
                    data_dir,
                    orders: views::HistoryOrders::new(),
                }),
                attempts: Mutex::new(attempts),
                live: std::sync::Mutex::new(None),
                watch_setups: std::sync::atomic::AtomicU64::new(0),
                syncing: std::sync::Mutex::new(HashMap::new()),
                complete_here: std::sync::Mutex::new(HashSet::new()),
                premium_changes: Mutex::new(()),
                premium_connect_after: std::sync::Mutex::new(None),
                #[cfg(test)]
                premium_public_key: std::sync::Mutex::new(None),
            }),
        })
    }

    // --- app lock ------------------------------------------------------

    /// The lock in place, without its hash.
    pub async fn app_lock(&self) -> Option<AppLock> {
        self.state
            .lock()
            .await
            .payload
            .settings
            .app_lock
            .clone()
            .map(|mut lock| {
                lock.secret = None;
                lock
            })
    }

    /// Sets a lock, or replaces the secret of the one in place. Replacing
    /// asks for the current secret: an unlocked phone in the wrong hands
    /// must not be able to change the PIN into one its holder knows.
    pub async fn set_app_lock(
        &self,
        kind: LockKind,
        secret: &str,
        current: Option<&str>,
    ) -> CoreResult<()> {
        lock::validate_secret(kind, secret)?;
        let existing = self.state.lock().await.payload.settings.app_lock.clone();
        if let Some(existing) = &existing {
            self.require_current(existing, current).await?;
        }
        let stored = lock::hash_secret(secret)?;
        self.state.lock().await.commit(|payload| {
            let previous = payload.settings.app_lock.take();
            payload.settings.app_lock = Some(AppLock {
                kind,
                biometric: previous.as_ref().is_some_and(|p| p.biometric),
                secret: Some(stored),
            });
            Ok(())
        })
    }

    /// Removes the lock. The current secret is required, for the same
    /// reason as above.
    pub async fn clear_app_lock(&self, current: &str) -> CoreResult<()> {
        let existing = self.existing_lock().await?;
        self.require_current(&existing, Some(current)).await?;
        self.state.lock().await.commit(|payload| {
            payload.settings.app_lock = None;
            Ok(())
        })
    }

    /// Tries a secret against the lock. Failures are counted and, past
    /// three, delayed: the verdict says how long before the next try
    /// is even looked at.
    pub async fn verify_app_lock(&self, secret: &str) -> CoreResult<LockVerdict> {
        let existing = self.existing_lock().await?;
        Ok(self.check_secret(&existing, secret).await)
    }

    /// Whether the platform's biometric prompt may stand in for the
    /// secret. Recorded here so both apps read one setting; the prompt
    /// itself is the platform's.
    ///
    /// Guarded by the secret in place: whoever has their own finger
    /// enrolled on this phone must not be able to turn their own
    /// fingerprint into a key to this vault.
    pub async fn set_biometric_unlock(&self, enabled: bool, current: &str) -> CoreResult<()> {
        let existing = self.existing_lock().await?;
        self.require_current(&existing, Some(current)).await?;
        self.state.lock().await.commit(|payload| {
            if let Some(lock) = &mut payload.settings.app_lock {
                lock.biometric = enabled;
            }
            Ok(())
        })
    }

    async fn existing_lock(&self) -> CoreResult<AppLock> {
        self.state
            .lock()
            .await
            .payload
            .settings
            .app_lock
            .clone()
            .ok_or_else(|| CoreError::InvalidInput {
                kind: "lock",
                detail: "no lock is set".to_owned(),
            })
    }

    /// The current secret must be given and must verify, delays
    /// included: changing the lock is an unlock attempt like any other.
    async fn require_current(&self, existing: &AppLock, current: Option<&str>) -> CoreResult<()> {
        let Some(current) = current else {
            return Err(CoreError::InvalidInput {
                kind: "lock",
                detail: "the current PIN or password is required".to_owned(),
            });
        };
        let verdict = self.check_secret(existing, current).await;
        if verdict.unlocked {
            return Ok(());
        }
        Err(CoreError::InvalidInput {
            kind: "lock",
            detail: if verdict.retry_after_secs > 0 {
                format!(
                    "too many attempts: try again in {} s",
                    verdict.retry_after_secs
                )
            } else {
                "wrong PIN or password".to_owned()
            },
        })
    }

    /// Hashes and compares under the attempts lock, so guesses are
    /// serialized and the delay cannot be raced. The vault lock is not
    /// held meanwhile: an unlock never waits on a sync. A delay runs
    /// from the verdict, not from the guess: Argon2 takes its time, and
    /// more on a busy device, and that time came off the delay.
    async fn check_secret(&self, existing: &AppLock, secret: &str) -> LockVerdict {
        let mut attempts = self.attempts.lock().await;
        let wait = attempts.retry_after(Instant::now());
        if wait > 0 {
            return LockVerdict {
                unlocked: false,
                failures: attempts.failures(),
                retry_after_secs: wait,
            };
        }
        match &existing.secret {
            Some(stored) if lock::verify_secret(secret, stored) => attempts.succeed(),
            _ => attempts.fail(Instant::now()),
        }
    }

    // --- backup ----------------------------------------------------------

    /// Seals the chosen wallets (every wallet by default) and, on
    /// request, the settings worth carrying over, under a password. The
    /// sealed bytes come back in both transport forms: base64 for a
    /// file, `ur:bytes` frames for an animated QR.
    pub async fn export_backup(
        &self,
        options: &BackupOptions,
        password: &str,
    ) -> CoreResult<BackupBundle> {
        let payload = {
            let state = self.state.lock().await;
            let settings = &state.payload.settings;
            let chosen = match &options.wallet_ids {
                Some(ids) => {
                    for id in ids {
                        find_record(&state.payload, id)?;
                    }
                    Some(ids.iter().map(String::as_str).collect::<HashSet<_>>())
                }
                None => None,
            };
            let wallets = state
                .payload
                .wallets
                .iter()
                .filter(|record| {
                    chosen
                        .as_ref()
                        .is_none_or(|ids| ids.contains(record.meta.id.as_str()))
                })
                .map(|record| BackupWallet {
                    name: record.meta.name.clone(),
                    network: record.meta.network,
                    kind: record.meta.kind.clone(),
                    // The effective limit is the global setting.
                    gap_limit: settings.gap_limit,
                    labels: record.meta.labels.clone(),
                    created_at: record.meta.created_at,
                    live_pinned: record.meta.live_pinned,
                })
                .collect();
            BackupPayload {
                version: BACKUP_VERSION,
                created_at: now_secs(),
                wallets,
                backends: options.include_settings.then(|| settings.backends.clone()),
                electrum_certs: options
                    .include_settings
                    .then(|| settings.electrum_certs.clone()),
                gap_limit: options.include_settings.then_some(settings.gap_limit),
            }
        };
        // The key derivation is slow on purpose: not under the lock.
        let sealed = backup::seal(&payload, password)?;
        Ok(BackupBundle {
            data: data_encoding::BASE64.encode(&sealed),
            frames: backup::frames(&sealed),
            wallet_count: payload.wallets.len() as u32,
            size_bytes: sealed.len() as u32,
        })
    }

    /// Reads a backup without touching the vault: what it holds, which
    /// of its wallets this vault already watches, and what its settings
    /// would put in place, spelled out so "apply node settings" is an
    /// answer to a question the screen actually asked.
    pub async fn preview_backup(&self, source: &str, password: &str) -> CoreResult<BackupPreview> {
        let payload = backup::open(&backup::decode_source(source)?, password)?;
        let state = self.state.lock().await;
        Ok(BackupPreview {
            created_at: payload.created_at,
            has_settings: payload.has_settings(),
            // The backends a restore would put in place: the same
            // reading as the import, so an address it would drop is not
            // promised here.
            backends: payload
                .backends
                .iter()
                .flatten()
                .filter_map(|(network, config)| {
                    let config = config.clone().canonical().ok()?;
                    Some(BackupBackendPreview {
                        network: *network,
                        backend: config.label(*network),
                    })
                })
                .collect(),
            // The hosts a restore would pin: the same check as the
            // import, so the list shows what would land and nothing
            // that would be dropped on the way.
            electrum_hosts: payload
                .electrum_certs
                .iter()
                .flatten()
                .filter(|(_, fingerprint)| chain::tls::is_fingerprint(fingerprint))
                .map(|(host, _)| host.clone())
                .collect(),
            wallets: payload
                .wallets
                .iter()
                .enumerate()
                .map(|(index, wallet)| BackupWalletPreview {
                    index: index as u32,
                    name: wallet.name.clone(),
                    network: wallet.network,
                    kind: wallet.kind.clone(),
                    already_watched: find_watched(&state.payload, wallet.network, &wallet.kind)
                        .is_some(),
                })
                .collect(),
        })
    }

    /// Restores the chosen wallets (all by default) as new records, the
    /// way [`Self::add_wallet`] creates them, keeping their names and
    /// labels; a wallet already watched is skipped, never duplicated or
    /// overwritten. The settings the backup carries are applied only
    /// when asked: backends replace the ones present for the same
    /// networks, accepted certificates are added but never replaced (a
    /// fingerprint that changed is exactly what pinning refuses to
    /// switch in silence), the gap limit is bounded like
    /// [`Self::set_gap_limit`].
    pub async fn import_backup(
        &self,
        source: &str,
        password: &str,
        choices: &ImportChoices,
    ) -> CoreResult<ImportReport> {
        let result: CoreResult<ImportReport> = async {
            let payload = backup::open(&backup::decode_source(source)?, password)?;
            let chosen: BTreeSet<usize> = match &choices.indexes {
                Some(indexes) => indexes
                    .iter()
                    .map(|&index| {
                        let index = index as usize;
                        if index < payload.wallets.len() {
                            Ok(index)
                        } else {
                            Err(CoreError::InvalidInput {
                                kind: "backup",
                                detail: format!("this backup has no wallet at index {index}"),
                            })
                        }
                    })
                    .collect::<CoreResult<_>>()?,
                None => (0..payload.wallets.len()).collect(),
            };
            let settings_applied = choices.apply_settings && payload.has_settings();

            let mut state = self.state.lock().await;
            // Restored wallets take the gap limit in force once the settings
            // are applied.
            let gap_limit = match payload.gap_limit.filter(|_| settings_applied) {
                Some(gap_limit) => gap_limit.clamp(1, 500),
                None => state.payload.settings.gap_limit,
            };

            // Everything that can fail happens before the vault changes: a
            // descriptor the engine refuses leaves nothing half-restored.
            let mut pending: Vec<(WalletRecord, Option<bdk_wallet::Wallet>)> = Vec::new();
            let mut skipped = (payload.wallets.len() - chosen.len()) as u32;
            for index in chosen {
                let wallet = &payload.wallets[index];
                let watched = find_watched(&state.payload, wallet.network, &wallet.kind).is_some()
                    || pending.iter().any(|(record, _)| {
                        record.meta.network == wallet.network && record.meta.kind == wallet.kind
                    });
                if watched {
                    skipped += 1;
                    continue;
                }
                let name = wallet.name.trim();
                if name.is_empty() {
                    return Err(CoreError::InvalidInput {
                        kind: "wallet name",
                        detail: "a wallet needs a name".to_owned(),
                    });
                }
                let mut meta = fresh_meta(
                    name,
                    wallet.network,
                    wallet.kind.clone(),
                    recognized_kind(&wallet.kind),
                    gap_limit,
                );
                meta.labels = wallet.labels.clone();
                meta.live_pinned = wallet.live_pinned;
                pending.push(build_record(meta)?);
            }

            // The vault changes as a whole or not at all, and the engines
            // are kept only once it has: a save that fails must not leave
            // wallets on screen that the disk never received.
            let mut added = Vec::with_capacity(pending.len());
            let mut engines = Vec::new();
            state.commit(|next| {
                if settings_applied {
                    let settings = &mut next.settings;
                    if let Some(backends) = &payload.backends {
                        // Stored the way the settings screen stores them: a
                        // backup from a vault older than that form, or one
                        // written by hand, must not put in place an address
                        // the screen would have refused. One that cannot be
                        // read is left out, and the backend of that network
                        // stays as it was.
                        settings.backends.extend(backends.iter().filter_map(
                            |(network, config)| Some((*network, config.clone().canonical().ok()?)),
                        ));
                    }
                    if let Some(certs) = &payload.electrum_certs {
                        for (host, fingerprint) in certs {
                            // The same check an acceptance made by hand goes
                            // through: a backup must not be able to pin what
                            // the dialog would have refused, nor a fingerprint
                            // shaped so that no real certificate can ever
                            // match it and the host becomes permanently
                            // unreachable.
                            if !chain::tls::is_fingerprint(fingerprint) {
                                continue;
                            }
                            settings
                                .electrum_certs
                                .entry(host.clone())
                                .or_insert_with(|| fingerprint.to_ascii_uppercase());
                        }
                    }
                    settings.gap_limit = gap_limit;
                }
                for (record, engine) in pending {
                    if let Some(engine) = engine {
                        engines.push((record.meta.id.clone(), engine));
                    }
                    added.push(record.meta.clone());
                    next.wallets.push(record);
                }
                Ok(())
            })?;
            state.engines.extend(engines);
            Ok(ImportReport {
                added,
                skipped,
                settings_applied,
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    // --- premium -------------------------------------------------------

    /// The premium account as the vault keeps it, the device token
    /// blanked: it never leaves the core. The rest is as stored, and
    /// [`PremiumState::device`] still says whether this device is
    /// connected.
    pub async fn premium_state(&self) -> PremiumState {
        let mut premium = self.state.lock().await.payload.settings.premium.clone();
        premium.redact();
        premium
    }

    /// Replaces what the apps keep in the premium account state: they
    /// read it, change what they need, and hand it back. Two things are
    /// theirs to write: the consents and the dismissed banner. A yes for
    /// a wallet also drops its removal still queued for the server, as
    /// [`PremiumState::consent`] does. Whatever the copy says of the
    /// rest is ignored, the queued removals included:
    /// [`Self::remove_wallet`] queues them, and a copy read before this
    /// device moved to another account would otherwise bring back the
    /// old account's, to go out with the new account's token. The key,
    /// the certificate, this device's connection, whether the server
    /// disowned it, and what was sent and not answered move only with
    /// the server's answer, through
    /// [`Self::premium_connect`], [`Self::premium_ensure_device`],
    /// [`Self::premium_refresh_licence`], [`Self::premium_change_key`],
    /// [`Self::premium_remove_device`], [`Self::premium_log_out`],
    /// [`Self::premium_flush_logouts`] and
    /// [`Self::premium_delete_account`], or when a call hears that the
    /// token is disowned. A copy read before one of those and handed
    /// back after it can then neither bring back a key that was logged
    /// out or replaced, nor drop the one that replaced it. What the
    /// account's safety card remembers has setters of its own, for the
    /// same reason: a stale copy must not mark a key just changed as
    /// saved. See [`Self::premium_set_key_saved`],
    /// [`Self::premium_hide_checklist`] and
    /// [`Self::premium_mark_announced`].
    ///
    /// A new yes for a wallet no longer on this device is dropped: a
    /// copy read before [`Self::remove_wallet`] would otherwise bring
    /// back the consent the removal took, and cancel the removal queued
    /// for the server.
    pub async fn set_premium_state(&self, mut premium: PremiumState) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            let stored = &payload.settings.premium;
            premium.watched.retain(|consent| {
                stored.is_consented(&consent.wallet_id)
                    || payload
                        .wallets
                        .iter()
                        .any(|record| record.meta.id == consent.wallet_id)
            });
            payload.settings.premium = payload.settings.premium.with_app_part_of(premium);
            Ok(())
        })
    }

    /// A client for the premium server at `base_url`, carrying the
    /// stored key and this device's token. A token the server disowns
    /// through it, whoever makes the call, is dropped from the vault
    /// before the error comes back, and the key stays: see
    /// [`PremiumError::DeviceDisconnected`].
    ///
    /// The client goes through Tor when the base URL is an onion, and
    /// when the backend of the active network is one: a person who
    /// reaches their own node through Tor chose not to show their
    /// address, and the premium server is not where to show it after
    /// all. The route is resolved before the client exists, and a Tor
    /// that cannot be reached is a client that is not built: nothing
    /// falls back to the clear. A clearnet backend with a clearnet base
    /// URL never probes for Tor.
    pub async fn premium_client(&self, base_url: &str) -> CoreResult<PremiumClient> {
        let (key, token) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            (
                premium.key.clone(),
                premium.device.as_ref().map(|d| d.token().to_owned()),
            )
        };
        self.premium_client_for(base_url, key, token).await
    }

    /// [`Self::premium_client`] carrying the key and the token a caller
    /// read beside what they go with.
    async fn premium_client_for(
        &self,
        base_url: &str,
        key: Option<String>,
        token: Option<String>,
    ) -> CoreResult<PremiumClient> {
        Ok(self
            .premium_client_with_key(base_url, key)
            .await?
            .with_device_token(token)
            .on_disowned(self.premium_disowned_hook()))
    }

    /// [`Self::premium_client`] carrying `key` instead of the stored
    /// one, and no device token: for connecting a key just typed,
    /// before anything is stored. The route is decided the same way.
    pub async fn premium_client_with_key(
        &self,
        base_url: &str,
        key: Option<String>,
    ) -> CoreResult<PremiumClient> {
        // Tor as soon as any backend is an onion, on any network, as for
        // the update check: the requests carry the device token, and
        // switching to a network whose backend is in the clear must
        // not show this device's address to the server beside it.
        let proxy = if chain::is_onion(base_url) || self.uses_tor().await {
            let (settings, data_dir) = self.tor_setup().await;
            Some(tor::resolve(&settings, &data_dir).await?.proxy())
        } else {
            None
        };
        let client = PremiumClient::new(base_url, key, proxy.as_deref())?;
        #[cfg(test)]
        let client = match self.premium_public_key.lock().unwrap().clone() {
            Some(public_key) => client.with_public_key(&public_key),
            None => client,
        };
        Ok(client)
    }

    /// What drops a token the server disowned: the stored one, if it is
    /// still that token. The manager is held weakly, so a client kept
    /// past it keeps nothing alive. A vault that cannot be written keeps
    /// the token, and the next call hears the same answer and tries
    /// again.
    fn premium_disowned_hook(&self) -> crate::premium::client::DisownedHook {
        let shared = std::sync::Arc::downgrade(&self.shared);
        std::sync::Arc::new(move |token: String| {
            let shared = shared.clone();
            Box::pin(async move {
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                let mut state = shared.state.lock().await;
                if state.payload.settings.premium.holds_token(&token) {
                    let _ = state.commit(|payload| {
                        payload.settings.premium.disown(&token);
                        Ok(())
                    });
                }
            })
        })
    }

    /// Confirms a channel with the code the server sent to it, through
    /// the client [`Self::premium_client`] builds: the same token, the
    /// same route.
    pub async fn premium_confirm_channel(
        &self,
        base_url: &str,
        id: &str,
        code: &str,
    ) -> CoreResult<Channel> {
        self.premium_client(base_url)
            .await?
            .confirm_channel(id, code)
            .await
    }

    /// Deletes the account on the server, then forgets it here: the
    /// key, the token, the certificate, the consents, the dismissed
    /// banner. A key with nothing behind it is not worth keeping, and
    /// the next key entered starts from nothing. Nothing is forgotten
    /// unless the server confirmed. A token the server disowns is not
    /// that: an account deleted from another device disowns it, and so
    /// does a device disconnected from one that is still there, which
    /// this device can no longer tell apart. The token goes, the key
    /// stays, and [`Self::premium_log_out`] is what forgets the rest.
    /// The tokens of past connections still to be dropped by the server,
    /// another account's among them, stay queued.
    pub async fn premium_delete_account(&self, base_url: &str) -> CoreResult<()> {
        let _change = self.premium_changes.lock().await;
        self.premium_client(base_url)
            .await?
            .delete_account()
            .await?;
        self.state.lock().await.commit(|payload| {
            let gone = std::mem::take(&mut payload.settings.premium);
            // Tokens of past connections, other accounts' among them,
            // are still to be dropped by the server.
            let premium = &mut payload.settings.premium;
            premium.pending_logouts = gone.pending_logouts;
            if let Some(pending) = &gone.pending_connect {
                premium.queue_logout(pending.token());
            }
            Ok(())
        })
    }

    /// Tells the server to stop watching a wallet that stays on this
    /// device: the switch in the settings turned off. The yes goes with
    /// it once the server has nothing under that id: told, or answered
    /// that there is nothing there ([`PremiumError::NotFound`]). A
    /// wallet the server does not watch needs no consent on file; one
    /// left behind would have a later removal queue a message the
    /// server has already heard, and the screens say the server is told
    /// when it has nothing to hear. Switching the wallet back on asks
    /// the question again, as it should: the descriptor leaves the
    /// device only on a yes said for that sending. Any other answer
    /// leaves everything as it was: a server that cannot be reached,
    /// one that refuses for lack of paid time, a device that waits or
    /// was disowned, a rate limit or any refusal of its own says
    /// nothing about what it still holds, and the wallet is still
    /// watched there, the yes still standing here, until it is told
    /// again.
    pub async fn premium_unwatch_wallet(&self, base_url: &str, id: &str) -> CoreResult<()> {
        match self.premium_client(base_url).await?.delete_wallet(id).await {
            Ok(()) | Err(CoreError::Premium(PremiumError::NotFound)) => {}
            Err(e) => return Err(e),
        }
        self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            premium.withdraw(id);
            premium.unwatched(id);
            Ok(())
        })
    }

    /// Tells the server about the wallets removed from this device
    /// since it last heard, one `DELETE` each in the order they went,
    /// through the client [`Self::premium_client`] builds. A wallet the
    /// server has nothing under counts as told. A wallet the server
    /// refuses stays queued and the round
    /// goes on to the next: a refusal is about that one id, and one
    /// the server never accepts must not hold every wallet behind it.
    /// Any other answer ends the round where it stands: a server that
    /// cannot be reached, and a rate limit, which is about this client
    /// and would turn away every request behind it as well. Either way what was told is
    /// forgotten, the rest waits for the next call, and the first
    /// error is returned. Nothing to tell, or no connected device to
    /// tell it with, costs no connection. Returns how many removals
    /// still wait.
    ///
    /// The removals and the token they go with are read together, and
    /// what the server answered settles them only while this device
    /// still holds that token: once it has moved to another account,
    /// the queue is that account's, and the old one's answers told it
    /// nothing.
    pub async fn premium_flush_unwatch(&self, base_url: &str) -> CoreResult<usize> {
        let (pending, key, token) = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            let token = match &premium.device {
                Some(device) if premium.has_key() => device.token().to_owned(),
                _ => return Ok(premium.pending_unwatch.len()),
            };
            (premium.pending_unwatch.clone(), premium.key.clone(), token)
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let client = self
            .premium_client_for(base_url, key, Some(token.clone()))
            .await?;
        let mut told = Vec::new();
        let mut failure = None;
        for id in &pending {
            match client.delete_wallet(id).await {
                Ok(()) => told.push(id.clone()),
                // Nothing under that id: the state we wanted.
                Err(CoreError::Premium(PremiumError::NotFound)) => {
                    told.push(id.clone());
                }
                // A refusal says nothing about what the server holds,
                // and the message waits. It is about this id, though,
                // and the next may fare better:
                // one the server refuses for good would otherwise hold
                // the rest for good too.
                Err(e @ CoreError::Premium(PremiumError::Rejected(_))) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                }
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                    break;
                }
            }
        }
        let left = self.state.lock().await.commit(|payload| {
            let premium = &mut payload.settings.premium;
            if premium.holds_token(&token) {
                for id in &told {
                    premium.unwatched(id);
                }
            }
            Ok(premium.pending_unwatch.len())
        })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(left),
        }
    }
}

// --- helpers -----------------------------------------------------------

/// One wallet as the live watch takes it: its scripts in the order a
/// transport should cover them, `per_wallet` at most, whether it waits
/// for a block, whether the user pinned it and whether it holds coins.
/// `None` for a wallet that cannot be read, which is then not watched.
pub(crate) fn watched_wallet(
    state: &mut ManagerState,
    id: &str,
    gap_limit: u32,
    per_wallet: usize,
) -> Option<crate::watch::WatchedWallet> {
    let record = find_record(&state.payload, id).ok()?;
    let pinned = record.meta.live_pinned;
    let (scripts, has_pending, holds_coins) = match &record.meta.kind {
        WalletKind::SingleAddress { address } => {
            let script = Address::from_str(address)
                .ok()?
                .require_network(record.meta.network.to_bitcoin())
                .ok()?
                .script_pubkey();
            let has_pending = record
                .address_state
                .as_ref()
                .is_some_and(|watch| watch.txs.iter().any(|tx| tx.height.is_none()));
            let holds_coins = record
                .address_state
                .as_ref()
                .is_some_and(|watch| !watch.utxos.is_empty());
            let scripts = (
                vec![crate::watch::WatchedScript {
                    script: script.to_hex_string(),
                    lookahead: false,
                    status: record
                        .address_state
                        .as_ref()
                        .and_then(views::address_status),
                    // Its history may be cut short: nothing to compare
                    // counters with.
                    counts: None,
                }],
                0,
            );
            (scripts, has_pending, holds_coins)
        }
        WalletKind::Descriptors { .. } => {
            let orders = std::mem::take(&mut state.orders);
            let listed = ensure_engine(state, id).ok().map(|engine| {
                (
                    views::watch_scripts(engine, gap_limit, &orders, per_wallet),
                    views::has_pending(engine),
                    views::holds_coins(engine),
                )
            });
            state.orders = orders;
            listed?
        }
    };
    // A wallet never synced holds nothing yet, which says nothing of
    // what its scripts hold: an empty status matches none a server
    // gives, and the watch syncs it once it starts.
    let never_synced = find_record(&state.payload, id)
        .ok()?
        .meta
        .last_sync
        .is_none();
    let (scripts, unlisted) = scripts;
    let scripts = scripts
        .into_iter()
        .map(|script| crate::watch::WatchedScript {
            status: if never_synced {
                Some(String::new())
            } else {
                script.status
            },
            ..script
        })
        .collect();
    Some(crate::watch::WatchedWallet {
        wallet_id: id.to_owned(),
        scripts,
        has_pending,
        pinned,
        holds_coins,
        unlisted,
    })
}

/// The scripts a sync reads to look again for the payments of a wallet
/// earlier syncs saw vanish, those whose second look is due at `now`:
/// `None` when none is, empty for a watched address, whose sync reads
/// its one script whatever it is asked.
pub(crate) fn vanished_scripts(
    state: &mut ManagerState,
    id: &str,
    now: u64,
) -> Option<Vec<String>> {
    let due = crate::live::news::vanishing_due(&state.payload, id, now);
    if due.is_empty() {
        return None;
    }
    let record = find_record(&state.payload, id).ok()?;
    if matches!(record.meta.kind, WalletKind::SingleAddress { .. }) {
        return Some(Vec::new());
    }
    let engine = ensure_engine(state, id).ok()?;
    Some(views::scripts_touched_by(engine, &due)).filter(|scripts| !scripts.is_empty())
}

fn find_record<'a>(payload: &'a VaultPayload, id: &str) -> CoreResult<&'a WalletRecord> {
    payload
        .wallets
        .iter()
        .find(|record| record.meta.id == id)
        .ok_or_else(|| CoreError::WalletNotFound(id.to_owned()))
}

fn find_record_mut<'a>(
    payload: &'a mut VaultPayload,
    id: &str,
) -> CoreResult<&'a mut WalletRecord> {
    payload
        .wallets
        .iter_mut()
        .find(|record| record.meta.id == id)
        .ok_or_else(|| CoreError::WalletNotFound(id.to_owned()))
}

fn create_engine(
    external: &str,
    internal: Option<&str>,
    network: Network,
) -> CoreResult<bdk_wallet::Wallet> {
    // The engine takes a descriptor with private keys as readily as one
    // without, and would sign with them. The text reaches here from the
    // parser, but also from a backup file and from whatever the app
    // hands back as a parsed input, so it is held to watch-only again.
    for descriptor in std::iter::once(external).chain(internal) {
        require_public_descriptor(descriptor)?;
    }
    let params = match internal {
        Some(internal) => bdk_wallet::Wallet::create(external.to_owned(), internal.to_owned()),
        None => bdk_wallet::Wallet::create_single(external.to_owned()),
    };
    params
        .network(network.to_bitcoin())
        .create_wallet_no_persist()
        .map_err(|e| CoreError::Descriptor(e.to_string()))
}

/// Refuses a descriptor that carries private key material, or that does
/// not read as a descriptor of public keys alone.
fn require_public_descriptor(descriptor: &str) -> CoreResult<()> {
    crate::input::reject_private_material(descriptor)?;
    use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey};
    descriptor
        .parse::<Descriptor<DescriptorPublicKey>>()
        .map(|_| ())
        .map_err(|e| CoreError::Descriptor(e.to_string()))
}

/// The wallet already watching the same material on the same network,
/// if any. Identity is the material, never the name.
fn find_watched<'a>(
    payload: &'a VaultPayload,
    network: Network,
    kind: &WalletKind,
) -> Option<&'a WalletRecord> {
    payload
        .wallets
        .iter()
        .find(|record| record.meta.network == network && record.meta.kind == *kind)
}

/// A brand new wallet identity: fresh id, created now, never scanned.
fn fresh_meta(
    name: &str,
    network: Network,
    kind: WalletKind,
    recognized_as: RecognizedKind,
    gap_limit: u32,
) -> WalletMeta {
    WalletMeta {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_owned(),
        icon: WalletIcon::default(),
        network,
        kind,
        recognized_as,
        created_at: now_secs(),
        gap_limit,
        scan_gap: 0,
        labels: Default::default(),
        last_sync: None,
        complete_at: None,
        cached: CachedTotals::default(),
        live_pinned: false,
    }
}

/// Turns a new identity into its stored record, plus the engine to cache
/// for a descriptor wallet. The engine is built now so an invalid
/// descriptor/network combination fails here, not at the first sync; a
/// single address is re-checked against its network as a defense in
/// depth, whatever validated it upstream.
fn build_record(meta: WalletMeta) -> CoreResult<(WalletRecord, Option<bdk_wallet::Wallet>)> {
    let kind = meta.kind.clone();
    match &kind {
        WalletKind::Descriptors {
            external, internal, ..
        } => {
            let mut engine = create_engine(external, internal.as_deref(), meta.network)?;
            let changeset = engine.take_staged().ok_or_else(|| {
                CoreError::Internal("new wallet produced no initial change set".to_owned())
            })?;
            Ok((
                WalletRecord {
                    meta,
                    changeset: Some(changeset),
                    address_state: None,
                },
                Some(engine),
            ))
        }
        WalletKind::SingleAddress { address } => {
            address
                .parse::<bdk_wallet::bitcoin::Address<_>>()
                .ok()
                .and_then(|a| a.require_network(meta.network.to_bitcoin()).ok())
                .ok_or_else(|| CoreError::NetworkMismatch {
                    expected: meta.network.to_string(),
                    found: "address".to_owned(),
                })?;
            Ok((
                WalletRecord {
                    meta,
                    changeset: None,
                    address_state: None,
                },
                None,
            ))
        }
    }
}

/// Loads the BDK engine for a wallet from its stored change set, caching
/// it for the manager's lifetime.
fn ensure_engine<'a>(
    state: &'a mut ManagerState,
    id: &str,
) -> CoreResult<&'a mut bdk_wallet::Wallet> {
    if !state.engines.contains_key(id) {
        let record = find_record(&state.payload, id)?;
        let changeset = record
            .changeset
            .clone()
            .ok_or_else(|| CoreError::Internal(format!("wallet {id} has no stored change set")))?;
        let network = record.meta.network;
        let engine = bdk_wallet::Wallet::load()
            .check_network(network.to_bitcoin())
            .load_wallet_no_persist(changeset)
            .map_err(|e| CoreError::Internal(format!("vault change set rejected: {e}")))?
            .ok_or_else(|| {
                CoreError::Internal(format!("wallet {id} change set holds no wallet"))
            })?;
        state.engines.insert(id.to_owned(), engine);
    }
    Ok(state
        .engines
        .get_mut(id)
        .expect("inserted or present just above"))
}

/// Merges a freshly staged change set into the stored aggregate.
fn merge_changeset(
    state: &mut ManagerState,
    id: &str,
    staged: bdk_wallet::ChangeSet,
) -> CoreResult<()> {
    use bdk_wallet::chain::Merge;
    let record = find_record_mut(&mut state.payload, id)?;
    record.changeset = Some(match record.changeset.take() {
        Some(mut aggregate) => {
            aggregate.merge(staged);
            aggregate
        }
        None => staged,
    });
    Ok(())
}

/// Takes every block above `height` out of a wallet's chain: blocks a
/// lying server put there, which no update can take out, since none
/// will ever hold a block at their height (see
/// [`chain::Synced::drop_above`]). The engine is loaded again from its
/// stored change set, what it staged merged in first, with those
/// heights removed.
fn drop_blocks_above(state: &mut ManagerState, id: &str, height: u32) -> CoreResult<()> {
    let engine = ensure_engine(state, id)?;
    let above: BTreeMap<u32, Option<bdk_wallet::bitcoin::BlockHash>> = engine
        .checkpoints()
        .map(|checkpoint| checkpoint.height())
        .take_while(|at| *at > height)
        .map(|at| (at, None))
        .collect();
    if above.is_empty() {
        return Ok(());
    }
    if let Some(staged) = engine.take_staged() {
        merge_changeset(state, id, staged)?;
    }
    let mut dropped = bdk_wallet::ChangeSet::default();
    dropped.local_chain.blocks = above;
    merge_changeset(state, id, dropped)?;
    state.engines.remove(id);
    ensure_engine(state, id).map(|_| ())
}

/// Puts a block in a wallet's stored chain, the way a sync that took it
/// from a lying server stored it before such blocks were refused.
#[cfg(test)]
pub(crate) fn store_block(
    state: &mut ManagerState,
    id: &str,
    block: bdk_wallet::chain::BlockId,
) -> CoreResult<()> {
    let engine = ensure_engine(state, id)?;
    let tip = engine
        .latest_checkpoint()
        .push(block)
        .map_err(|_| CoreError::Internal("a block below the tip".to_owned()))?;
    engine
        .apply_update(bdk_wallet::Update {
            chain: Some(tip),
            ..Default::default()
        })
        .map_err(|e| CoreError::Internal(e.to_string()))?;
    if let Some(staged) = engine.take_staged() {
        merge_changeset(state, id, staged)?;
    }
    state.engines.remove(id);
    Ok(())
}

/// The height of a wallet's tip, as its stored change set gives it.
#[cfg(test)]
pub(crate) fn stored_tip(state: &mut ManagerState, id: &str) -> CoreResult<u32> {
    state.engines.remove(id);
    Ok(ensure_engine(state, id)?.latest_checkpoint().height())
}

/// What the import screen would have recognized a restored wallet as:
/// the material says it all.
fn recognized_kind(kind: &WalletKind) -> RecognizedKind {
    match kind {
        WalletKind::Descriptors {
            internal: Some(_), ..
        } => RecognizedKind::DescriptorPair,
        WalletKind::Descriptors { .. } => RecognizedKind::Descriptor,
        WalletKind::SingleAddress { .. } => RecognizedKind::Address,
    }
}

#[cfg(test)]
mod tests {
    pub(crate) mod support;

    use super::*;
    use crate::chain::tor::{TorMode, TorSettings};
    use crate::input::{ParsedPayload, parse_input};
    use support::*;

    #[tokio::test]
    async fn app_lock_set_verify_change_clear() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        assert!(manager.app_lock().await.is_none());
        assert!(manager.verify_app_lock("1234").await.is_err());

        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        let lock = manager.app_lock().await.unwrap();
        assert_eq!(lock.kind, LockKind::Pin);
        assert!(lock.secret.is_none(), "the hash never leaves the vault");
        assert!(manager.settings().await.app_lock.unwrap().secret.is_none());
        assert!(manager.verify_app_lock("1234").await.unwrap().unlocked);
        assert!(!manager.verify_app_lock("4321").await.unwrap().unlocked);
        assert!(manager.verify_app_lock("1234").await.unwrap().unlocked);

        // Changing or clearing needs the current secret.
        assert!(
            manager
                .set_app_lock(LockKind::Password, "long enough", None)
                .await
                .is_err()
        );
        assert!(
            manager
                .set_app_lock(LockKind::Password, "long enough", Some("0000"))
                .await
                .is_err()
        );
        manager
            .set_app_lock(LockKind::Password, "long enough", Some("1234"))
            .await
            .unwrap();
        assert_eq!(manager.app_lock().await.unwrap().kind, LockKind::Password);
        assert!(
            manager
                .verify_app_lock("long enough")
                .await
                .unwrap()
                .unlocked
        );
        assert!(manager.clear_app_lock("nope nope").await.is_err());
        manager.clear_app_lock("long enough").await.unwrap();
        assert!(manager.app_lock().await.is_none());

        // It survives a reopen, hash included.
        manager
            .set_app_lock(LockKind::Pin, "9876", None)
            .await
            .unwrap();
        drop(manager);
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        assert!(reopened.verify_app_lock("9876").await.unwrap().unlocked);
    }

    #[tokio::test]
    async fn app_lock_slows_down_after_three_failures() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        for expected in 1..=2 {
            let verdict = manager.verify_app_lock("0000").await.unwrap();
            assert_eq!(verdict.failures, expected);
            assert_eq!(verdict.retry_after_secs, 0);
        }
        let verdict = manager.verify_app_lock("0000").await.unwrap();
        assert_eq!(verdict.failures, 3);
        assert!(verdict.retry_after_secs >= 4);
        // While delayed, even the right secret is not looked at.
        let verdict = manager.verify_app_lock("1234").await.unwrap();
        assert!(!verdict.unlocked);
        assert!(verdict.retry_after_secs > 0);
        assert!(manager.clear_app_lock("1234").await.is_err());
    }

    /// Quitting and relaunching the app is the obvious way around a
    /// delay, and the one a script would take: the count and the block
    /// must come back with the vault.
    #[tokio::test]
    async fn app_lock_delay_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let attempts_file = dir.path().join(ATTEMPTS_FILE);
        let manager = manager(dir.path()).await;
        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(!manager.verify_app_lock("0000").await.unwrap().unlocked);
        }
        assert!(attempts_file.exists());
        drop(manager);

        // The right PIN, straight after relaunching: still not looked at.
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        let verdict = reopened.verify_app_lock("1234").await.unwrap();
        assert!(!verdict.unlocked);
        assert_eq!(verdict.failures, 3);
        assert!(verdict.retry_after_secs > 0, "{verdict:?}");
        drop(reopened);

        // Two failures carry no delay yet, but they are counted: the
        // first guess after a relaunch is the third, not the first.
        let dir = tempfile::tempdir().unwrap();
        let counted = WalletManager::open(dir.path(), key()).unwrap();
        counted
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        for _ in 0..2 {
            counted.verify_app_lock("0000").await.unwrap();
        }
        drop(counted);
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        let verdict = reopened.verify_app_lock("0000").await.unwrap();
        assert_eq!(verdict.failures, 3);
        assert!(verdict.retry_after_secs >= 4);
        drop(reopened);

        // A success clears the record, file included.
        let dir = tempfile::tempdir().unwrap();
        let attempts_file = dir.path().join(ATTEMPTS_FILE);
        let cleared = WalletManager::open(dir.path(), key()).unwrap();
        cleared
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        cleared.verify_app_lock("0000").await.unwrap();
        assert!(attempts_file.exists());
        assert!(cleared.verify_app_lock("1234").await.unwrap().unlocked);
        assert!(!attempts_file.exists());
    }

    /// The record is a convenience for the delays, not part of the
    /// vault: a file that cannot be read must never lock the owner out.
    #[tokio::test]
    async fn a_corrupt_attempts_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        drop(manager);
        std::fs::write(dir.path().join(ATTEMPTS_FILE), b"\x00\xff not a record").unwrap();
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        let verdict = reopened.verify_app_lock("1234").await.unwrap();
        assert!(verdict.unlocked);
        assert_eq!(verdict.failures, 0);
    }

    #[tokio::test]
    async fn biometric_unlock_needs_a_lock_and_its_secret() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        assert!(manager.set_biometric_unlock(true, "1234").await.is_err());
        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        // Guarded by the secret in place: a wrong one changes nothing,
        // the right one goes through.
        assert!(manager.set_biometric_unlock(true, "0000").await.is_err());
        assert!(!manager.app_lock().await.unwrap().biometric);
        manager.set_biometric_unlock(true, "1234").await.unwrap();
        assert!(manager.app_lock().await.unwrap().biometric);
        // A new secret keeps the biometric choice.
        manager
            .set_app_lock(LockKind::Pin, "5678", Some("1234"))
            .await
            .unwrap();
        assert!(manager.app_lock().await.unwrap().biometric);
    }

    /// A descriptor with a private key is refused however it arrives:
    /// from a backup file written by hand, or from a parsed input the
    /// app hands back altered. Nothing reaches the vault.
    #[tokio::test]
    async fn private_keys_never_reach_the_vault() {
        const TPRV: &str = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
        // The textbook WIF example, public for years.
        const WIF: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let private = [
            format!("wpkh({TPRV}/84'/1'/0'/0/*)"),
            format!("wpkh({WIF})"),
        ];
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

        for descriptor in &private {
            let mut parsed = parse_input(MULTIPATH).unwrap();
            parsed.payload = ParsedPayload::Descriptors {
                external: descriptor.clone(),
                internal: None,
                script: crate::input::ScriptKind::Segwit,
            };
            let error = manager
                .add_wallet("Hot", &parsed, Network::Signet)
                .await
                .unwrap_err();
            assert!(
                matches!(error, CoreError::PrivateMaterialRejected),
                "{error}"
            );

            let payload = BackupPayload {
                version: BACKUP_VERSION,
                created_at: 1_755_000_000,
                wallets: vec![BackupWallet {
                    name: "Hot".to_owned(),
                    network: Network::Signet,
                    kind: WalletKind::Descriptors {
                        external: descriptor.clone(),
                        internal: None,
                        script: crate::input::ScriptKind::Segwit,
                    },
                    gap_limit: 20,
                    labels: Default::default(),
                    created_at: 1_755_000_000,
                    live_pinned: false,
                }],
                backends: None,
                electrum_certs: None,
                gap_limit: None,
            };
            let sealed = backup::seal(&payload, BACKUP_PASSWORD).unwrap();
            let source = data_encoding::BASE64.encode(&sealed);
            let error = manager
                .import_backup(
                    &source,
                    BACKUP_PASSWORD,
                    &ImportChoices {
                        indexes: None,
                        apply_settings: false,
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, CoreError::PrivateMaterialRejected),
                "{error}"
            );
        }

        assert!(manager.list_wallets(None).await.is_empty());
        drop(manager);
        let raw = crate::store::Vault::open_or_create(dir.path().join(VAULT_FILE), key())
            .unwrap()
            .1;
        let json = serde_json::to_string(&raw).unwrap();
        assert!(!json.contains("prv") && !json.contains(&private[1][5..20]));
    }

    /// An app reads the premium state, the wallet goes meanwhile, and
    /// the copy comes back to dismiss a banner: its yes for the wallet
    /// is stale, and the removal queued for the server stays.
    #[tokio::test]
    async fn a_stale_copy_cannot_take_back_a_removal() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        store_premium(
            &manager,
            PremiumState {
                key: Some("abcdefghijkmnpqr".to_owned()),
                ..PremiumState::default()
            },
        )
        .await;
        let mut premium = manager.premium_state().await;
        premium.consent(&meta.id, 100);
        manager.set_premium_state(premium).await.unwrap();

        let mut stale = manager.premium_state().await;
        assert!(stale.is_consented(&meta.id));
        manager.remove_wallet(&meta.id).await.unwrap();
        stale.acknowledged_offline_until = Some(5);
        manager.set_premium_state(stale).await.unwrap();
        let premium = manager.premium_state().await;
        assert!(!premium.is_consented(&meta.id));
        assert_eq!(premium.pending_unwatch, vec![meta.id]);
        assert_eq!(premium.acknowledged_offline_until, Some(5));
    }

    /// A premium server that gives these answers in order, one
    /// connection each, and hands the request line of each to the
    /// test. After the last answer it is gone: the next connection is
    /// refused.
    async fn answering(
        answers: Vec<String>,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, seen) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            for answer in answers {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = vec![0u8; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                let first_line = String::from_utf8_lossy(&bytes[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                sender.send(first_line).unwrap();
                stream.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}"), seen)
    }

    /// An HTTP answer with a JSON body, connection closed after it.
    fn answer(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn the_flush_tells_the_server_and_keeps_what_it_could_not() {
        // Two answers, then the server is gone: 200 for the first
        // wallet, 404 for the second (already unknown, which is what we
        // wanted), and a refused connection for the third.
        let (base_url, mut seen) = answering(vec![
            answer("200 OK", "{}"),
            answer("404 Not Found", r#"{"error":"no such wallet"}"#),
        ])
        .await;

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        for id in ["w1", "w2", "w3"] {
            premium.queue_unwatch(id);
        }
        store_premium(&manager, connected(premium)).await;

        let outcome = manager.premium_flush_unwatch(&base_url).await;
        assert!(
            matches!(
                outcome,
                Err(CoreError::Premium(PremiumError::Unreachable(_)))
            ),
            "the third wallet met no server: {outcome:?}"
        );
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
        assert_eq!(
            manager.premium_state().await.pending_unwatch,
            vec!["w3".to_owned()],
            "told and already-gone leave the queue, the unreached one stays"
        );

        // Nothing waiting: no connection is even attempted.
        store_premium(
            &manager,
            connected(PremiumState {
                key: Some("abcdefghijkmnpqr".to_owned()),
                ..PremiumState::default()
            }),
        )
        .await;
        assert_eq!(manager.premium_flush_unwatch(&base_url).await.unwrap(), 0);
    }

    /// A refusal that is not "nothing under that id" says nothing
    /// about what the server holds, and is about that one id: the
    /// wallet it refused stays queued, the ones behind it are still
    /// told, and the refusal comes back once the round is over. One id
    /// the server never accepts used to hold every wallet behind it
    /// for good.
    #[tokio::test]
    async fn the_flush_goes_on_past_a_refused_wallet_and_keeps_it() {
        let (base_url, mut seen) = answering(vec![
            answer("422 Unprocessable Entity", r#"{"error":"not a wallet id"}"#),
            answer("200 OK", "{}"),
        ])
        .await;

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        for id in ["w1", "w2"] {
            premium.queue_unwatch(id);
        }
        store_premium(&manager, connected(premium)).await;

        let outcome = manager.premium_flush_unwatch(&base_url).await;
        assert!(
            matches!(
                &outcome,
                Err(CoreError::Premium(PremiumError::Rejected(words))) if words == "not a wallet id"
            ),
            "{outcome:?}"
        );
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
        assert_eq!(
            manager.premium_state().await.pending_unwatch,
            vec!["w1".to_owned()],
            "the refused wallet waits for the next round, the one behind it was told"
        );

        // The next round starts again from the refused one, and meets
        // no server.
        let left = manager.premium_flush_unwatch(&base_url).await;
        assert!(
            matches!(left, Err(CoreError::Premium(PremiumError::Unreachable(_)))),
            "{left:?}"
        );
        assert_eq!(
            manager.premium_state().await.pending_unwatch,
            vec!["w1".to_owned()]
        );
    }

    /// The first error of the round is the one returned, and a server
    /// that cannot be reached still ends the round where it stands:
    /// the wallets after it are not tried, and wait with the refused
    /// one.
    #[tokio::test]
    async fn the_flush_returns_its_first_error_and_stops_at_a_lost_server() {
        let (base_url, mut seen) = answering(vec![
            answer("200 OK", "{}"),
            answer("400 Bad Request", r#"{"error":"not a wallet id"}"#),
            answer("200 OK", "{}"),
        ])
        .await;

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        for id in ["w1", "w2", "w3", "w4"] {
            premium.queue_unwatch(id);
        }
        store_premium(&manager, connected(premium)).await;

        let outcome = manager.premium_flush_unwatch(&base_url).await;
        assert!(
            matches!(
                &outcome,
                Err(CoreError::Premium(PremiumError::Rejected(words))) if words == "not a wallet id"
            ),
            "{outcome:?}"
        );
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w3 HTTP/1.1");
        assert_eq!(
            manager.premium_state().await.pending_unwatch,
            vec!["w2".to_owned(), "w4".to_owned()],
            "the refused wallet and the one the lost server never heard of wait"
        );
    }

    /// A rate limit is about this client, not about the wallet it was
    /// answered for: the round stops there, the requests behind it are
    /// not sent to be turned away in their turn, and the queue waits
    /// with the time the server asked for.
    #[tokio::test]
    async fn the_flush_stops_at_a_rate_limit_and_keeps_the_queue() {
        let body = r#"{"error":"too many requests"}"#;
        let (base_url, mut seen) = answering(vec![
            answer("200 OK", "{}"),
            format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
            answer("200 OK", "{}"),
        ])
        .await;

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        for id in ["w1", "w2", "w3"] {
            premium.queue_unwatch(id);
        }
        store_premium(&manager, connected(premium)).await;

        let outcome = manager.premium_flush_unwatch(&base_url).await;
        assert!(
            matches!(
                &outcome,
                Err(CoreError::Premium(PremiumError::RateLimited {
                    retry_after: Some(17)
                }))
            ),
            "{outcome:?}"
        );
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
        assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
        assert_eq!(
            manager.premium_state().await.pending_unwatch,
            vec!["w2".to_owned(), "w3".to_owned()],
            "the limited wallet and the one never sent wait"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), seen.recv())
                .await
                .is_err(),
            "nothing is sent behind a rate limit"
        );
    }

    /// Switching a wallet off withdraws the yes once the server has
    /// nothing under its id: told, or already unknown. Removing the
    /// wallet after that queues nothing, since the server has nothing
    /// to hear. A refusal for lack of paid time, words about a key the
    /// request never carried, a rate limit, or a server that cannot be
    /// reached, leaves the yes in place, and a removal still queues its
    /// message.
    #[tokio::test]
    async fn switching_a_wallet_off_withdraws_the_yes_once_the_server_has_heard() {
        let (base_url, mut seen) = answering(vec![
            answer("200 OK", "{}"),
            answer("404 Not Found", r#"{"error":"no such wallet"}"#),
            answer("401 Unauthorized", r#"{"error":"unknown key"}"#),
            answer("403 Forbidden", r#"{"error":"no paid time"}"#),
            answer("429 Too Many Requests", r#"{"error":"too many requests"}"#),
        ])
        .await;

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        for id in [meta.id.as_str(), "w2", "w3", "w4", "w5", "w6"] {
            premium.consent(id, 100);
        }
        store_premium(&manager, connected(premium)).await;

        // Told: the yes goes, and the removal that follows has nothing
        // to queue.
        manager
            .premium_unwatch_wallet(&base_url, &meta.id)
            .await
            .unwrap();
        assert_eq!(
            seen.recv().await.unwrap(),
            format!("DELETE /v1/wallets/{} HTTP/1.1", meta.id)
        );
        assert!(!manager.premium_state().await.is_consented(&meta.id));
        manager.remove_wallet(&meta.id).await.unwrap();
        let premium = manager.premium_state().await;
        assert!(premium.pending_unwatch.is_empty(), "{premium:?}");
        assert!(!premium.is_consented(&meta.id));

        // Already unknown to the server: as unwatched as told.
        manager
            .premium_unwatch_wallet(&base_url, "w2")
            .await
            .unwrap();
        assert!(!manager.premium_state().await.is_consented("w2"));
        // "unknown key" where a token went is not about a key, and
        // proves nothing about the wallet: the yes stands.
        let unknown = manager
            .premium_unwatch_wallet(&base_url, "w3")
            .await
            .unwrap_err();
        assert!(
            matches!(&unknown, CoreError::Premium(PremiumError::Rejected(words)) if words == "unknown key"),
            "{unknown}"
        );
        assert!(manager.premium_state().await.is_consented("w3"));

        // Refused for lack of paid time: still watched, the yes stands.
        let refused = manager
            .premium_unwatch_wallet(&base_url, "w4")
            .await
            .unwrap_err();
        assert!(
            matches!(refused, CoreError::Premium(PremiumError::NoPaidTime)),
            "{refused}"
        );
        assert!(manager.premium_state().await.is_consented("w4"));

        // Rate limited: the server still watches the wallet, and the
        // yes stands until it is told and heard.
        let limited = manager
            .premium_unwatch_wallet(&base_url, "w6")
            .await
            .unwrap_err();
        assert!(
            matches!(&limited, CoreError::Premium(PremiumError::Rejected(words)) if words == "too many requests"),
            "{limited}"
        );
        assert!(manager.premium_state().await.is_consented("w6"));

        // The server is gone: nothing changes here either.
        let unreached = manager
            .premium_unwatch_wallet(&base_url, "w5")
            .await
            .unwrap_err();
        assert!(
            matches!(unreached, CoreError::Premium(PremiumError::Unreachable(_))),
            "{unreached}"
        );
        let premium = manager.premium_state().await;
        assert!(premium.is_consented("w4") && premium.is_consented("w5"));
        assert!(premium.is_consented("w3") && premium.is_consented("w6"));
        assert_eq!(premium.watched.len(), 4);

        // The yes withdrawn, the question is asked again: a new yes
        // starts a fresh date.
        let mut premium = manager.premium_state().await;
        premium.consent("w2", 200);
        assert_eq!(premium.consented_at("w2"), Some(200));
    }

    #[tokio::test]
    async fn the_premium_state_lives_in_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        assert_eq!(manager.premium_state().await, PremiumState::default());
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        premium.consent("w1", 100);
        store_premium(&manager, premium.clone()).await;

        drop(manager);
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(manager.premium_state().await, premium);
        // The client built from it carries the stored key, and a
        // clearnet server needs no Tor.
        let client = manager
            .premium_client("https://api.example.org/")
            .await
            .unwrap();
        assert_eq!(client.key(), Some("abcdefghijkmnpqr"));
        assert_eq!(client.base_url(), "https://api.example.org");
    }

    fn fingerprint(byte: &str) -> String {
        vec![byte; 32].join(":")
    }

    /// A backup handed over by someone else, settings included: what
    /// "apply node settings" would put in place is named in the
    /// preview, host by host, before the person agrees to it. A backup
    /// without settings names nothing.
    #[tokio::test]
    async fn the_preview_names_what_the_settings_would_apply() {
        let wallet = BackupWallet {
            name: "Friend's wallet".to_owned(),
            network: Network::Signet,
            kind: WalletKind::Descriptors {
                external: "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)".to_owned(),
                internal: None,
                script: crate::input::ScriptKind::Segwit,
            },
            gap_limit: 20,
            labels: Default::default(),
            created_at: 1_755_000_000,
            live_pinned: false,
        };
        let with_settings = BackupPayload {
            version: BACKUP_VERSION,
            created_at: 1_756_000_000,
            wallets: vec![wallet.clone()],
            backends: Some(
                [
                    (
                        Network::Signet,
                        BackendConfig::CustomElectrum {
                            url: "ssl://127.0.0.1:1".to_owned(),
                            own_node: false,
                        },
                    ),
                    (
                        Network::Mainnet,
                        BackendConfig::CustomEsplora {
                            url: "https://user:pass@node.example.org:3002/api".to_owned(),
                            own_node: false,
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            electrum_certs: Some(
                [
                    ("127.0.0.1:1".to_owned(), fingerprint("AA")),
                    // Not a fingerprint: the import would drop it, so
                    // the preview does not promise it.
                    ("bogus.example:50002".to_owned(), "nope".to_owned()),
                ]
                .into_iter()
                .collect(),
            ),
            gap_limit: Some(30),
        };
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let text =
            data_encoding::BASE64.encode(&backup::seal(&with_settings, BACKUP_PASSWORD).unwrap());
        let preview = manager
            .preview_backup(&text, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert!(preview.has_settings);
        assert_eq!(
            preview.backends,
            vec![
                BackupBackendPreview {
                    network: Network::Mainnet,
                    backend: "node.example.org".to_owned(),
                },
                BackupBackendPreview {
                    network: Network::Signet,
                    backend: "127.0.0.1".to_owned(),
                },
            ]
        );
        assert_eq!(preview.electrum_hosts, vec!["127.0.0.1:1".to_owned()]);
        // What the restore screen receives says it all, and never the
        // credentials a URL may carry.
        let json = serde_json::to_string(&preview).unwrap();
        assert!(
            json.contains(r#""backends":[{"network":"mainnet","backend":"node.example.org"}"#),
            "{json}"
        );
        assert!(
            json.contains(r#""electrum_hosts":["127.0.0.1:1"]"#),
            "{json}"
        );
        assert!(!json.contains("pass@"), "{json}");

        let without = BackupPayload {
            backends: None,
            electrum_certs: None,
            gap_limit: None,
            ..with_settings
        };
        let text = data_encoding::BASE64.encode(&backup::seal(&without, BACKUP_PASSWORD).unwrap());
        let preview = manager
            .preview_backup(&text, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert!(!preview.has_settings);
        assert!(preview.backends.is_empty());
        assert!(preview.electrum_hosts.is_empty());
    }

    /// A backup carries addresses as the vault that wrote it held
    /// them. One from before addresses were stored in canonical form
    /// lands in that form, and one the settings screen would have
    /// refused does not land at all: the preview does not promise it,
    /// and the backend of that network stays as it was.
    #[tokio::test]
    async fn a_restored_backend_is_stored_canonical_or_left_out() {
        let payload = BackupPayload {
            version: BACKUP_VERSION,
            created_at: 1_756_000_000,
            wallets: Vec::new(),
            backends: Some(
                [
                    (
                        Network::Mainnet,
                        BackendConfig::CustomEsplora {
                            url: "HTTPS://Esplora.Example.ORG./api/".to_owned(),
                            own_node: false,
                        },
                    ),
                    (
                        Network::Signet,
                        BackendConfig::CustomElectrum {
                            url: "tcp://x.onion:50001:extra".to_owned(),
                            own_node: false,
                        },
                    ),
                    (
                        Network::Testnet4,
                        BackendConfig::Public {
                            server: Some("mempool.emzy.de".to_owned()),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            electrum_certs: None,
            gap_limit: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let kept = BackendConfig::CustomElectrum {
            url: "ssl://node.example.org:50002".to_owned(),
            own_node: false,
        };
        manager
            .set_backend(Network::Signet, kept.clone())
            .await
            .unwrap();
        let text = data_encoding::BASE64.encode(&backup::seal(&payload, BACKUP_PASSWORD).unwrap());

        let preview = manager
            .preview_backup(&text, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert_eq!(
            preview.backends,
            vec![
                BackupBackendPreview {
                    network: Network::Mainnet,
                    backend: "esplora.example.org".to_owned(),
                },
                BackupBackendPreview {
                    network: Network::Testnet4,
                    backend: "mempool.emzy.de".to_owned(),
                },
            ]
        );

        let choices = ImportChoices {
            indexes: None,
            apply_settings: true,
        };
        manager
            .import_backup(&text, BACKUP_PASSWORD, &choices)
            .await
            .unwrap();
        let settings = manager.settings().await;
        assert_eq!(
            settings.backend_for(Network::Mainnet),
            BackendConfig::CustomEsplora {
                url: "https://esplora.example.org/api".to_owned(),
                own_node: false,
            }
        );
        assert_eq!(settings.backend_for(Network::Signet), kept);
        assert_eq!(
            settings.backend_for(Network::Testnet4),
            BackendConfig::Public {
                server: Some("mempool.emzy.de".to_owned()),
            }
        );
    }

    #[tokio::test]
    async fn backup_restores_wallets_in_a_fresh_vault() {
        let source_dir = tempfile::tempdir().unwrap();
        let (source, cold, watch) = seeded(source_dir.path()).await;
        source.set_gap_limit(50).await.unwrap();
        let esplora = BackendConfig::CustomEsplora {
            url: "https://esplora.example.org/api".to_owned(),
            own_node: false,
        };
        source
            .set_backend(Network::Signet, esplora.clone())
            .await
            .unwrap();
        source
            .trust_certificate("ssl://electrum.example.org:50002", &fingerprint("AB"))
            .await
            .unwrap();

        let options = BackupOptions {
            wallet_ids: None,
            include_settings: true,
        };
        let bundle = source
            .export_backup(&options, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert_eq!(bundle.wallet_count, 2);
        let file = data_encoding::BASE64
            .decode(bundle.data.as_bytes())
            .unwrap();
        assert_eq!(bundle.size_bytes as usize, file.len());
        assert!(bundle.frames.len() > 1);

        let target_dir = tempfile::tempdir().unwrap();
        let target = manager(target_dir.path()).await;
        let preview = target
            .preview_backup(&bundle.data, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert!(preview.has_settings);
        assert_eq!(preview.wallets.len(), 2);
        assert!(preview.wallets.iter().all(|w| !w.already_watched));
        assert_eq!(preview.wallets[0].name, "Cold");
        assert_eq!(preview.wallets[1].index, 1);

        // Wallets only: the settings stay as they were.
        let wallets_only = ImportChoices {
            indexes: None,
            apply_settings: false,
        };
        let report = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &wallets_only)
            .await
            .unwrap();
        assert_eq!(report.added.len(), 2);
        assert_eq!(report.skipped, 0);
        assert!(!report.settings_applied);
        let settings = target.settings().await;
        assert_eq!(settings.gap_limit, 20);
        assert_eq!(
            settings.backend_for(Network::Signet),
            BackendConfig::default()
        );

        let restored = target.list_wallets(None).await;
        let identity = |m: &WalletMeta| (m.name.clone(), m.network, m.kind.clone());
        assert_eq!(
            restored.iter().map(identity).collect::<Vec<_>>(),
            vec![identity(&cold), identity(&watch)]
        );
        assert_ne!(restored[0].id, cold.id, "a restored wallet gets its own id");
        assert_eq!(restored[0].recognized_as, RecognizedKind::DescriptorPair);
        assert_eq!(restored[1].recognized_as, RecognizedKind::Address);
        assert_eq!(
            target.receive_addresses(&restored[0].id, 0).await.unwrap()[0].address,
            source.receive_addresses(&cold.id, 0).await.unwrap()[0].address,
            "the restored engine derives the source's addresses"
        );

        // A second pass finds everything already there.
        let preview = target
            .preview_backup(&bundle.data, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert!(preview.wallets.iter().all(|w| w.already_watched));
        let report = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &wallets_only)
            .await
            .unwrap();
        assert!(report.added.is_empty());
        assert_eq!(report.skipped, 2);

        // Settings when asked; an acceptance made here is never replaced.
        target
            .trust_certificate("ssl://electrum.example.org:50002", &fingerprint("CD"))
            .await
            .unwrap();
        let with_settings = ImportChoices {
            indexes: None,
            apply_settings: true,
        };
        let report = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &with_settings)
            .await
            .unwrap();
        assert!(report.settings_applied);
        let settings = target.settings().await;
        assert_eq!(settings.gap_limit, 50);
        assert_eq!(settings.backend_for(Network::Signet), esplora);
        assert_eq!(
            settings.electrum_certs.values().collect::<Vec<_>>(),
            vec![&fingerprint("CD")]
        );

        // Everything survived on disk.
        drop(target);
        let target = WalletManager::open(target_dir.path(), key()).unwrap();
        assert_eq!(target.list_wallets(None).await.len(), 2);
        assert_eq!(target.settings().await.gap_limit, 50);
    }

    #[tokio::test]
    async fn backup_picks_wallets_on_both_sides() {
        let source_dir = tempfile::tempdir().unwrap();
        let (source, cold, _) = seeded(source_dir.path()).await;
        let only_cold = BackupOptions {
            wallet_ids: Some(vec![cold.id.clone()]),
            include_settings: false,
        };
        let bundle = source
            .export_backup(&only_cold, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert_eq!(bundle.wallet_count, 1);
        let unknown = BackupOptions {
            wallet_ids: Some(vec!["nope".to_owned()]),
            include_settings: false,
        };
        assert!(matches!(
            source.export_backup(&unknown, BACKUP_PASSWORD).await,
            Err(CoreError::WalletNotFound(_))
        ));

        let target_dir = tempfile::tempdir().unwrap();
        let target = manager(target_dir.path()).await;
        let preview = target
            .preview_backup(&bundle.data, BACKUP_PASSWORD)
            .await
            .unwrap();
        assert!(!preview.has_settings);
        assert_eq!(preview.wallets.len(), 1);
        assert_eq!(preview.wallets[0].name, "Cold");

        // Both wallets in, one chosen: the other counts as skipped, and
        // there are no settings to apply.
        let full = source
            .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
            .await
            .unwrap();
        let second_only = ImportChoices {
            indexes: Some(vec![1, 1]),
            apply_settings: true,
        };
        let report = target
            .import_backup(&full.data, BACKUP_PASSWORD, &second_only)
            .await
            .unwrap();
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].name, "Watch");
        assert_eq!(report.skipped, 1);
        assert!(!report.settings_applied);
        let out_of_range = ImportChoices {
            indexes: Some(vec![7]),
            apply_settings: false,
        };
        let error = target
            .import_backup(&full.data, BACKUP_PASSWORD, &out_of_range)
            .await
            .unwrap_err();
        assert!(
            matches!(error, CoreError::InvalidInput { kind: "backup", .. }),
            "{error}"
        );
    }

    /// The whole crossing, the way it actually happens: a desktop with
    /// a few wallets shows the animated code, a phone reads it frame by
    /// frame, and the phone already watches one of those wallets.
    ///
    /// The wallet already there must come back as such and be skipped,
    /// never added a second time — the vault would otherwise end up
    /// with two records for one descriptor, syncing the same addresses
    /// twice and counting the same coins twice.
    #[tokio::test]
    async fn a_scanned_backup_never_doubles_a_wallet_already_watched() {
        let source_dir = tempfile::tempdir().unwrap();
        let (source, _, _) = seeded(source_dir.path()).await;
        let bundle = source
            .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
            .await
            .unwrap();
        assert_eq!(bundle.wallet_count, 2);

        // The phone already watches the address, under a name of its
        // own and with its own id.
        let target_dir = tempfile::tempdir().unwrap();
        let target = manager(target_dir.path()).await;
        let mine = target
            .add_wallet(
                "Already here",
                &parse_input(ADDRESS).unwrap(),
                Network::Signet,
            )
            .await
            .unwrap();

        // The camera reads the loop one frame at a time, joining it
        // wherever it happens to be.
        let frames = &bundle.frames;
        let mut seen: Vec<String> = Vec::new();
        let start = frames.len() / 2;
        let text = loop {
            assert!(
                seen.len() < frames.len(),
                "one turn of the loop should be enough"
            );
            seen.push(frames[(start + seen.len()) % frames.len()].clone());
            let progress = crate::input::qr::assemble(&seen).unwrap();
            assert_eq!(progress.received as usize, seen.len());
            if let Some(text) = progress.text {
                assert!(progress.complete);
                break text;
            }
        };

        let preview = target.preview_backup(&text, BACKUP_PASSWORD).await.unwrap();
        let watched: Vec<_> = preview
            .wallets
            .iter()
            .map(|w| (w.name.as_str(), w.already_watched))
            .collect();
        assert_eq!(watched, vec![("Cold", false), ("Watch", true)]);

        // Restoring everything anyway: the one already here is counted
        // as skipped, and the name it carries on this device stands.
        let report = target
            .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
            .await
            .unwrap();
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].name, "Cold");
        assert_eq!(report.skipped, 1);

        let wallets = target.list_wallets(None).await;
        assert_eq!(wallets.len(), 2);
        assert_eq!(
            wallets.iter().filter(|w| w.kind == mine.kind).count(),
            1,
            "the address is watched once, not twice"
        );
        assert!(wallets.iter().any(|w| w.name == "Already here"));

        // And a second crossing changes nothing at all.
        let again = target
            .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
            .await
            .unwrap();
        assert!(again.added.is_empty());
        assert_eq!(again.skipped, 2);
        assert_eq!(target.list_wallets(None).await.len(), 2);
    }

    #[tokio::test]
    async fn backup_needs_its_password_and_scans_as_a_qr() {
        let source_dir = tempfile::tempdir().unwrap();
        let (source, _, _) = seeded(source_dir.path()).await;
        let error = source
            .export_backup(&BackupOptions::default(), "short")
            .await
            .unwrap_err();
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
        let bundle = source
            .export_backup(&BackupOptions::default(), BACKUP_PASSWORD)
            .await
            .unwrap();

        let target_dir = tempfile::tempdir().unwrap();
        let target = manager(target_dir.path()).await;
        assert!(matches!(
            target
                .preview_backup(&bundle.data, "not the password")
                .await,
            Err(CoreError::Vault(
                crate::error::VaultError::WrongKeyOrCorrupted
            ))
        ));
        assert!(matches!(
            target
                .import_backup("not a backup", BACKUP_PASSWORD, &ImportChoices::default())
                .await,
            Err(CoreError::InvalidInput { kind: "backup", .. })
        ));

        // The frames a camera sees assemble into the text the restore
        // accepts, and the wallet import refuses by name.
        let scanned = crate::input::qr::assemble(&bundle.frames).unwrap();
        assert!(scanned.complete);
        let text = scanned.text.unwrap();
        assert!(text.starts_with(crate::backup::BACKUP_PREFIX));
        let report = target
            .import_backup(&text, BACKUP_PASSWORD, &ImportChoices::default())
            .await
            .unwrap();
        assert_eq!(report.added.len(), 2);
        assert!(matches!(
            parse_input(&text),
            Err(CoreError::InvalidInput { kind: "backup", .. })
        ));
    }

    /// A save that fails must leave the vault in memory exactly as it
    /// was. Otherwise the screen shows wallets the disk never received,
    /// and the next save, made for anything else, commits an import the
    /// user was told had failed.
    #[tokio::test]
    async fn a_failed_save_changes_nothing_in_memory() {
        let source_dir = tempfile::tempdir().unwrap();
        let (source, _, _) = seeded(source_dir.path()).await;
        source.set_gap_limit(50).await.unwrap();
        let bundle = source
            .export_backup(
                &BackupOptions {
                    wallet_ids: None,
                    include_settings: true,
                },
                BACKUP_PASSWORD,
            )
            .await
            .unwrap();
        let everything = ImportChoices {
            indexes: None,
            apply_settings: true,
        };

        let target_dir = tempfile::tempdir().unwrap();
        let target = manager(target_dir.path()).await;
        // Every save fails from here, before the vault itself is
        // touched, as it would on a full disk.
        let fail_saves = |fail: bool| {
            let target = target.clone();
            async move { target.state.lock().await.vault.fail_saves(fail) }
        };
        fail_saves(true).await;

        let error = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &everything)
            .await
            .unwrap_err();
        assert!(
            matches!(error, CoreError::Vault(crate::error::VaultError::Io(_))),
            "{error}"
        );
        assert!(target.list_wallets(None).await.is_empty());
        assert_eq!(target.settings().await.gap_limit, 20);
        assert!(
            target
                .preview_backup(&bundle.data, BACKUP_PASSWORD)
                .await
                .unwrap()
                .wallets
                .iter()
                .all(|w| !w.already_watched)
        );
        assert!(
            target
                .add_wallet("Cold", &parse_input(MULTIPATH).unwrap(), Network::Signet)
                .await
                .is_err()
        );
        assert!(target.list_wallets(None).await.is_empty());
        assert!(target.set_gap_limit(30).await.is_err());
        assert_eq!(target.settings().await.gap_limit, 20);

        // The disk back: the same import goes through whole, and a
        // fresh open finds exactly what the report said.
        fail_saves(false).await;
        let report = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &everything)
            .await
            .unwrap();
        assert_eq!(report.added.len(), 2);
        assert_eq!(target.settings().await.gap_limit, 50);
        let cold = report.added[0].id.clone();

        // Renaming and removing are held to the same rule.
        fail_saves(true).await;
        assert!(target.rename_wallet(&cold, "Renamed").await.is_err());
        assert!(target.remove_wallet(&cold).await.is_err());
        let wallets = target.list_wallets(None).await;
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].name, "Cold");
        assert!(target.wallet_snapshot(&cold).await.is_ok());
        fail_saves(false).await;

        drop(target);
        let reopened = WalletManager::open(target_dir.path(), key()).unwrap();
        assert_eq!(reopened.list_wallets(None).await.len(), 2);
        assert_eq!(reopened.settings().await.gap_limit, 50);
    }

    /// The premium client goes through Tor as soon as a backend of any
    /// network is an onion, not only the one on screen: switching to a
    /// network whose backend is in the clear must not show this
    /// device's address to the premium server. Without Tor to be had,
    /// no client is built at all.
    #[tokio::test]
    async fn the_premium_client_takes_tor_when_any_backend_is_an_onion() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(
                Network::Signet,
                BackendConfig::CustomEsplora {
                    url: "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api"
                        .to_owned(),
                    own_node: false,
                },
            )
            .await
            .unwrap();
        manager
            .set_tor_settings(TorSettings {
                mode: TorMode::System,
                socks_proxy: Some(closed_port().await),
            })
            .await
            .unwrap();
        manager.set_active_network(Network::Mainnet).await.unwrap();

        let refused = manager
            .premium_client_with_key("https://api.gerfaut-wallet.com", None)
            .await;
        assert!(matches!(refused, Err(CoreError::Tor(_))));
    }

    /// A premium server on loopback that answers every request the
    /// same way and hands each request head to the test.
    async fn premium_answering(
        status: u16,
        body: &'static str,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let _ = sender.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let response = format!(
                    "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{address}"), receiver)
    }

    /// The account the vault keeps: a key, the device it connected, a
    /// certificate, a consent, a banner dismissed.
    fn premium_account() -> PremiumState {
        let mut premium = connected(PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            certificate: Some("not.checked.here".to_owned()),
            acknowledged_offline_until: Some(1_800_000_000),
            pending_unwatch: Vec::new(),
            ..PremiumState::default()
        });
        premium.consent("w1", 1_790_000_000);
        premium
    }

    /// Deleting the account is one request with the stored token, and
    /// the vault forgets the account only once the server said it did.
    #[tokio::test]
    async fn premium_delete_account_forgets_the_account_once_the_server_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

        // Not connected: nothing to delete, and nothing is asked.
        let (base_url, mut seen) = premium_answering(200, r#"{"deleted":true}"#).await;
        let error = manager.premium_delete_account(&base_url).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Premium(PremiumError::NoDevice)),
            "{error}"
        );
        assert!(seen.try_recv().is_err());

        store_premium(&manager, premium_account()).await;
        manager.premium_delete_account(&base_url).await.unwrap();
        let request = seen.recv().await.unwrap();
        assert!(
            request.starts_with("DELETE /v1/account HTTP/1.1"),
            "{request}"
        );
        assert!(request.contains(&format!("Bearer {TOKEN}")), "{request}");
        assert!(!request.contains("abcdefghijkmnpqr"), "{request}");
        assert_eq!(stored_premium(&manager).await, PremiumState::default());
        // Forgotten on disk as well.
        drop(manager);
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(stored_premium(&reopened).await, PremiumState::default());

        // The server did not confirm: the account stays.
        let refusing = tempfile::tempdir().unwrap();
        let kept = WalletManager::open(refusing.path(), key()).unwrap();
        store_premium(&kept, premium_account()).await;
        let (base_url, _) = premium_answering(503, r#"{"error":"node unreachable"}"#).await;
        assert!(kept.premium_delete_account(&base_url).await.is_err());
        assert_eq!(stored_premium(&kept).await, premium_account());
    }

    /// A disowned token is not a deleted account: the account may be
    /// there still, and only this device lost it. The token goes, the
    /// key and the rest stay. Any other refusal keeps everything.
    #[tokio::test]
    async fn premium_delete_account_keeps_the_account_the_server_did_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        store_premium(&manager, premium_account()).await;
        let (base_url, mut seen) = premium_answering(
            401,
            r#"{"error":"this device was disconnected from the Premium account","code":"device_disconnected"}"#,
        )
        .await;
        let error = manager.premium_delete_account(&base_url).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Premium(PremiumError::DeviceDisconnected)),
            "{error}"
        );
        let request = seen.recv().await.unwrap();
        assert!(
            request.starts_with("DELETE /v1/account HTTP/1.1"),
            "{request}"
        );
        let disowned = PremiumState {
            device: None,
            disconnected: true,
            ..premium_account()
        };
        assert_eq!(stored_premium(&manager).await, disowned);
        // On disk as well.
        drop(manager);
        let reopened = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(stored_premium(&reopened).await, disowned);

        // Words about a key the request never carried: kept whole.
        let refusing = tempfile::tempdir().unwrap();
        let kept = WalletManager::open(refusing.path(), key()).unwrap();
        store_premium(&kept, premium_account()).await;
        let (base_url, _) = premium_answering(401, r#"{"error":"unknown key"}"#).await;
        assert!(kept.premium_delete_account(&base_url).await.is_err());
        assert_eq!(stored_premium(&kept).await, premium_account());

        // Any other answer, a server without the route among them:
        // not gone, and kept.
        let (base_url, _) = premium_answering(404, r#"{"error":"no such route"}"#).await;
        let error = kept.premium_delete_account(&base_url).await.unwrap_err();
        assert!(
            matches!(error, CoreError::Premium(PremiumError::NotFound)),
            "{error}"
        );
        assert_eq!(stored_premium(&kept).await, premium_account());

        // A 401 without the server's envelope is a portal asking for a
        // login, not the server disowning the key: kept as well.
        let (base_url, _) = premium_answering(401, "<html>Sign in to continue</html>").await;
        let error = kept.premium_delete_account(&base_url).await.unwrap_err();
        assert!(
            matches!(&error, CoreError::Premium(PremiumError::UnexpectedResponse(words)) if words == "HTTP 401"),
            "{error}"
        );
        assert_eq!(stored_premium(&kept).await, premium_account());
    }

    #[tokio::test]
    async fn premium_confirm_channel_goes_through_the_stored_token() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        store_premium(&manager, premium_account()).await;
        let (base_url, mut seen) = premium_answering(
            200,
            r#"{"id":"4f8f5252-b152-4fae-b142-5e6f70819203","kind":"email","target":"a…@example.org","linked":true,"link_code":null,"link_url":null,"linked_name":null,"enabled":true,"created_at":1789000004}"#,
        )
        .await;
        let channel = manager
            .premium_confirm_channel(&base_url, "4f8f5252-b152-4fae-b142-5e6f70819203", "482913")
            .await
            .unwrap();
        assert!(channel.linked);
        let request = seen.recv().await.unwrap();
        assert!(
            request.starts_with(
                "POST /v1/channels/4f8f5252-b152-4fae-b142-5e6f70819203/confirm HTTP/1.1"
            ),
            "{request}"
        );
        assert!(request.contains(&format!("Bearer {TOKEN}")), "{request}");
        assert!(!request.contains("abcdefghijkmnpqr"), "{request}");
        assert!(request.ends_with(r#"{"code":"482913"}"#), "{request}");
    }
}
