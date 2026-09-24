//! The wallet manager: the single facade every consumer talks to.
//!
//! Desktop (Tauri commands), mobile (FFI bridge), and later the server
//! all drive this type. It owns the encrypted vault, keeps loaded BDK
//! engines in memory, and coordinates syncs so that network I/O never
//! blocks reads: requests are built under the lock, executed outside it,
//! and applied back under the lock.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use std::str::FromStr;

use bdk_wallet::bitcoin::{Address, Amount, TxOut};

use crate::backup::{
    self, BACKUP_VERSION, BackupBackendPreview, BackupBundle, BackupOptions, BackupPayload,
    BackupPreview, BackupWallet, BackupWalletPreview, ImportChoices, ImportReport,
};
use crate::broadcast::{
    self, BroadcastReport, BroadcastStatus, InputFacts, OutputFacts, TxPreview, WalletRef,
};
use crate::chain::tor::{self, TorRoute, TorSettings, TorStatus};
use crate::chain::{
    self, BackendConfig, CertificateReport, CertificateStatus, Endpoint, EngineRequest,
    EngineResponse,
};
use crate::error::PremiumError;
use crate::error::{CoreError, CoreResult};
use crate::export::{ExportOptions, ExportResult};
use crate::input::{ParsedInput, ParsedPayload, RecognizedKind};
use crate::lock::{self, AppLock, LockAttempts, LockKind, LockVerdict};
use crate::network::Network;
use crate::premium::{Channel, PremiumClient, PremiumState};
use crate::store::{Settings, Vault, VaultKey, VaultPayload, WalletRecord};
use crate::wallet::meta::{CachedTotals, SyncStamp, WalletIcon, WalletKind, WalletMeta};
use crate::wallet::policy::{self, PolicySnapshot};
use crate::wallet::snapshot::{
    AddressEntry, AddressList, SyncReport, TxDetail, UtxoInfo, WalletSnapshot,
};
use crate::wallet::views;
use crate::wallet::{AddressTx, AddressWatchState};

mod devices;

/// Vault file name inside the data directory.
const VAULT_FILE: &str = "gerfaut.vault";
/// The failed unlock attempts, beside the vault: a count and a time,
/// nothing secret, kept so a restart does not reset the delays.
const ATTEMPTS_FILE: &str = "gerfaut.attempts";

/// Outcome of syncing every wallet of a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAllReport {
    pub reports: Vec<SyncReport>,
    pub failures: Vec<SyncFailure>,
}

/// One wallet that failed to sync; the others are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFailure {
    pub wallet_id: String,
    pub message: String,
}

pub(crate) struct ManagerState {
    vault: Vault,
    pub(crate) payload: VaultPayload,
    /// Loaded BDK engines, keyed by wallet id. Lazily populated.
    engines: HashMap<String, bdk_wallet::Wallet>,
    /// Where the vault lives, and where the embedded Tor client keeps
    /// its state.
    pub(crate) data_dir: PathBuf,
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

/// The last sync of a wallet to finish, behind the lock a sync of that
/// wallet holds while it runs.
type SyncSlot = std::sync::Arc<Mutex<Option<(Instant, SyncReport)>>>;

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
                }),
                attempts: Mutex::new(attempts),
                live: std::sync::Mutex::new(None),
                watch_setups: std::sync::atomic::AtomicU64::new(0),
                syncing: std::sync::Mutex::new(HashMap::new()),
                premium_changes: Mutex::new(()),
                premium_connect_after: std::sync::Mutex::new(None),
                #[cfg(test)]
                premium_public_key: std::sync::Mutex::new(None),
            }),
        })
    }

    // --- settings ------------------------------------------------------

    /// The settings as the apps may see them: the lock's hash stays in
    /// the vault, the apps only need to know a lock exists and its kind,
    /// and the premium device token stays too, as in
    /// [`Self::premium_state`].
    pub async fn settings(&self) -> Settings {
        let mut settings = self.state.lock().await.payload.settings.clone();
        if let Some(lock) = &mut settings.app_lock {
            lock.secret = None;
        }
        settings.premium.redact();
        settings
    }

    pub async fn set_active_network(&self, network: Network) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            self.state.lock().await.commit(|payload| {
                payload.settings.active_network = network;
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Remembers the backend of a network. A custom address is stored
    /// in the form a scan reads it into, the host in lower case and an
    /// IPv6 literal in brackets, and refused with the reason when the
    /// parser the sync reads with cannot read it: stored as typed, an
    /// address that parser gives up on has no host to be an onion, and
    /// the sync would hand it to the resolver in the clear. One already
    /// in that form is stored byte for byte, and the certificate
    /// accepted for it stays keyed to it.
    pub async fn set_backend(&self, network: Network, config: BackendConfig) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            let config = config.canonical()?;
            self.state.lock().await.commit(|payload| {
                payload.settings.backends.insert(network, config);
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    // --- Electrum certificates ------------------------------------------

    /// What this server's certificate amounts to right now, and the
    /// fingerprint to show when the user has to decide. Reads only: the
    /// settings screen asks, the user answers.
    pub async fn inspect_certificate(&self, url: &str) -> CoreResult<CertificateReport> {
        let host = chain::electrum::certificate_key(url);
        let pin = self
            .state
            .lock()
            .await
            .payload
            .settings
            .electrum_certs
            .get(&host)
            .cloned();
        let status = match chain::inspect_certificate(url.to_owned(), pin.clone()).await {
            Ok(chain::electrum::Inspection::NotTls) => CertificateStatus::NotTls,
            Ok(chain::electrum::Inspection::Tor) => CertificateStatus::Tor,
            Ok(chain::electrum::Inspection::Tls(verdict)) => match verdict {
                chain::tls::Verdict::Trusted => CertificateStatus::Trusted,
                chain::tls::Verdict::Pinned => CertificateStatus::Pinned {
                    fingerprint: pin.unwrap_or_default(),
                },
                chain::tls::Verdict::Unknown {
                    fingerprint,
                    reason,
                    subject,
                    expires,
                } => CertificateStatus::Unknown {
                    fingerprint,
                    reason,
                    subject,
                    expires,
                },
                chain::tls::Verdict::Changed { stored, presented } => {
                    CertificateStatus::Changed { stored, presented }
                }
            },
            Err(detail) => CertificateStatus::Unreachable { detail },
        };
        Ok(CertificateReport { host, status })
    }

    /// Remembers the certificate the user accepted for this server.
    /// From then on that host must present exactly this certificate:
    /// anything else is refused, never accepted again in silence.
    pub async fn trust_certificate(&self, url: &str, fingerprint: &str) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            if !chain::tls::is_fingerprint(fingerprint) {
                return Err(CoreError::InvalidInput {
                    kind: "certificate fingerprint",
                    detail: "expected 32 hexadecimal bytes separated by colons".to_owned(),
                });
            }
            let host = chain::electrum::certificate_key(url);
            self.state.lock().await.commit(|payload| {
                payload
                    .settings
                    .electrum_certs
                    .insert(host, fingerprint.to_ascii_uppercase());
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Drops an accepted certificate: the next connection to that host
    /// asks again.
    pub async fn forget_certificate(&self, host: &str) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            self.state.lock().await.commit(|payload| {
                payload.settings.electrum_certs.remove(host);
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Sets the gap limit shared by every wallet. Takes effect on the
    /// next sync; a raised limit widens the scan, a lowered one only
    /// narrows future scans (revealed addresses stay watched).
    pub async fn set_gap_limit(&self, gap_limit: u32) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            if !(1..=500).contains(&gap_limit) {
                return Err(CoreError::InvalidInput {
                    kind: "gap limit",
                    detail: "must be between 1 and 500".to_owned(),
                });
            }
            self.state.lock().await.commit(|payload| {
                payload.settings.gap_limit = gap_limit;
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Stores one small app preference (theme, hidden balances, ...) in
    /// the encrypted vault.
    pub async fn set_app_pref(&self, key: String, value: String) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            payload.settings.app_prefs.insert(key, value);
            Ok(())
        })
    }

    // --- wallet lifecycle ---------------------------------------------

    /// Lists wallet metadata, optionally restricted to one network.
    pub async fn list_wallets(&self, network: Option<Network>) -> Vec<WalletMeta> {
        let state = self.state.lock().await;
        let gap_limit = state.payload.settings.gap_limit;
        state
            .payload
            .wallets
            .iter()
            .map(|record| {
                let mut meta = record.meta.clone();
                // Present the effective, global gap limit.
                meta.gap_limit = gap_limit;
                meta
            })
            .filter(|meta| network.is_none_or(|n| meta.network == n))
            .collect()
    }

    /// Adds a wallet from classified input, on an explicit network the
    /// user confirmed among the input's candidates.
    pub async fn add_wallet(
        &self,
        name: &str,
        parsed: &ParsedInput,
        network: Network,
    ) -> CoreResult<WalletMeta> {
        let result: CoreResult<WalletMeta> = async {
            if !parsed.networks.contains(&network) {
                return Err(CoreError::NetworkMismatch {
                    expected: network.to_string(),
                    found: parsed
                        .networks
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join("/"),
                });
            }
            let name = name.trim();
            if name.is_empty() {
                return Err(CoreError::InvalidInput {
                    kind: "wallet name",
                    detail: "a wallet needs a name".to_owned(),
                });
            }

            let kind = match &parsed.payload {
                ParsedPayload::Descriptors {
                    external,
                    internal,
                    script,
                } => WalletKind::Descriptors {
                    external: external.clone(),
                    internal: internal.clone(),
                    script: *script,
                },
                ParsedPayload::Address { address } => WalletKind::SingleAddress {
                    address: address.clone(),
                },
            };

            let mut state = self.state.lock().await;
            if let Some(existing) = find_watched(&state.payload, network, &kind) {
                return Err(CoreError::DuplicateWallet(existing.meta.name.clone()));
            }

            let meta = fresh_meta(
                name,
                network,
                kind,
                parsed.kind,
                state.payload.settings.gap_limit,
            );
            let (record, engine) = build_record(meta.clone())?;
            state.commit(|payload| {
                payload.wallets.push(record);
                Ok(())
            })?;
            if let Some(engine) = engine {
                state.engines.insert(meta.id.clone(), engine);
            }
            Ok(meta)
        }
        .await;
        self.live_refresh().await;
        result
    }

    pub async fn rename_wallet(&self, id: &str, name: &str) -> CoreResult<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::InvalidInput {
                kind: "wallet name",
                detail: "a wallet needs a name".to_owned(),
            });
        }
        self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.name = name.to_owned();
            Ok(())
        })
    }

    /// Changes the glyph a wallet shows next to its name.
    pub async fn set_wallet_icon(&self, id: &str, icon: WalletIcon) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.icon = icon;
            Ok(())
        })
    }

    /// Puts the named wallets in the given order. Only the slots those
    /// wallets occupy are rearranged: a list shown for one network can
    /// be reordered without moving the wallets of another. Every id must
    /// name a wallet, and none may repeat.
    pub async fn reorder_wallets(&self, ids: &[String]) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            let mut seen = std::collections::HashSet::with_capacity(ids.len());
            for id in ids {
                if !seen.insert(id.as_str()) {
                    return Err(CoreError::InvalidInput {
                        kind: "wallet order",
                        detail: format!("wallet {id} is listed twice"),
                    });
                }
                if !payload.wallets.iter().any(|record| &record.meta.id == id) {
                    return Err(CoreError::WalletNotFound(id.clone()));
                }
            }
            // Take the moving records out, keep every other record where
            // it stands, and pour the movers back into the freed slots in
            // the requested order.
            let slots: Vec<usize> = payload
                .wallets
                .iter()
                .enumerate()
                .filter(|(_, record)| seen.contains(record.meta.id.as_str()))
                .map(|(index, _)| index)
                .collect();
            let mut movers: Vec<Option<WalletRecord>> = Vec::with_capacity(ids.len());
            for id in ids {
                let position = payload
                    .wallets
                    .iter()
                    .position(|record| &record.meta.id == id)
                    .expect("checked above");
                movers.push(Some(payload.wallets[position].clone()));
            }
            for (slot, mover) in slots.into_iter().zip(movers.iter_mut()) {
                payload.wallets[slot] = mover.take().expect("one mover per slot");
            }
            Ok(())
        })
    }

    /// Removes a wallet from this device. One the user agreed to have
    /// watched by the premium server is queued to be unwatched there
    /// too, in the same write: the promise is that removing a wallet
    /// here removes it there, and the removal cannot wait for the
    /// network. [`Self::premium_flush_unwatch`] carries the message.
    pub async fn remove_wallet(&self, id: &str) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            let mut state = self.state.lock().await;
            state.commit(|payload| {
                let before = payload.wallets.len();
                payload.wallets.retain(|record| record.meta.id != id);
                if payload.wallets.len() == before {
                    return Err(CoreError::WalletNotFound(id.to_owned()));
                }
                payload.unclaimed.retain(|news| news.wallet_id != id);
                payload.announced.retain(|told| told.wallet_id != id);
                let premium = &mut payload.settings.premium;
                if premium.has_key() && premium.is_consented(id) {
                    premium.queue_unwatch(id);
                }
                Ok(())
            })?;
            state.engines.remove(id);
            Ok(())
        }
        .await;
        self.live_refresh().await;
        result
    }

    // --- views ---------------------------------------------------------

    pub async fn wallet_snapshot(&self, id: &str) -> CoreResult<WalletSnapshot> {
        let mut state = self.state.lock().await;
        let mut record = find_record(&state.payload, id)?.clone();
        // Present the effective, global gap limit.
        record.meta.gap_limit = state.payload.settings.gap_limit;
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                Ok(WalletSnapshot {
                    balance: views::balance(engine),
                    txs: views::tx_summaries(engine),
                    tip_height: views::tip_height(engine),
                    truncated: false,
                    meta: record.meta,
                })
            }
            WalletKind::SingleAddress { .. } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(WalletSnapshot {
                    balance: views::address_balance(&watch),
                    txs: views::address_tx_summaries(&watch),
                    tip_height: watch.tip_height,
                    truncated: watch.truncated,
                    meta: record.meta,
                })
            }
        }
    }

    pub async fn tx_detail(&self, id: &str, txid: &str) -> CoreResult<TxDetail> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let network = record.meta.network;
                let engine = ensure_engine(&mut state, id)?;
                views::tx_detail(engine, network, txid)
            }
            WalletKind::SingleAddress { .. } => {
                let watch = record.address_state.clone().unwrap_or_default();
                views::address_tx_detail(&watch, txid)
            }
        }
    }

    pub async fn utxos(&self, id: &str) -> CoreResult<Vec<UtxoInfo>> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let network = record.meta.network;
                let engine = ensure_engine(&mut state, id)?;
                Ok(views::utxos(engine, network))
            }
            WalletKind::SingleAddress { address } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(views::address_utxos(&watch, address))
            }
        }
    }

    /// The wallet's spending policy: its keys, its branches, and where
    /// every timelock stands against the tip and the coins. A watched
    /// address has no descriptor to read.
    pub async fn policy(&self, id: &str) -> CoreResult<PolicySnapshot> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        // Before the first sync the engine's tip is zero, which would
        // put every height lock the whole chain away: no tip is given
        // until one has been seen.
        let synced = record.meta.last_sync.is_some();
        match &record.meta.kind {
            WalletKind::Descriptors {
                external, script, ..
            } => {
                let engine = ensure_engine(&mut state, id)?;
                policy::analyze(policy::PolicyInput {
                    external_descriptor: external,
                    script: *script,
                    coins: views::coins(engine),
                    tip_height: synced.then(|| views::tip_height(engine)),
                    now_unix: now_secs(),
                })
            }
            WalletKind::SingleAddress { address } => {
                let watch = record.address_state.clone().unwrap_or_default();
                Ok(policy::address_snapshot(
                    address,
                    synced.then_some(watch.tip_height),
                    watch.utxos.len() as u32,
                    now_secs(),
                ))
            }
        }
    }

    /// The next unused receive address plus `lookahead` upcoming ones.
    ///
    /// Single-address wallets return their one address.
    pub async fn receive_addresses(
        &self,
        id: &str,
        lookahead: u32,
    ) -> CoreResult<Vec<AddressEntry>> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                let entries = views::receive_addresses(engine, lookahead);
                // Revealing may stage a change set; persist it.
                let staged = engine.take_staged();
                if let Some(staged) = staged {
                    merge_changeset(&mut state, id, staged)?;
                    let state = &mut *state;
                    state.vault.save(&state.payload)?;
                }
                Ok(entries)
            }
            WalletKind::SingleAddress { address } => Ok(vec![AddressEntry {
                index: 0,
                address: address.clone(),
                used: record
                    .address_state
                    .as_ref()
                    .is_some_and(|s| !s.txs.is_empty()),
                derivation: None,
            }]),
        }
    }

    /// Revealed addresses of a wallet, by keychain, with usage and the
    /// balance on each. Capped: an audit view, not an infinite scroll.
    pub async fn address_list(&self, id: &str) -> CoreResult<AddressList> {
        let mut state = self.state.lock().await;
        let record = find_record(&state.payload, id)?.clone();
        match &record.meta.kind {
            WalletKind::Descriptors { .. } => {
                let engine = ensure_engine(&mut state, id)?;
                let list = views::address_list(engine);
                // Revealing may stage a change set; persist it.
                let staged = engine.take_staged();
                if let Some(staged) = staged {
                    merge_changeset(&mut state, id, staged)?;
                    let state = &mut *state;
                    state.vault.save(&state.payload)?;
                }
                Ok(list)
            }
            WalletKind::SingleAddress { address } => {
                let (used, balance_sats) = record
                    .address_state
                    .as_ref()
                    .map(|s| {
                        (
                            !s.txs.is_empty(),
                            s.utxos.iter().map(|u| u.value_sats).sum(),
                        )
                    })
                    .unwrap_or((false, 0));
                Ok(AddressList {
                    external: vec![crate::wallet::snapshot::AddressRow {
                        index: 0,
                        address: address.clone(),
                        used,
                        balance_sats,
                    }],
                    internal: Vec::new(),
                    truncated: false,
                })
            }
        }
    }

    /// Builds a CSV export of one wallet's transactions: exactly the
    /// rows the screens show, filtered. Everything stays local.
    pub async fn export_transactions(
        &self,
        id: &str,
        options: &ExportOptions,
    ) -> CoreResult<ExportResult> {
        let snapshot = self.wallet_snapshot(id).await?;
        Ok(crate::export::transactions_csv(&snapshot.txs, options))
    }

    // --- sync ----------------------------------------------------------

    /// Syncs one wallet against its network's backend. Public backends
    /// are tried in order until one answers.
    pub async fn sync_wallet(&self, id: &str) -> CoreResult<SyncReport> {
        self.sync_wallet_with(id, false).await
    }

    /// Scans a wallet again from its first address with the current gap
    /// limit, whatever it already knows: an incremental sync only
    /// watches the addresses it revealed, so funds that landed past
    /// them, or a descriptor also used elsewhere, are only found by
    /// starting over. A watched address has no gap: this is a sync.
    pub async fn rescan_wallet(&self, id: &str) -> CoreResult<SyncReport> {
        self.sync_wallet_with(id, true).await
    }

    /// One sync of a wallet at a time, whoever asks: the app, a
    /// background job, the live watch. A caller that arrives while one
    /// runs waits for it, and takes its result instead of asking the
    /// backend the same question again, with nothing listed as new:
    /// the lists went to the caller that ran it. What that sync found
    /// worth announcing is in the vault for whoever claims it
    /// ([`Self::claim_announcements`]), so neither caller can lose it.
    async fn sync_wallet_with(&self, id: &str, from_scratch: bool) -> CoreResult<SyncReport> {
        let arrived = Instant::now();
        let slot = match self.syncing.lock() {
            Ok(mut slots) => slots.entry(id.to_owned()).or_default().clone(),
            Err(_) => SyncSlot::default(),
        };
        let mut last = slot.lock().await;
        if !from_scratch
            && let Some((finished, report)) = last.as_ref()
            && *finished > arrived
        {
            return Ok(SyncReport {
                new_tx_count: 0,
                new_txs: Vec::new(),
                confirmed_txs: Vec::new(),
                ..report.clone()
            });
        }
        let report = self.sync_wallet_alone(id, from_scratch).await?;
        *last = Some((Instant::now(), report.clone()));
        drop(last);
        // The scripts this sync revealed, and whether something is
        // still waiting for a block.
        self.live_refresh().await;
        Ok(report)
    }

    async fn sync_wallet_alone(&self, id: &str, from_scratch: bool) -> CoreResult<SyncReport> {
        let started = Instant::now();

        // Snapshot what the sync needs; do not hold the lock during I/O.
        let (meta, config, certs) = {
            let state = self.state.lock().await;
            let record = find_record(&state.payload, id)?;
            let mut meta = record.meta.clone();
            // The effective gap limit is the global setting.
            meta.gap_limit = state.payload.settings.gap_limit;
            let (config, certs) = state.chain_setup(record.meta.network);
            (meta, config, certs)
        };
        let mut endpoints = chain::endpoints(&config, meta.network, &certs)?;
        // Try the backend that answered last time first: on networks
        // where one public instance is blocked, this skips a dead
        // 20-second timeout on every sync.
        if let Some(stamp) = &meta.last_sync
            && let Some(position) = endpoints
                .iter()
                .position(|endpoint| endpoint.label() == stamp.backend)
            && position > 0
        {
            let preferred = endpoints.remove(position);
            endpoints.insert(0, preferred);
        }
        let proxy = self.tor_proxy_for(&endpoints).await?;

        match &meta.kind {
            WalletKind::Descriptors { .. } => {
                self.sync_descriptor_wallet(
                    &meta,
                    &endpoints,
                    proxy.as_deref(),
                    started,
                    from_scratch,
                )
                .await
            }
            WalletKind::SingleAddress { address } => {
                self.sync_address_wallet(&meta, address, &endpoints, proxy.as_deref(), started)
                    .await
            }
        }
    }

    async fn sync_descriptor_wallet(
        &self,
        meta: &WalletMeta,
        endpoints: &[Endpoint],
        proxy: Option<&str>,
        started: Instant,
        from_scratch: bool,
    ) -> CoreResult<SyncReport> {
        // First sync, a gap limit raised since the last full scan, or a
        // rescan asked for: only a full scan looks past the addresses
        // already revealed.
        let full = from_scratch || meta.last_sync.is_none() || meta.scan_gap < meta.gap_limit;
        let mut attempts: Vec<String> = Vec::new();

        for endpoint in endpoints {
            // Build a fresh request under the lock (requests are consumed
            // by each attempt).
            let (request, known) = {
                let mut state = self.state.lock().await;
                let engine = ensure_engine(&mut state, &meta.id)?;
                let request = if full {
                    EngineRequest::Full(engine.start_full_scan().build())
                } else {
                    EngineRequest::Incremental(
                        engine.start_sync_with_revealed_spks().build(),
                        views::receive_tail(engine),
                    )
                };
                (request, views::known(engine))
            };

            match chain::sync_engine(endpoint, request, meta.gap_limit, proxy).await {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(response) => {
                    let mut state = self.state.lock().await;
                    let engine = ensure_engine(&mut state, &meta.id)?;
                    let apply = match response {
                        EngineResponse::Full(update) => engine.apply_update(update),
                        EngineResponse::Incremental(update, tail) => engine
                            .apply_update(update)
                            .and_then(|()| engine.apply_update(tail)),
                    };
                    apply.map_err(|e| CoreError::Sync {
                        backend: endpoint.label(),
                        detail: e.to_string(),
                    })?;

                    let balance = views::balance(engine);
                    let tip_height = views::tip_height(engine);
                    let tx_count_after = engine.transactions().count() as u32;
                    let moves = views::moves(engine, &known);
                    let (new_txs, confirmed_txs) = moves.lines();
                    let staged = engine.take_staged();

                    if let Some(staged) = staged {
                        merge_changeset(&mut state, &meta.id, staged)?;
                    }
                    crate::live::news::record(
                        &mut state.payload,
                        &meta.id,
                        meta.last_sync.is_none(),
                        &moves,
                        now_secs(),
                    );
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
                        confirmed_txs,
                        balance,
                        tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    let scanned = full.then_some(meta.gap_limit);
                    finish_sync(&mut state, &meta.id, &report, tx_count_after, scanned)?;
                    return Ok(report);
                }
            }
        }

        Err(sync_failure(endpoints, attempts))
    }

    async fn sync_address_wallet(
        &self,
        meta: &WalletMeta,
        address: &str,
        endpoints: &[Endpoint],
        proxy: Option<&str>,
        started: Instant,
    ) -> CoreResult<SyncReport> {
        let mut attempts: Vec<String> = Vec::new();
        for endpoint in endpoints {
            match chain::fetch_address_state(endpoint, address, meta.network, proxy).await {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(mut watch) => {
                    let mut state = self.state.lock().await;
                    // Against the state as stored, before the older
                    // rounds are carried over into the fresh one.
                    let moves = views::address_moves(
                        find_record(&state.payload, &meta.id)?
                            .address_state
                            .as_ref(),
                        &watch,
                    );
                    let (new_txs, confirmed_txs) = moves.lines();
                    // A sync fetches the newest round only. Keep the older
                    // rounds the user already loaded, otherwise every sync
                    // would silently undo "load older transactions".
                    if let Some(previous) = find_record(&state.payload, &meta.id)?
                        .address_state
                        .as_ref()
                    {
                        keep_older_history(&mut watch, previous);
                    }
                    let tx_count_after = watch.txs.len() as u32;
                    crate::live::news::record(
                        &mut state.payload,
                        &meta.id,
                        meta.last_sync.is_none(),
                        &moves,
                        now_secs(),
                    );
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
                        confirmed_txs,
                        balance: views::address_balance(&watch),
                        tip_height: watch.tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    find_record_mut(&mut state.payload, &meta.id)?.address_state = Some(watch);
                    finish_sync(&mut state, &meta.id, &report, tx_count_after, None)?;
                    return Ok(report);
                }
            }
        }
        Err(sync_failure(endpoints, attempts))
    }

    /// Fetches an older round of history for a watched address and
    /// appends it to the stored list. The balance and the UTXO set
    /// already cover the whole chain, so only the list grows.
    ///
    /// Returns how many transactions were added. Zero means the history
    /// is exhausted.
    pub async fn load_more_history(&self, id: &str) -> CoreResult<u32> {
        let (meta, config, certs, cursor) = {
            let state = self.state.lock().await;
            let record = find_record(&state.payload, id)?;
            let cursor = record
                .address_state
                .as_ref()
                .and_then(|watch| watch.history_cursor.clone());
            let (config, certs) = state.chain_setup(record.meta.network);
            (record.meta.clone(), config, certs, cursor)
        };
        let WalletKind::SingleAddress { address } = &meta.kind else {
            return Err(CoreError::InvalidInput {
                kind: "wallet_kind",
                detail: "descriptor wallets already carry their full history".to_owned(),
            });
        };
        let Some(cursor) = cursor else {
            return Ok(0);
        };
        let endpoints = chain::endpoints(&config, meta.network, &certs)?;
        let proxy = self.tor_proxy_for(&endpoints).await?;

        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::fetch_address_history(
                endpoint,
                address,
                meta.network,
                &cursor,
                proxy.as_deref(),
            )
            .await
            {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(round) => {
                    let mut state = self.state.lock().await;
                    let record = find_record_mut(&mut state.payload, id)?;
                    let Some(watch) = record.address_state.as_mut() else {
                        return Ok(0);
                    };
                    let known: std::collections::HashSet<String> =
                        watch.txs.iter().map(|tx| tx.txid.clone()).collect();
                    let fresh: Vec<_> = round
                        .txs
                        .into_iter()
                        .filter(|tx| !known.contains(&tx.txid))
                        .collect();
                    let added = fresh.len() as u32;
                    watch.txs.extend(fresh);
                    watch.history_cursor = round.cursor;
                    watch.truncated = watch.history_cursor.is_some();
                    let tx_count = watch.txs.len() as u32;
                    record.meta.cached.tx_count = tx_count;
                    state.vault.save(&state.payload)?;
                    return Ok(added);
                }
            }
        }
        Err(sync_failure(&endpoints, attempts))
    }

    // --- broadcast -------------------------------------------------------

    /// Decodes a transaction and shows what it does, before anything
    /// leaves the machine. What the container does not carry (previous
    /// outputs, ownership) is taken from the watched wallets first and
    /// from the backend second; a backend that does not answer costs a
    /// less complete preview, never an error.
    pub async fn preview_transaction(
        &self,
        input: &str,
        network: Network,
    ) -> CoreResult<TxPreview> {
        let decoded = broadcast::decode_transaction(input)?;
        let outpoints = broadcast::outpoints(&decoded);

        // Everything the vault knows, under the lock.
        let (config, certs, mut input_facts, output_facts, tip_height) = {
            let mut state = self.state.lock().await;
            let (config, certs) = state.chain_setup(network);
            let ids: Vec<(String, String, WalletKind)> = state
                .payload
                .wallets
                .iter()
                .filter(|record| record.meta.network == network)
                .map(|record| {
                    (
                        record.meta.id.clone(),
                        record.meta.name.clone(),
                        record.meta.kind.clone(),
                    )
                })
                .collect();
            let mut input_facts: Vec<InputFacts> =
                outpoints.iter().map(|_| InputFacts::default()).collect();
            let mut output_facts: Vec<OutputFacts> = decoded
                .tx
                .output
                .iter()
                .map(|_| OutputFacts::default())
                .collect();
            let mut tip_height: Option<u32> = None;
            for (id, name, kind) in ids {
                let wallet_ref = WalletRef {
                    id: id.clone(),
                    name,
                };
                match kind {
                    WalletKind::Descriptors { .. } => {
                        let engine = ensure_engine(&mut state, &id)?;
                        tip_height = tip_height.max(Some(views::tip_height(engine)));
                        for (i, outpoint) in outpoints.iter().enumerate() {
                            if let Some(utxo) = engine.get_utxo(*outpoint) {
                                input_facts[i].prevout = Some(utxo.txout.clone());
                                input_facts[i].wallet = Some(wallet_ref.clone());
                                input_facts[i].spent = Some(false);
                            } else if let Some(tx) = engine.get_tx(outpoint.txid)
                                && let Some(txout) = tx.tx_node.output.get(outpoint.vout as usize)
                                && engine.is_mine(txout.script_pubkey.clone())
                            {
                                // A coin of this wallet, no longer unspent.
                                input_facts[i].prevout = Some(txout.clone());
                                input_facts[i].wallet = Some(wallet_ref.clone());
                                input_facts[i].spent = Some(true);
                            }
                        }
                        for (i, output) in decoded.tx.output.iter().enumerate() {
                            if engine.is_mine(output.script_pubkey.clone()) {
                                output_facts[i].wallet = Some(wallet_ref.clone());
                                output_facts[i].change = engine
                                    .derivation_of_spk(output.script_pubkey.clone())
                                    .is_some_and(|(keychain, _)| {
                                        keychain == bdk_wallet::KeychainKind::Internal
                                    });
                            }
                        }
                    }
                    WalletKind::SingleAddress { address } => {
                        let script = Address::from_str(&address)
                            .ok()
                            .and_then(|a| a.require_network(network.to_bitcoin()).ok())
                            .map(|a| a.script_pubkey());
                        let Some(script) = script else {
                            continue;
                        };
                        let watch = find_record(&state.payload, &id)?
                            .address_state
                            .clone()
                            .unwrap_or_default();
                        for (i, outpoint) in outpoints.iter().enumerate() {
                            if let Some(utxo) = watch.utxos.iter().find(|u| {
                                u.txid == outpoint.txid.to_string() && u.vout == outpoint.vout
                            }) {
                                input_facts[i].prevout = Some(TxOut {
                                    value: Amount::from_sat(utxo.value_sats),
                                    script_pubkey: script.clone(),
                                });
                                input_facts[i].wallet = Some(wallet_ref.clone());
                                input_facts[i].spent = Some(false);
                            }
                        }
                        for (i, output) in decoded.tx.output.iter().enumerate() {
                            if output.script_pubkey == script {
                                output_facts[i].wallet = Some(wallet_ref.clone());
                            }
                        }
                    }
                }
            }
            (config, certs, input_facts, output_facts, tip_height)
        };

        // What only the chain knows, outside the lock: the coins the
        // vault does not hold, and whether known coins are still
        // unspent. One endpoint, the first that answers. A coin the
        // PSBT describes is asked about all the same: its word is its
        // author's, and the preview confronts it with the chain's.
        let needs_chain = input_facts
            .iter()
            .any(|f| f.prevout.is_none() || f.spent.is_none());
        // No backend for this network, or a Tor route that cannot be
        // opened, is no answer at all: the coins stay unchecked below,
        // the same as when every endpoint stopped answering. Without
        // this the PSBT's word went through unconfronted and unmarked.
        let route = if needs_chain {
            match chain::endpoints(&config, network, &certs) {
                Ok(endpoints) => match self.tor_proxy_for(&endpoints).await {
                    Ok(proxy) => Some((endpoints, proxy)),
                    Err(_) => None,
                },
                Err(_) => None,
            }
        } else {
            None
        };
        if let Some((endpoints, proxy)) = route {
            // A coin is settled once an endpoint has spoken for it:
            // either it handed the output over, or it said it has no
            // such outpoint. Anything else is still an open question,
            // and an open question goes to the next endpoint.
            let settled =
                |f: &broadcast::InputFacts| (f.prevout.is_some() && f.spent.is_some()) || f.unknown;
            for endpoint in &endpoints {
                for (i, facts) in input_facts.iter_mut().enumerate() {
                    if settled(facts) {
                        continue;
                    }
                    match chain::fetch_prevout(endpoint, outpoints[i], proxy.as_deref()).await {
                        Ok(chain_facts) => {
                            if facts.prevout.is_none() {
                                match chain_facts.txout {
                                    Some(txout) => facts.prevout = Some(txout),
                                    None => facts.unknown = true,
                                }
                            }
                            if facts.spent.is_none() {
                                facts.spent = chain_facts.spent;
                            }
                        }
                        // This one has stopped answering — throttled,
                        // timed out, cut off. Asking it about the coins
                        // it has not been asked about yet would only
                        // make that worse, so they go to the next
                        // endpoint instead of being dropped.
                        Err(_) => break,
                    }
                }
                if input_facts.iter().all(settled) {
                    break;
                }
            }
        }
        // A coin no endpoint spoke for is not a confirmed coin. The
        // preview still has the PSBT's word for it and still shows a
        // fee, but it says which coin nobody stood behind: without
        // this, a backend that stopped answering, or no backend at all,
        // was indistinguishable from one that agreed.
        if needs_chain {
            for facts in input_facts.iter_mut() {
                if facts.prevout.is_none() && !facts.unknown {
                    facts.unchecked = true;
                }
            }
        }

        Ok(broadcast::build_preview(
            &decoded,
            network,
            &input_facts,
            &output_facts,
            tip_height,
            now_secs(),
        ))
    }

    /// Hands a signed transaction to the network through the backend
    /// configured for it. Every endpoint is tried in turn; the node's
    /// own refusal (a missing signature, a spent input, a fee below the
    /// floor) is returned verbatim.
    pub async fn broadcast_transaction(
        &self,
        network: Network,
        hex: &str,
    ) -> CoreResult<BroadcastReport> {
        let decoded = broadcast::decode_transaction(hex)?;
        if !decoded.ready {
            return Err(CoreError::InvalidInput {
                kind: "transaction",
                detail: "the transaction is not fully signed".to_owned(),
            });
        }
        let (config, certs) = self.state.lock().await.chain_setup(network);
        let endpoints = chain::endpoints(&config, network, &certs)?;
        let proxy = self.tor_proxy_for(&endpoints).await?;
        let mut refusals: Vec<(String, String)> = Vec::new();
        for endpoint in &endpoints {
            match chain::broadcast(endpoint, &decoded.tx, proxy.as_deref()).await {
                Ok(()) => {
                    return Ok(BroadcastReport {
                        txid: decoded.tx.compute_txid().to_string(),
                        backend: endpoint.label(),
                        at: now_secs(),
                    });
                }
                Err(detail) => refusals.push((endpoint.label(), detail)),
            }
        }
        Err(broadcast_failure(refusals))
    }

    /// Where a broadcast transaction stands now. `hex` is the transaction
    /// itself: Electrum can only look a transaction up through one of
    /// its scripts, and the apps already hold the bytes.
    pub async fn transaction_status(
        &self,
        network: Network,
        hex: &str,
    ) -> CoreResult<BroadcastStatus> {
        let decoded = broadcast::decode_transaction(hex)?;
        let txid = decoded.tx.compute_txid();
        let script = decoded
            .tx
            .output
            .first()
            .map(|o| o.script_pubkey.clone())
            .ok_or_else(|| CoreError::InvalidInput {
                kind: "transaction",
                detail: "the transaction creates nothing".to_owned(),
            })?;
        let (config, certs) = self.state.lock().await.chain_setup(network);
        let endpoints = chain::endpoints(&config, network, &certs)?;
        let proxy = self.tor_proxy_for(&endpoints).await?;
        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::tx_standing(endpoint, txid, script.clone(), proxy.as_deref()).await {
                Ok(standing) => {
                    let confirmations = standing
                        .block_height
                        .map(|height| standing.tip_height.saturating_sub(height) + 1)
                        .unwrap_or(0);
                    return Ok(BroadcastStatus {
                        txid: txid.to_string(),
                        found: standing.found,
                        confirmed: standing.block_height.is_some(),
                        block_height: standing.block_height,
                        confirmations,
                        backend: endpoint.label(),
                        at: now_secs(),
                    });
                }
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
            }
        }
        Err(sync_failure(&endpoints, attempts))
    }

    /// Syncs every wallet of a network (or all of them), sequentially:
    /// public backends are shared infrastructure, not something to
    /// hammer in parallel. One failure does not stop the others.
    pub async fn sync_all(&self, network: Option<Network>) -> SyncAllReport {
        let metas = self.list_wallets(network).await;
        let mut report = SyncAllReport {
            reports: Vec::new(),
            failures: Vec::new(),
        };
        for meta in metas {
            match self.sync_wallet(&meta.id).await {
                Ok(sync) => report.reports.push(sync),
                Err(error) => report.failures.push(SyncFailure {
                    wallet_id: meta.id,
                    message: error.to_string(),
                }),
            }
        }
        report
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
    /// held meanwhile: an unlock never waits on a sync.
    async fn check_secret(&self, existing: &AppLock, secret: &str) -> LockVerdict {
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        let wait = attempts.retry_after(now);
        if wait > 0 {
            return LockVerdict {
                unlocked: false,
                failures: attempts.failures(),
                retry_after_secs: wait,
            };
        }
        match &existing.secret {
            Some(stored) if lock::verify_secret(secret, stored) => attempts.succeed(),
            _ => attempts.fail(now),
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

    // --- tor -----------------------------------------------------------

    /// Where Tor stands: the mode, the proxy in effect, and how far the
    /// embedded client got. Reads only; nothing is probed or started.
    pub async fn tor_status(&self) -> TorStatus {
        let settings = self.state.lock().await.payload.settings.tor.clone();
        tor::status(&settings).await
    }

    /// Persists how `.onion` hosts are reached. A proxy address is
    /// `host:port`, checked here so a typo fails at the settings screen
    /// and not at the next sync; blank means the default.
    pub async fn set_tor_settings(&self, settings: TorSettings) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            let socks_proxy = settings
                .socks_proxy
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(tor::parse_socks_address)
                .transpose()?;
            self.state.lock().await.commit(|payload| {
                payload.settings.tor = TorSettings {
                    mode: settings.mode,
                    socks_proxy,
                };
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Reaches Tor now, the way the settings say, so a settings screen
    /// can show the outcome before any wallet needs it. With the
    /// embedded client this is its bootstrap: up to about 90 seconds on
    /// a first run, a few on later ones. A mode that leads to a system
    /// proxy costs one probe.
    pub async fn tor_connect(&self) -> CoreResult<TorRoute> {
        let (settings, data_dir) = self.tor_setup().await;
        tor::resolve(&settings, &data_dir).await
    }

    /// The proxy to hand the chain layer for these endpoints: a Tor
    /// route when at least one host is an onion, nothing otherwise. A
    /// clearnet-only list never probes for Tor, let alone starts it.
    /// The lock is released before resolving: a first bootstrap takes
    /// a while, and reads must not wait on it.
    async fn tor_proxy_for(&self, endpoints: &[Endpoint]) -> CoreResult<Option<String>> {
        if !chain::needs_tor(endpoints) {
            return Ok(None);
        }
        let (settings, data_dir) = self.tor_setup().await;
        let route = tor::resolve(&settings, &data_dir).await?;
        Ok(Some(route.proxy()))
    }

    /// What resolving a route needs from the state, copied out.
    async fn tor_setup(&self) -> (TorSettings, PathBuf) {
        let state = self.state.lock().await;
        (state.payload.settings.tor.clone(), state.data_dir.clone())
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
    /// read it, change what they need, and hand it back. Three things
    /// are theirs to write: the consents, the removals queued for the
    /// server, and the dismissed banner. Whatever the copy says of the
    /// rest is ignored. The key, the certificate, this device's
    /// connection, whether the server disowned it, and what was sent
    /// and not answered move only with the server's answer, through
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
    pub async fn set_premium_state(&self, premium: PremiumState) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
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
        let proxy = if chain::is_onion(base_url) || self.backend_needs_tor().await {
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
    pub async fn premium_flush_unwatch(&self, base_url: &str) -> CoreResult<usize> {
        let pending = {
            let state = self.state.lock().await;
            let premium = &state.payload.settings.premium;
            if !premium.has_key() || !premium.has_device() {
                return Ok(premium.pending_unwatch.len());
            }
            premium.pending_unwatch.clone()
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let client = self.premium_client(base_url).await?;
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
            for id in &told {
                premium.unwatched(id);
            }
            Ok(premium.pending_unwatch.len())
        })?;
        match failure {
            Some(e) => Err(e),
            None => Ok(left),
        }
    }

    /// Whether this user reaches a backend through Tor: the active
    /// network's, or the one configured for any other network. It
    /// decides the route of what is not a sync and must not give away
    /// more than one, the update check first: someone who set an onion
    /// backend anywhere is not someone whose address GitHub should see.
    /// For the apps, the reason a check is paused while Tor is down.
    pub async fn uses_tor(&self) -> bool {
        if self.backend_needs_tor().await {
            return true;
        }
        let state = self.state.lock().await;
        let settings = &state.payload.settings;
        settings.backends.iter().any(|(network, config)| {
            match chain::endpoints(config, *network, &settings.electrum_certs) {
                Ok(endpoints) => chain::needs_tor(&endpoints),
                // An address kept from before addresses were checked,
                // which no sync will connect to: if it so much as names
                // an onion, its owner meant Tor.
                Err(_) => match config {
                    BackendConfig::CustomEsplora { url }
                    | BackendConfig::CustomElectrum { url } => {
                        url.to_ascii_lowercase().contains(".onion")
                    }
                    BackendConfig::Public { .. } => false,
                },
            }
        })
    }

    /// Asks GitHub for the latest release of `owner/repo` and compares
    /// it with the running version: for the button, and for the check
    /// the apps run on their own once a day. It takes the route the
    /// syncs take. When [`Self::uses_tor`] says so it goes through the
    /// Tor proxy a sync would resolve, and when that proxy cannot be
    /// had it fails with [`CoreError::Tor`] before any request exists:
    /// never a request in the clear. Anything else that goes wrong is
    /// "could not check".
    pub async fn check_update(
        &self,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<crate::updates::UpdateCheck> {
        self.check_update_at(crate::updates::GITHUB_API, repo, current_version)
            .await
    }

    pub(crate) async fn check_update_at(
        &self,
        api: &str,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<crate::updates::UpdateCheck> {
        let proxy = if self.uses_tor().await {
            let (settings, data_dir) = self.tor_setup().await;
            Some(tor::resolve(&settings, &data_dir).await?.proxy())
        } else {
            None
        };
        crate::updates::check_update(api, repo, current_version, proxy.as_deref()).await
    }

    /// Whether the backend of the active network is reached through
    /// Tor: the same question a sync asks, over the same endpoints.
    async fn backend_needs_tor(&self) -> bool {
        let (config, certs, network) = {
            let state = self.state.lock().await;
            let network = state.payload.settings.active_network;
            let (config, certs) = state.chain_setup(network);
            (config, certs, network)
        };
        chain::endpoints(&config, network, &certs)
            .is_ok_and(|endpoints| chain::needs_tor(&endpoints))
    }
}

// --- helpers -----------------------------------------------------------

/// Every node said the same thing: say it once, with the first host.
/// Different answers are listed, each with its host.
fn broadcast_failure(refusals: Vec<(String, String)>) -> CoreError {
    let Some((first_host, first_detail)) = refusals.first().cloned() else {
        return CoreError::Broadcast {
            backend: "backend".to_owned(),
            detail: "no backend available".to_owned(),
        };
    };
    if refusals.iter().all(|(_, detail)| *detail == first_detail) {
        return CoreError::Broadcast {
            backend: first_host,
            detail: first_detail,
        };
    }
    CoreError::Broadcast {
        backend: refusals
            .iter()
            .map(|(host, _)| host.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        detail: refusals
            .iter()
            .map(|(host, detail)| format!("{host}: {detail}"))
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// One error covering every endpoint tried, so the user sees each
/// backend's outcome instead of only the last one.
fn sync_failure(endpoints: &[Endpoint], attempts: Vec<String>) -> CoreError {
    CoreError::Sync {
        backend: config_label(endpoints),
        detail: if attempts.is_empty() {
            "no backend available".to_owned()
        } else {
            attempts.join("; ")
        },
    }
}

fn config_label(endpoints: &[Endpoint]) -> String {
    endpoints
        .first()
        .map(|e| e.label())
        .unwrap_or_else(|| "backend".to_owned())
}

/// Carries the deep history of `previous` over to a freshly synced
/// `watch`, which only holds the newest round.
///
/// Only transactions confirmed strictly below the fresh round's oldest
/// block are kept: that part of the chain is settled, while anything
/// inside the fresh window is authoritative in `watch` (a replacement or
/// a reorg must not be resurrected).
fn keep_older_history(watch: &mut AddressWatchState, previous: &AddressWatchState) {
    let Some(oldest_fresh) = watch.txs.iter().filter_map(|tx| tx.height).min() else {
        return;
    };
    let known: std::collections::HashSet<&str> =
        watch.txs.iter().map(|tx| tx.txid.as_str()).collect();
    let older: Vec<AddressTx> = previous
        .txs
        .iter()
        .filter(|tx| tx.height.is_some_and(|height| height < oldest_fresh))
        .filter(|tx| !known.contains(tx.txid.as_str()))
        .cloned()
        .collect();
    if older.is_empty() {
        return;
    }
    watch.txs.extend(older);
    // The deeper cursor wins: the list now reaches at least that far.
    watch.history_cursor = previous.history_cursor.clone();
    watch.truncated = watch.history_cursor.is_some();
}

/// One wallet as the live watch takes it: its scripts in the order a
/// transport should cover them, and whether it waits for a block.
/// `None` for a wallet that cannot be read, which is then not watched.
pub(crate) fn watched_wallet(
    state: &mut ManagerState,
    id: &str,
    gap_limit: u32,
) -> Option<crate::watch::WatchedWallet> {
    let record = find_record(&state.payload, id).ok()?;
    let (scripts, has_pending) = match &record.meta.kind {
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
            let scripts = vec![crate::watch::WatchedScript {
                script: script.to_hex_string(),
                lookahead: false,
            }];
            (scripts, has_pending)
        }
        WalletKind::Descriptors { .. } => {
            let engine = ensure_engine(state, id).ok()?;
            (
                views::watch_scripts(engine, gap_limit),
                views::has_pending(engine),
            )
        }
    };
    Some(crate::watch::WatchedWallet {
        wallet_id: id.to_owned(),
        scripts,
        has_pending,
    })
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
    let params = match internal {
        Some(internal) => bdk_wallet::Wallet::create(external.to_owned(), internal.to_owned()),
        None => bdk_wallet::Wallet::create_single(external.to_owned()),
    };
    params
        .network(network.to_bitcoin())
        .create_wallet_no_persist()
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
        cached: CachedTotals::default(),
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

/// Updates cached totals and the sync stamp, then persists the vault.
///
/// `tx_count` is the absolute engine count after the sync, never an
/// accumulated delta: replacements, evictions, and interleaved syncs
/// must not make the cached figure drift. `scanned_gap` is the gap limit
/// a full scan just covered, `None` after an incremental sync.
fn finish_sync(
    state: &mut ManagerState,
    id: &str,
    report: &SyncReport,
    tx_count: u32,
    scanned_gap: Option<u32>,
) -> CoreResult<()> {
    {
        let record = find_record_mut(&mut state.payload, id)?;
        record.meta.cached = CachedTotals {
            balance: report.balance,
            tx_count,
        };
        if let Some(gap) = scanned_gap {
            record.meta.scan_gap = gap;
        }
        record.meta.last_sync = Some(SyncStamp {
            at: now_secs(),
            tip_height: report.tip_height,
            backend: report.backend.clone(),
        });
    }
    state.vault.save(&state.payload)?;
    Ok(())
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
    use super::*;
    use crate::chain::tor::TorMode;
    use crate::input::parse_input;

    const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";

    fn key() -> VaultKey {
        VaultKey::Raw([9u8; 32])
    }

    async fn manager(dir: &std::path::Path) -> WalletManager {
        WalletManager::open(dir, key()).unwrap()
    }

    /// The token of the device the premium tests speak for.
    pub(crate) const TOKEN: &str = "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA";

    /// `premium` on a device the key connected.
    pub(crate) fn connected(premium: PremiumState) -> PremiumState {
        PremiumState {
            device: Some(crate::premium::DeviceCredential::new(
                "0f3b7c2e-1a2b-4c3d-8e9f-a0b1c2d3e4f5".to_owned(),
                TOKEN.to_owned(),
                1_790_000_000,
            )),
            ..premium
        }
    }

    /// Writes the premium state as it is, the device's connection
    /// included, which [`WalletManager::set_premium_state`] leaves to the
    /// core.
    pub(crate) async fn store_premium(manager: &WalletManager, premium: PremiumState) {
        manager
            .state
            .lock()
            .await
            .commit(|payload| {
                payload.settings.premium = premium;
                Ok(())
            })
            .unwrap();
    }

    /// The premium state as the vault holds it, token included.
    pub(crate) async fn stored_premium(manager: &WalletManager) -> PremiumState {
        manager.state.lock().await.payload.settings.premium.clone()
    }

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

    #[tokio::test]
    async fn add_list_snapshot_descriptor_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;

        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        assert_eq!(meta.network, Network::Signet);

        let wallets = manager.list_wallets(Some(Network::Signet)).await;
        assert_eq!(wallets.len(), 1);
        assert!(
            manager
                .list_wallets(Some(Network::Mainnet))
                .await
                .is_empty()
        );

        let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
        assert_eq!(snapshot.balance.total, 0);
        assert!(snapshot.txs.is_empty());
        assert_eq!(snapshot.tip_height, 0);
    }

    #[tokio::test]
    async fn policy_of_a_descriptor_wallet_reads_its_keys() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();

        let snapshot = manager.policy(&meta.id).await.unwrap();
        assert_eq!(snapshot.kind, policy::PolicyKind::SingleKey);
        assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
        assert_eq!(snapshot.keys.len(), 1);
        assert_eq!(snapshot.keys[0].fingerprint.as_deref(), Some("9a6a2580"));
        assert_eq!(snapshot.keys[0].origin_path.as_deref(), Some("m/84'/1'/0'"));
        assert_eq!(snapshot.branches.len(), 1);
        assert!(snapshot.branches[0].spendable_now);
        assert_eq!(snapshot.coins, 0);
        assert_eq!(
            snapshot.tip_height, None,
            "never synced: no tip to measure from"
        );
        assert!(matches!(
            manager.policy("nope").await,
            Err(CoreError::WalletNotFound(_))
        ));
    }

    #[tokio::test]
    async fn policy_of_a_watched_address_has_no_branches() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let parsed = parse_input(address).unwrap();
        let meta = manager
            .add_wallet("Watched address", &parsed, Network::Signet)
            .await
            .unwrap();

        let snapshot = manager.policy(&meta.id).await.unwrap();
        assert_eq!(snapshot.kind, policy::PolicyKind::Address);
        assert_eq!(snapshot.script, crate::input::ScriptKind::Segwit);
        assert_eq!(snapshot.descriptor, address);
        assert_eq!(snapshot.policy, "address");
        assert!(snapshot.keys.is_empty());
        assert!(snapshot.branches.is_empty());
        assert!(!snapshot.has_timelocks);
    }

    #[tokio::test]
    async fn receive_addresses_derive_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();

        let entries = manager.receive_addresses(&meta.id, 2).await.unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].address.starts_with("tb1"));
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[2].index, 2);
        // Single-origin descriptor: the absolute path is unambiguous.
        assert_eq!(entries[0].derivation.as_deref(), Some("m/84'/1'/0'/0/0"));
        assert_eq!(entries[2].derivation.as_deref(), Some("m/84'/1'/0'/0/2"));

        // A fresh manager reloads the engine from the vault and derives
        // the same addresses.
        drop(manager);
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        let again = manager.receive_addresses(&meta.id, 2).await.unwrap();
        assert_eq!(again[0].address, entries[0].address);
    }

    #[tokio::test]
    async fn address_list_and_export_read_the_same_state() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();

        // Fresh wallet: one revealed external address, no change yet.
        let list = manager.address_list(&meta.id).await.unwrap();
        assert_eq!(list.external.len(), 1);
        assert_eq!(list.external[0].index, 0);
        assert!(!list.external[0].used);
        assert_eq!(list.external[0].balance_sats, 0);
        assert!(list.internal.is_empty());
        assert!(!list.truncated);

        // Peeking receive addresses reveals further external rows.
        let _ = manager.receive_addresses(&meta.id, 0).await.unwrap();
        let again = manager.address_list(&meta.id).await.unwrap();
        assert!(!again.external.is_empty());
        assert_eq!(again.external[0].address, list.external[0].address);

        // An empty wallet exports a header and nothing else.
        let export = manager
            .export_transactions(&meta.id, &crate::export::ExportOptions::default())
            .await
            .unwrap();
        assert_eq!(export.rows, 0);
        assert!(export.csv.starts_with("txid,date_utc,"));
        assert_eq!(export.csv.lines().count(), 1);
    }

    #[tokio::test]
    async fn gap_limit_is_global_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        assert_eq!(meta.gap_limit, 20, "default follows the setting");
        assert_eq!(manager.settings().await.gap_limit, 20);

        manager.set_gap_limit(50).await.unwrap();
        // Every surface presents the new effective value.
        assert_eq!(manager.settings().await.gap_limit, 50);
        assert_eq!(manager.list_wallets(None).await[0].gap_limit, 50);
        assert_eq!(
            manager
                .wallet_snapshot(&meta.id)
                .await
                .unwrap()
                .meta
                .gap_limit,
            50
        );
        // Bounds are enforced.
        assert!(manager.set_gap_limit(0).await.is_err());
        assert!(manager.set_gap_limit(501).await.is_err());

        // A fresh manager reloads the value from the vault.
        drop(manager);
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(manager.settings().await.gap_limit, 50);
    }

    #[tokio::test]
    async fn duplicates_and_network_mismatch_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        manager
            .add_wallet("One", &parsed, Network::Signet)
            .await
            .unwrap();

        assert!(matches!(
            manager.add_wallet("Two", &parsed, Network::Signet).await,
            Err(CoreError::DuplicateWallet(_))
        ));
        assert!(matches!(
            manager.add_wallet("Three", &parsed, Network::Mainnet).await,
            Err(CoreError::NetworkMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn single_address_wallet_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
        let meta = manager
            .add_wallet("Watched address", &parsed, Network::Signet)
            .await
            .unwrap();

        let snapshot = manager.wallet_snapshot(&meta.id).await.unwrap();
        assert_eq!(snapshot.balance.total, 0);

        let entries = manager.receive_addresses(&meta.id, 5).await.unwrap();
        assert_eq!(entries.len(), 1, "a single address has a single entry");

        manager.remove_wallet(&meta.id).await.unwrap();
        assert!(manager.list_wallets(None).await.is_empty());
        assert!(matches!(
            manager.wallet_snapshot(&meta.id).await,
            Err(CoreError::WalletNotFound(_))
        ));
    }

    #[tokio::test]
    async fn rename_persists() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Old name", &parsed, Network::Signet)
            .await
            .unwrap();
        manager.rename_wallet(&meta.id, "New name").await.unwrap();

        let manager = WalletManager::open(dir.path(), key()).unwrap();
        let wallets = manager.list_wallets(None).await;
        assert_eq!(wallets[0].name, "New name");
    }

    #[tokio::test]
    async fn icon_defaults_to_the_wallet_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Cold", &parsed, Network::Signet)
            .await
            .unwrap();
        assert_eq!(meta.icon, WalletIcon::Wallet);
        manager
            .set_wallet_icon(&meta.id, WalletIcon::Snowflake)
            .await
            .unwrap();
        assert!(matches!(
            manager.set_wallet_icon("nope", WalletIcon::Key).await,
            Err(CoreError::WalletNotFound(_))
        ));

        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(
            manager.list_wallets(None).await[0].icon,
            WalletIcon::Snowflake
        );
    }

    #[tokio::test]
    async fn reorder_persists_and_leaves_the_rest_alone() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let mut ids = Vec::new();
        for (name, input) in [
            ("A", MULTIPATH),
            ("B", ADDRESS),
            (
                "C",
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            ),
        ] {
            let parsed = parse_input(input).unwrap();
            let meta = manager
                .add_wallet(name, &parsed, Network::Signet)
                .await
                .unwrap();
            ids.push(meta.id);
        }
        let names = |wallets: Vec<WalletMeta>| -> Vec<String> {
            wallets.into_iter().map(|meta| meta.name).collect()
        };

        // Only two of the three are named: they swap, the third keeps
        // its slot.
        manager
            .reorder_wallets(&[ids[2].clone(), ids[0].clone()])
            .await
            .unwrap();
        assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);

        let refused = manager
            .reorder_wallets(&[ids[0].clone(), ids[0].clone()])
            .await
            .unwrap_err();
        assert!(
            matches!(refused, CoreError::InvalidInput { .. }),
            "{refused}"
        );
        assert!(matches!(
            manager.reorder_wallets(&["nope".to_owned()]).await,
            Err(CoreError::WalletNotFound(_))
        ));

        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(names(manager.list_wallets(None).await), ["C", "B", "A"]);
    }

    #[tokio::test]
    async fn settings_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager.set_active_network(Network::Signet).await.unwrap();
        manager
            .set_backend(
                Network::Signet,
                BackendConfig::CustomEsplora {
                    url: "https://esplora.example.org/api".to_owned(),
                },
            )
            .await
            .unwrap();
        manager
            .set_app_pref("theme".to_owned(), "dark".to_owned())
            .await
            .unwrap();

        let manager = WalletManager::open(dir.path(), key()).unwrap();
        let settings = manager.settings().await;
        assert_eq!(settings.active_network, Network::Signet);
        assert_eq!(
            settings.backend_for(Network::Signet),
            BackendConfig::CustomEsplora {
                url: "https://esplora.example.org/api".to_owned()
            }
        );
        assert_eq!(settings.app_prefs.get("theme").unwrap(), "dark");
    }

    /// A custom address is stored the way a scan reads it, and refused
    /// when the parser cannot read it: stored as typed, the sync would
    /// see no onion in `tcp://x.onion:50001:extra` and hand it to the
    /// resolver in the clear. A refusal leaves the setting as it was.
    #[tokio::test]
    async fn a_custom_backend_is_stored_canonical_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let electrum = |url: &str| BackendConfig::CustomElectrum {
            url: url.to_owned(),
        };
        let esplora = |url: &str| BackendConfig::CustomEsplora {
            url: url.to_owned(),
        };

        manager
            .set_backend(Network::Signet, electrum("ssl://node.example.org:50002"))
            .await
            .unwrap();
        for (config, problem) in [
            (electrum("tcp://x.onion:50001:extra"), "more than one colon"),
            (
                electrum("ssl://x.onion:99999"),
                "99999 is not a port number",
            ),
            (esplora("ssl://x.onion:50002"), "http:// or https://"),
        ] {
            let refused = manager
                .set_backend(Network::Signet, config.clone())
                .await
                .unwrap_err();
            assert!(
                matches!(&refused, CoreError::InvalidInput { kind: "server", detail } if detail.contains(problem)),
                "{config:?}: {refused}"
            );
        }
        assert_eq!(
            manager.settings().await.backend_for(Network::Signet),
            electrum("ssl://node.example.org:50002"),
            "a refused address leaves the setting as it was"
        );

        manager
            .set_backend(Network::Signet, electrum("SSL://Node.Example.ORG.:50002"))
            .await
            .unwrap();
        assert_eq!(
            manager.settings().await.backend_for(Network::Signet),
            electrum("ssl://node.example.org:50002")
        );
        manager
            .set_backend(
                Network::Signet,
                esplora("HTTPS://Esplora.Example.ORG./api/"),
            )
            .await
            .unwrap();
        assert_eq!(
            manager.settings().await.backend_for(Network::Signet),
            esplora("https://esplora.example.org/api")
        );
        // Already in that form: byte for byte, the key of an accepted
        // certificate among what stays the same.
        for config in [
            electrum("tcp://x.onion:50001"),
            electrum("ssl://[2001:db8::1]:50002"),
            esplora("https://esplora.example.org/api"),
        ] {
            manager
                .set_backend(Network::Signet, config.clone())
                .await
                .unwrap();
            assert_eq!(
                manager.settings().await.backend_for(Network::Signet),
                config
            );
        }
    }

    #[tokio::test]
    async fn removing_a_watched_wallet_queues_its_unwatch() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();

        // No key: there is no server to tell.
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        manager.remove_wallet(&meta.id).await.unwrap();
        assert!(manager.premium_state().await.pending_unwatch.is_empty());

        // A key and a yes: the removal waits for the server, and the yes
        // goes with the wallet.
        let meta = manager
            .add_wallet("Signet cold", &parsed, Network::Signet)
            .await
            .unwrap();
        let mut premium = PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        };
        premium.consent(&meta.id, 100);
        store_premium(&manager, premium).await;
        manager.remove_wallet(&meta.id).await.unwrap();
        let premium = manager.premium_state().await;
        assert_eq!(premium.pending_unwatch, vec![meta.id.clone()]);
        assert!(!premium.is_consented(&meta.id));

        // It survives a reopen: the message waits in the vault.
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(manager.premium_state().await.pending_unwatch, vec![meta.id]);
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

    #[test]
    fn deep_history_survives_a_sync() {
        let tx = |txid: &str, height: Option<u32>| AddressTx {
            txid: txid.to_owned(),
            net_sats: 0,
            fee_sats: None,
            height,
            timestamp: None,
            vsize: 100,
            inputs: vec![],
            outputs: vec![],
            extras: None,
        };
        // The user had loaded two rounds; a sync only refetches the newest.
        let previous = AddressWatchState {
            txs: vec![
                tx("aa", Some(900)),
                tx("bb", Some(500)),
                tx("cc", Some(100)),
            ],
            history_cursor: Some("cc".to_owned()),
            truncated: true,
            ..Default::default()
        };
        let mut fresh = AddressWatchState {
            txs: vec![tx("new", None), tx("aa", Some(900))],
            history_cursor: Some("aa".to_owned()),
            truncated: true,
            ..Default::default()
        };
        keep_older_history(&mut fresh, &previous);
        let ids: Vec<&str> = fresh.txs.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(ids, vec!["new", "aa", "bb", "cc"], "older rounds are kept");
        assert_eq!(
            fresh.history_cursor.as_deref(),
            Some("cc"),
            "the deeper cursor wins"
        );
    }

    #[test]
    fn a_replaced_transaction_is_not_resurrected() {
        let tx = |txid: &str, height: Option<u32>| AddressTx {
            txid: txid.to_owned(),
            net_sats: 0,
            fee_sats: None,
            height,
            timestamp: None,
            vsize: 100,
            inputs: vec![],
            outputs: vec![],
            extras: None,
        };
        // "gone" sat inside the fresh window and vanished from the chain.
        let previous = AddressWatchState {
            txs: vec![tx("gone", Some(950)), tx("old", Some(10))],
            ..Default::default()
        };
        let mut fresh = AddressWatchState {
            txs: vec![tx("kept", Some(900))],
            ..Default::default()
        };
        keep_older_history(&mut fresh, &previous);
        let ids: Vec<&str> = fresh.txs.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(
            ids,
            vec!["kept", "old"],
            "only settled history is carried over"
        );
    }

    #[tokio::test]
    async fn load_more_history_refuses_descriptor_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Cold", &parsed, Network::Signet)
            .await
            .unwrap();
        let error = manager.load_more_history(&meta.id).await.unwrap_err();
        assert!(
            error.to_string().contains("full history"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn load_more_history_is_a_no_op_without_a_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
        let meta = manager
            .add_wallet("Watch", &parsed, Network::Signet)
            .await
            .unwrap();
        assert_eq!(manager.load_more_history(&meta.id).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn regtest_public_backend_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Regtest", &parsed, Network::Regtest)
            .await
            .unwrap();
        assert!(matches!(
            manager.sync_wallet(&meta.id).await,
            Err(CoreError::BackendUnavailable(_))
        ));
    }

    const BACKUP_PASSWORD: &str = "correct horse battery staple";
    const ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn fingerprint(byte: &str) -> String {
        vec![byte; 32].join(":")
    }

    /// A manager watching a descriptor wallet and a single address.
    async fn seeded(dir: &std::path::Path) -> (WalletManager, WalletMeta, WalletMeta) {
        let manager = manager(dir).await;
        let cold = manager
            .add_wallet("Cold", &parse_input(MULTIPATH).unwrap(), Network::Signet)
            .await
            .unwrap();
        let watch = manager
            .add_wallet("Watch", &parse_input(ADDRESS).unwrap(), Network::Signet)
            .await
            .unwrap();
        (manager, cold, watch)
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
                        },
                    ),
                    (
                        Network::Mainnet,
                        BackendConfig::CustomEsplora {
                            url: "https://user:pass@node.example.org:3002/api".to_owned(),
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
                        },
                    ),
                    (
                        Network::Signet,
                        BackendConfig::CustomElectrum {
                            url: "tcp://x.onion:50001:extra".to_owned(),
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
        // The vault is written to a temporary file first and renamed
        // into place; a directory under that name makes every save fail
        // before the vault itself is touched.
        let blocker = target_dir.path().join("gerfaut.tmp");
        std::fs::create_dir(&blocker).unwrap();

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
        std::fs::remove_dir(&blocker).unwrap();
        let report = target
            .import_backup(&bundle.data, BACKUP_PASSWORD, &everything)
            .await
            .unwrap();
        assert_eq!(report.added.len(), 2);
        assert_eq!(target.settings().await.gap_limit, 50);
        let cold = report.added[0].id.clone();

        // Renaming and removing are held to the same rule.
        std::fs::create_dir(&blocker).unwrap();
        assert!(target.rename_wallet(&cold, "Renamed").await.is_err());
        assert!(target.remove_wallet(&cold).await.is_err());
        let wallets = target.list_wallets(None).await;
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].name, "Cold");
        assert!(target.wallet_snapshot(&cold).await.is_ok());
        std::fs::remove_dir(&blocker).unwrap();

        drop(target);
        let reopened = WalletManager::open(target_dir.path(), key()).unwrap();
        assert_eq!(reopened.list_wallets(None).await.len(), 2);
        assert_eq!(reopened.settings().await.gap_limit, 50);
    }

    #[tokio::test]
    async fn tor_settings_are_checked_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        assert_eq!(manager.settings().await.tor, TorSettings::default());

        manager
            .set_tor_settings(TorSettings {
                mode: TorMode::Embedded,
                socks_proxy: Some(" 127.0.0.1:9150 ".to_owned()),
            })
            .await
            .unwrap();
        let status = manager.tor_status().await;
        assert_eq!(status.mode, TorMode::Embedded);
        assert_eq!(status.socks_proxy, "127.0.0.1:9150");
        assert_eq!(status.embedded_available, cfg!(feature = "embedded-tor"));
        assert_eq!(status.system_socks_trusted, tor::TRUST_LOOPBACK_SOCKS);

        // Blank means the default.
        manager
            .set_tor_settings(TorSettings {
                mode: TorMode::System,
                socks_proxy: Some("  ".to_owned()),
            })
            .await
            .unwrap();
        assert_eq!(manager.settings().await.tor.socks_proxy, None);

        // A typo is refused before it is stored.
        let error = manager
            .set_tor_settings(TorSettings {
                mode: TorMode::Auto,
                socks_proxy: Some("nonsense".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::InvalidInput {
                kind: "tor proxy",
                ..
            }
        ));

        let manager = WalletManager::open(dir.path(), key()).unwrap();
        assert_eq!(
            manager.settings().await.tor,
            TorSettings {
                mode: TorMode::System,
                socks_proxy: None
            }
        );
    }

    /// A loopback port nothing listens on: a system Tor that is not
    /// there, without depending on what runs on this machine.
    async fn closed_port() -> String {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        address
    }

    #[tokio::test]
    async fn an_onion_backend_without_tor_fails_before_any_connection() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let parsed = parse_input(MULTIPATH).unwrap();
        let meta = manager
            .add_wallet("Over Tor", &parsed, Network::Signet)
            .await
            .unwrap();
        manager
            .set_backend(
                Network::Signet,
                BackendConfig::CustomEsplora {
                    url: "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api"
                        .to_owned(),
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

        let started = Instant::now();
        let error = manager.sync_wallet(&meta.id).await.unwrap_err();
        assert!(matches!(error, CoreError::Tor(_)), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the onion host is never contacted, let alone looked up"
        );
        assert!(matches!(
            manager.tor_connect().await,
            Err(CoreError::Tor(_))
        ));

        // A workspace sync reports it per wallet, like any other failure.
        let report = manager.sync_all(Some(Network::Signet)).await;
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].message.starts_with("tor: "),
            "{}",
            report.failures[0].message
        );
    }

    /// What the loopback Esplora below does with a question it has no
    /// answer for.
    #[derive(Clone, Copy)]
    enum Unknown {
        /// It says so, the way a backend reports a coin it never saw.
        NotFound,
        /// It says nothing at all and drops the connection. A throttled
        /// instance, a timeout and a reset all reach the chain layer as
        /// the same refusal; this one costs no backoff to reproduce.
        NoAnswer,
    }

    /// An Esplora on loopback that knows exactly one transaction: it
    /// serves its bytes and says its first output is unspent, and knows
    /// nothing else. What a real backend would answer about a coin the
    /// vault does not hold.
    async fn esplora_knowing(tx: bdk_wallet::bitcoin::Transaction, unknown: Unknown) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let txid = tx.compute_txid().to_string();
        let raw = bdk_wallet::bitcoin::consensus::serialize(&tx);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("");
                let answer: Option<(&str, &str, Vec<u8>)> = if path == format!("/api/tx/{txid}/raw")
                {
                    Some(("200 OK", "application/octet-stream", raw.clone()))
                } else if path == format!("/api/tx/{txid}/outspend/0") {
                    Some(("200 OK", "application/json", br#"{"spent":false}"#.to_vec()))
                } else {
                    match unknown {
                        Unknown::NotFound => {
                            Some(("404 Not Found", "text/plain", b"not found".to_vec()))
                        }
                        Unknown::NoAnswer => None,
                    }
                };
                if let Some((status, kind, body)) = answer {
                    let mut response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    response.extend(body);
                    let _ = stream.write_all(&response).await;
                }
                let _ = stream.shutdown().await;
            }
        });
        format!("http://{address}/api")
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
            matches!(&error, CoreError::Premium(PremiumError::Rejected(words)) if words == "HTTP 401"),
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

    /// The same lie with no backend to ask: regtest has no public
    /// server and none was configured. The preview cannot catch the
    /// lie, so it must say so: the coin is marked unchecked, with the
    /// warning a backend that stopped answering would earn.
    #[tokio::test]
    async fn a_psbt_lie_with_no_backend_at_all_is_marked_unchecked() {
        use crate::broadcast::TxWarningKind;
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
            absolute, transaction,
        };

        const CLAIMED: u64 = 10_200;
        const PAID: u64 = 10_000;
        let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
        let spend = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x44; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(PAID),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
            }],
        };
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: spk,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let text = data_encoding::BASE64.encode(&psbt.serialize());

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        let preview = manager
            .preview_transaction(&text, Network::Regtest)
            .await
            .unwrap();
        let kinds: Vec<_> = preview.warnings.iter().map(|w| w.kind).collect();
        assert!(
            kinds.contains(&TxWarningKind::InputUnknown),
            "nobody checked this coin and the preview must say so: {kinds:?}"
        );
        assert!(
            !kinds.contains(&TxWarningKind::InputMismatch),
            "no one contradicted the PSBT either: {kinds:?}"
        );
        assert_eq!(
            preview.inputs[0].value_sats,
            Some(CLAIMED),
            "the value shown is the transaction's own word"
        );
    }

    /// A finalized PSBT spends a coin no watched wallet holds and
    /// declares it worth a tenth of what it is. The backend is asked
    /// all the same, and its answer, not the PSBT's, is what the
    /// preview goes by: the real fee, and the disagreement in red.
    #[tokio::test]
    async fn a_psbt_lie_about_an_unwatched_coin_is_caught_by_the_backend() {
        use crate::broadcast::{TxSeverity, TxWarningKind};
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
            absolute, transaction,
        };

        const REAL: u64 = 100_000;
        const CLAIMED: u64 = 10_200;
        const PAID: u64 = 10_000;
        let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(REAL),
                script_pubkey: spk.clone(),
            }],
        };
        let spend = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(funding.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(PAID),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
            }],
        };
        // Finalized: readiness is about presence, and a finalized input
        // never meets the interpreter.
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: spk,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let text = data_encoding::BASE64.encode(&psbt.serialize());

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(
                Network::Regtest,
                BackendConfig::CustomEsplora {
                    url: esplora_knowing(funding, Unknown::NotFound).await,
                },
            )
            .await
            .unwrap();
        let preview = manager
            .preview_transaction(&text, Network::Regtest)
            .await
            .unwrap();
        assert!(preview.ready);
        assert_eq!(preview.inputs[0].value_sats, Some(REAL));
        assert_eq!(preview.fee_sats, Some(REAL - PAID));
        let mismatch = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputMismatch)
            .expect("the backend's word contradicts the PSBT's");
        assert_eq!(mismatch.severity, TxSeverity::Alert);
        assert!(
            mismatch.message.contains("the backend"),
            "{}",
            mismatch.message
        );
        let kinds: Vec<TxWarningKind> = preview.warnings.iter().map(|w| w.kind).collect();
        assert!(kinds.contains(&TxWarningKind::HighFeeShare), "{kinds:?}");
        assert!(!kinds.contains(&TxWarningKind::InputUnknown), "{kinds:?}");
    }

    /// The same lie, told about the second of two coins, by a PSBT whose
    /// word on the first one is true. The backend answers about the
    /// first and then stops answering — one throttled request is all it
    /// takes — so nothing ever contradicts the second declaration.
    ///
    /// The value shown for that coin, and therefore the whole of the fee,
    /// is then the transaction's own arithmetic. A preview that says
    /// nothing about it reads as a confirmed 200 sat fee on a transaction
    /// that burns 90 000: whatever else it shows, it must say that this
    /// coin was never checked.
    #[tokio::test]
    async fn a_backend_that_stops_answering_confirms_nothing_about_the_rest() {
        use crate::broadcast::TxWarningKind;
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, Txid, WPubkeyHash, Witness,
            absolute, transaction,
        };

        /// What each of the two coins is really worth.
        const REAL: u64 = 100_000;
        /// What the PSBT claims the second one is worth.
        const CLAIMED: u64 = 10_200;
        /// Paid out, so the declared fee is an unremarkable 200 sats
        /// while the real one is 90 000: nothing else in the preview
        /// has anything to complain about.
        const PAID: u64 = REAL + CLAIMED - 200;

        let coin = |seed: u8| {
            let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]));
            let funding = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(REAL),
                    script_pubkey: spk.clone(),
                }],
            };
            (funding, spk)
        };
        let (answered, answered_spk) = coin(0x33);
        let (refused, refused_spk) = coin(0x44);
        let spending = |funding: &Transaction| TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let spend = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending(&answered), spending(&refused)],
            output: vec![TxOut {
                value: Amount::from_sat(PAID),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20])),
            }],
        };
        let mut witness = Witness::new();
        witness.push([0x30; 71]);
        witness.push([0x02; 33]);
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        // The truth about the coin the backend will confirm, so that
        // nothing but the second input is ever in question.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(REAL),
            script_pubkey: answered_spk,
        });
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(CLAIMED),
            script_pubkey: refused_spk,
        });
        psbt.inputs[0].final_script_witness = Some(witness.clone());
        psbt.inputs[1].final_script_witness = Some(witness);
        let text = data_encoding::BASE64.encode(&psbt.serialize());

        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        manager
            .set_backend(
                Network::Regtest,
                BackendConfig::CustomEsplora {
                    url: esplora_knowing(answered, Unknown::NoAnswer).await,
                },
            )
            .await
            .unwrap();
        let preview = manager
            .preview_transaction(&text, Network::Regtest)
            .await
            .unwrap();

        assert!(preview.ready);
        assert_eq!(
            preview.inputs[0].value_sats,
            Some(REAL),
            "the coin the backend did answer about is still read from it"
        );
        assert!(
            !preview.warnings.is_empty(),
            "an input no backend answered about passed for a confirmed one"
        );
        let caution = preview
            .warnings
            .iter()
            .find(|w| w.kind == TxWarningKind::InputUnknown)
            .expect("the coin nobody confirmed is named");
        assert!(caution.message.contains("Input 1"), "{}", caution.message);
        // The declaration is still all there is to show for that coin,
        // and the fee still follows from it. What changes is that the
        // preview no longer passes either off as established.
        assert_eq!(preview.inputs[1].value_sats, Some(CLAIMED));
        assert_eq!(preview.fee_sats, Some(200));
    }
}
