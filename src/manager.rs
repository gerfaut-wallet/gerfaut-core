//! The wallet manager: the single facade every consumer talks to.
//!
//! Desktop (Tauri commands), mobile (FFI bridge), and later the server
//! all drive this type. It owns the encrypted vault, keeps loaded BDK
//! engines in memory, and coordinates syncs so that network I/O never
//! blocks reads: requests are built under the lock, executed outside it,
//! and applied back under the lock.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use std::str::FromStr;

use bdk_wallet::bitcoin::{Address, Amount, TxOut};

use crate::broadcast::{
    self, BroadcastReport, BroadcastStatus, InputFacts, OutputFacts, TxPreview, WalletRef,
};
use crate::chain::{
    self, BackendConfig, CertificateReport, CertificateStatus, Endpoint, EngineRequest,
    EngineResponse,
};
use crate::error::{CoreError, CoreResult};
use crate::export::{ExportOptions, ExportResult};
use crate::input::{ParsedInput, ParsedPayload};
use crate::lock::{self, AppLock, LockAttempts, LockKind, LockVerdict};
use crate::network::Network;
use crate::store::{Settings, Vault, VaultKey, VaultPayload, WalletRecord};
use crate::wallet::meta::{CachedTotals, SyncStamp, WalletKind, WalletMeta};
use crate::wallet::snapshot::{
    AddressEntry, AddressList, NewTx, SyncReport, TxDetail, UtxoInfo, WalletSnapshot,
};
use crate::wallet::views;
use crate::wallet::{AddressTx, AddressWatchState};

/// Vault file name inside the data directory.
const VAULT_FILE: &str = "gerfaut.vault";

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

struct ManagerState {
    vault: Vault,
    payload: VaultPayload,
    /// Loaded BDK engines, keyed by wallet id. Lazily populated.
    engines: HashMap<String, bdk_wallet::Wallet>,
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
}

/// The facade. Cheap to share behind an `Arc`.
pub struct WalletManager {
    state: Mutex<ManagerState>,
    /// Recent failed unlock attempts, kept apart from the vault lock so
    /// an unlock never waits on a sync.
    attempts: Mutex<LockAttempts>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WalletManager {
    /// Opens (or creates) the vault at `data_dir/gerfaut.vault`.
    pub fn open(data_dir: impl Into<PathBuf>, key: VaultKey) -> CoreResult<Self> {
        let path = data_dir.into().join(VAULT_FILE);
        let (vault, payload) = Vault::open_or_create(path, key)?;
        Ok(WalletManager {
            state: Mutex::new(ManagerState {
                vault,
                payload,
                engines: HashMap::new(),
            }),
            attempts: Mutex::new(LockAttempts::default()),
        })
    }

    // --- settings ------------------------------------------------------

    /// The settings as the apps may see them: the lock's hash stays in
    /// the vault, the apps only need to know a lock exists and its kind.
    pub async fn settings(&self) -> Settings {
        let mut settings = self.state.lock().await.payload.settings.clone();
        if let Some(lock) = &mut settings.app_lock {
            lock.secret = None;
        }
        settings
    }

    pub async fn set_active_network(&self, network: Network) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        state.payload.settings.active_network = network;
        state.vault.save(&state.payload)?;
        Ok(())
    }

    pub async fn set_backend(&self, network: Network, config: BackendConfig) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        state.payload.settings.backends.insert(network, config);
        state.vault.save(&state.payload)?;
        Ok(())
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
        if !chain::tls::is_fingerprint(fingerprint) {
            return Err(CoreError::InvalidInput {
                kind: "certificate fingerprint",
                detail: "expected 32 hexadecimal bytes separated by colons".to_owned(),
            });
        }
        let host = chain::electrum::certificate_key(url);
        let mut state = self.state.lock().await;
        state
            .payload
            .settings
            .electrum_certs
            .insert(host, fingerprint.to_ascii_uppercase());
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Drops an accepted certificate: the next connection to that host
    /// asks again.
    pub async fn forget_certificate(&self, host: &str) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        state.payload.settings.electrum_certs.remove(host);
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Sets the gap limit shared by every wallet. Takes effect on the
    /// next sync; a raised limit widens the scan, a lowered one only
    /// narrows future scans (revealed addresses stay watched).
    pub async fn set_gap_limit(&self, gap_limit: u32) -> CoreResult<()> {
        if !(1..=500).contains(&gap_limit) {
            return Err(CoreError::InvalidInput {
                kind: "gap limit",
                detail: "must be between 1 and 500".to_owned(),
            });
        }
        let mut state = self.state.lock().await;
        state.payload.settings.gap_limit = gap_limit;
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Stores one small app preference (theme, hidden balances, ...) in
    /// the encrypted vault.
    pub async fn set_app_pref(&self, key: String, value: String) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        state.payload.settings.app_prefs.insert(key, value);
        state.vault.save(&state.payload)?;
        Ok(())
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
        for record in &state.payload.wallets {
            if record.meta.network == network && record.meta.kind == kind {
                return Err(CoreError::DuplicateWallet(record.meta.name.clone()));
            }
        }

        let meta = WalletMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_owned(),
            network,
            kind: kind.clone(),
            recognized_as: parsed.kind,
            created_at: now_secs(),
            gap_limit: state.payload.settings.gap_limit,
            scan_gap: 0,
            labels: Default::default(),
            last_sync: None,
            cached: CachedTotals::default(),
        };

        // Build the engine now: an invalid descriptor/network combination
        // must fail here, not at the first sync.
        let record = match &kind {
            WalletKind::Descriptors {
                external, internal, ..
            } => {
                let mut engine = create_engine(external, internal.as_deref(), network)?;
                let changeset = engine.take_staged().ok_or_else(|| {
                    CoreError::Internal("new wallet produced no initial change set".to_owned())
                })?;
                state.engines.insert(meta.id.clone(), engine);
                WalletRecord {
                    meta: meta.clone(),
                    changeset: Some(changeset),
                    address_state: None,
                }
            }
            WalletKind::SingleAddress { address } => {
                // The classifier validated the address; re-check against
                // the chosen network as a defense in depth.
                address
                    .parse::<bdk_wallet::bitcoin::Address<_>>()
                    .ok()
                    .and_then(|a| a.require_network(network.to_bitcoin()).ok())
                    .ok_or_else(|| CoreError::NetworkMismatch {
                        expected: network.to_string(),
                        found: "address".to_owned(),
                    })?;
                WalletRecord {
                    meta: meta.clone(),
                    changeset: None,
                    address_state: None,
                }
            }
        };

        state.payload.wallets.push(record);
        state.vault.save(&state.payload)?;
        Ok(meta)
    }

    pub async fn rename_wallet(&self, id: &str, name: &str) -> CoreResult<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::InvalidInput {
                kind: "wallet name",
                detail: "a wallet needs a name".to_owned(),
            });
        }
        let mut state = self.state.lock().await;
        let record = find_record_mut(&mut state.payload, id)?;
        record.meta.name = name.to_owned();
        state.vault.save(&state.payload)?;
        Ok(())
    }

    pub async fn remove_wallet(&self, id: &str) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        let before = state.payload.wallets.len();
        state.payload.wallets.retain(|record| record.meta.id != id);
        if state.payload.wallets.len() == before {
            return Err(CoreError::WalletNotFound(id.to_owned()));
        }
        state.engines.remove(id);
        state.vault.save(&state.payload)?;
        Ok(())
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

    async fn sync_wallet_with(&self, id: &str, from_scratch: bool) -> CoreResult<SyncReport> {
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

        match &meta.kind {
            WalletKind::Descriptors { .. } => {
                self.sync_descriptor_wallet(&meta, &endpoints, started, from_scratch)
                    .await
            }
            WalletKind::SingleAddress { address } => {
                self.sync_address_wallet(&meta, address, &endpoints, started)
                    .await
            }
        }
    }

    async fn sync_descriptor_wallet(
        &self,
        meta: &WalletMeta,
        endpoints: &[Endpoint],
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
                    EngineRequest::Incremental(engine.start_sync_with_revealed_spks().build())
                };
                let known: HashSet<_> = engine.transactions().map(|tx| tx.tx_node.txid).collect();
                (request, known)
            };

            match chain::sync_engine(endpoint, request, meta.gap_limit).await {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(response) => {
                    let mut state = self.state.lock().await;
                    let engine = ensure_engine(&mut state, &meta.id)?;
                    let apply = match response {
                        EngineResponse::Full(update) => engine.apply_update(update),
                        EngineResponse::Incremental(update) => engine.apply_update(update),
                    };
                    apply.map_err(|e| CoreError::Sync {
                        backend: endpoint.label(),
                        detail: e.to_string(),
                    })?;

                    let balance = views::balance(engine);
                    let tip_height = views::tip_height(engine);
                    let tx_count_after = engine.transactions().count() as u32;
                    let new_txs = views::new_txs(engine, &known);
                    let staged = engine.take_staged();

                    if let Some(staged) = staged {
                        merge_changeset(&mut state, &meta.id, staged)?;
                    }
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
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
        started: Instant,
    ) -> CoreResult<SyncReport> {
        let mut attempts: Vec<String> = Vec::new();
        for endpoint in endpoints {
            match chain::fetch_address_state(endpoint, address, meta.network).await {
                Err(detail) => attempts.push(format!("{}: {detail}", endpoint.label())),
                Ok(mut watch) => {
                    let mut state = self.state.lock().await;
                    let known: HashSet<String> = find_record(&state.payload, &meta.id)?
                        .address_state
                        .as_ref()
                        .map(|s| s.txs.iter().map(|tx| tx.txid.clone()).collect())
                        .unwrap_or_default();
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
                    let new_txs: Vec<NewTx> = watch
                        .txs
                        .iter()
                        .filter(|tx| !known.contains(&tx.txid))
                        .map(|tx| NewTx {
                            txid: tx.txid.clone(),
                            net_sats: tx.net_sats,
                            confirmed: tx.height.is_some(),
                        })
                        .collect();
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: new_txs.len() as u32,
                        new_txs,
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

        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::fetch_address_history(endpoint, address, meta.network, &cursor).await {
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
        // unspent. One endpoint, the first that answers.
        let unresolved: Vec<usize> = (0..outpoints.len())
            .filter(|&i| decoded.inputs[i].prevout.is_none() && input_facts[i].prevout.is_none())
            .collect();
        let needs_chain = !unresolved.is_empty() || input_facts.iter().any(|f| f.spent.is_none());
        if needs_chain && let Ok(endpoints) = chain::endpoints(&config, network, &certs) {
            for endpoint in &endpoints {
                let mut answered = false;
                for (i, facts) in input_facts.iter_mut().enumerate() {
                    let wanted = unresolved.contains(&i) || facts.spent.is_none();
                    if !wanted {
                        continue;
                    }
                    match chain::fetch_prevout(endpoint, outpoints[i]).await {
                        Ok(chain_facts) => {
                            answered = true;
                            if unresolved.contains(&i) {
                                match chain_facts.txout {
                                    Some(txout) => facts.prevout = Some(txout),
                                    None => facts.unknown = true,
                                }
                            }
                            if facts.spent.is_none() {
                                facts.spent = chain_facts.spent;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if answered {
                    break;
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
        let mut refusals: Vec<(String, String)> = Vec::new();
        for endpoint in &endpoints {
            match chain::broadcast(endpoint, &decoded.tx).await {
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
        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::tx_standing(endpoint, txid, script.clone()).await {
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
        let mut state = self.state.lock().await;
        let previous = state.payload.settings.app_lock.take();
        state.payload.settings.app_lock = Some(AppLock {
            kind,
            auto_lock_secs: previous
                .as_ref()
                .map_or(Some(lock::DEFAULT_AUTO_LOCK_SECS), |p| p.auto_lock_secs),
            biometric: previous.as_ref().is_some_and(|p| p.biometric),
            secret: Some(stored),
        });
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Removes the lock. The current secret is required, for the same
    /// reason as above.
    pub async fn clear_app_lock(&self, current: &str) -> CoreResult<()> {
        let existing = self.existing_lock().await?;
        self.require_current(&existing, Some(current)).await?;
        let mut state = self.state.lock().await;
        state.payload.settings.app_lock = None;
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Tries a secret against the lock. Failures are counted and, past
    /// three, delayed: the verdict says how long before the next try
    /// is even looked at.
    pub async fn verify_app_lock(&self, secret: &str) -> CoreResult<LockVerdict> {
        let existing = self.existing_lock().await?;
        Ok(self.check_secret(&existing, secret).await)
    }

    /// How long the app may stay in the background before locking:
    /// `Some(0)` at once, `None` only at launch and on request.
    pub async fn set_auto_lock(&self, secs: Option<u32>) -> CoreResult<()> {
        self.existing_lock().await?;
        let mut state = self.state.lock().await;
        if let Some(lock) = &mut state.payload.settings.app_lock {
            lock.auto_lock_secs = secs;
        }
        state.vault.save(&state.payload)?;
        Ok(())
    }

    /// Whether the platform's biometric prompt may stand in for the
    /// secret. Recorded here so both apps read one setting; the prompt
    /// itself is the platform's.
    pub async fn set_biometric_unlock(&self, enabled: bool) -> CoreResult<()> {
        self.existing_lock().await?;
        let mut state = self.state.lock().await;
        if let Some(lock) = &mut state.payload.settings.app_lock {
            lock.biometric = enabled;
        }
        state.vault.save(&state.payload)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::parse_input;

    const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";

    fn key() -> VaultKey {
        VaultKey::Raw([9u8; 32])
    }

    async fn manager(dir: &std::path::Path) -> WalletManager {
        WalletManager::open(dir, key()).unwrap()
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

    #[tokio::test]
    async fn app_lock_timing_and_biometric_need_a_lock() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(dir.path()).await;
        assert!(manager.set_auto_lock(Some(300)).await.is_err());
        assert!(manager.set_biometric_unlock(true).await.is_err());
        manager
            .set_app_lock(LockKind::Pin, "1234", None)
            .await
            .unwrap();
        manager.set_auto_lock(None).await.unwrap();
        manager.set_biometric_unlock(true).await.unwrap();
        let lock = manager.app_lock().await.unwrap();
        assert_eq!(lock.auto_lock_secs, None);
        assert!(lock.biometric);
        // A new secret keeps the timing and the biometric choice.
        manager
            .set_app_lock(LockKind::Pin, "5678", Some("1234"))
            .await
            .unwrap();
        let lock = manager.app_lock().await.unwrap();
        assert_eq!(lock.auto_lock_secs, None);
        assert!(lock.biometric);
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
}
