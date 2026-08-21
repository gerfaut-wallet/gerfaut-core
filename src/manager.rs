//! The wallet manager: the single facade every consumer talks to.
//!
//! Desktop (Tauri commands), mobile (FFI bridge), and later the server
//! all drive this type. It owns the encrypted vault, keeps loaded BDK
//! engines in memory, and coordinates syncs so that network I/O never
//! blocks reads: requests are built under the lock, executed outside it,
//! and applied back under the lock.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::chain::{self, BackendConfig, Endpoint, EngineRequest, EngineResponse};
use crate::error::{CoreError, CoreResult};
use crate::input::{ParsedInput, ParsedPayload};
use crate::network::Network;
use crate::store::{Settings, Vault, VaultKey, VaultPayload, WalletRecord};
use crate::wallet::meta::{CachedTotals, DEFAULT_GAP_LIMIT, SyncStamp, WalletKind, WalletMeta};
use crate::wallet::snapshot::{AddressEntry, SyncReport, TxDetail, UtxoInfo, WalletSnapshot};
use crate::wallet::views;

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

/// The facade. Cheap to share behind an `Arc`.
pub struct WalletManager {
    state: Mutex<ManagerState>,
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
        })
    }

    // --- settings ------------------------------------------------------

    pub async fn settings(&self) -> Settings {
        self.state.lock().await.payload.settings.clone()
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
        state
            .payload
            .wallets
            .iter()
            .map(|record| record.meta.clone())
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
            gap_limit: DEFAULT_GAP_LIMIT,
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
        let record = find_record(&state.payload, id)?.clone();
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
            }]),
        }
    }

    // --- sync ----------------------------------------------------------

    /// Syncs one wallet against its network's backend. Public backends
    /// are tried in order until one answers.
    pub async fn sync_wallet(&self, id: &str) -> CoreResult<SyncReport> {
        let started = Instant::now();

        // Snapshot what the sync needs; do not hold the lock during I/O.
        let (meta, config) = {
            let state = self.state.lock().await;
            let record = find_record(&state.payload, id)?;
            (
                record.meta.clone(),
                state.payload.settings.backend_for(record.meta.network),
            )
        };
        let mut endpoints = chain::endpoints(&config, meta.network)?;
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
                self.sync_descriptor_wallet(&meta, &endpoints, started)
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
    ) -> CoreResult<SyncReport> {
        let full = meta.last_sync.is_none();
        let mut last_error = String::from("no backend available");

        for endpoint in endpoints {
            // Build a fresh request under the lock (requests are consumed
            // by each attempt).
            let (request, tx_count_before) = {
                let mut state = self.state.lock().await;
                let engine = ensure_engine(&mut state, &meta.id)?;
                let request = if full {
                    EngineRequest::Full(engine.start_full_scan().build())
                } else {
                    EngineRequest::Incremental(engine.start_sync_with_revealed_spks().build())
                };
                (request, engine.transactions().count() as u32)
            };

            match chain::sync_engine(endpoint, request, meta.gap_limit).await {
                Err(detail) => last_error = format!("{}: {detail}", endpoint.label()),
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
                    let staged = engine.take_staged();

                    if let Some(staged) = staged {
                        merge_changeset(&mut state, &meta.id, staged)?;
                    }
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: tx_count_after.saturating_sub(tx_count_before),
                        balance,
                        tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    finish_sync(&mut state, &meta.id, &report, tx_count_after)?;
                    return Ok(report);
                }
            }
        }

        Err(CoreError::Sync {
            backend: config_label(endpoints),
            detail: last_error,
        })
    }

    async fn sync_address_wallet(
        &self,
        meta: &WalletMeta,
        address: &str,
        endpoints: &[Endpoint],
        started: Instant,
    ) -> CoreResult<SyncReport> {
        let mut last_error = String::from("no backend available");
        for endpoint in endpoints {
            match chain::fetch_address_state(endpoint, address, meta.network).await {
                Err(detail) => last_error = format!("{}: {detail}", endpoint.label()),
                Ok(watch) => {
                    let mut state = self.state.lock().await;
                    let tx_count_before = {
                        let record = find_record(&state.payload, &meta.id)?;
                        record
                            .address_state
                            .as_ref()
                            .map_or(0, |s| s.txs.len() as u32)
                    };
                    let tx_count_after = watch.txs.len() as u32;
                    let report = SyncReport {
                        wallet_id: meta.id.clone(),
                        new_tx_count: tx_count_after.saturating_sub(tx_count_before),
                        balance: views::address_balance(&watch),
                        tip_height: watch.tip_height,
                        took_ms: started.elapsed().as_millis() as u64,
                        backend: endpoint.label(),
                    };
                    find_record_mut(&mut state.payload, &meta.id)?.address_state = Some(watch);
                    finish_sync(&mut state, &meta.id, &report, tx_count_after)?;
                    return Ok(report);
                }
            }
        }
        Err(CoreError::Sync {
            backend: config_label(endpoints),
            detail: last_error,
        })
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
}

// --- helpers -----------------------------------------------------------

fn config_label(endpoints: &[Endpoint]) -> String {
    endpoints
        .first()
        .map(|e| e.label())
        .unwrap_or_else(|| "backend".to_owned())
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
/// must not make the cached figure drift.
fn finish_sync(
    state: &mut ManagerState,
    id: &str,
    report: &SyncReport,
    tx_count: u32,
) -> CoreResult<()> {
    {
        let record = find_record_mut(&mut state.payload, id)?;
        record.meta.cached = CachedTotals {
            balance: report.balance,
            tx_count,
        };
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

        // A fresh manager reloads the engine from the vault and derives
        // the same addresses.
        drop(manager);
        let manager = WalletManager::open(dir.path(), key()).unwrap();
        let again = manager.receive_addresses(&meta.id, 2).await.unwrap();
        assert_eq!(again[0].address, entries[0].address);
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
