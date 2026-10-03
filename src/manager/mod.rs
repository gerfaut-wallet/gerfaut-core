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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::chain::{self, BackendConfig};
use crate::error::{CoreError, CoreResult};
use crate::input::RecognizedKind;
use crate::lock::LockAttempts;
use crate::network::Network;
use crate::store::{Vault, VaultKey, VaultPayload, WalletRecord};
use crate::wallet::meta::{CachedTotals, WalletIcon, WalletKind, WalletMeta};
use crate::wallet::snapshot::SyncReport;
use crate::wallet::views;

mod app_lock;
mod backup;
mod broadcast;
mod devices;
mod premium;
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
    pub(crate) orders: views::HistoryOrders,
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
}

// --- helpers -----------------------------------------------------------

pub(crate) fn find_record<'a>(payload: &'a VaultPayload, id: &str) -> CoreResult<&'a WalletRecord> {
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
pub(crate) fn ensure_engine<'a>(
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

#[cfg(test)]
mod tests;
