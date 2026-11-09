//! Where the sync of each wallet stands: idle, syncing, or failed since
//! its last good sync. One answer for every screen, whoever started the
//! sync: the app, a rescan, a sync of every wallet, the live watch.
//!
//! A sync takes a turn on the board ([`WalletManager::sync_turn`]) and
//! gives it back when it ends, or when it is given up halfway. The
//! first turn of a wallet says it is syncing; the last one given back
//! says where it now stands, read from the vault: failed while its last
//! failure is kept ([`crate::wallet::meta::WalletMeta::last_failure`]),
//! idle otherwise. Both are sent to whoever listens
//! ([`WalletManager::sync_changes`]), and the same answer can be asked
//! at any time ([`WalletManager::sync_states`]).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::error::CoreError;
use crate::network::Network;
use crate::now_secs;
use crate::wallet::meta::{StoredMeta, SyncFailureStamp};

use super::super::{ManagerState, WalletManager, find_record, find_record_mut};

/// Where the sync of a wallet stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WalletSyncState {
    /// No sync runs, and the last one did not fail.
    Idle,
    /// A sync runs, whoever asked for it.
    Syncing,
    /// No sync runs, and the last one failed: what the wallet shows is
    /// from its last good sync, if it ever had one. Its fields sit flat
    /// beside `state`.
    Failed(SyncFailureStamp),
}

impl WalletSyncState {
    fn of(meta: &StoredMeta, running: bool) -> Self {
        if running {
            return WalletSyncState::Syncing;
        }
        match &meta.last_failure {
            Some(failure) => WalletSyncState::Failed(failure.clone()),
            None => WalletSyncState::Idle,
        }
    }
}

/// The state of one wallet's sync, beside its id: what
/// [`WalletManager::sync_states`] lists and [`WalletManager::sync_changes`]
/// sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSync {
    pub wallet_id: String,
    #[serde(flatten)]
    pub state: WalletSyncState,
}

/// How many changes a listener that falls behind may miss before it
/// loses the oldest: it then asks [`WalletManager::sync_states`] again.
const CHANGES: usize = 64;

/// The syncs under way, by wallet, and whoever listens to their changes.
pub(crate) struct SyncBoard {
    /// How many turns each wallet has out: a sync waiting for another
    /// one of the same wallet holds one too.
    running: HashMap<String, usize>,
    changes: broadcast::Sender<WalletSync>,
}

impl Default for SyncBoard {
    fn default() -> Self {
        SyncBoard {
            running: HashMap::new(),
            changes: broadcast::channel(CHANGES).0,
        }
    }
}

impl SyncBoard {
    fn running(&self, id: &str) -> bool {
        self.running.get(id).is_some_and(|turns| *turns > 0)
    }

    /// Sends a change; nobody listening is not a failure.
    fn tell(&self, wallet_id: &str, state: WalletSyncState) {
        let _ = self.changes.send(WalletSync {
            wallet_id: wallet_id.to_owned(),
            state,
        });
    }
}

/// A turn of a wallet on the board, out while a sync of it runs. Given
/// back by [`SyncTurn::end`]; dropped without it, a sync given up
/// halfway, it is given back all the same, and where the wallet stands
/// is said all the same.
pub(crate) struct SyncTurn {
    manager: WalletManager,
    id: String,
    left: bool,
    settled: bool,
}

impl SyncTurn {
    /// Gives the turn back, and says where the wallet stands if it was
    /// the last one out.
    pub(crate) async fn end(mut self) {
        self.manager.leave(&self.id);
        self.left = true;
        self.manager.settle(&self.id).await;
        self.settled = true;
    }
}

impl Drop for SyncTurn {
    fn drop(&mut self) {
        if !self.left {
            self.manager.leave(&self.id);
        }
        if self.settled {
            return;
        }
        // The vault's lock cannot be awaited here. With a runtime, where
        // the wallet stands is said from a task of its own; without one,
        // now, if the lock is free.
        let manager = self.manager.clone();
        let id = std::mem::take(&mut self.id);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move { manager.settle(&id).await });
            }
            Err(_) => {
                if let Ok(state) = manager.state.try_lock() {
                    manager.settle_in(&state, &id);
                }
            }
        }
    }
}

impl WalletManager {
    /// Where the sync of each wallet of a network (or of all of them)
    /// stands, in the order of the wallets.
    pub async fn sync_states(&self, network: Option<Network>) -> Vec<WalletSync> {
        let state = self.state.lock().await;
        let board = self.board();
        state
            .payload
            .wallets
            .iter()
            .filter(|record| network.is_none_or(|n| record.meta.network == n))
            .map(|record| WalletSync {
                wallet_id: record.meta.id.clone(),
                state: WalletSyncState::of(&record.meta, board.running(&record.meta.id)),
            })
            .collect()
    }

    /// Every change of where a wallet's sync stands from now on: its
    /// first turn out, then where it stands once the last one is back.
    /// A listener that falls behind loses the oldest changes, and then
    /// reads [`Self::sync_states`] again.
    pub fn sync_changes(&self) -> broadcast::Receiver<WalletSync> {
        self.board().changes.subscribe()
    }

    /// Takes a turn for a sync of `id`: the first one out says the
    /// wallet is syncing.
    pub(crate) fn sync_turn(&self, id: &str) -> SyncTurn {
        let mut board = self.board();
        let turns = board.running.entry(id.to_owned()).or_default();
        *turns += 1;
        if *turns == 1 {
            board.tell(id, WalletSyncState::Syncing);
        }
        SyncTurn {
            manager: self.clone(),
            id: id.to_owned(),
            left: false,
            settled: false,
        }
    }

    fn leave(&self, id: &str) {
        let mut board = self.board();
        if let Some(turns) = board.running.get_mut(id) {
            *turns = turns.saturating_sub(1);
            if *turns == 0 {
                board.running.remove(id);
            }
        }
    }

    /// Says where the sync of `id` stands, unless a sync of it runs
    /// again: that one has said it is syncing, and will say where it
    /// ends. Read under the vault's lock, so no failure is written
    /// between the reading and the saying.
    async fn settle(&self, id: &str) {
        // Nothing to say while another turn is out: the vault's lock is
        // not waited for.
        if self.board().running(id) {
            return;
        }
        let state = self.state.lock().await;
        self.settle_in(&state, id);
    }

    fn settle_in(&self, state: &ManagerState, id: &str) {
        let board = self.board();
        if board.running(id) {
            return;
        }
        match find_record(&state.payload, id) {
            Ok(record) => board.tell(id, WalletSyncState::of(&record.meta, false)),
            // Removed while it synced: nothing stands in its way.
            Err(_) => board.tell(id, WalletSyncState::Idle),
        }
    }

    fn board(&self) -> std::sync::MutexGuard<'_, SyncBoard> {
        // A thread that panicked holding the board left counts and a
        // sender, both still whole.
        self.sync_board
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Keeps the failure of a sync of `id` with the wallet, until a sync
/// succeeds; called under the wallet's turn to sync, so no later sync
/// of it can be overwritten. A wallet that is gone has nothing to keep
/// it in. The same failure again keeps the time of the first, and the
/// vault is not written for it; a new one is saved as any chain state
/// is: a save that fails keeps it in memory, and a later save writes it.
pub(crate) fn keep_sync_failure(state: &mut ManagerState, id: &str, error: &CoreError) {
    let Ok(record) = find_record_mut(&mut state.payload, id) else {
        return;
    };
    let (message, kind) = (error.to_string(), error.code());
    if record
        .meta
        .last_failure
        .as_ref()
        .is_some_and(|kept| kept.kind == kind && kept.message == message)
    {
        return;
    }
    record.meta.last_failure = Some(SyncFailureStamp {
        at: now_secs(),
        message,
        kind,
    });
    if let Err(error) = state.vault.save(&state.payload) {
        log::warn!("a failed sync was not saved with its wallet: {error}");
    }
}

/// Forgets the failure kept with `id`, after a read that stands for a
/// good sync without going through one: confirmations the live watch
/// proved. A sync clears it as it records its stamp.
pub(crate) fn clear_sync_failure(state: &mut ManagerState, id: &str) {
    let Ok(record) = find_record_mut(&mut state.payload, id) else {
        return;
    };
    if record.meta.last_failure.take().is_none() {
        return;
    }
    if let Err(error) = state.vault.save(&state.payload) {
        log::warn!("a cleared sync failure was not saved with its wallet: {error}");
    }
}
