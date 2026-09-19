//! Live alerts: the watcher of [`crate::watch`] wired to the vault.
//!
//! [`crate::watch::LiveWatch`] says "this wallet moved" and knows
//! nothing of the vault. Here the manager, which owns the vault,
//! answers: it syncs the wallet that was named, with the sync every
//! other caller uses, and turns what that sync found into events. One
//! process holds one manager, so the watch, the syncs it triggers and
//! the record of what was announced all have a single owner, however
//! many isolates or tasks call in.
//!
//! # For the apps
//!
//! - [`WalletManager::live_start`] returns the single receiver of the
//!   events. Consume it from one task, in Rust: a desktop window that
//!   is minimised throttles its timers, a Tauri task does not care.
//! - [`LiveEvent::Transaction`] is what to announce: a transaction
//!   seen for the first time, in the mempool or already in a block,
//!   and later its first confirmation. Each is handed out once, and
//!   the record of that lives in the vault: a restart, a second
//!   isolate or a background job syncing on its own never makes it
//!   twice. A caller that announces from a sync report of its own
//!   takes it through [`WalletManager::claim_announcements`] first.
//! - Settings and wallets change under a running watch without any
//!   call from the app: the backend, the network, Tor, an accepted
//!   certificate, a wallet added or removed, the scripts a sync
//!   revealed.
//! - [`WalletManager::live_tick`] is for a host whose timers stop
//!   while it sleeps: call it from an alarm every few minutes, and
//!   when the network comes back.
//! - Stop the watch before the vault locks.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::error::CoreResult;
use crate::manager::WalletManager;
use crate::network::Network;
use crate::store::{Announced, TxStage};
use crate::wallet::snapshot::SyncReport;
use crate::watch::{ChangeReason, LiveWatch, WatchConfig, WatchEvent, WatchStatus, WatchedWallet};

/// Announcements remembered. Past this the oldest are forgotten, which
/// costs nothing: a sync reports a transaction once, and the record
/// only has to outlive the callers racing for that one report.
pub(crate) const ANNOUNCED_MAX: usize = 2_000;
/// Events held for a consumer that lags.
const EVENT_QUEUE: usize = 256;
/// When a change was pushed and the sync found nothing, the sync is
/// run again after these delays: with the automatic backend the push
/// comes from one server and the sync reads another, which may hear of
/// the transaction a moment later.
const RETRIES: [Duration; 2] = [Duration::from_secs(3), Duration::from_secs(10)];

/// One transaction to announce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTx {
    pub wallet_id: String,
    pub txid: String,
    /// Net effect on the wallet, in satoshis.
    pub net_sats: i64,
    pub stage: TxStage,
}

/// What a running live watch says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// Announce this. Handed out once per transaction and stage.
    Transaction(LiveTx),
    /// A wallet was synced because it moved: refresh what shows it.
    WalletSynced {
        report: SyncReport,
    },
    /// The sync a change asked for failed; the next change, or the
    /// next regular sync, tries again.
    SyncFailed {
        wallet_id: String,
        message: String,
    },
    NewBlock {
        height: u32,
    },
    Status(WatchStatus),
}

/// The single receiver of the live events.
#[derive(Debug)]
pub struct LiveEvents {
    events: mpsc::Receiver<LiveEvent>,
}

impl LiveEvents {
    /// The next event; `None` once the watch has stopped.
    pub async fn next(&mut self) -> Option<LiveEvent> {
        self.events.recv().await
    }
}

/// A running watch, kept by the manager.
pub(crate) struct Running {
    watch: LiveWatch,
    config: WatchConfig,
}

impl WalletManager {
    /// Starts the live watch of the active network, or starts it over:
    /// a watch already running is stopped and its receiver closes.
    /// Must be called inside a tokio runtime.
    pub async fn live_start(&self) -> CoreResult<LiveEvents> {
        self.live_start_with(None).await
    }

    pub(crate) async fn live_start_with(
        &self,
        timings: Option<crate::watch::Timings>,
    ) -> CoreResult<LiveEvents> {
        let mut running = self.live.lock().await;
        if let Some(previous) = running.take() {
            previous.watch.stop();
        }
        let config = self.watch_config().await;
        let wallets = self.watch_list(config.network).await;
        let (watch, mut changes) = LiveWatch::start_with(config.clone(), wallets, timings);
        *running = Some(Running { watch, config });

        let (events, receiver) = mpsc::channel(EVENT_QUEUE);
        let manager = self.clone();
        tokio::spawn(async move {
            while let Some(change) = changes.next().await {
                match change {
                    WatchEvent::WalletChanged {
                        wallet_id,
                        reason,
                        rescan,
                    } => {
                        // Its own task: one wallet that takes long to
                        // sync never holds back the others.
                        let manager = manager.clone();
                        let events = events.clone();
                        tokio::spawn(async move {
                            manager.live_sync(&wallet_id, reason, rescan, &events).await;
                        });
                    }
                    WatchEvent::NewBlock { height } => {
                        let _ = events.send(LiveEvent::NewBlock { height }).await;
                    }
                    WatchEvent::Status(status) => {
                        let _ = events.send(LiveEvent::Status(status)).await;
                    }
                }
            }
        });
        Ok(LiveEvents { events: receiver })
    }

    /// Stops the live watch and closes its connection. Idempotent.
    pub async fn live_stop(&self) {
        if let Some(running) = self.live.lock().await.take() {
            running.watch.stop();
        }
    }

    /// Checks the connection now; see [`LiveWatch::tick`]. Nothing
    /// when no watch runs.
    pub async fn live_tick(&self) {
        if let Some(running) = self.live.lock().await.as_ref() {
            running.watch.tick();
        }
    }

    /// Where the watch stands; off when none runs.
    pub async fn live_status(&self) -> WatchStatus {
        match self.live.lock().await.as_ref() {
            Some(running) => running.watch.status(),
            None => WatchStatus::default(),
        }
    }

    /// Hands a running watch the settings and the wallets as they are
    /// now. Every change that matters calls this; with no watch running
    /// it costs a lock.
    pub(crate) async fn live_refresh(&self) {
        let mut running = self.live.lock().await;
        let Some(running) = running.as_mut() else {
            return;
        };
        let config = self.watch_config().await;
        let wallets = self.watch_list(config.network).await;
        if config == running.config {
            running.watch.set_wallets(wallets);
        } else {
            running.config = config.clone();
            running.watch.reconfigure(config, wallets);
        }
    }

    /// What the watcher needs to reach the backend of the active
    /// network: a copy of four settings, and nothing of the wallets.
    pub async fn watch_config(&self) -> WatchConfig {
        let state = self.state.lock().await;
        let settings = &state.payload.settings;
        WatchConfig {
            network: settings.active_network,
            backend: settings.backend_for(settings.active_network),
            electrum_certs: settings.electrum_certs.clone(),
            tor: settings.tor.clone(),
            data_dir: state.data_dir.clone(),
            keepalive_secs: None,
        }
    }

    /// The scripts of every wallet of a network, in the order a
    /// transport should cover them; see
    /// [`crate::wallet::views::watch_scripts`]. A wallet whose engine
    /// cannot be loaded is left out.
    pub async fn watch_list(&self, network: Network) -> Vec<WatchedWallet> {
        let mut state = self.state.lock().await;
        let gap_limit = state.payload.settings.gap_limit;
        let ids: Vec<String> = state
            .payload
            .wallets
            .iter()
            .filter(|record| record.meta.network == network)
            .map(|record| record.meta.id.clone())
            .collect();
        ids.into_iter()
            .filter_map(|id| crate::manager::watched_wallet(&mut state, &id, gap_limit))
            .collect()
    }

    /// Of what a sync report lists, what nobody has announced yet, now
    /// recorded as announced. The record is in the vault, so the answer
    /// holds across restarts and across every caller of this process: a
    /// transaction is handed out once when it shows up and once when it
    /// confirms, whoever asks first.
    pub async fn claim_announcements(&self, report: &SyncReport) -> CoreResult<Vec<LiveTx>> {
        let stage_of = |confirmed: bool| {
            if confirmed {
                TxStage::Confirmed
            } else {
                TxStage::Mempool
            }
        };
        let listed = report
            .new_txs
            .iter()
            .map(|tx| (tx, stage_of(tx.confirmed)))
            .chain(
                report
                    .confirmed_txs
                    .iter()
                    .map(|tx| (tx, TxStage::Confirmed)),
            );
        let mut state = self.state.lock().await;
        let mut claimed: Vec<LiveTx> = Vec::new();
        for (tx, stage) in listed {
            let told = |entry: &Announced| {
                entry.txid == tx.txid && (entry.stage == stage || entry.stage == TxStage::Confirmed)
            };
            if state.payload.announced.iter().any(told)
                || claimed
                    .iter()
                    .any(|c| c.txid == tx.txid && c.stage == stage)
            {
                continue;
            }
            claimed.push(LiveTx {
                wallet_id: report.wallet_id.clone(),
                txid: tx.txid.clone(),
                net_sats: tx.net_sats,
                stage,
            });
        }
        if claimed.is_empty() {
            return Ok(claimed);
        }
        state.commit(|payload| {
            payload.announced.extend(claimed.iter().map(|tx| Announced {
                txid: tx.txid.clone(),
                stage: tx.stage,
            }));
            let excess = payload.announced.len().saturating_sub(ANNOUNCED_MAX);
            payload.announced.drain(..excess);
            Ok(())
        })?;
        Ok(claimed)
    }

    /// The sync a change asked for, and what it amounts to.
    async fn live_sync(
        &self,
        wallet_id: &str,
        reason: ChangeReason,
        rescan: bool,
        events: &mpsc::Sender<LiveEvent>,
    ) {
        // A wallet that was never synced holds its whole history as
        // "new": that is an import, not news.
        let first_sync = self
            .list_wallets(None)
            .await
            .iter()
            .find(|meta| meta.id == wallet_id)
            .is_none_or(|meta| meta.last_sync.is_none());
        let sync = async || {
            if rescan {
                self.rescan_wallet(wallet_id).await
            } else {
                self.sync_wallet(wallet_id).await
            }
        };
        let mut outcome = sync().await;
        for delay in RETRIES {
            let found_nothing = matches!(
                &outcome,
                Ok(report) if report.new_txs.is_empty() && report.confirmed_txs.is_empty()
            );
            if reason != ChangeReason::Activity || !found_nothing {
                break;
            }
            tokio::time::sleep(delay).await;
            outcome = sync().await;
        }
        match outcome {
            Ok(report) => {
                match self.claim_announcements(&report).await {
                    Ok(claimed) if !first_sync => {
                        for tx in claimed {
                            let _ = events.send(LiveEvent::Transaction(tx)).await;
                        }
                    }
                    _ => {}
                }
                let _ = events.send(LiveEvent::WalletSynced { report }).await;
            }
            Err(error) => {
                let _ = events
                    .send(LiveEvent::SyncFailed {
                        wallet_id: wallet_id.to_owned(),
                        message: error.to_string(),
                    })
                    .await;
            }
        }
    }
}
