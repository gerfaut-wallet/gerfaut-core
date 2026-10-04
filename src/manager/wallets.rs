//! The wallets: adding, naming, ordering and removing them, and what
//! the screens read of each one.

use crate::error::{CoreError, CoreResult};
use crate::export::{ExportOptions, ExportResult};
use crate::input::{ParsedInput, ParsedPayload};
use crate::network::Network;
use crate::now_secs;
use crate::store::WalletRecord;
use crate::wallet::meta::{WalletIcon, WalletKind, WalletMeta};
use crate::wallet::policy::{self, PolicySnapshot};
use crate::wallet::snapshot::{AddressEntry, AddressList, TxDetail, UtxoInfo, WalletSnapshot};
use crate::wallet::views;

use super::{
    WalletManager, build_record, ensure_engine, find_record, find_record_mut, find_watched,
    fresh_meta, merge_changeset,
};

impl WalletManager {
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

    /// Pins a wallet to the live watch, or unpins it. The scripts of the
    /// pinned wallets are watched before any other wallet's, up to what
    /// a watch takes of one wallet; the others share what is left, the
    /// wallets holding coins first. An advanced setting, off unless set,
    /// kept in the vault and carried by a backup.
    pub async fn set_wallet_live_pinned(&self, id: &str, pinned: bool) -> CoreResult<()> {
        let result = self.state.lock().await.commit(|payload| {
            find_record_mut(payload, id)?.meta.live_pinned = pinned;
            Ok(())
        });
        self.live_refresh().await;
        result
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
    /// With the key logged out, the removal waits for that same key to
    /// be entered again.
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
                payload.vanishing.retain(|missed| missed.wallet_id != id);
                let premium = &mut payload.settings.premium;
                let account = premium.has_key() || premium.pending_unwatch_account.is_some();
                if account && premium.is_consented(id) {
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
                    .map(|s| (!s.txs.is_empty(), views::address_balance(s).total))
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
}

#[cfg(test)]
mod tests;
