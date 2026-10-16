//! Transactions handed in by the user: what one does before anything
//! leaves the device, sending it, the last ones sent, and where each
//! stands.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use bdk_wallet::bitcoin::{Address, Amount, OutPoint, Transaction, TxOut, Txid};
use bdk_wallet::chain::CanonicalizationParams;

use crate::broadcast::{
    self, BroadcastReport, BroadcastStatus, InputFacts, OutputFacts, RecentBroadcast, Satisfaction,
    SpentBy, TxPreview, WalletRef,
};
use crate::chain;
use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::now_secs;
use crate::wallet::meta::WalletKind;
use crate::wallet::views;

use super::sync::sync_failure;
use super::{WalletManager, ensure_engine, find_record};

impl WalletManager {
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
                        let coins = wallet_coins(engine, &outpoints);
                        for (i, coin) in coins.into_iter().enumerate() {
                            // A coin of this wallet: unspent, or spent by the one
                            // transaction it holds as canonical.
                            let Some((txout, spender)) = coin else {
                                continue;
                            };
                            // The most its policy can take to sign, whatever
                            // the PSBT says.
                            input_facts[i].satisfaction = engine
                                .derivation_of_spk(txout.script_pubkey.clone())
                                .and_then(|(keychain, _)| {
                                    Satisfaction::of_descriptor(engine.public_descriptor(keychain))
                                });
                            input_facts[i].prevout = Some(txout);
                            input_facts[i].wallet = Some(wallet_ref.clone());
                            input_facts[i].spent = Some(spender.is_some());
                            input_facts[i].spent_by = spender;
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
                                // The server's figure, not a transaction.
                                input_facts[i].listed = true;
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

        // A listing that the previous transaction the PSBT carries
        // contradicts is set aside: the transaction is the coin, the
        // listing a server's figure. Its attribution and its "unspent" go
        // with it, and the coin is looked up as one no wallet holds.
        for (facts, described) in input_facts.iter_mut().zip(&decoded.inputs) {
            let proof = described
                .prevout
                .as_ref()
                .filter(|_| described.prevout_proven);
            if facts.listed
                && let (Some(listed), Some(proof)) = (facts.prevout.clone(), proof)
                && listed != *proof
            {
                *facts = InputFacts {
                    contradicted_listing: facts.wallet.take().map(|wallet| (wallet, listed)),
                    ..InputFacts::default()
                };
            }
        }

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
                                facts.spent_by = chain_facts.spent_by;
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
    /// floor) is returned verbatim. A transaction the network took is
    /// kept among the [`Self::recent_broadcasts`].
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
                    let report = BroadcastReport {
                        txid: decoded.tx.compute_txid().to_string(),
                        backend: endpoint.label(),
                        at: now_secs(),
                    };
                    self.remember_broadcast(network, &decoded.tx, &report).await;
                    return Ok(report);
                }
                Err(detail) => refusals.push((endpoint.label(), detail)),
            }
        }
        Err(broadcast_failure(refusals))
    }

    /// Keeps a transaction the network just took at the head of the
    /// recent broadcasts. Written in place, then saved: the transaction
    /// is on the network whatever the disk says, so a save that fails
    /// costs the next launch its record, never this broadcast its
    /// answer, and the next save that goes through writes it.
    async fn remember_broadcast(
        &self,
        network: Network,
        tx: &Transaction,
        report: &BroadcastReport,
    ) {
        let mut state = self.state.lock().await;
        state.payload.remember_broadcast(RecentBroadcast {
            txid: report.txid.clone(),
            network,
            hex: bdk_wallet::bitcoin::consensus::encode::serialize_hex(tx),
            backend: report.backend.clone(),
            at: report.at,
        });
        if let Err(error) = state.vault.save(&state.payload) {
            log::warn!("a broadcast could not be saved among the recent ones: {error}");
        }
    }

    /// The last transactions this app broadcast on `network`, newest
    /// first, as the vault keeps them across restarts. Nothing is asked
    /// of the backend here: where each stands is
    /// [`Self::transaction_status`], asked when the app wants to know.
    pub async fn recent_broadcasts(&self, network: Network) -> Vec<RecentBroadcast> {
        self.state
            .lock()
            .await
            .payload
            .broadcasts
            .iter()
            .filter(|sent| sent.network == network)
            .cloned()
            .collect()
    }

    /// Drops the vault's record of a broadcast, with no way back. The
    /// transaction itself is on the network and untouched. A txid the
    /// vault does not hold is no error: what was asked is already so.
    pub async fn forget_broadcast(&self, txid: &str) -> CoreResult<()> {
        let mut state = self.state.lock().await;
        if !state
            .payload
            .broadcasts
            .iter()
            .any(|sent| sent.txid == txid)
        {
            return Ok(());
        }
        state.commit(|payload| {
            payload.broadcasts.retain(|sent| sent.txid != txid);
            Ok(())
        })
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
        let scripts = chain::lookup_scripts(&decoded.tx);
        if scripts.is_empty() {
            return Err(CoreError::InvalidInput {
                kind: "transaction",
                detail: "the transaction creates nothing".to_owned(),
            });
        }
        let (config, certs) = self.state.lock().await.chain_setup(network);
        let endpoints = chain::endpoints(&config, network, &certs)?;
        let proxy = self.tor_proxy_for(&endpoints).await?;
        let mut attempts: Vec<String> = Vec::new();
        for endpoint in &endpoints {
            match chain::tx_standing(endpoint, txid, scripts.clone(), proxy.as_deref()).await {
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
}

/// For each outpoint, the coin of the wallet it names and the transaction
/// that spends it, as the wallet holds them canonical; `None` where it
/// names no coin of the wallet. This runs under the manager's lock: a
/// wallet that holds none of the transactions the outpoints come from is
/// passed over without making its graph canonical, and one that holds
/// some has it made canonical once, its spends read once.
fn wallet_coins(
    engine: &bdk_wallet::Wallet,
    outpoints: &[OutPoint],
) -> Vec<Option<(TxOut, Option<SpentBy>)>> {
    let graph = engine.tx_graph();
    if outpoints
        .iter()
        .all(|outpoint| graph.get_tx(outpoint.txid).is_none())
    {
        return vec![None; outpoints.len()];
    }
    let spends: Vec<Vec<Txid>> = outpoints
        .iter()
        .map(|outpoint| graph.outspends(*outpoint).iter().copied().collect())
        .collect();
    let wanted: HashSet<Txid> = outpoints
        .iter()
        .map(|outpoint| outpoint.txid)
        .chain(spends.iter().flatten().copied())
        .collect();
    let chain = engine.local_chain();
    // Each wanted transaction the wallet holds as canonical, with whether
    // it is in a block.
    let canonical: HashMap<Txid, (Arc<Transaction>, bool)> = graph
        .list_canonical_txs(
            chain,
            chain.tip().block_id(),
            CanonicalizationParams::default(),
        )
        .filter(|ctx| wanted.contains(&ctx.tx_node.txid))
        .map(|ctx| {
            (
                ctx.tx_node.txid,
                (ctx.tx_node.tx.clone(), ctx.chain_position.is_confirmed()),
            )
        })
        .collect();
    outpoints
        .iter()
        .zip(&spends)
        .map(|(outpoint, spenders)| {
            let (funding, _) = canonical.get(&outpoint.txid)?;
            let txout = funding.output.get(outpoint.vout as usize)?;
            if !engine.is_mine(txout.script_pubkey.clone()) {
                return None;
            }
            // At most one spend is canonical.
            let spender = spenders.iter().find_map(|txid| {
                canonical.get(txid).map(|&(_, confirmed)| SpentBy {
                    txid: *txid,
                    confirmed,
                })
            });
            Some((txout.clone(), spender))
        })
        .collect()
}

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

#[cfg(test)]
mod tests;
