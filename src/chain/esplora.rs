//! Esplora backend: descriptor wallet sync and single-address tracking.

use bdk_esplora::EsploraAsyncExt;
use bdk_esplora::esplora_client::{self, AsyncClient, Builder};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState};

/// Concurrent requests during scans.
const PARALLEL_REQUESTS: usize = 4;
/// Hard cap on fetched address history pages (25 confirmed txs each).
const MAX_HISTORY_PAGES: usize = 20;

/// Socket timeout, seconds. Bounded so that an unreachable instance
/// fails fast and the caller's fallback to the next endpoint actually
/// happens within a tolerable delay.
const TIMEOUT_SECS: u64 = 20;

pub(crate) fn client(url: &str) -> Result<AsyncClient, esplora_client::Error> {
    Builder::new(url).timeout(TIMEOUT_SECS).build_async()
}

pub(crate) async fn full_scan(
    client: &AsyncClient,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
) -> Result<FullScanResponse<KeychainKind>, Box<esplora_client::Error>> {
    client
        .full_scan(request, stop_gap as usize, PARALLEL_REQUESTS)
        .await
}

pub(crate) async fn sync(
    client: &AsyncClient,
    request: SyncRequest<(KeychainKind, u32)>,
) -> Result<SyncResponse, Box<esplora_client::Error>> {
    client.sync(request, PARALLEL_REQUESTS).await
}

/// Fetches the complete state of a single watched address.
pub(crate) async fn fetch_address_state(
    client: &AsyncClient,
    address: &str,
    network: Network,
) -> Result<AddressWatchState, String> {
    let address: Address = address
        .parse::<Address<_>>()
        .map_err(|e| format!("invalid address: {e}"))?
        .require_network(network.to_bitcoin())
        .map_err(|e| format!("address/network mismatch: {e}"))?;
    let our_script = address.script_pubkey();

    let tip_height = client.get_height().await.map_err(|e| e.to_string())?;
    let stats = client
        .get_address_stats(&address)
        .await
        .map_err(|e| e.to_string())?;

    // First page: mempool transactions plus the newest confirmed ones.
    let mut raw_txs = client
        .get_address_txs(&address, None)
        .await
        .map_err(|e| e.to_string())?;
    let confirmed_total = stats.chain_stats.tx_count as usize;
    let mut truncated = false;
    for _ in 0..MAX_HISTORY_PAGES {
        let confirmed_fetched = raw_txs.iter().filter(|t| t.status.confirmed).count();
        if confirmed_fetched >= confirmed_total {
            break;
        }
        let Some(last_seen) = raw_txs
            .iter()
            .rev()
            .find(|t| t.status.confirmed)
            .map(|t| t.txid)
        else {
            break;
        };
        let page = client
            .get_address_txs(&address, Some(last_seen))
            .await
            .map_err(|e| e.to_string())?;
        if page.is_empty() {
            break;
        }
        raw_txs.extend(page);
    }
    if raw_txs.iter().filter(|t| t.status.confirmed).count() < confirmed_total {
        truncated = true;
    }

    let utxos = client
        .get_address_utxos(&address)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|utxo| AddressUtxo {
            txid: utxo.txid.to_string(),
            vout: utxo.vout,
            value_sats: utxo.value.to_sat(),
            height: utxo.status.block_height,
            timestamp: utxo.status.block_time,
        })
        .collect();

    let txs = raw_txs
        .into_iter()
        .map(|tx| {
            let received: u64 = tx
                .vout
                .iter()
                .filter(|v| v.scriptpubkey == our_script)
                .map(|v| v.value)
                .sum();
            let spent: u64 = tx
                .vin
                .iter()
                .filter_map(|v| v.prevout.as_ref())
                .filter(|p| p.scriptpubkey == our_script)
                .map(|p| p.value)
                .sum();
            let inputs = tx
                .vin
                .iter()
                .map(|vin| match &vin.prevout {
                    Some(prevout) => TxIo {
                        address: script_address(&prevout.scriptpubkey, network),
                        value_sats: Some(prevout.value),
                        is_mine: prevout.scriptpubkey == our_script,
                    },
                    None => TxIo {
                        address: None,
                        value_sats: None,
                        is_mine: false,
                    },
                })
                .collect();
            let outputs = tx
                .vout
                .iter()
                .map(|vout| TxIo {
                    address: script_address(&vout.scriptpubkey, network),
                    value_sats: Some(vout.value),
                    is_mine: vout.scriptpubkey == our_script,
                })
                .collect();
            AddressTx {
                txid: tx.txid.to_string(),
                net_sats: received as i64 - spent as i64,
                fee_sats: Some(tx.fee),
                height: tx.status.block_height,
                timestamp: tx.status.block_time,
                vsize: tx.weight.div_ceil(4),
                inputs,
                outputs,
            }
        })
        .collect();

    Ok(AddressWatchState {
        txs,
        utxos,
        tip_height,
        funded_sats: stats.chain_stats.funded_txo_sum + stats.mempool_stats.funded_txo_sum,
        spent_sats: stats.chain_stats.spent_txo_sum + stats.mempool_stats.spent_txo_sum,
        truncated,
    })
}

fn script_address(script: &bdk_wallet::bitcoin::ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network.to_bitcoin())
        .ok()
        .map(|a| a.to_string())
}
