//! Esplora backend: descriptor wallet sync and single-address tracking.

use bdk_esplora::EsploraAsyncExt;
use bdk_esplora::esplora_client::{self, AsyncClient, Builder};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::address::Address;
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

use bdk_wallet::bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};

use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState, tx_extras};

/// Concurrent requests during scans.
const PARALLEL_REQUESTS: usize = 4;
/// Address history pages fetched per request round (25 confirmed txs
/// each). A sync stays fast; anything older is fetched on demand by
/// [`fetch_address_history`], so nothing stays out of reach.
pub(crate) const HISTORY_PAGES_PER_ROUND: usize = 40;

/// Socket timeout, seconds. Bounded so that an unreachable instance
/// fails fast and the caller's fallback to the next endpoint actually
/// happens within a tolerable delay.
const TIMEOUT_SECS: u64 = 20;
/// Onion endpoints get more room: Tor circuits are slow to build.
const TOR_TIMEOUT_SECS: u64 = 60;

pub(crate) fn client(url: &str) -> Result<AsyncClient, esplora_client::Error> {
    let mut builder = Builder::new(url).timeout(TIMEOUT_SECS);
    if crate::chain::is_onion(url) {
        // socks5h: the proxy resolves the name; .onion never touches DNS.
        builder = builder
            .proxy(&format!("socks5h://{}", crate::chain::TOR_SOCKS_PROXY))
            .timeout(TOR_TIMEOUT_SECS);
    }
    builder.build_async()
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

/// One round of address history: the transactions fetched and, when
/// older ones remain, the cursor to continue from.
pub(crate) struct HistoryRound {
    pub txs: Vec<AddressTx>,
    /// Txid to pass as `from` to fetch the next round; `None` when the
    /// history is exhausted.
    pub cursor: Option<String>,
}

/// Fetches the complete state of a single watched address.
pub(crate) async fn fetch_address_state(
    client: &AsyncClient,
    address: &str,
    network: Network,
) -> Result<AddressWatchState, String> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();

    let tip_height = client.get_height().await.map_err(|e| e.to_string())?;
    let stats = client
        .get_address_stats(&address)
        .await
        .map_err(|e| e.to_string())?;

    let round = history_round(
        client,
        &address,
        &our_script,
        network,
        None,
        Some(stats.chain_stats.tx_count as usize),
    )
    .await?;

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

    Ok(AddressWatchState {
        txs: round.txs,
        utxos,
        tip_height,
        funded_sats: stats.chain_stats.funded_txo_sum + stats.mempool_stats.funded_txo_sum,
        spent_sats: stats.chain_stats.spent_txo_sum + stats.mempool_stats.spent_txo_sum,
        truncated: round.cursor.is_some(),
        history_cursor: round.cursor,
    })
}

/// Fetches the next round of older transactions, continuing after
/// `from`. Used by "load older transactions": the balance and the UTXO
/// set already cover the full history, only the list grows.
pub(crate) async fn fetch_address_history(
    client: &AsyncClient,
    address: &str,
    network: Network,
    from: &str,
) -> Result<HistoryRound, String> {
    let address = parse_address(address, network)?;
    let our_script = address.script_pubkey();
    let from: Txid = from
        .parse()
        .map_err(|_| format!("invalid history cursor: {from}"))?;
    history_round(client, &address, &our_script, network, Some(from), None).await
}

fn parse_address(address: &str, network: Network) -> Result<Address, String> {
    address
        .parse::<Address<_>>()
        .map_err(|e| format!("invalid address: {e}"))?
        .require_network(network.to_bitcoin())
        .map_err(|e| format!("address/network mismatch: {e}"))
}

/// Pages through the address history from `from` (newest first when
/// `None`), at most [`HISTORY_PAGES_PER_ROUND`] pages.
async fn history_round(
    client: &AsyncClient,
    address: &Address,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
    from: Option<Txid>,
    confirmed_total: Option<usize>,
) -> Result<HistoryRound, String> {
    let mut raw_txs = client
        .get_address_txs(address, from)
        .await
        .map_err(|e| e.to_string())?;
    let mut cursor: Option<String> = None;
    let mut pages = 1usize;
    loop {
        // The whole history is in hand: `confirmed_total` counts it from
        // the address stats, so no probing request is needed.
        if let Some(total) = confirmed_total
            && raw_txs.iter().filter(|t| t.status.confirmed).count() >= total
        {
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
        if pages >= HISTORY_PAGES_PER_ROUND {
            cursor = Some(last_seen.to_string());
            break;
        }
        let page = client
            .get_address_txs(address, Some(last_seen))
            .await
            .map_err(|e| e.to_string())?;
        pages += 1;
        if page.is_empty() {
            break;
        }
        raw_txs.extend(page);
    }

    let txs = raw_txs
        .into_iter()
        .map(|tx| to_address_tx(tx, our_script, network))
        .collect();
    Ok(HistoryRound { txs, cursor })
}

/// One esplora transaction as seen from the watched address.
fn to_address_tx(
    tx: esplora_client::api::Tx,
    our_script: &bdk_wallet::bitcoin::ScriptBuf,
    network: Network,
) -> AddressTx {
    let received: u64 = tx
        .vout
        .iter()
        .filter(|v| v.scriptpubkey == *our_script)
        .map(|v| v.value)
        .sum();
    let spent: u64 = tx
        .vin
        .iter()
        .filter_map(|v| v.prevout.as_ref())
        .filter(|p| p.scriptpubkey == *our_script)
        .map(|p| p.value)
        .sum();
    let inputs = tx
        .vin
        .iter()
        .map(|vin| match &vin.prevout {
            Some(prevout) => TxIo {
                address: script_address(&prevout.scriptpubkey, network),
                value_sats: Some(prevout.value),
                is_mine: prevout.scriptpubkey == *our_script,
                ..TxIo::default()
            },
            None => TxIo::default(),
        })
        .collect();
    let outputs = tx
        .vout
        .iter()
        .map(|vout| TxIo {
            address: script_address(&vout.scriptpubkey, network),
            value_sats: Some(vout.value),
            is_mine: vout.scriptpubkey == *our_script,
            change: false,
            op_return: tx_extras::op_return_of(&vout.scriptpubkey),
        })
        .collect();
    // A coinbase transaction has no fee; Esplora reports 0.
    let is_coinbase = tx.vin.first().is_some_and(|vin| vin.is_coinbase);
    // The prevouts Esplora attaches to each input make the deep
    // analysis (taproot spend, sigops) as accurate as the API is.
    let prevouts: std::collections::HashMap<OutPoint, TxOut> = tx
        .vin
        .iter()
        .filter_map(|vin| {
            vin.prevout.as_ref().map(|p| {
                (
                    OutPoint::new(vin.txid, vin.vout),
                    TxOut {
                        value: Amount::from_sat(p.value),
                        script_pubkey: p.scriptpubkey.clone(),
                    },
                )
            })
        })
        .collect();
    let extras = tx_extras::analyze(&tx.to_tx(), |op| prevouts.get(op).cloned());
    AddressTx {
        txid: tx.txid.to_string(),
        net_sats: received as i64 - spent as i64,
        fee_sats: (!is_coinbase).then_some(tx.fee),
        height: tx.status.block_height,
        timestamp: tx.status.block_time,
        vsize: tx.weight.div_ceil(4),
        inputs,
        outputs,
        extras: Some(extras),
    }
}

fn script_address(script: &bdk_wallet::bitcoin::ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network.to_bitcoin())
        .ok()
        .map(|a| a.to_string())
}

// --- broadcast ------------------------------------------------------------

/// Hands a signed transaction to the network through this instance.
/// The instance's own node validates it; its refusal comes back as the
/// message, verbatim, which is the most useful thing to show.
pub(crate) async fn broadcast(client: &AsyncClient, tx: &Transaction) -> Result<(), String> {
    client.broadcast(tx).await.map_err(|e| broadcast_error(&e))
}

/// Esplora wraps the node's refusal in an HTTP error whose body is the
/// reason (`sendrawtransaction RPC error: {"code":-26,"message":"..."}`);
/// keep the message, drop the wrapping.
fn broadcast_error(error: &esplora_client::Error) -> String {
    let text = error.to_string();
    if let Some(start) = text.find("\"message\":\"") {
        let rest = &text[start + 11..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_owned();
        }
    }
    text
}

/// The output an input spends, and whether it is already spent.
pub(crate) struct PrevoutFacts {
    pub txout: Option<TxOut>,
    pub spent: Option<bool>,
}

/// Fetches a previous output. `None` in `txout` means the backend does
/// not know the transaction at all.
pub(crate) async fn fetch_prevout(
    client: &AsyncClient,
    outpoint: OutPoint,
) -> Result<PrevoutFacts, String> {
    let tx = client
        .get_tx(&outpoint.txid)
        .await
        .map_err(|e| e.to_string())?;
    let Some(tx) = tx else {
        return Ok(PrevoutFacts {
            txout: None,
            spent: None,
        });
    };
    let txout = tx.output.get(outpoint.vout as usize).cloned();
    let spent = client
        .get_output_status(&outpoint.txid, outpoint.vout as u64)
        .await
        .ok()
        .flatten()
        .map(|status| status.spent);
    Ok(PrevoutFacts { txout, spent })
}

/// Where a transaction stands: unknown, in the mempool, or at a height.
pub(crate) struct TxStanding {
    pub found: bool,
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub tip_height: u32,
}

pub(crate) async fn tx_standing(client: &AsyncClient, txid: &Txid) -> Result<TxStanding, String> {
    let tip_height = client.get_height().await.map_err(|e| e.to_string())?;
    let found = client
        .get_tx_info(txid)
        .await
        .map_err(|e| e.to_string())?
        .is_some();
    if !found {
        return Ok(TxStanding {
            found: false,
            confirmed: false,
            block_height: None,
            tip_height,
        });
    }
    let status = client
        .get_tx_status(txid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(TxStanding {
        found: true,
        confirmed: status.confirmed,
        block_height: status.block_height,
        tip_height,
    })
}
