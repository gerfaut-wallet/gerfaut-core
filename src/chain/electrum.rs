//! Electrum backend: descriptor wallet sync over the user's own server.
//!
//! The Electrum client is blocking; callers run these functions inside
//! `spawn_blocking`.

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::{self, Client, Config, ElectrumApi, Socks5Config};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

/// Requests per Electrum batch call.
const BATCH_SIZE: usize = 10;
/// Socket timeout. Without it a stalled server blocks the sync forever
/// inside `spawn_blocking`, with no way to cancel.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Onion endpoints get more room: Tor circuits are slow to build.
const TOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn client(url: &str) -> Result<BdkElectrumClient<Client>, electrum_client::Error> {
    let mut builder = Config::builder();
    if crate::chain::is_onion(url) {
        builder = builder
            .socks5(Some(Socks5Config::new(crate::chain::TOR_SOCKS_PROXY)))
            .timeout(Some(TOR_TIMEOUT));
    } else {
        builder = builder.timeout(Some(TIMEOUT));
    }
    Ok(BdkElectrumClient::new(Client::from_config(
        url,
        builder.build(),
    )?))
}

pub(crate) fn full_scan_blocking(
    url: &str,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
) -> Result<FullScanResponse<KeychainKind>, electrum_client::Error> {
    client(url)?.full_scan(request, stop_gap as usize, BATCH_SIZE, true)
}

pub(crate) fn sync_blocking(
    url: &str,
    request: SyncRequest<(KeychainKind, u32)>,
) -> Result<SyncResponse, electrum_client::Error> {
    client(url)?.sync(request, BATCH_SIZE, true)
}

// --- broadcast ------------------------------------------------------------

pub(crate) fn broadcast_blocking(url: &str, tx: &Transaction) -> Result<Txid, String> {
    client(url)
        .map_err(|e| e.to_string())?
        .inner
        .transaction_broadcast(tx)
        .map_err(|e| broadcast_error(&e))
}

/// Electrum returns the node's refusal as a protocol error whose
/// message is the reason; keep that.
fn broadcast_error(error: &electrum_client::Error) -> String {
    match error {
        electrum_client::Error::Protocol(value) => value
            .get("message")
            .and_then(|m| m.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string()),
        other => other.to_string(),
    }
}

/// The output an input spends. Electrum has no "is it spent" call
/// without the script's whole history, which is more than a preview
/// needs: spent-ness stays unknown here and the node says so on
/// broadcast.
pub(crate) fn fetch_prevout_blocking(
    url: &str,
    outpoint: OutPoint,
) -> Result<Option<TxOut>, String> {
    let client = client(url).map_err(|e| e.to_string())?;
    match client.inner.transaction_get(&outpoint.txid) {
        Ok(tx) => Ok(tx.output.get(outpoint.vout as usize).cloned()),
        Err(electrum_client::Error::Protocol(_)) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Where a transaction stands, read off the history of one of its
/// output scripts: height 0 means mempool, a height means confirmed,
/// absence means the server does not have it.
pub(crate) fn tx_standing_blocking(
    url: &str,
    txid: &Txid,
    script: &ScriptBuf,
) -> Result<(bool, Option<u32>, u32), String> {
    let client = client(url).map_err(|e| e.to_string())?;
    let tip = client
        .inner
        .block_headers_subscribe()
        .map_err(|e| e.to_string())?
        .height as u32;
    let history = client
        .inner
        .script_get_history(script)
        .map_err(|e| e.to_string())?;
    let entry = history.iter().find(|entry| entry.tx_hash == *txid);
    Ok(match entry {
        None => (false, None, tip),
        Some(entry) if entry.height > 0 => (true, Some(entry.height as u32), tip),
        Some(_) => (true, None, tip),
    })
}
