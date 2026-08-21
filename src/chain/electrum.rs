//! Electrum backend: descriptor wallet sync over the user's own server.
//!
//! The Electrum client is blocking; callers run these functions inside
//! `spawn_blocking`.

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::{self, Client};
use bdk_wallet::KeychainKind;
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

/// Requests per Electrum batch call.
const BATCH_SIZE: usize = 10;

pub(crate) fn full_scan_blocking(
    url: &str,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
) -> Result<FullScanResponse<KeychainKind>, electrum_client::Error> {
    let client = BdkElectrumClient::new(Client::new(url)?);
    client.full_scan(request, stop_gap as usize, BATCH_SIZE, true)
}

pub(crate) fn sync_blocking(
    url: &str,
    request: SyncRequest<(KeychainKind, u32)>,
) -> Result<SyncResponse, electrum_client::Error> {
    let client = BdkElectrumClient::new(Client::new(url)?);
    client.sync(request, BATCH_SIZE, true)
}
