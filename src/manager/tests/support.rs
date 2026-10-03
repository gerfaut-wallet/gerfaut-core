//! What the tests of the facade share: a manager on a vault of its
//! own, the wallets it watches, and a premium account this device is
//! connected to.

use crate::input::parse_input;
use crate::manager::WalletManager;
use crate::network::Network;
use crate::premium::PremiumState;
use crate::store::VaultKey;
use crate::wallet::meta::WalletMeta;

pub(crate) const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";

pub(crate) fn key() -> VaultKey {
    VaultKey::Raw([9u8; 32])
}

pub(crate) async fn manager(dir: &std::path::Path) -> WalletManager {
    WalletManager::open(dir, key()).unwrap()
}

/// The token of the device the premium tests speak for.
pub(crate) const TOKEN: &str = "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA";

/// `premium` on a device the key connected.
pub(crate) fn connected(premium: PremiumState) -> PremiumState {
    PremiumState {
        device: Some(crate::premium::DeviceCredential::new(
            "0f3b7c2e-1a2b-4c3d-8e9f-a0b1c2d3e4f5".to_owned(),
            TOKEN.to_owned(),
            1_790_000_000,
        )),
        ..premium
    }
}

/// Writes the premium state as it is, the device's connection
/// included, which [`WalletManager::set_premium_state`] leaves to the
/// core.
pub(crate) async fn store_premium(manager: &WalletManager, premium: PremiumState) {
    manager
        .state
        .lock()
        .await
        .commit(|payload| {
            payload.settings.premium = premium;
            Ok(())
        })
        .unwrap();
}

/// The premium state as the vault holds it, token included.
pub(crate) async fn stored_premium(manager: &WalletManager) -> PremiumState {
    manager.state.lock().await.payload.settings.premium.clone()
}

pub(crate) const BACKUP_PASSWORD: &str = "correct horse battery staple";
pub(crate) const ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

/// A manager watching a descriptor wallet and a single address.
pub(crate) async fn seeded(dir: &std::path::Path) -> (WalletManager, WalletMeta, WalletMeta) {
    let manager = manager(dir).await;
    let cold = manager
        .add_wallet("Cold", &parse_input(MULTIPATH).unwrap(), Network::Signet)
        .await
        .unwrap();
    let watch = manager
        .add_wallet("Watch", &parse_input(ADDRESS).unwrap(), Network::Signet)
        .await
        .unwrap();
    (manager, cold, watch)
}

/// A loopback port nothing listens on: a system Tor that is not
/// there, without depending on what runs on this machine.
pub(crate) async fn closed_port() -> String {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    address
}
