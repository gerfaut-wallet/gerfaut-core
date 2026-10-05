//! What the tests of the facade share: a manager on a vault of its
//! own, and the wallets it watches.

use crate::input::parse_input;
use crate::manager::WalletManager;
use crate::network::Network;
use crate::store::VaultKey;
use crate::wallet::meta::WalletMeta;

pub(crate) const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";

pub(crate) fn key() -> VaultKey {
    VaultKey::Raw([9u8; 32])
}

pub(crate) async fn manager(dir: &std::path::Path) -> WalletManager {
    WalletManager::open(dir, key()).unwrap()
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
