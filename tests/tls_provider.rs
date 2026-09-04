//! Which TLS backend actually serves.
//!
//! Two are compiled in: `electrum-client`'s `rustls` feature turns on
//! `rustls/default`, which brings `aws-lc-rs` along even under
//! `use-rustls-ring`. `rustls` then has no single obvious default, and
//! the first caller to install one decides for the whole process, so
//! `WalletManager::open` installs ring before anything can open a
//! socket.
//!
//! This lives in its own file on purpose: an integration test gets a
//! process of its own, and the question here is precisely who got there
//! first. Asked from inside the unit-test binary, the answer would
//! depend on which other test ran before it.

use gerfaut_core::manager::WalletManager;
use gerfaut_core::store::VaultKey;
use rustls::crypto::CryptoProvider;

/// Key exchange groups tell the two backends apart: ring offers three,
/// `aws-lc-rs` leads with a post-quantum hybrid.
fn groups(provider: &CryptoProvider) -> Vec<String> {
    provider
        .kx_groups
        .iter()
        .map(|group| format!("{:?}", group.name()))
        .collect()
}

#[test]
fn opening_a_vault_settles_the_tls_backend_on_ring() {
    assert!(
        CryptoProvider::get_default().is_none(),
        "nothing may install a backend before the vault opens"
    );

    let dir = tempfile::tempdir().unwrap();
    let _manager = WalletManager::open(dir.path(), VaultKey::Raw([7u8; 32])).unwrap();

    let installed = CryptoProvider::get_default().expect("opening a vault installs one");
    assert_eq!(
        groups(installed),
        groups(&rustls::crypto::ring::default_provider())
    );
}
