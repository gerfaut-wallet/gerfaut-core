<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/images/mark-dark.svg">
  <img src=".github/images/mark-light.svg" alt="" width="64">
</picture>

# gerfaut-core

The Rust library behind [Gerfaut](https://gerfaut-wallet.com), a Bitcoin watch-only wallet. The [desktop app](https://github.com/gerfaut-wallet/gerfaut-desktop) and the [Android app](https://github.com/gerfaut-wallet/gerfaut-mobile) both call it for everything but their interface, so they read a descriptor, sync a wallet and word a notification the same way.

[![CI](https://github.com/gerfaut-wallet/gerfaut-core/actions/workflows/ci.yml/badge.svg)](https://github.com/gerfaut-wallet/gerfaut-core/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE)

The crate contains no code to generate keys, handle seeds or sign transactions, and never will. Input that holds a private key is refused at the parser, and checked again before any wallet is created.

## What it covers

- Import: output descriptors and Miniscript, BIP-389 multipath descriptors, extended keys with SLIP-132 prefixes, addresses and payment URIs, BSMS records (BIP-129), Sparrow and Coldcard exports, and QR codes in UR or BBQr, animated ones included. Everything becomes a descriptor.
- Wallets: address derivation with a gap limit, balances, history, UTXOs, and the spending paths of a Miniscript policy with each timelock measured against the chain.
- Chain: Esplora and Electrum, public or self-hosted, with self-signed Electrum certificates pinned by fingerprint. `.onion` hosts go through a system Tor, or through [arti](https://gitlab.torproject.org/tpo/core/arti) with the `embedded-tor` feature.
- Live watch: one connection held open to the backend, through Electrum subscriptions, the WebSocket of a mempool instance or polling, and the text of every notification the apps post.
- Broadcast: a raw transaction or a PSBT decoded and checked, then sent through the configured backend.
- Storage: a vault sealed with XChaCha20-Poly1305, and backups sealed under a password with Argon2id that move wallets between devices.

It is built on [BDK](https://bitcoindevkit.org) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).

## Use it

The crate is not on crates.io. Depend on it through git, pinned to a commit:

```toml
[dependencies]
gerfaut-core = { git = "https://github.com/gerfaut-wallet/gerfaut-core", rev = "<commit>" }
```

With `features = ["embedded-tor"]`, also copy the `[patch.crates-io]` section at the end of this crate's `Cargo.toml` into your root manifest. Cargo only reads that section there, and without it the Tor client hangs on Windows.

Everything goes through `WalletManager`, which owns the encrypted vault. Its API is async, on tokio:

```rust
use gerfaut_core::input::parse_input;
use gerfaut_core::store::VaultKey;
use gerfaut_core::{Network, WalletManager};

#[tokio::main]
async fn main() -> gerfaut_core::CoreResult<()> {
    let descriptor = std::env::args()
        .nth(1)
        .expect("a descriptor, an xpub or an address");
    let passphrase =
        std::env::var("VAULT_PASSPHRASE").expect("the vault passphrase in VAULT_PASSPHRASE");

    let manager = WalletManager::open("gerfaut-data", VaultKey::Password(passphrase))?;
    let parsed = parse_input(&descriptor)?;
    let wallet = manager
        .add_wallet("Cold storage", &parsed, Network::Signet)
        .await?;

    let report = manager.sync_wallet(&wallet.id).await?;
    println!(
        "{} sat at block {}",
        report.balance.total, report.tip_height
    );
    Ok(())
}
```

Run it with a signet descriptor as its argument and a passphrase in `VAULT_PASSPHRASE`: it creates the vault in `gerfaut-data`, adds the wallet and prints its balance after one sync.

`cargo doc --no-deps --open` builds the API reference. The module map is in [CONTRIBUTING.md](CONTRIBUTING.md#where-things-are). Every 0.x release can change the API.

## Develop

The toolchain is pinned in `rust-toolchain.toml`. CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features embedded-tor -- -D warnings
cargo test
```

`cargo test` stays offline. The tests that need public servers, Tor or Docker are marked `#[ignore]`, and [CONTRIBUTING.md](CONTRIBUTING.md#checks) gives the command for each.

## Contributing

Bug reports and pull requests are welcome. Report a problem you saw in an app in that app's issues, and a problem in the library [here](https://github.com/gerfaut-wallet/gerfaut-core/issues). Open an issue before any change beyond a small fix, and read [CONTRIBUTING.md](CONTRIBUTING.md) first: it explains the license of contributions and the one hard rule, which is that the crate stays watch-only.

## Security

Do not report a vulnerability in a public issue. Use [private vulnerability reporting](https://github.com/gerfaut-wallet/gerfaut-core/security/advisories/new) or write to info@pandul.fr. [SECURITY.md](SECURITY.md) lists what is in scope and what to expect.

## License

[AGPL-3.0-only](LICENSE). Commercial licenses for products whose terms are incompatible with the AGPL: info@pandul.fr.

The Gerfaut name and logo are not covered by the code license. See [TRADEMARK.md](TRADEMARK.md).
