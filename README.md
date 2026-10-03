# gerfaut-core

The Rust core of [Gerfaut](https://github.com/gerfaut-wallet), a Bitcoin watch-only wallet.

![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange) ![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)

> Status: pre-alpha. The library parses descriptors, keys, and addresses, syncs wallets over Esplora and Electrum, and persists everything in an encrypted vault. APIs are still moving.

This library does everything a wallet does, except handle keys. It is the single implementation shared by the mobile app, the desktop app, and the server: all 3 read a descriptor exactly the same way because they all read it here.

## Scope

- Output descriptors and Miniscript (every wallet becomes a descriptor internally)
- Address derivation and wallet state
- Chain data sources: Esplora and Electrum, directly or over Tor
- Encrypted persistence, and encrypted backups that also carry wallets from one device to another

Built on [BDK](https://bitcoindevkit.org) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).

## Watch-only, by design

Gerfaut never touches private keys. This library contains no code to generate keys, handle seeds, or sign transactions, and it never will. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Building

The crate builds with the toolchain pinned in `rust-toolchain.toml`. The checks CI runs, and the tests that need the network or Docker, are in [CONTRIBUTING.md](CONTRIBUTING.md#checks).

An app that depends on this crate copies the `[patch.crates-io]` section at the end of `Cargo.toml` into its own root manifest: Cargo only reads that section there, and without it the Tor client loops forever on Windows.

## Project

| Repository | Role |
|---|---|
| `gerfaut-core` | Core Rust library, this repository |
| [`gerfaut-mobile`](https://github.com/gerfaut-wallet/gerfaut-mobile) | Mobile app (Flutter, Android first) |
| [`gerfaut-desktop`](https://github.com/gerfaut-wallet/gerfaut-desktop) | Desktop app (Tauri v2, for Windows, macOS, and Linux) |
| [`gerfaut-web`](https://github.com/gerfaut-wallet/gerfaut-web) | Website, documentation, downloads |

## License

[AGPL-3.0-only](LICENSE). Commercial licenses are available to integrate gerfaut-core into products with incompatible terms: info@pandul.fr.

The Gerfaut name and logo are not covered by the code license. See [TRADEMARK.md](TRADEMARK.md).

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).
