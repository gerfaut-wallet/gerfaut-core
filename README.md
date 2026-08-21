# gerfaut-core

The Rust core of [Gerfaut](https://github.com/gerfaut-wallet), a Bitcoin watch-only wallet.

![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange) ![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)

> Status: pre-development. The repository only holds conventions and scaffolding for now, no code yet.

This library does everything a wallet does, except handle keys. It is the single implementation shared by the mobile app, the desktop app, and the server: all 3 read a descriptor exactly the same way because they all read it here.

## Scope

- Output descriptors and Miniscript (every wallet becomes a descriptor internally)
- Address derivation and wallet state
- Chain data sources (Esplora first)
- Encrypted persistence and end-to-end encrypted sync payloads

Built on [BDK](https://bitcoindevkit.org) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).

## Watch-only, by design

Gerfaut never touches private keys. This library contains no code to generate keys, handle seeds, or sign transactions, and it never will. See [CONTRIBUTING.md](CONTRIBUTING.md).

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
