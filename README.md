# gerfaut-core

**The Rust core of [Gerfaut](https://github.com/gerfaut-wallet), a Bitcoin watch-only wallet.**

![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange) ![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)

> **Status: pre-development.** Repository conventions and scaffolding only — no code yet.

Everything a wallet does, except keys. This library is the single implementation shared by the mobile app, the desktop app, and the server: all three read a descriptor exactly the same way because they all read it here.

## Scope

- Output descriptors and Miniscript — every wallet becomes a descriptor internally
- Address derivation and wallet state
- Chain data sources (Esplora first)
- Encrypted persistence and end-to-end-encrypted sync payloads

Built on [BDK](https://bitcoindevkit.org) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).

## Watch-only, by design

Gerfaut never touches private keys. This library contains **no key generation, no seed handling, no signing** — and never will. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project

| Repository | Role |
|---|---|
| `gerfaut-core` | Core Rust library — this repository |
| [`gerfaut-mobile`](https://github.com/gerfaut-wallet/gerfaut-mobile) | Mobile app (Flutter, Android & iOS) |
| [`gerfaut-desktop`](https://github.com/gerfaut-wallet/gerfaut-desktop) | Desktop app (Tauri v2 — Windows, macOS, Linux) |
| [`gerfaut-web`](https://github.com/gerfaut-wallet/gerfaut-web) | Website, documentation, downloads |

## License

[AGPL-3.0-only](LICENSE). Commercial licenses are available for integrating gerfaut-core into products with incompatible terms: **info@pandul.fr**.

The Gerfaut name and logo are not covered by the code license — see [TRADEMARK.md](TRADEMARK.md).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
