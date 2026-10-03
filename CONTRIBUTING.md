# Contributing to Gerfaut

Thank you for your interest in Gerfaut. The project is in early development and moving fast; expect significant changes until the first release.

## Before you start

- Open an issue first for anything beyond a trivial fix. It avoids wasted work on changes that don't fit the roadmap.
- Everything public happens in English: issues, pull requests, code, comments, commit messages.
- Security vulnerabilities are never reported through issues or pull requests. See [SECURITY.md](SECURITY.md).

## License of contributions

Gerfaut's code is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only), with copyright kept centralized. This is what makes commercial licensing and signed store builds possible, and those are what fund the project.

By submitting a contribution (pull request, patch, or code suggestion), you agree that:

1. Your contribution is licensed under the AGPL-3.0, like the rest of the project.
2. You grant Loïc Morel a perpetual, worldwide, irrevocable right to also license your contribution under other terms, for example a commercial license, or the exceptions required for app-store distribution.
3. You wrote the contribution yourself, or otherwise have the right to submit it under these terms.

Accepted contributions remain published under the AGPL forever. There is no CLA to sign; submitting a pull request constitutes agreement.

## The one hard rule

Gerfaut is watch-only. The codebase contains no code that generates keys, handles seeds, or signs transactions, and pull requests introducing any of it will be closed.

## Pull requests

- Keep them small and focused, one concern per pull request.
- Write commit messages in English, imperative mood, with a short subject line.
- Run the checks below before you push: CI runs the same ones.
- Brand assets (name, logo, visual identity) are out of contribution scope. See [TRADEMARK.md](TRADEMARK.md).

## Checks

CI runs these commands on every pull request, with the toolchain pinned in `rust-toolchain.toml`:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features embedded-tor -- -D warnings
cargo test
```

The second lint builds the Tor client both apps ship with (`embedded-tor`), which the default build leaves out. Expect a long first build.

`cargo test` stays offline: the servers it needs run on loopback, inside the tests. The tests that need the network or Docker are marked `#[ignore]`, with the reason, and CI skips them. Run them by hand:

| What they need | Command |
|---|---|
| Public Esplora, Electrum and price servers, and signet | `cargo test --lib -- --ignored` and `cargo test --test signet_sync -- --ignored` |
| The embedded Tor client and a public onion Esplora | `cargo test --lib --features embedded-tor -- --ignored the_embedded_client_reaches_an_onion_esplora` |
| Docker, for a regtest node and electrs | `cargo test --test regtest_sync -- --ignored --nocapture` |

Public servers come and go: a test that fails against one is worth a second run before a bug report. The first Tor bootstrap takes up to a minute, and Docker pulls two public images the first time.

## Where things are

Every app goes through `WalletManager`. The rest of `src/` answers one question per module:

| Module | Question |
|---|---|
| `manager/`, `live.rs` | What can an app ask? The facade, one file per question, listed at the top of `manager/mod.rs`: settings and Tor, wallets, syncs, transactions to send, the app lock, backups, the Premium account and its devices. Live alerts are in `live.rs`. |
| `input/` | What did the user paste, scan or open? Descriptors, keys, addresses, exports, BSMS records, QR envelopes (`qr`), SLIP-132 prefixes (`xpub`). |
| `wallet/` | What does a wallet hold, and who can spend it? Metadata, snapshots, the views the screens read, the policy page (`policy`). |
| `chain/` | How does a sync reach a server? Esplora and Electrum, certificates, the public servers, Tor, and the sockets (`net`) that the live watch opens too. |
| `watch/` | Did a watched wallet just move? The live connection. |
| `live.rs` | What is worth announcing, and was it announced already? |
| `store/` | How is it all kept on disk? The vault and its encryption (`cipher`). |
| `backup.rs` | How do wallets leave the device? The encrypted backup file and its animated QR. |
| `lock.rs` | Who may open the app? The PIN or password, and the delay after wrong guesses. |
| `premium/` | What does the Premium account hold? The key, the devices, the licence, the server client. |
| `broadcast.rs` | What does a signed transaction or a PSBT do, and how is it sent? |
| `export.rs`, `format.rs` | How does an amount or a date read? The CSV export and the shared formatting. |
| `price.rs`, `updates.rs` | What is a bitcoin worth, and is there a newer release? |
| `network.rs`, `error.rs` | Which networks exist, and which errors can an app match on? |
