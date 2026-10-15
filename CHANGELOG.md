# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release: the Rust library both Gerfaut apps are built on. It does everything a watch-only wallet needs and nothing with keys: there is no code to generate a key, handle a seed or sign a transaction.

### Added

- Output descriptors as the single internal format. Extended keys, SLIP-132 keys (`zpub`, `vpub`, `Zpub` and the rest), single public keys, plain addresses and multisig setups all become a descriptor. A pair of receive and change descriptors must describe the same wallet.
- Import from text, pasted or read from a file, or from a static or animated QR code (UR and BBQr). Besides descriptors, keys and addresses, the parser reads a BSMS record (BIP-129), a payment URI, a Sparrow descriptor file and a JSON wallet export such as Coldcard's. It recognises the format on its own and reports whatever it had to assume or rewrite, so the app can ask before it stores anything.
- Address derivation with a configurable gap limit. Upcoming receive addresses skip any address a payment already reached, and every sync reads past the last revealed address up to the gap limit, so a payment to an address handed out elsewhere shows without a rescan. A full rescan stays available, and so does watching a single address.
- Balances, transaction history and UTXOs over Esplora or Electrum: a public server, picked by name or in automatic rotation, or a server of your own. A sync fetches only what the wallet lacks, and reads every script again when the vault opens and once a day.
- Electrum over TLS with trust on first use: a self-signed certificate is pinned by its fingerprint and refused if it ever changes.
- Miniscript policy analysis. A descriptor reads as named spending branches with their keys, thresholds and timelocks, and each lock is measured against the chain height and the device clock. The unspendable internal key of a Liana vault is read as such.
- Transaction and PSBT preview, then broadcast through the configured backend. The preview warns on missing signatures, on amounts no backend could confirm, and on `SIGHASH_NONE` or `SIGHASH_SINGLE` signatures (`uncommitted_outputs`).
- A built-in Tor client (arti) behind the `embedded-tor` feature, exposed as a local SOCKS5 proxy, so a `.onion` backend works on a machine with no Tor daemon. Without the feature, `.onion` hosts go through a system Tor.
- A live watch on the wallet manager. It keeps one connection to the backend: Electrum subscriptions, a mempool WebSocket, or polling of any other Esplora. It follows up to 200 scripts per wallet and 2,000 in all, or 20,000 on a backend marked `own_node`, shares them out rank by rank with pinned wallets first, and reports each wallet's coverage in `WatchStatus`. With the automatic backend, syncs go first to the watch's server, so a single operator sees the wallet's addresses.
- Live alerts: each transaction is handed out once when it enters the mempool and once when it confirms, and the vault remembers what was announced across restarts. A fee bump is not announced again (`replaces` names the first txid), and an incoming payment that leaves the mempool is announced as dropped once a second sync confirms it is gone.
- Encrypted storage. The vault is sealed with XChaCha20-Poly1305 under a key the platform keeps, and one process at a time opens it (`VaultError::AlreadyOpen`). The app lock is hashed with Argon2id, and its delay between attempts survives a restart.
- An encrypted backup file, sealed under a password with Argon2id (64 MiB, 3 passes), that carries the wallets from one device to another, and the node settings when asked. A backup from a newer version is refused by name.
- Fiat price and update check from the wallet manager, on the route the syncs take: through Tor when a backend is an onion address, and not sent at all when Tor cannot be reached.
- CSV export of a wallet's transactions, filtered by date and direction.

### Security

- A private key is refused wherever it comes from: the parser, a backup file, an export that hides it behind JSON escapes, and a last check as each wallet is created. An error never quotes it.
- What a server sends is bounded. Every Esplora answer is capped once decompressed, a sync keeps at most 256 MiB of the transactions it reads, and no HTTP client follows a redirect to another host. A server's error or refusal reaches the app as one short line, without control characters or bidirectional marks.
- A server of another network is refused by its genesis block. Block headers are taken only as a linked chain, under a tip height the chain can have reached. A transaction worth more than 21 million bitcoin, one that spends the same coin twice, and amounts that overflow are refused like a failed server.
- A `.onion` name never reaches the system resolver: server addresses go through the URL parser of the HTTP client, and an Electrum host that hides a port is refused.
- An animated UR that announces more than 5,000 parts is refused, and so is a QR code nested in another.
- A key derived from a password or a platform key is wiped after use, a failure included, and Argon2 wipes its own working memory.
