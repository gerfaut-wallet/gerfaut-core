# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release: the library both Gerfaut apps are built on.

### Added

- Output descriptors as the single internal format. Extended keys, single
  public keys, plain addresses and multisig setups all become a descriptor,
  and the parser refuses anything that carries private key material.
- Import from pasted text, from a file, from a static QR code and from an
  animated one (UR and BBQr), from a BSMS record (BIP-129), and from the
  JSON export of another wallet. The format is recognised on its own, and
  whatever had to be assumed is reported back so the app can ask first.
- Address derivation with a configurable gap limit, used addresses marked,
  and a full rescan on demand.
- Balances, transaction history and UTXOs, read from Esplora or Electrum.
  Gerfaut opens the Electrum TLS connection itself and checks the
  certificate, so a self-signed node can be trusted once by its fingerprint
  and is refused if that fingerprint ever changes.
- Miniscript policy: a descriptor is read as named branches with their keys,
  thresholds and timelocks, and every lock is measured against the chain
  height and the device clock, down to what each branch can spend today.
- Signed transactions and PSBTs are decoded, explained, and broadcast
  through whichever backend is configured.
- A Tor client of its own (arti) behind a feature flag, exposed as a local
  SOCKS5 proxy on an ephemeral port, so an .onion backend works on a machine
  with no Tor daemon installed.
- Encrypted local storage: XChaCha20-Poly1305 under an Argon2id key, an app
  lock that slows repeated attempts and survives a restart, and an encrypted
  backup file that doubles as the sync format between two devices.

### Changed

- Backup files are sealed under a heavier Argon2id profile than the vault
  (64 MiB of memory, three passes): a backup travels, and whoever holds a
  copy can guess at its password offline for as long as the file exists.
  This version still opens backups written under the lighter profile, but
  a build older than this one cannot open the files it writes. A backup
  from a newer Gerfaut is now refused by name, with a message that says to
  update, instead of being reported as a wrong password.

### Fixed

- A descriptor written with SLIP-132 keys (`zpub`, `vpub`, `Zpub` and the
  rest) is accepted the way a bare key already was: every key is rewritten
  to `xpub` or `tpub`, the checksum is recomputed, and the import says so.
- A PSBT input that carries its whole previous transaction takes the amount
  from that transaction, the one its outpoint pins. A `witness_utxo` that
  says otherwise never sets the amount shown and is called out on the
  input, the way a coin the wallet knows differently already was.
- Server addresses are read by the URL parser the HTTP client uses, so an
  onion disguised with a backslash, a percent-encoded dot or a trailing dot
  goes where the client would take it: through Tor when it is one, in the
  clear when it is not. The host is stored in lower case; the userinfo
  before an `@` keeps its own.
- The ids the premium server hands out are percent-encoded before they go
  into a URL path.
- Switching a wallet off on the premium server withdraws the consent kept
  for it once the server has nothing left under its id, so removing the
  wallet later has nothing to tell the server.
- A custom server address is stored the way a scan reads it, the host in
  lower case and an IPv6 literal in brackets, and one the URL parser cannot
  read is refused when saved, with the reason. Stored as typed, an address
  such as `tcp://x.onion:50001:extra` showed the sync no onion, and its name
  went to the resolver in the clear.
- A SLIP-132 key inside a descriptor is held to what its prefix says: a
  `zpub` under `pkh()`, a `ypub` under `wpkh()` or a `Zpub` in a single-key
  descriptor is refused, naming both the prefix and the function, since a
  descriptor written for another key derives addresses the exporting wallet
  never shows. A prefix that agrees with the function is read as before,
  with the notice that the key was rewritten.
