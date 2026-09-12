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
