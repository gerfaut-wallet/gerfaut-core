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
- A live watch. One connection to the configured backend stays open and
  says when a watched wallet moved, so the app syncs that wallet at once
  instead of at the next scheduled sync. An Electrum server pushes every
  script. A mempool instance pushes blocks and as many scripts as it allows
  per connection, ten on the public ones, and the rest are polled. Any other
  Esplora is polled once a minute, 240 requests an hour at most. The
  connection takes the route a sync takes: Tor for an onion host, and never
  around it, with the same certificate checks. The server learns what a sync
  already tells it, plus how long the app stays connected.
- A sync report lists the transactions it saw confirm, next to the ones it
  saw for the first time, so an app can announce both.
- Live alerts on the wallet manager. It starts the watch, syncs the wallet
  that moved, and hands out each transaction to announce once when it
  enters the mempool and once when it confirms. A fee bump is not
  announced again. A replacement that pays the wallet much less, or sends
  much more out, gets its own alert for what it moves. An incoming payment
  already announced as pending is announced as dropped when it leaves the
  mempool, or when such a replacement cuts it down. The record of what was
  announced is kept in the vault, so a restart or a second caller never
  repeats one. Settings and wallets change under a running watch without a
  call from the app, and a host whose timers sleep can ask for a connection
  check from an alarm.
- The premium client reads a wallet the server refused: `watching` is false
  and `refusal` says why, in the list and in a `wallet_refused` event. A
  single address can be registered like a descriptor.
- One sync of a wallet runs at a time. A caller that arrives while one runs
  waits for it and takes its result instead of asking the backend again.
- On a phone, the built-in Tor client uses reduced channel padding, so a
  connection held open for hours lets the radio sleep between cells. A
  desktop keeps the normal level.
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
- A 401, 403, 404 or 410 from the premium server counts as its answer only
  when it comes in the server's own error body. The bare status is what a
  captive portal or a proxy answers, and it no longer makes the app forget
  a key or a wallet the server still holds.
- A 429 from the premium server that names a wait is a rate limit of its
  own, with the wait it named, an hour at most. Telling the server about
  removed wallets stops at one and keeps the rest for later, instead of
  sending every request behind it to be turned away too.
- The update check takes the route the syncs take. With an onion backend
  configured on any network it goes through the same Tor proxy, and when
  Tor cannot be had it does not go at all, where it used to ask GitHub in
  the clear. It now runs from the wallet manager only.
- Switching a wallet off on the premium server withdraws the consent kept
  for it once the server has nothing left under its id, so removing the
  wallet later has nothing to tell the server.
- A custom server address is stored the way a scan reads it, the host in
  lower case and an IPv6 literal in brackets, and one the URL parser cannot
  read is refused when saved, with the reason. Stored as typed, an address
  such as `tcp://x.onion:50001:extra` looked to the sync like one with no
  onion in it, and its name went to the resolver in the clear. An address
  a vault or a backup holds from before that is read the same way: a sync
  puts it in stored form before it connects, a restore stores it in that
  form, and one that cannot be read is refused by the sync and left out by
  the restore.
- A SLIP-132 key inside a descriptor is held to what its prefix says: a
  `zpub` under `pkh()`, a `ypub` under `wpkh()` or a `Zpub` in a single-key
  descriptor is refused, naming both the prefix and the function, since a
  descriptor written for another key derives addresses the exporting wallet
  never shows. A prefix that agrees with the function is read as before,
  with the notice that the key was rewritten.
