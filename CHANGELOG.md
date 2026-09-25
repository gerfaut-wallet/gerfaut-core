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
  instead of waiting for the next scheduled sync. An Electrum server pushes
  changes on up to 200 scripts per wallet, 2,000 in all, and the regular
  syncs cover the rest. A mempool instance pushes blocks and as many
  scripts as it allows per connection, ten on the public ones, and the rest
  are polled. Any other Esplora is polled about once a minute, around 240
  requests an hour. The connection takes the route a sync takes: Tor for
  an onion host, and never around it, with the same certificate checks.
  The server learns what a sync already tells it, plus how long the app
  stays connected. When a server keeps reporting changes that no sync can
  find, each sync it asks for waits longer than the last, up to ten
  minutes.
- A sync report lists the transactions it saw confirm, next to the ones it
  saw for the first time, so an app can announce both.
- Live alerts on the wallet manager. It starts the watch, syncs the wallet
  that moved, and hands out each transaction to announce once when it
  enters the mempool and once when it confirms. A payment from one watched
  wallet to another is announced for each of them. A fee bump is not
  announced again, and when it confirms, `replaces` names the txid the
  payment was first announced under, so an app can keep one notice per
  payment. A payment dropped after a bump is announced under that txid.
  A replacement that pays the wallet much less, or sends much more out,
  gets its own alert for what it moves. An incoming payment already
  announced as pending is announced as dropped when it leaves the mempool,
  or when such a replacement cuts it down. The record of what was
  announced is kept in the vault, so a restart or a second caller never
  repeats one. Settings and wallets change under a running watch without a
  call from the app, and a host whose timers sleep can ask for a connection
  check from an alarm.
- The premium client reads a wallet the server refused: `watching` is false
  and `refusal` says why, in the list and in a `wallet_refused` event. A
  single address can be registered like a descriptor.
- Premium devices. The account key now only connects a device: the server
  hands that device a token of its own, which the vault keeps and which is
  never shown, logged or handed to the apps, and every later request
  carries that token instead of the key. A new device sees nothing and
  changes nothing until another device approves it, or for ten days; the
  first device an account ever has gets full access at once. The wallet
  manager connects this device, lists the others, approves and disconnects
  them, changes the key, logs out, and hands out each waiting device once
  for a local notification. A vault written before devices, with a key and
  no token, connects on its own, once. A device the server disowned, or
  whose key it refuses for good (for example a key that already has every
  device the server takes), keeps its key and waits for the user to
  connect it again. A rate limit holds back only the key that hit it,
  until the wait ends, rather than being met at every poll. A debug build
  can point the premium client at a local server with
  `GERFAUT_PREMIUM_URL` and `GERFAUT_PREMIUM_PUBLIC_KEY`; a release build
  has no code that reads them.
- A lost answer from the premium server costs neither a key nor a device.
  The device token and the new key of a key change are drawn on the device
  and written to the vault before the request leaves, and the same request
  is sent again until the server answers it; the server takes it as the
  one it already carried out. While a key change is unanswered the apps
  say so, and nothing that would lose the new key is allowed. If the
  server disconnects the device in the meantime, the change was never
  applied, and the device drops it. A device that logs out while the
  server is out of reach keeps its token queued, never shown, until the
  server hears of it. Moving to another account first tells the old one
  about its removed wallets, with the old token, and none of those
  removals ever goes to the new account.
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
- A sync of a descriptor wallet also reads its receive addresses past the
  last one it revealed, the way a full scan does: up to the gap limit, and
  further past any that holds a transaction. A payment to an address the
  wallet never showed, one another app or the signing device handed out,
  is found and announced by the next sync, whoever runs it, where only a
  rescan used to find it. With the default gap limit of 20, that costs a
  sync 21 more requests on Esplora, and 2 more round trips carrying 20
  requests on Electrum, plus the tip and the latest headers.
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
  the restore. The certificate check of an Electrum server, which can run
  on an address before it is saved, also reads `ssl://[x.onion]:50002` as
  the onion it names and never sends that name to the resolver.
- A SLIP-132 key inside a descriptor is held to what its prefix says: a
  `zpub` under `pkh()`, a `ypub` under `wpkh()` or a `Zpub` in a single-key
  descriptor is refused, naming both the prefix and the function, since a
  descriptor written for another key derives addresses the exporting wallet
  never shows. A prefix that agrees with the function is read as before,
  with the notice that the key was rewritten.
- A vault opens once at a time. Two copies of the app on the same data
  directory used to save over each other's changes; now opening the vault
  takes an exclusive lock on `gerfaut.vault.lock` beside it, held until the
  wallet manager is dropped, and a second open, from another process or
  from the same one, fails with the new `VaultError::AlreadyOpen` before
  anything is read. The system releases the lock when the process ends,
  a crash included. A file system that cannot lock at all opens the vault
  unlocked, as before, and says so in the log. Each save writes to a
  temporary file of its own, removed if the save fails, and an open clears
  the ones a crash left behind.
- A vault file that cannot be looked at, for a permission or a storage
  error, fails the open. It used to be taken for a first launch and
  replaced with an empty vault.
- A descriptor with a private key is refused wherever it comes from. The
  parser always refused one, but a backup file written by hand, or a
  parsed input the app handed back altered, went straight to the wallet
  engine, which took the key and stored it in the vault. Every wallet is
  now checked again as it is created.
- A multi-part UR that announces more than 100,000 parts is refused. One
  frame announcing about four billion, pasted or scanned, made the decoder
  ask for tens of gigabytes and ended the app on the spot.
- An Electrum address whose host still holds a port, such as
  `ssl://[x.onion:50001]:50002` or `x.onion:50001:50002`, is refused. The
  Tor check did not see the onion in it, and the certificate check, which
  runs before an address is saved, asked the system resolver for that
  name. The host of every Electrum address is now read the way the Tor
  check reads it, and no clear connection is ever opened to an onion.
- A sync that brings a transaction worth more than 21 million bitcoin,
  which only a lying server can send for one still out of a block, is
  refused like a failed server, and the next one is tried. Stored, such a
  transaction made every later look at the wallet crash the app. The
  balance of a watched address saturates instead of wrapping around when
  a server lists coins no one can hold.
- The transaction preview reads the signature hash type of every
  signature it finds, and a signature made with `SIGHASH_NONE` or
  `SIGHASH_SINGLE` gets a warning of its own, `uncommitted_outputs`,
  read as an alert. Such a signature leaves some or all of the outputs
  open, so a node that relays the transaction can send that money
  elsewhere, and the outputs the preview showed were only a suggestion.
- The Telegram link puts the server's code in the link only when Telegram
  would take it as a start parameter: 1 to 64 letters, digits, `_` and
  `-`. Any other code, which could have changed what the link says, is
  left out, and the link only opens the bot.
- The key derived from a password or a platform key is wiped on every way
  out of a seal or an open, a failure included, and Argon2 now wipes its
  own working hashes as well.
- The premium client follows no redirect and reads at most 2 MiB of an
  answer. A redirect used to take the request on to the host it named,
  body included, and with it the device token or a new key; an answer of
  any size was held in memory whole.
- The premium client goes through Tor as soon as a backend of any network
  is an onion, the way the update check does. It used to look at the
  network on screen only, so switching to one whose backend is in the
  clear showed this device's address to the premium server.
- A previous transaction fetched for the transaction preview is checked
  against its txid, on Electrum as on Esplora. A server could answer with
  another transaction and set the value of the coin, and so the fee, the
  preview showed.
- A node's refusal of a broadcast is shown in at most 200 characters,
  control characters dropped, as other sentences from a server already
  were. A server could fill the screen with a page of text of its own.
- The transaction preview adds amounts with overflow checks, so values no
  transaction can carry no longer crash a debug build or wrap around into
  a fee in a release one, and outputs worth more than known inputs are
  said to be just that. A time lock is flagged only when an input's
  sequence turns it on, and until the right block: a transaction locked
  to height 1,000 was shown free at a tip of 999, one block before the
  network takes it.
- Upcoming receive addresses skip one that a payment already reached, so
  an address another app handed out and a sync found paid is not offered
  again as unused. At most 200 are derived at once, whatever the app
  asks, and a descriptor without a wildcard gives its one address once
  instead of the same address over and over.
- A live watch that read an impossible tip height, from a lying server or
  a slip, no longer ignores every block after it: a height more than a
  day of blocks below the one kept becomes the baseline again.
- The update check keeps the page it links to only when it is one of the
  repository's release pages on GitHub, and falls back to the latest
  release page otherwise. A tag longer than 32 characters, or with
  spaces in it, is not taken for a version, and at most 1 MiB of the
  answer is read.
- `Licence::paid_until` is the end of the paid time the certificate
  signs, never the unsigned date the server sends beside it.
- The key of a Coldcard-style JSON export is held to its SLIP-132 prefix
  like a pasted key: a multisig cosigner key, or a prefix for another
  script than the account's, is refused instead of imported under the
  account's script with addresses the exporting wallet never shows.
