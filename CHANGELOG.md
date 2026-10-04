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
  scripts as it allows per connection, ten on the public mainnet ones and
  some six hundred on those of signet and the testnets, and the rest are
  polled. Any other Esplora is polled about once a minute, around 240
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
- "This is my node". A custom backend can be marked as the user's own
  node with `own_node`, on `BackendConfig::CustomElectrum` and
  `CustomEsplora`. It is off by default and left out of the stored form
  while off, so a vault or a backup written before it reads and writes
  back the same; the public backend cannot be one, and nothing checks the
  claim. On the user's own node the live watch takes 20,000 scripts in all
  instead of 2,000, and one wallet may take all of them instead of 200:
  a public server charges every subscription and refuses them past its
  own limit, a node of one's own does not. The switch travels with the
  backend in a backup.
- The live watch shares its scripts out between wallets rank by rank, the
  first script of every wallet, then the second, and so on. Wallets the
  user pinned come first, up to what a watch takes of one wallet; then,
  at each rank, a wallet that holds coins goes before an empty one.
  `WalletManager::set_wallet_live_pinned` pins a wallet, and
  `WalletMeta.live_pinned`, kept in the vault and carried by backups,
  says which are.
- The status of the live watch says how much of each wallet it hears.
  `WatchStatus.wallets` gives each wallet `live`, `partial` or
  `sync_only`, with the scripts it watches and the ones it leaves to the
  regular syncs, and `left_out_scripts` and `left_out_wallets` add them
  up, so an app can say when a payment will only show at the next sync.
- `WatchStatus.server_software` gives what an Electrum server says it
  runs, as it answers `server.version` ("ElectrumX 1.18.0", "Fulcrum
  1.12.0"), so that on the user's own node, when the watch leaves
  scripts out, an app can name the setting of that server that takes
  more. It is `None` over the other transports, and absent from a
  status written before.
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
  waits for it, then runs its own, since the running sync may have read
  the wallet before the payment the caller came for arrived. Callers that
  wait together share that next sync instead of each asking the backend.
- On a phone, the built-in Tor client uses reduced channel padding, so a
  connection held open for hours lets the radio sleep between cells. A
  desktop keeps the normal level.
- Encrypted local storage: XChaCha20-Poly1305 under a key the platform
  keeps, an app lock hashed with Argon2id that slows repeated attempts and
  survives a restart, and an encrypted backup file, sealed under a password
  with Argon2id, that also carries the wallets from one device to another.
- The channels of a Premium account say when each one last delivered a
  message, and since when it fails: `last_sent_at`, `failing_since` and
  `last_failure` on `Channel`, all `null` from a server that predates them.
  A channel that has failed for an hour or more, behind a blocked bot or an
  expired webhook domain, delivers nothing, and nothing else showed it.

### Changed

- Syncs fetch only what a wallet lacks. A transaction the wallet already
  holds is never downloaded again, and a confirmation it has already
  proven is not proven twice. Over Electrum, a sync reads the history of
  each script, a short list of txids, then asks only for the transactions
  it does not have, plus the coins they spend so that their fee can be
  shown. A confirmation is proven again only when a reorganisation moved
  it. Over Esplora, a sync first reads the counters of each script, reads
  its history only when they moved, and stops paging at the first
  transaction it already holds; answers now come gzipped. On a busy
  signet wallet of 274 transactions, a sync that finds nothing new went
  from 5.8 MB to 131 KB over Esplora, and from 6.4 MB to 74 KB over
  Electrum. The first sync of a wallet after the vault opens, and one a
  day after that, also lists the unconfirmed transactions of every script
  that has some: that is how a replacement paying the same amount gets
  caught. `WalletMeta.complete_at` records when that last happened, and
  any sync that comes a day or more after it reads every script, whoever
  asked for it. Every Esplora answer is capped at 32 MiB once
  decompressed, including the requests of the live watch, single
  addresses and broadcasts, and so is every price answer: a small gzip of
  a huge body is cut off instead of being held in memory. JSON answers
  are parsed as they arrive, so the fields a sync skips, such as the
  assembly of each script, cost no memory. Each JSON answer is capped at
  64 MiB, and a sync keeps at most 256 MiB of the transactions it reads.
  A witness takes about the memory it takes on the wire, and a
  transaction the wallet already holds is not kept. A page listing one of
  the largest inscriptions, some 16 MB of JSON, still syncs.
- A sync that the live watch asks for goes first to the watch's server
  only when that server serves the wallet's own network under its
  backend. After a network or backend change, the syncs the watch owed
  under the old one are dropped. An Electrum server whose chain never
  meets the wallet's, even one behind it, makes the sync fail instead of
  making the wallet's transactions look gone, and an Esplora server whose
  latest blocks contradict the chain it agreed on is refused.
- A payment that a reorganisation replaced with a conflicting spend to
  someone else costs nothing more once a sync has seen it go. Before,
  each Esplora sync read the whole history of its address, and each watch
  start synced it again. The wallet still lists it as pending, as it did
  before.
- The live watch says which scripts moved. `WatchEvent::WalletChanged`
  carries them in `scripts`, empty when the transport cannot tell, and the
  sync that follows reads only those scripts, on the server the watch
  listens to. With the automatic backend, that server is the Electrum
  server of an operator the rotation already uses, so no new third party
  is involved. Each `WatchedScript` also carries the Electrum `status` of
  what the wallet holds for it. A watch that starts or reconnects compares
  it with the server's and syncs only the scripts whose status differs,
  instead of every wallet. On the busy wallet above, a pushed payment or
  confirmation now costs 12 to 26 KB instead of 6.4 MB, a restart about
  55 KB, and an hour of watching went from 38 MB to 177 KB. When the
  server refuses to watch a script, or gives up on the rest after
  refusing several in a row, those scripts are synced when the watch
  starts, and so is every script of a wallet that the 2,000-script cap of
  a watch cut short. Polling compares the first counters it reads for a
  script with what the wallet holds, so a payment that arrives after the
  watch starts, but before polling reaches its address, is still
  announced. A change heard on one script at the same time as a
  reconnection no longer narrows the whole-wallet sync the reconnection
  asks for.
- The list of scripts the live watch follows, built after every sync,
  reads each script the wallet revealed from the wallet's index instead
  of deriving it again. On a wallet that revealed tens of thousands of
  addresses, that is milliseconds instead of seconds. While an Electrum
  server takes the subscriptions, the count the status gives moves in
  steps of a hundred, not one event per script.
- The live watch lists each wallet's scripts that hold coins first, where
  a spend shows, then the newest receive addresses it revealed and has
  not seen used, up to the gap limit, and the gap limit ahead of them,
  then the change addresses the same way, then the rest, newest first.
  The unused receive addresses used to come first, oldest first: a
  merchant's wallet that reveals an address per invoice, many never
  paid, filled the 200 scripts a watch takes of a wallet with them, and
  neither a spend of its coins nor a payment to its next addresses was
  heard before the next sync.
- A sync of a watched address reads only what is new or moved. Over
  Electrum, a transaction the wallet holds, at the height the server
  lists it now, is kept as it is, with the time of its block, and only
  the others are fetched, with the transactions their inputs spend. Over
  Esplora, the reading stops at the first page that lists nothing but
  what the wallet holds, and the rest of the round comes from it. An
  address paid a thousand times, watched live, used to cost thousands of
  requests and megabytes for each payment.
- The core no longer depends on `bdk_esplora`, nor on `esplora-client`
  with it: it already spoke to Esplora on its own, and kept them for six
  types of what a server answers, which it now reads itself. Nor on
  `bdk_electrum`, kept only to reach `electrum-client`, on which it now
  depends directly, at the same version and with the same features.
- On the WebSocket of a mempool instance, the live watch asks for as
  many scripts as one message carries, some six hundred, instead of a
  hundred: the public instances of signet and the testnets track 1,337
  on one connection, and the rest were polled three a minute. The
  message stays under the 50,000 bytes past which such an instance cuts
  the connection.
- The keepalive ping of the live watch comes at random between seven
  tenths of its wait and all of it, never later: a ping every four
  minutes on the dot marked the connection even through Tor.
- On the user's own node, polling reads thirty scripts a minute, four at
  a time, instead of three. On a server that pushes nothing, polling
  reads the first two scripts of the list every round and the rest in
  turn, so with N scripts past those two, each is read about every N
  minutes, and every N/28 minutes on one's own node. Past what a mempool
  instance pushes, every script polled takes its turn: every N/3
  minutes, or N/30 on one's own node. All of them are read at the next
  regular sync. Every minute for each would be N requests a minute,
  which no public server would take from every client.
- The live watch keeps each wallet complete on its own. At each block,
  and every ten minutes, it reruns any sync that failed, and reads every
  script of any wallet that has gone a day without a complete sync. A
  phone can keep a watch running for days with no other sync, and the
  watch cannot hear every script.
- Backup files are sealed under a heavier Argon2id profile than before
  (64 MiB of memory, three passes): a backup travels, and whoever holds a
  copy can guess at its password offline for as long as the file exists.
  This version still opens backups written under the lighter profile, but
  a build older than this one cannot open the files it writes. A backup
  from a newer Gerfaut is now refused by name, with a message that says to
  update, instead of being reported as a wrong password.
- `PremiumClient::with_http` is no longer public: a client built elsewhere
  skipped the refusal of an onion without a proxy and could follow
  redirects. Nor are `price::fetch_price` and `price::fetch_price_history`:
  an app asks the wallet manager, which takes the route of the syncs.
- A 4xx from the Premium server without its own error body is now
  `PremiumError::UnexpectedResponse`. It used to be
  `PremiumError::Rejected`, with the bare status as its words.

### Removed

- Nothing called these, so they are gone: `store::VaultKdf`,
  `cipher::kdf_kind`, `format_btc_signed`, `truncate_middle`,
  `truncate_address`, `PremiumClient::set_key` and `broadcast::sats`. So
  are the `funded_sats` and `spent_sats` fields of `AddressWatchState`,
  which nothing read. A vault still writes them as zero, for the older
  builds that require them.

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
- The live watch asks a server for its genesis block before it hears of
  any script, over Electrum as over Esplora, and refuses one of another
  network: a signet port typed for testnet4 reported changes that never
  happened on the wallet's network. A refused server is left alone for a
  quarter of an hour while the next one is tried. A sync whose server
  disagrees with the wallet on a block now asks for its genesis block
  too, and says "the server is on another network" at once, instead of
  walking the wallet's chain down to it one request a block.
- The live watch remembers what an Electrum server refuses, for as long
  as its configuration holds. A server takes so many subscriptions on one
  connection, 100 on the Electrum server of mempool.space, and at each
  reconnection the watch used to ask it for the whole list again, be
  refused the rest, and sync every script it gave up on. Now a refused
  script is synced once, when it is refused, and the next connection asks
  only for the head of the list, up to what the server took; the rest is
  left to the regular syncs. The status counts those scripts out, so
  `WatchStatus.wallets` and `left_out_scripts` say what the server really
  took, on the user's own node as on a public server.
- An Electrum server that cuts the live watch for what it costs, an
  ElectrumX past its budget, is left alone for a quarter of an hour, as
  one of another network is, and asked for half as many scripts when the
  watch comes back to it. ElectrumX keeps that cost against the address
  for a while, and the watch used to come back within two minutes with
  the same burst. Subscriptions go out ten at a time instead of 25, as
  many as ElectrumX serves at once before it slows a session down.
- Over Electrum, a block now syncs a wallet waiting for a confirmation
  when the live watch does not hear all of its scripts, past the caps on
  the list or refused by the server. The confirmation comes as news on
  the scripts of the transaction, and on a script nobody pushes it used
  to wait for the next regular sync.
- An Esplora server that limits the rate of requests (HTTP 429) is asked
  again once, after the wait its `Retry-After` names, in seconds or as a
  date, five seconds at least, instead of three times within two
  seconds; past a minute the
  request fails at once and says how long the server asked for.
  mempool.space bans a client that keeps coming back too soon. Polling
  a server that limits it waits twice as long between rounds each time,
  up to ten minutes, and back to a minute half an hour after the last
  limit; a round turned away no longer counts as a server lost.
- A sync of a watched address keeps 256 MiB at most of the transactions
  it reads, as a sync of a descriptor wallet already did: each one is
  kept whole, its raw bytes and every input and output, and a server
  could list transactions of hundreds of thousands of inputs until the
  phone ran out of memory. Over Electrum, a connection of that sync also
  reads 256 MiB at most, every answer together.
- The HTTP clients of the core no longer follow a redirection anywhere:
  an Esplora server's not at all, and the price and update services'
  only to their own host, over HTTPS. A redirection carried the request,
  the scripts of a wallet among them, where its route was never checked:
  in the clear, or an onion name to the system's resolver.
- What a server writes in a refusal or an error reaches a screen as one
  short line on every path: 200 characters at most, without control
  characters or the marks that turn the text around them, the line and
  paragraph separators included. A sync over Electrum passed a server's
  error on whole, sixteen megabytes or a text that read backwards.
- A watched address sums the amounts a server lists without wrapping
  around, over Esplora as it already did over Electrum, and the net of a
  transaction stops at what a signed number holds. A made-up amount past
  what any coin holds made a build that checks panic, and showed in one
  that does not as a huge payment out.
- On a desktop, the built-in Tor client checks again, as arti does by
  default, that no other account of the machine can write to its state,
  where it keeps its guards and the directory it trusts. Only a phone,
  whose app storage the system keeps private to the app, skips it.
- A server that drops the live watch's connection again and again, and
  names scripts it made up as moved on each new one, has the syncs they
  ask for wait longer and longer, as a server that pushes made-up changes
  already did. A connection dropped every minute had those scripts
  synced every minute, day and night.
- Over Electrum, where a broadcast transaction stands is read through
  an output a coin may sit on, an OP_RETURN only last, and through the
  next one when the server refuses a history. It was read through the
  first output, an OP_RETURN or an exchange's deposit address with a
  history too long for the server, and failed while the transaction
  confirmed.
- An incoming payment announced as pending is said dropped only once a
  second sync, ten minutes or more after the first one that missed it,
  has read its scripts again and not seen it either. A server that lags,
  or one of the rotation that never heard of the payment, made a single
  sync announce as dropped a payment that was still coming. A sync that
  sees the payment again, or a fee bump of it, forgets it; a sync that
  did not read its scripts says nothing of it; a replacement that cuts
  the payment down is still said at once. The vault keeps what this
  needs only while such a payment waits, so a vault written before reads
  and writes the same. While the live watch runs, it reads the scripts
  of such a payment again itself ten minutes on, nothing moving on them
  once it left. A wallet removed takes such a payment out of the vault
  with it.
- A watched address is never read from a server of another network.
  Testnet, testnet4 and signet spell an address alike, and a server of
  the wrong one answered for it with transactions the wallet's network
  never saw. A descriptor wallet's sync already caught it, walking the
  wallet's chain; an address keeps none, so its sync now asks the server
  for its genesis block first, over Electrum and Esplora, and is refused
  by one of another network.
- An OP_RETURN payload that holds a character changing the direction of
  the text, a bidirectional mark, embedding, override or isolate, or a
  line or paragraph separator, is no longer read as text: shown as text,
  it could make an amount or an address beside it read backwards, or push
  it onto a line of its own. Its bytes are shown in hex instead.
- A 401, 403, 404 or 410 from the premium server counts as its answer only
  when it comes in the server's own error body. The bare status is what a
  captive portal or a proxy answers, and it no longer makes the app forget
  a key or a wallet the server still holds.
- A 429 from the premium server that names a wait is a rate limit of its
  own, with the wait it named, a day at most: what the server holds back
  for the day comes back the next day. Telling the server about
  removed wallets stops at one and keeps the rest for later, instead of
  sending every request behind it to be turned away too.
- The update check takes the route the syncs take. With an onion backend
  configured on any network it goes through the same Tor proxy, and when
  Tor cannot be had it does not go at all, where it used to ask GitHub in
  the clear. It now runs from the wallet manager only.
- The price now takes the route the syncs take, as the update check
  already does. When a backend on any network is an onion address, the
  price goes through the same Tor proxy, and when Tor cannot be reached it
  does not go out at all. Before, the price source was asked in the clear
  every minute. The request now runs from the wallet manager only, which
  refuses a currency or a range the source cannot serve before it resolves
  any route.
- The first address shown before a wallet is added is now derived for the
  network the wallet goes to, given in `ImportOptions::network`. On
  regtest, a test key showed the `tb1…` address of signet, which no
  regtest wallet ever gives. It now shows its `bcrt1…` address.
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
  unlocked, as before, and says so in the log. So does a lock file that
  cannot be opened for writing, such as a read-only one restored from a
  copy. Each save writes to a temporary file of its own, removed if the
  save fails, and an open that holds the lock clears the ones a crash left
  behind. On Windows, a save waits a moment when a scanner still holds the
  new file, instead of failing at once.
- A vault file that cannot be looked at, for a permission or a storage
  error, fails the open. It used to be taken for a first launch and
  replaced with an empty vault.
- A descriptor with a private key is refused wherever it comes from. The
  parser always refused one, but a backup file written by hand, or a
  parsed input the app handed back altered, went straight to the wallet
  engine, which took the key and stored it in the vault. Every wallet is
  now checked again as it is created.
- A multi-part UR that announces more than 5,000 parts is refused. One
  frame announcing about four billion, pasted or scanned, made the decoder
  ask for tens of gigabytes and ended the app on the spot, and a frame of a
  few bytes that mixed half of 100,000 parts cost seconds of work, paid
  again for every frame scanned after it.
- An Electrum address whose host still holds a port, such as
  `ssl://[x.onion:50001]:50002` or `x.onion:50001:50002`, is refused. The
  Tor check did not see the onion in it, and the certificate check, which
  runs before an address is saved, asked the system resolver for that
  name. The host of every Electrum address is now read the way the Tor
  check reads it, and no clear connection is ever opened to an onion.
- A sync that brings a transaction worth more than 21 million bitcoin,
  which only a lying server can send for one still out of a block, is
  refused like a failed server, and the next one is tried. Stored, such a
  transaction made every later look at the wallet crash the app. So is
  one that spends the same coin twice, and an answer whose amounts,
  added to what the wallet already holds, pass what the wallet's sums
  can hold: thousands of invented unconfirmed payments, each within the
  21 million, crashed the app the same way once added up into a balance.
  The balance of a watched address saturates instead of wrapping around
  when a server lists coins no one can hold.
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
- A server can no longer put made-up blocks into a wallet's chain for
  good. Its tip is refused past any height a chain can have reached (one
  block a minute since the genesis block, with a clock set back read as
  the day this release was written), and its latest blocks are taken
  only as a chain: one per height, each the parent of the next, and over
  Electrum the last one the tip it announced, each mined on mainnet and
  testnet4 at a target no easier than the network allows. That stops a
  header no one mined; it does not prove the work the chain asks for at
  that height. A wallet that already holds such blocks, far above
  the tip of the server it syncs with next, drops them: a single answer
  with a height of four billion used to give every transaction billions
  of confirmations, every timelock of the policy as expired, and every
  later Esplora sync a failure, even on an honest server. An Esplora
  server a little behind the wallet now leaves its chain as it is, as an
  Electrum server already did, instead of failing the sync.
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
- A watched address whose sync comes back with a full page of 50
  unconfirmed transactions no longer announces a payment as dropped for
  missing from that page. Anyone could push it off by sending the
  address enough dust.
- The policy page reads the internal key of a Liana taproot vault for what
  it is. Liana writes that unspendable key as an extended key built on the
  BIP 341 point, and the page took it for a key of its own: on every vault
  with several keys on its main path, it showed a "Key A" that could spend
  at once, alone.
- A threshold that counts one key twice says so, "Any 2 of 3 keys, Key A
  counted twice". A coordinator holding two places in a 2-of-3 used to read
  as three keys.
- When a branch needs two locks together, a date and a delay, both are
  marked as required, where they read as optional, and the branch is no
  longer called primary as if it could spend now.
- A 1-of-n beside a timed path stays one way to spend, "Any of n keys",
  instead of n primary branches. So do a taproot key path and a leaf of a
  single key: "Any of 2 keys", beside the timed leaf.
- A pair of descriptors is held together: the change descriptor must have
  the receive descriptor's script type, keys and conditions, on other
  paths. The policy page reads the receive one, and change goes to the
  other: a pair that disagreed, a 2-of-3 for payments and a single key for
  change, was imported without a word.
- A QR code that holds another QR code is refused. Each level opened cost a
  frame of the stack, and a pasted text, or a file dropped on the broadcast
  page, could hold enough of them to end the app.
- "Forget this key" first tells the Premium server about the wallets
  removed from this device, and the removals it could not send stay queued
  for the same key, entered again, along with any watched wallet removed
  in between. They used to be dropped, and the server went on watching
  wallets the app no longer had.
- A Premium connection the vault failed to record stays on the server and
  is sent again. It used to be revoked, and the retry made a new device
  that waited ten days for an approval, the account's first one included.
- A Coldcard export is read under its master fingerprint, the one a signer
  knows the wallet by, not the account's. A descriptor copied to a
  coordinator gave PSBTs the Coldcard would not sign. An account whose
  `first` address is not the one its key derives is refused.
- A copy of the Premium state handed back after a wallet was removed no
  longer brings its consent back, nor cancels its removal.
- A private key written with JSON escapes inside an export is refused like
  any other, and never quoted in the error.
- The Premium server's sentence is kept to one line of 200 characters,
  control and direction characters dropped, on screen and in the vault.
- A 4xx from the Premium server without its own error body settles
  nothing: a connection or a key change under way is sent again as it was.
  A proxy's page during a deployment used to drop the only copy of a new
  key.
- A Premium certificate replaces only an older one, so a slow refresh
  answered after a key change no longer brings the old paid time back.
- The balance of a watched address in the address list, and the date a coin
  unlocks on the policy page, saturate instead of wrapping around when a
  server sends values no coin can hold.
- A QR code is refused rather than guessed at: a key path step out of
  range, a network its format does not name, a 32-byte key, which is a
  private key in that format, or two animated BBQr codes scanned at once,
  whose parts used to be glued together.
- More imports work: a key scanned alone as `ur:crypto-hdkey`, the
  descriptor file Sparrow exports, a payment URI (`bitcoin:…?amount=…`)
  scanned from another wallet's receive screen, a BSMS record inside a QR
  envelope, and a BSMS record for regtest. A BSMS record with more than
  four lines is refused, and so is a descriptor file whose three
  descriptors do not describe the same wallet.
- A `ypub` or a `zpub` keeps the script its prefix names: picking another
  one no longer builds a wallet of addresses the exporting wallet never
  shows, and the confirmation screen no longer offers another. A key under
  a BIP-48 or BIP-45 origin is refused as a multisig cosigner's key, as its
  SLIP-132 prefix already was.
- A vault is written back at payload version 2, so a build older than this
  one refuses to open it rather than rewrite it without the fields it does
  not know, the Premium device token and a key change under way among
  them. The version is read first, on its own, so a vault from a later
  build that gives a field another shape is refused as newer instead of
  being reported as corrupted.
- The app lock's delay now starts when the answer comes back. It used to
  start at the guess, so the time Argon2 took to check it came off the
  delay.
