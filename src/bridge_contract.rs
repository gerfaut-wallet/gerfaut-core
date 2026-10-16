//! The contract of the bridges, written down as JSON.
//!
//! The serde types of this crate are what both apps receive and send:
//! the desktop through Tauri, Android through the JSON strings of its
//! Rust API. For every type that crosses, `tests/bridge/<Type>.json`
//! holds what serde writes for it, as an object of named cases: every
//! variant of an enum, and optional fields both present and absent.
//! The values are built below, through the functions of the core
//! wherever one makes them, from public test material only: BIP-32
//! test vectors, the public descriptor of the BDK documentation,
//! BIP-173 addresses.
//!
//! The tests of both apps read these files from the gerfaut-core
//! checkout beside them and decode every case with their own types: a
//! field added, renamed or dropped here fails a test there, before it
//! fails a screen.
//!
//! The test below fails when a file differs from what the core now
//! writes, or when a file names a type nothing writes any more. After a
//! change to a type, write them again and commit them with the change:
//!
//! ```text
//! GERFAUT_WRITE_BRIDGE=1 cargo test --lib bridge_contract
//! ```
//!
//! A type that starts crossing a bridge gets its builder here. Two
//! types never cross: `LockSecret`, taken out of every `AppLock` before
//! it leaves the vault, and `CoreError` itself, which crosses as the
//! failure the bridges build from it, `CoreError.json` here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::str::FromStr;

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey};
use serde::Serialize;

use crate::backup::{
    self, BackupBackendPreview, BackupBundle, BackupOptions, BackupPreview, BackupWalletPreview,
    ImportChoices, ImportReport,
};
use crate::broadcast::{
    self, BroadcastReport, BroadcastStatus, DecodedInput, DecodedTx, FeeRateBasis, InputFacts,
    OutputFacts, RecentBroadcast, SigningHints, TxOutputPreview, TxPreview, TxReadiness,
    TxSeverity, TxSource, TxWarning, TxWarningKind, WalletRef,
};
use crate::chain::connect::{ScannedBackendKind, parse_backend};
use crate::chain::public::{PublicServer, ServerProtocol, public_servers};
use crate::chain::tls::fingerprint_of;
use crate::chain::tor::{TorMode, TorRoute, TorSettings, TorStatus, TorVia};
use crate::chain::{BackendConfig, CertificateReport, CertificateStatus};
use crate::error::{CoreError, ErrorCode, VaultError};
use crate::export::{ExportDirection, ExportOptions, transactions_csv};
use crate::input::qr::{QrFormat, QrProgress, assemble};
use crate::input::{
    DerivationChoice, ImportOptions, InputWarning, ParsedPayload, RecognizedKind, ScriptKind,
    parse_input,
};
use crate::live::notice::{self, Context, Held, Notice, NoticeId, NoticeKind};
use crate::live::{LiveEvent, LiveTx};
use crate::lock::{AppLock, LockKind, LockVerdict};
use crate::manager::{SyncAllReport, SyncFailure};
use crate::network::Network;
use crate::prefs::{Preferences, PreferencesChange, Unit};
use crate::price::{
    CurrencyEntry, CurrencyReach, FiatCurrency, PriceHistory, PricePoint, PriceQuote, PriceRange,
    PriceSource, SourceEntry, price_table,
};
use crate::store::{Settings, TxStage};
use crate::updates::UpdateStatus;
use crate::wallet::meta::{CachedTotals, SyncStamp, WalletIcon, WalletKind, WalletMeta};
use crate::wallet::policy::{
    AbsoluteLock, BranchRole, BranchState, BranchTone, Coin, Condition, LockState, PolicyBranch,
    PolicyInput, PolicyKind, PolicySnapshot, RelativeLock, Remaining, TimeBasis, Timelock,
    TimelockRef, address_snapshot, analyze,
};
use crate::wallet::snapshot::{
    AddressEntry, AddressList, AddressRow, BalanceSnapshot, Keychain, NewTx, SyncReport, TxDetail,
    TxIo, TxStatus, TxSummary, UtxoInfo, WalletSnapshot,
};
use crate::wallet::tx_extras::{self, OpReturnData, op_return_of};
use crate::watch::{
    Coverage, LeftOut, LeftOutReason, Remedy, ServerSoftware, WalletCoverage, WatchLimits,
    WatchLimitsChoice, WatchState, WatchStatus, WatchTransport,
};

/// Set, the test writes the files instead of comparing them.
const WRITE: &str = "GERFAUT_WRITE_BRIDGE";

// --- the files ---------------------------------------------------------

/// The cases of one type, each already serialized.
struct Fixture {
    name: &'static str,
    cases: Vec<(String, String)>,
}

fn fixture<T: Serialize>(name: &'static str, cases: Vec<(&str, T)>) -> Fixture {
    let cases = cases
        .into_iter()
        .map(|(case, value)| {
            let json = serde_json::to_string_pretty(&value).expect("a bridge type serializes");
            (case.to_owned(), json)
        })
        .collect();
    Fixture { name, cases }
}

/// Every variant of an enum of unit variants, each under its own name.
fn variants<T: Serialize>(name: &'static str, all: Vec<T>) -> Fixture {
    let cases = all
        .into_iter()
        .map(|value| {
            let json = serde_json::to_value(&value).expect("a bridge type serializes");
            let case = json
                .as_str()
                .expect("a unit variant is a string")
                .to_owned();
            (case, json.to_string())
        })
        .collect();
    Fixture { name, cases }
}

/// The variants of an enum of unit variants. The match is what makes
/// it every one: a variant added to the enum does not compile here
/// until it is listed.
macro_rules! every {
    ($ty:ident { $($variant:ident),+ $(,)? }) => {{
        let all = vec![$($ty::$variant),+];
        for value in &all {
            match value {
                $($ty::$variant)|+ => {}
            }
        }
        all
    }};
}

/// Asserts the cases of an enum with data reach every variant: `arm`
/// is an exhaustive match, so a variant added fails to compile there.
fn reaches_every<T>(name: &str, cases: &[(&str, T)], arms: usize, arm: fn(&T) -> usize) {
    let reached: BTreeSet<usize> = cases.iter().map(|(_, value)| arm(value)).collect();
    assert_eq!(reached.len(), arms, "the cases of {name} miss a variant");
}

/// The file: one key per case, in order, two-space indents, and an
/// object or a list that fits in [`WIDTH`] columns kept on its line.
fn render(fixture: &Fixture) -> String {
    let mut out = String::from("{\n");
    for (i, (case, json)) in fixture.cases.iter().enumerate() {
        let comma = if i + 1 < fixture.cases.len() { "," } else { "" };
        let key = serde_json::to_string(case).expect("a case name serializes");
        out.push_str(&format!("  {key}: {}{comma}\n", json.replace('\n', "\n  ")));
    }
    out.push('}');
    let mut lines = Vec::new();
    for item in &parse_lines(&mut out.lines()) {
        lay_out(item, 0, "", &mut lines);
    }
    lines.join("\n") + "\n"
}

const WIDTH: usize = 80;

/// A line of pretty JSON, or an object or a list with what it holds.
enum Line {
    Value(String),
    Block {
        head: String,
        items: Vec<Line>,
        close: String,
    },
}

/// Reads pretty JSON as serde writes it: an object or a list opens on
/// a line ending in `{` or `[` and closes on a line of its own, and a
/// string never ends a line with either.
fn parse_lines<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Vec<Line> {
    let mut items = Vec::new();
    while let Some(line) = lines.next() {
        let text = line.trim().trim_end_matches(',');
        if text.starts_with('}') || text.starts_with(']') {
            break;
        }
        if text.ends_with('{') || text.ends_with('[') {
            let close = if text.ends_with('{') { "}" } else { "]" };
            items.push(Line::Block {
                head: text.to_owned(),
                items: parse_lines(lines),
                close: close.to_owned(),
            });
        } else {
            items.push(Line::Value(text.to_owned()));
        }
    }
    items
}

fn flat(line: &Line) -> String {
    match line {
        Line::Value(text) => text.clone(),
        Line::Block { head, items, close } => {
            let inner: Vec<String> = items.iter().map(flat).collect();
            format!("{head}{}{close}", inner.join(", "))
        }
    }
}

fn lay_out(line: &Line, indent: usize, comma: &str, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    let one = flat(line);
    match line {
        Line::Block { head, items, close }
            if indent + one.chars().count() + comma.len() > WIDTH =>
        {
            out.push(format!("{pad}{head}"));
            for (i, item) in items.iter().enumerate() {
                lay_out(
                    item,
                    indent + 2,
                    if i + 1 < items.len() { "," } else { "" },
                    out,
                );
            }
            out.push(format!("{pad}{close}{comma}"));
        }
        _ => out.push(format!("{pad}{one}{comma}")),
    }
}

#[test]
fn the_reference_json_is_what_the_core_writes() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bridge");
    let write = std::env::var_os(WRITE).is_some();
    if write {
        std::fs::create_dir_all(&dir).expect("tests/bridge can be made");
    }
    let mut names = BTreeSet::new();
    let mut differ = Vec::new();
    for fixture in fixtures() {
        assert!(
            names.insert(fixture.name),
            "{} is written twice",
            fixture.name
        );
        assert!(!fixture.cases.is_empty(), "{} has no case", fixture.name);
        let cases: BTreeSet<&str> = fixture
            .cases
            .iter()
            .map(|(case, _)| case.as_str())
            .collect();
        assert_eq!(
            cases.len(),
            fixture.cases.len(),
            "{} repeats a case",
            fixture.name
        );
        let path = dir.join(format!("{}.json", fixture.name));
        let text = render(&fixture);
        if write {
            std::fs::write(&path, text).expect("a reference file can be written");
        } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            differ.push(fixture.name.to_owned());
        }
    }
    for entry in std::fs::read_dir(&dir).expect("tests/bridge exists") {
        let path = entry.expect("tests/bridge can be listed").path();
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if path.extension().is_some_and(|ext| ext == "json") && !names.contains(stem) {
            if write {
                std::fs::remove_file(&path).expect("a stale reference file can be removed");
            } else {
                differ.push(format!("{stem} (written by nothing)"));
            }
        }
    }
    assert!(
        differ.is_empty(),
        "tests/bridge is not what the core writes: {}. Run `{WRITE}=1 cargo test --lib \
         bridge_contract` and commit the files with the change.",
        differ.join(", ")
    );
}

fn fixtures() -> Vec<Fixture> {
    let mut all = Vec::new();
    all.extend(input());
    all.extend(chain());
    all.extend(wallet());
    all.extend(policy());
    all.extend(files());
    all.extend(broadcasts());
    all.extend(settings());
    all.extend(prices());
    all.extend(live());
    all.extend(errors());
    all
}

// --- public test material ----------------------------------------------

/// The public two-path descriptor of the BDK documentation, a BIP-84
/// account on the test networks.
const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
const RECEIVE: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";
const CHANGE: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/1/*)";
/// BIP-32 test vector 1: the master key, then chains m/0H, m/0H/1 and
/// m/0H/1/2H.
const KEY_A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const KEY_B: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
const KEY_C: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
const KEY_D: &str = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
/// BIP-173 test vectors: P2WPKH on mainnet and on testnet.
const MAINNET_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TESTNET_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

/// Wallet ids, as the vault hands them out.
const SAVINGS: &str = "3f1c2a64-8b7e-4d21-9c5a-6e0f7b2d9a13";
const COLD: &str = "a7d40b19-5c3e-4f82-b6a1-2e9c8d7f0b54";
const DONATIONS: &str = "e2b85c07-1f6a-4c93-8d4e-7a0b3c5f9e26";

/// The clock and the tip every fixture is read at.
const NOW: u64 = 1_750_000_000;
const TIP: u32 = 800_000;

/// A transaction id nobody's: the hash of a word.
fn txid(seed: &str) -> String {
    sha256::Hash::hash(seed.as_bytes()).to_string()
}

/// Address `index` of a descriptor of the BDK tpub, on signet.
fn address(descriptor: &str, index: u32) -> String {
    Descriptor::<DescriptorPublicKey>::from_str(descriptor)
        .expect("a test descriptor")
        .at_derivation_index(index)
        .expect("a wildcard descriptor")
        .address(bdk_wallet::bitcoin::Network::Signet)
        .expect("an address descriptor")
        .to_string()
}

fn wallet_ref(id: &str, name: &str) -> WalletRef {
    WalletRef {
        id: id.to_owned(),
        name: name.to_owned(),
    }
}

// --- input -------------------------------------------------------------

fn input() -> Vec<Fixture> {
    let multipath = parse_input(MULTIPATH).expect("a two-path descriptor");
    let receive_only = parse_input(RECEIVE).expect("a descriptor");
    let lone_key = parse_input(KEY_A).expect("an extended key");
    let watched = parse_input(MAINNET_ADDRESS).expect("an address");

    let payloads = vec![
        ("descriptors", multipath.payload.clone()),
        ("descriptors_without_change", receive_only.payload.clone()),
        ("address", watched.payload.clone()),
    ];
    reaches_every("ParsedPayload", &payloads, 2, |payload| match payload {
        ParsedPayload::Descriptors { .. } => 0,
        ParsedPayload::Address { .. } => 1,
    });

    let usual = lone_key
        .derivation
        .clone()
        .expect("a lone key has a derivation");
    let chosen = DerivationChoice {
        receive: "0/*".to_owned(),
        change: Some("1/*".to_owned()),
        origin: Some("[73c5da0a/84'/0'/0']".to_owned()),
    };

    vec![
        variants(
            "Network",
            every!(Network {
                Mainnet,
                Signet,
                Testnet4,
                Regtest,
            }),
        ),
        variants(
            "ScriptKind",
            every!(ScriptKind {
                Legacy,
                NestedSegwit,
                Segwit,
                Taproot,
                WitnessScript,
                LegacyScript,
                Bare,
            }),
        ),
        variants(
            "RecognizedKind",
            every!(RecognizedKind {
                Descriptor,
                DescriptorPair,
                MultipathDescriptor,
                ExtendedKey,
                Address,
                WalletExport,
                Bsms,
            }),
        ),
        variants(
            "InputWarning",
            every!(InputWarning {
                AssumedSegwit,
                Slip132Converted,
                ChangeNotTracked,
                MultipleAccountsInFile,
                NonStandardDerivation,
                AssumedBranches,
            }),
        ),
        fixture("ParsedPayload", payloads),
        fixture(
            "ParsedInput",
            vec![
                ("multipath_descriptor", multipath),
                ("descriptor_without_change", receive_only),
                ("extended_key", lone_key),
                ("address", watched),
            ],
        ),
        fixture(
            "DerivationChoice",
            vec![
                ("usual", usual.clone()),
                ("chosen", chosen.clone()),
                (
                    "receive_only",
                    DerivationChoice {
                        receive: "0/*".to_owned(),
                        change: None,
                        origin: None,
                    },
                ),
            ],
        ),
        fixture(
            "ImportOptions",
            vec![
                ("as_read", ImportOptions::default()),
                (
                    "chosen",
                    ImportOptions {
                        script: Some(ScriptKind::Segwit),
                        derivation: Some(chosen),
                        network: Some(Network::Mainnet),
                    },
                ),
            ],
        ),
        variants("QrFormat", every!(QrFormat { Plain, Ur, Bbqr })),
        fixture(
            "QrProgress",
            vec![
                (
                    "plain",
                    assemble(&[MULTIPATH.to_owned()]).expect("a plain QR code"),
                ),
                (
                    "part_of_ur",
                    QrProgress {
                        format: QrFormat::Ur,
                        received: 1,
                        total: 3,
                        complete: false,
                        text: None,
                        warnings: vec![],
                    },
                ),
                (
                    "ur_read_with_assumptions",
                    QrProgress {
                        format: QrFormat::Ur,
                        received: 3,
                        total: 3,
                        complete: true,
                        text: Some(MULTIPATH.to_owned()),
                        warnings: vec![InputWarning::AssumedBranches],
                    },
                ),
            ],
        ),
    ]
}

// --- chain -------------------------------------------------------------

fn chain() -> Vec<Fixture> {
    let servers = public_servers(Network::Mainnet);
    let esplora = servers
        .iter()
        .find(|server| server.protocol == ServerProtocol::Esplora)
        .expect("a public Esplora server")
        .clone();
    let electrum = servers
        .iter()
        .find(|server| server.protocol == ServerProtocol::Electrum)
        .expect("a public Electrum server")
        .clone();
    let mut public: Vec<(&str, PublicServer)> = vec![("esplora", esplora.clone())];
    public.push(("electrum", electrum));
    if let Some(self_signed) = servers.iter().find(|server| server.self_signed) {
        public.push(("self_signed", self_signed.clone()));
    }

    let backends = vec![
        ("public_rotation", BackendConfig::Public { server: None }),
        (
            "public_one",
            BackendConfig::Public {
                server: Some(esplora.id.clone()),
            },
        ),
        (
            "custom_esplora",
            BackendConfig::CustomEsplora {
                url: "https://esplora.example.org/api".to_owned(),
                own_node: false,
            },
        ),
        (
            "custom_esplora_own_node",
            BackendConfig::CustomEsplora {
                url: "http://umbrel.local:3002/api".to_owned(),
                own_node: true,
            },
        ),
        (
            "custom_electrum",
            BackendConfig::CustomElectrum {
                url: "ssl://electrum.example.org:50002".to_owned(),
                own_node: false,
            },
        ),
        (
            "custom_electrum_own_node",
            BackendConfig::CustomElectrum {
                url: "tcp://umbrel.local:50001".to_owned(),
                own_node: true,
            },
        ),
    ];
    reaches_every("BackendConfig", &backends, 3, |backend| match backend {
        BackendConfig::Public { .. } => 0,
        BackendConfig::CustomEsplora { .. } => 1,
        BackendConfig::CustomElectrum { .. } => 2,
    });

    let pinned = fingerprint_of(b"the certificate the user accepted");
    let presented = fingerprint_of(b"the certificate the server shows now");
    let statuses = vec![
        ("not_tls", CertificateStatus::NotTls),
        ("tor", CertificateStatus::Tor),
        ("trusted", CertificateStatus::Trusted),
        (
            "pinned",
            CertificateStatus::Pinned {
                fingerprint: pinned.clone(),
            },
        ),
        (
            "unknown",
            CertificateStatus::Unknown {
                fingerprint: presented.clone(),
                reason: "self-signed, or signed by an authority this machine does not know"
                    .to_owned(),
                subject: Some("electrum.example.org".to_owned()),
                expires: Some(1_830_297_600),
            },
        ),
        (
            "unknown_bare",
            CertificateStatus::Unknown {
                fingerprint: presented.clone(),
                reason: "written in X.509 version 1, older than the standard verifier reads"
                    .to_owned(),
                subject: None,
                expires: None,
            },
        ),
        (
            "changed",
            CertificateStatus::Changed {
                stored: pinned,
                presented,
            },
        ),
        (
            "unreachable",
            CertificateStatus::Unreachable {
                detail: "connection refused".to_owned(),
            },
        ),
    ];
    reaches_every("CertificateStatus", &statuses, 7, |status| match status {
        CertificateStatus::NotTls => 0,
        CertificateStatus::Tor => 1,
        CertificateStatus::Trusted => 2,
        CertificateStatus::Pinned { .. } => 3,
        CertificateStatus::Unknown { .. } => 4,
        CertificateStatus::Changed { .. } => 5,
        CertificateStatus::Unreachable { .. } => 6,
    });
    let reports: Vec<(&str, CertificateReport)> = statuses
        .iter()
        .map(|(case, status)| {
            let host = match status {
                CertificateStatus::Tor => {
                    "fixturefixturefixturefixturefixturefixturefixturefixture.onion:50002"
                }
                _ => "electrum.example.org:50002",
            };
            let report = CertificateReport {
                host: host.to_owned(),
                status: status.clone(),
            };
            (*case, report)
        })
        .collect();

    let scanned = vec![
        (
            "electrum_line",
            parse_backend("electrum.example.org:50002:s").expect("an Electrum line"),
        ),
        (
            "esplora",
            parse_backend("https://esplora.example.org/api").expect("an Esplora address"),
        ),
        (
            "onion",
            parse_backend(
                "tcp://fixturefixturefixturefixturefixturefixturefixturefixture.onion:50001",
            )
            .expect("an onion address"),
        ),
    ];

    let idle = TorStatus {
        mode: TorMode::Auto,
        socks_proxy: "127.0.0.1:9050".to_owned(),
        via: None,
        socks: None,
        running: false,
        bootstrapped: false,
        bootstrap_percent: 0,
        error: None,
        embedded_available: true,
        system_socks_trusted: true,
    };

    vec![
        fixture("BackendConfig", backends),
        variants(
            "ServerProtocol",
            every!(ServerProtocol { Esplora, Electrum }),
        ),
        fixture("PublicServer", public),
        variants(
            "ScannedBackendKind",
            every!(ScannedBackendKind { Electrum, Esplora }),
        ),
        fixture("ScannedBackend", scanned),
        fixture("CertificateStatus", statuses),
        fixture("CertificateReport", reports),
        variants(
            "TorMode",
            every!(TorMode {
                Auto,
                System,
                Embedded
            }),
        ),
        variants("TorVia", every!(TorVia { System, Embedded })),
        fixture(
            "TorSettings",
            vec![
                ("default", TorSettings::default()),
                (
                    "system_proxy",
                    TorSettings {
                        mode: TorMode::System,
                        socks_proxy: Some("127.0.0.1:9150".to_owned()),
                    },
                ),
            ],
        ),
        fixture(
            "TorRoute",
            vec![
                (
                    "system",
                    TorRoute::without_credentials("127.0.0.1:9050", TorVia::System),
                ),
                (
                    "embedded",
                    TorRoute::without_credentials("127.0.0.1:41935", TorVia::Embedded),
                ),
            ],
        ),
        fixture(
            "TorStatus",
            vec![
                ("idle", idle.clone()),
                (
                    "through_system",
                    TorStatus {
                        via: Some(TorVia::System),
                        socks: Some("127.0.0.1:9050".to_owned()),
                        ..idle.clone()
                    },
                ),
                (
                    "built_in_starting",
                    TorStatus {
                        mode: TorMode::Embedded,
                        running: true,
                        bootstrap_percent: 40,
                        ..idle.clone()
                    },
                ),
                (
                    "built_in_running_untrusted_loopback",
                    TorStatus {
                        via: Some(TorVia::Embedded),
                        socks: Some("127.0.0.1:41935".to_owned()),
                        running: true,
                        bootstrapped: true,
                        bootstrap_percent: 100,
                        system_socks_trusted: false,
                        ..idle.clone()
                    },
                ),
                (
                    "built_in_failed",
                    TorStatus {
                        mode: TorMode::Embedded,
                        error: Some("could not reach the Tor network".to_owned()),
                        ..idle
                    },
                ),
            ],
        ),
    ]
}

// --- wallets and their transactions --------------------------------------

fn balance() -> BalanceSnapshot {
    BalanceSnapshot {
        confirmed: 1_250_000,
        trusted_pending: 0,
        untrusted_pending: 0,
        immature: 0,
        total: 1_250_000,
        pending_net_sats: None,
    }
}

fn pending_balance() -> BalanceSnapshot {
    BalanceSnapshot {
        confirmed: 1_250_000,
        trusted_pending: 0,
        untrusted_pending: 84_000,
        immature: 0,
        total: 1_334_000,
        pending_net_sats: Some(84_000),
    }
}

fn descriptors_kind() -> WalletKind {
    match parse_input(MULTIPATH)
        .expect("a two-path descriptor")
        .payload
    {
        ParsedPayload::Descriptors {
            external,
            internal,
            script,
        } => WalletKind::Descriptors {
            external,
            internal,
            script,
        },
        ParsedPayload::Address { .. } => unreachable!("a descriptor"),
    }
}

fn electrum_stamp() -> SyncStamp {
    SyncStamp {
        at: NOW - 120,
        tip_height: TIP,
        backend: "electrum.example.org".to_owned(),
        server: Some("ssl://electrum.example.org:50002".to_owned()),
    }
}

fn savings() -> WalletMeta {
    WalletMeta {
        id: SAVINGS.to_owned(),
        name: "Savings".to_owned(),
        icon: WalletIcon::PiggyBank,
        network: Network::Signet,
        kind: descriptors_kind(),
        recognized_as: RecognizedKind::MultipathDescriptor,
        created_at: NOW - 86_400 * 30,
        gap_limit: 20,
        scan_gap: 20,
        labels: BTreeMap::from([(txid("salary"), "October salary".to_owned())]),
        last_sync: Some(electrum_stamp()),
        complete_at: Some(NOW - 3_600),
        cached: CachedTotals {
            balance: balance(),
            tx_count: 2,
        },
        live_pinned: true,
    }
}

fn fresh() -> WalletMeta {
    WalletMeta {
        id: COLD.to_owned(),
        name: "Cold storage".to_owned(),
        icon: WalletIcon::Wallet,
        network: Network::Signet,
        kind: descriptors_kind(),
        recognized_as: RecognizedKind::MultipathDescriptor,
        created_at: NOW,
        gap_limit: 20,
        scan_gap: 20,
        labels: BTreeMap::new(),
        last_sync: None,
        complete_at: None,
        cached: CachedTotals::default(),
        live_pinned: false,
    }
}

fn donations() -> WalletMeta {
    WalletMeta {
        id: DONATIONS.to_owned(),
        name: "Donations".to_owned(),
        icon: WalletIcon::Landmark,
        network: Network::Mainnet,
        kind: WalletKind::SingleAddress {
            address: MAINNET_ADDRESS.to_owned(),
        },
        recognized_as: RecognizedKind::Address,
        created_at: NOW - 86_400 * 400,
        gap_limit: 20,
        scan_gap: 20,
        labels: BTreeMap::new(),
        last_sync: Some(SyncStamp {
            at: NOW - 600,
            tip_height: TIP,
            backend: "mempool.space".to_owned(),
            server: None,
        }),
        complete_at: None,
        cached: CachedTotals {
            balance: BalanceSnapshot {
                confirmed: 21_000,
                total: 21_000,
                ..BalanceSnapshot::default()
            },
            tx_count: 1,
        },
        live_pinned: false,
    }
}

fn received() -> TxSummary {
    TxSummary {
        txid: txid("salary"),
        net_sats: 1_000_000,
        fee_sats: None,
        status: TxStatus::Confirmed {
            height: TIP - 5,
            timestamp: Some(NOW - 3_000),
        },
        confirmations: 6,
    }
}

fn sent() -> TxSummary {
    TxSummary {
        txid: txid("rent"),
        net_sats: -250_340,
        fee_sats: Some(340),
        status: TxStatus::Pending,
        confirmations: 0,
    }
}

fn new_tx(summary: &TxSummary) -> NewTx {
    NewTx {
        txid: summary.txid.clone(),
        net_sats: summary.net_sats,
        confirmed: matches!(summary.status, TxStatus::Confirmed { .. }),
    }
}

fn sync_report() -> SyncReport {
    SyncReport {
        wallet_id: SAVINGS.to_owned(),
        new_tx_count: 1,
        new_txs: vec![new_tx(&sent())],
        confirmed_txs: vec![new_tx(&received())],
        balance: pending_balance(),
        tip_height: TIP,
        took_ms: 840,
        backend: "electrum.example.org".to_owned(),
    }
}

fn op_return(bytes: &[u8]) -> OpReturnData {
    let push = PushBytesBuf::try_from(bytes.to_vec()).expect("a short payload");
    op_return_of(&ScriptBuf::new_op_return(push)).expect("an OP_RETURN script")
}

fn wallet() -> Vec<Fixture> {
    let mut commitment = vec![0xaa, 0x21, 0xa9, 0xed];
    commitment.extend([0x5c; 32]);
    let returns = vec![
        ("text", op_return(b"Hello from the Gerfaut tests")),
        ("witness_commitment", op_return(&commitment)),
        ("bytes", op_return(&[0x00, 0xff, 0x13, 0x37])),
    ];

    let statuses = vec![
        (
            "confirmed",
            TxStatus::Confirmed {
                height: TIP - 5,
                timestamp: Some(NOW - 3_000),
            },
        ),
        (
            "confirmed_without_time",
            TxStatus::Confirmed {
                height: TIP,
                timestamp: None,
            },
        ),
        ("pending", TxStatus::Pending),
    ];
    reaches_every("TxStatus", &statuses, 2, |status| match status {
        TxStatus::Confirmed { .. } => 0,
        TxStatus::Pending => 1,
    });

    let kinds = vec![
        ("descriptors", descriptors_kind()),
        (
            "descriptors_without_change",
            WalletKind::Descriptors {
                external: RECEIVE.to_owned(),
                internal: None,
                script: ScriptKind::Segwit,
            },
        ),
        (
            "single_address",
            WalletKind::SingleAddress {
                address: MAINNET_ADDRESS.to_owned(),
            },
        ),
    ];
    reaches_every("WalletKind", &kinds, 2, |kind| match kind {
        WalletKind::Descriptors { .. } => 0,
        WalletKind::SingleAddress { .. } => 1,
    });

    let input_mine = TxIo {
        address: Some(address(RECEIVE, 0)),
        value_sats: Some(1_000_000),
        is_mine: true,
        change: false,
        op_return: None,
        prev_txid: Some(txid("salary")),
        prev_vout: Some(0),
    };
    let payee = TxIo {
        address: Some(TESTNET_ADDRESS.to_owned()),
        value_sats: Some(250_000),
        is_mine: false,
        change: false,
        op_return: None,
        prev_txid: None,
        prev_vout: None,
    };
    let change = TxIo {
        address: Some(address(CHANGE, 0)),
        value_sats: Some(749_660),
        is_mine: true,
        change: true,
        ..TxIo::default()
    };
    let data = TxIo {
        address: None,
        value_sats: Some(0),
        is_mine: false,
        op_return: Some(op_return(b"Hello from the Gerfaut tests")),
        ..TxIo::default()
    };
    let unknown_input = TxIo {
        address: None,
        value_sats: None,
        is_mine: false,
        prev_txid: Some(txid("unknown")),
        prev_vout: Some(3),
        ..TxIo::default()
    };

    let extras = tx_extras::analyze(&spend(true).tx, |_| Some(spent_coin()));
    let coinbase = tx_extras::analyze(&coinbase(), |_| None);

    let rows = |keychain: &str, used: u32, count: u32| -> Vec<AddressRow> {
        (0..count)
            .map(|index| AddressRow {
                index,
                address: address(keychain, index),
                used: index < used,
                balance_sats: if index == 0 { 1_000_000 } else { 0 },
            })
            .collect()
    };

    let snapshot = WalletSnapshot {
        meta: savings(),
        balance: pending_balance(),
        txs: vec![sent(), received()],
        tip_height: TIP,
        truncated: false,
    };

    vec![
        fixture("WalletKind", kinds),
        fixture(
            "SyncStamp",
            vec![
                ("electrum", electrum_stamp()),
                (
                    "before_servers_were_named",
                    SyncStamp {
                        server: None,
                        ..electrum_stamp()
                    },
                ),
            ],
        ),
        fixture(
            "CachedTotals",
            vec![
                ("synced", savings().cached),
                ("never_synced", CachedTotals::default()),
            ],
        ),
        variants(
            "WalletIcon",
            every!(WalletIcon {
                Wallet,
                Key,
                Shield,
                MapPin,
                Snowflake,
                Landmark,
                PiggyBank,
            }),
        ),
        fixture(
            "WalletMeta",
            vec![
                ("synced", savings()),
                ("just_added", fresh()),
                ("single_address", donations()),
            ],
        ),
        fixture(
            "BalanceSnapshot",
            vec![("settled", balance()), ("pending", pending_balance())],
        ),
        fixture("TxStatus", statuses),
        fixture(
            "TxSummary",
            vec![("received", received()), ("sent", sent())],
        ),
        fixture("OpReturnData", returns),
        fixture(
            "TxIo",
            vec![
                ("input_of_the_wallet", input_mine.clone()),
                ("unknown_input", unknown_input),
                ("payment", payee.clone()),
                ("change", change.clone()),
                ("op_return", data.clone()),
            ],
        ),
        fixture(
            "TxExtras",
            vec![("payment", extras.clone()), ("coinbase", coinbase)],
        ),
        fixture(
            "TxDetail",
            vec![
                (
                    "sent",
                    TxDetail {
                        summary: sent(),
                        inputs: vec![input_mine],
                        outputs: vec![payee, change, data],
                        vsize: extras.vsize,
                        fee_rate_sat_vb: Some(340.0 / extras.vsize as f64),
                        extras: Some(extras),
                    },
                ),
                (
                    "older_watched_address",
                    TxDetail {
                        summary: received(),
                        inputs: vec![],
                        outputs: vec![],
                        vsize: 0,
                        fee_rate_sat_vb: None,
                        extras: None,
                    },
                ),
            ],
        ),
        variants("Keychain", every!(Keychain { External, Internal })),
        fixture(
            "UtxoInfo",
            vec![
                (
                    "received",
                    UtxoInfo {
                        txid: txid("salary"),
                        vout: 0,
                        address: Some(address(RECEIVE, 0)),
                        value_sats: 1_000_000,
                        status: TxStatus::Confirmed {
                            height: TIP - 5,
                            timestamp: Some(NOW - 3_000),
                        },
                        keychain: Some(Keychain::External),
                        derivation_index: Some(0),
                    },
                ),
                (
                    "change_pending",
                    UtxoInfo {
                        txid: txid("rent"),
                        vout: 1,
                        address: Some(address(CHANGE, 0)),
                        value_sats: 749_660,
                        status: TxStatus::Pending,
                        keychain: Some(Keychain::Internal),
                        derivation_index: Some(0),
                    },
                ),
                (
                    "watched_address",
                    UtxoInfo {
                        txid: txid("donation"),
                        vout: 2,
                        address: Some(MAINNET_ADDRESS.to_owned()),
                        value_sats: 21_000,
                        status: TxStatus::Confirmed {
                            height: TIP - 100,
                            timestamp: Some(NOW - 60_000),
                        },
                        keychain: None,
                        derivation_index: None,
                    },
                ),
            ],
        ),
        fixture(
            "AddressEntry",
            vec![
                (
                    "derived",
                    AddressEntry {
                        index: 1,
                        address: address(RECEIVE, 1),
                        used: false,
                        derivation: Some("m/84'/1'/0'/0/1".to_owned()),
                    },
                ),
                (
                    "watched_address",
                    AddressEntry {
                        index: 0,
                        address: MAINNET_ADDRESS.to_owned(),
                        used: true,
                        derivation: None,
                    },
                ),
            ],
        ),
        fixture(
            "AddressRow",
            vec![
                ("used", rows(RECEIVE, 1, 1).remove(0)),
                (
                    "unused",
                    AddressRow {
                        index: 1,
                        address: address(RECEIVE, 1),
                        used: false,
                        balance_sats: 0,
                    },
                ),
            ],
        ),
        fixture(
            "AddressList",
            vec![(
                "revealed",
                AddressList {
                    external: rows(RECEIVE, 1, 2),
                    internal: rows(CHANGE, 1, 1),
                    truncated: false,
                },
            )],
        ),
        fixture(
            "WalletSnapshot",
            vec![
                ("synced", snapshot.clone()),
                (
                    "busy_address",
                    WalletSnapshot {
                        meta: donations(),
                        balance: donations().cached.balance,
                        txs: vec![],
                        tip_height: TIP,
                        truncated: true,
                    },
                ),
            ],
        ),
        fixture(
            "NewTx",
            vec![("received", new_tx(&received())), ("sent", new_tx(&sent()))],
        ),
        fixture(
            "SyncReport",
            vec![
                ("news", sync_report()),
                (
                    "nothing_new",
                    SyncReport {
                        new_tx_count: 0,
                        new_txs: vec![],
                        confirmed_txs: vec![],
                        balance: balance(),
                        ..sync_report()
                    },
                ),
            ],
        ),
        fixture(
            "SyncFailure",
            vec![(
                "unreachable",
                SyncFailure {
                    wallet_id: COLD.to_owned(),
                    message: "sync failed via electrum.example.org: connection refused".to_owned(),
                },
            )],
        ),
        fixture(
            "SyncAllReport",
            vec![(
                "one_failed",
                SyncAllReport {
                    reports: vec![sync_report()],
                    failures: vec![SyncFailure {
                        wallet_id: COLD.to_owned(),
                        message: "sync failed via electrum.example.org: connection refused"
                            .to_owned(),
                    }],
                },
            )],
        ),
    ]
}

// --- policy ------------------------------------------------------------

/// A coin of `tag`, confirmed at `height` with the time a block there
/// would have, or waiting in the mempool.
fn coin(tag: &str, height: Option<u32>) -> Coin {
    Coin {
        outpoint: format!("{}:0", tag.repeat(32)),
        value_sats: 100_000,
        height,
        timestamp: height.map(|h| NOW - u64::from(TIP - h) * 600),
    }
}

fn read_policy(descriptor: &str, script: ScriptKind, coins: Vec<Coin>) -> PolicySnapshot {
    analyze(PolicyInput {
        external_descriptor: descriptor,
        script,
        coins,
        tip_height: Some(TIP),
        now_unix: NOW,
    })
    .expect("a test policy")
}

fn policies() -> Vec<(&'static str, PolicySnapshot)> {
    let (a, b, c, d) = (KEY_A, KEY_B, KEY_C, KEY_D);
    let script = ScriptKind::WitnessScript;
    let never_synced = analyze(PolicyInput {
        external_descriptor: &format!(
            "wsh(or_d(pk({a}/0/*),or_i(and_v(v:pkh({b}/0/*),after(1899979200)),and_v(v:pkh({c}/0/*),after(801432)))))"
        ),
        script,
        coins: vec![],
        tip_height: None,
        now_unix: NOW,
    })
    .expect("a test policy");
    vec![
        // Keys A and B any time; C and D after 4,320 blocks, D alone
        // after 26,280, C alone after 52,560, written farthest first.
        // One coin past every lock, one 4,001 blocks old, one waiting.
        (
            "recovery_paths",
            read_policy(
                &format!(
                    "wsh(or_d(multi(2,{a}/0/*,{b}/0/*),or_i(and_v(v:pkh({c}/0/*),older(52560)),or_i(and_v(v:pkh({d}/0/*),older(26280)),and_v(v:multi(2,{c}/1/*,{d}/1/*),older(4320))))))"
                ),
                script,
                vec![
                    coin("aa", Some(740_000)),
                    coin("bb", Some(796_000)),
                    coin("cc", None),
                ],
            ),
        ),
        // Liana's everyday shape: A any time, B once a coin has waited
        // 52,560 blocks. One coin past the lock, one 10,001 blocks old.
        (
            "relative",
            read_policy(
                &format!("wsh(or_d(pk({a}/0/*),and_v(v:pkh({b}/0/*),older(52560))))"),
                script,
                vec![coin("aa", Some(700_000)), coin("bb", Some(790_000))],
            ),
        ),
        // The same wallet, both coins past the lock.
        (
            "relative_open",
            read_policy(
                &format!("wsh(or_d(pk({a}/0/*),and_v(v:pkh({b}/0/*),older(52560))))"),
                script,
                vec![coin("aa", Some(700_000)), coin("bb", Some(740_000))],
            ),
        ),
        // A any time, B after noon UTC on 17 March 2030, C after block
        // 801,432, the date written first.
        (
            "absolute",
            read_policy(
                &format!(
                    "wsh(or_d(pk({a}/0/*),or_i(and_v(v:pkh({b}/0/*),after(1899979200)),and_v(v:pkh({c}/0/*),after(801432)))))"
                ),
                script,
                vec![coin("aa", Some(799_000))],
            ),
        ),
        // Any 2 of 3 keys.
        (
            "multisig",
            read_policy(
                &format!("wsh(sortedmulti(2,{a}/0/*,{b}/0/*,{c}/0/*))"),
                script,
                vec![coin("aa", Some(799_000))],
            ),
        ),
        (
            "single_key",
            read_policy(RECEIVE, ScriptKind::Segwit, vec![]),
        ),
        ("never_synced", never_synced),
        (
            "address",
            address_snapshot(MAINNET_ADDRESS, Some(TIP), 1, NOW),
        ),
    ]
}

fn policy() -> Vec<Fixture> {
    let snapshots = policies();
    let read = |case: &str| -> PolicySnapshot {
        snapshots
            .iter()
            .find(|(name, _)| *name == case)
            .map(|(_, snapshot)| snapshot.clone())
            .expect("a policy case")
    };
    let recovery = read("recovery_paths");
    let single = read("single_key");

    let blocks = Remaining {
        remaining_blocks: Some(4_320),
        remaining_seconds: Some(2_592_000),
        unlocks_at_unix: Some(NOW + 2_592_000),
    };
    let date = Remaining {
        remaining_blocks: None,
        remaining_seconds: Some(149_979_200),
        unlocks_at_unix: Some(1_899_979_200),
    };
    let unknown = Remaining::default();
    let height_lock = AbsoluteLock::Height { height: 801_432 };
    let time_lock = AbsoluteLock::Time {
        unix: 1_899_979_200,
    };
    let older = RelativeLock::Blocks { blocks: 52_560 };
    let older_time = RelativeLock::Seconds { seconds: 7_776_000 };

    let absolute_locks = vec![("height", height_lock), ("time", time_lock)];
    reaches_every("AbsoluteLock", &absolute_locks, 2, |lock| match lock {
        AbsoluteLock::Height { .. } => 0,
        AbsoluteLock::Time { .. } => 1,
    });
    let relative_locks = vec![("blocks", older), ("seconds", older_time)];
    reaches_every("RelativeLock", &relative_locks, 2, |lock| match lock {
        RelativeLock::Blocks { .. } => 0,
        RelativeLock::Seconds { .. } => 1,
    });
    let key = |id: &str| Condition::Key {
        key_id: id.to_owned(),
    };
    let conditions = vec![
        ("key", key("k0")),
        (
            "thresh",
            Condition::Thresh {
                k: 2,
                n: 2,
                items: vec![key("k1"), Condition::Older { lock: older }],
            },
        ),
        ("after", Condition::After { lock: height_lock }),
        ("older", Condition::Older { lock: older }),
        (
            "preimage",
            Condition::Preimage {
                hash: sha256::Hash::hash(b"a secret nobody holds").to_string(),
            },
        ),
    ];
    reaches_every("Condition", &conditions, 5, |condition| match condition {
        Condition::Key { .. } => 0,
        Condition::Thresh { .. } => 1,
        Condition::After { .. } => 2,
        Condition::Older { .. } => 3,
        Condition::Preimage { .. } => 4,
    });
    let refs = vec![
        ("absolute", TimelockRef::Absolute { lock: time_lock }),
        ("relative", TimelockRef::Relative { lock: older }),
    ];
    reaches_every("TimelockRef", &refs, 2, |lock| match lock {
        TimelockRef::Absolute { .. } => 0,
        TimelockRef::Relative { .. } => 1,
    });
    let lock_states = vec![
        ("unlocked", LockState::Unlocked),
        ("locked", LockState::Locked { until: date }),
        (
            "per_coin",
            LockState::PerCoin {
                unlocked: 1,
                waiting: 1,
                locked: 1,
                next: Some(blocks),
            },
        ),
        (
            "per_coin_none_left",
            LockState::PerCoin {
                unlocked: 2,
                waiting: 0,
                locked: 0,
                next: None,
            },
        ),
        (
            "no_coins",
            LockState::NoCoins {
                blocks: Some(52_560),
                seconds: None,
            },
        ),
        (
            "no_coins_time",
            LockState::NoCoins {
                blocks: None,
                seconds: Some(7_776_000),
            },
        ),
    ];
    reaches_every("LockState", &lock_states, 4, |state| match state {
        LockState::Unlocked => 0,
        LockState::Locked { .. } => 1,
        LockState::PerCoin { .. } => 2,
        LockState::NoCoins { .. } => 3,
    });
    let branch_states = vec![
        ("spendable_now", BranchState::SpendableNow),
        ("locked", BranchState::Locked { until: unknown }),
        (
            "per_coin",
            BranchState::PerCoin {
                unlocked: 0,
                waiting: 1,
                locked: 1,
                next: Some(blocks),
            },
        ),
        (
            "per_coin_none_left",
            BranchState::PerCoin {
                unlocked: 2,
                waiting: 0,
                locked: 0,
                next: None,
            },
        ),
        ("no_coins", BranchState::NoCoins),
        ("needs_preimage", BranchState::NeedsPreimage),
    ];
    reaches_every("BranchState", &branch_states, 5, |state| match state {
        BranchState::SpendableNow => 0,
        BranchState::Locked { .. } => 1,
        BranchState::PerCoin { .. } => 2,
        BranchState::NoCoins => 3,
        BranchState::NeedsPreimage => 4,
    });
    let branch = |id: &str| -> PolicyBranch {
        recovery
            .branches
            .iter()
            .find(|branch| branch.id == id)
            .expect("a branch of the recovery policy")
            .clone()
    };
    let with_timelock = recovery
        .branches
        .iter()
        .find(|branch| !branch.timelocks.is_empty())
        .expect("a branch with a lock")
        .clone();

    vec![
        variants(
            "PolicyKind",
            every!(PolicyKind {
                SingleKey,
                Multisig,
                Miniscript,
                Address,
            }),
        ),
        variants(
            "BranchRole",
            every!(BranchRole {
                Primary,
                Recovery,
                Emergency,
                Other,
            }),
        ),
        variants("TimeBasis", every!(TimeBasis { WallClock })),
        variants(
            "BranchTone",
            every!(BranchTone {
                Confirmed,
                Pending,
                Neutral,
            }),
        ),
        fixture(
            "PolicyKey",
            vec![
                ("bare", recovery.keys[0].clone()),
                ("with_origin", single.keys[0].clone()),
            ],
        ),
        fixture("AbsoluteLock", absolute_locks),
        fixture("RelativeLock", relative_locks),
        fixture("Condition", conditions),
        fixture("TimelockRef", refs),
        fixture(
            "Remaining",
            vec![("blocks", blocks), ("date", date), ("unknown", unknown)],
        ),
        fixture("LockState", lock_states),
        fixture(
            "Timelock",
            vec![
                ("required", with_timelock.timelocks[0].clone()),
                (
                    "optional",
                    Timelock {
                        lock: TimelockRef::Absolute { lock: height_lock },
                        required: false,
                        state: LockState::Locked { until: blocks },
                    },
                ),
            ],
        ),
        fixture("BranchState", branch_states),
        fixture(
            "PolicyBranch",
            vec![("primary", branch("b0")), ("recovery", with_timelock)],
        ),
        fixture("PolicySnapshot", snapshots),
    ]
}

// --- files: export, backup ----------------------------------------------

fn files() -> Vec<Fixture> {
    let everything = ExportOptions {
        from: None,
        to: None,
        direction: None,
        include_pending: true,
    };
    let filtered = ExportOptions {
        from: Some(NOW - 86_400 * 31),
        to: Some(NOW),
        direction: Some(ExportDirection::Incoming),
        include_pending: false,
    };
    // What a sealed backup looks like to the bridge: base64 and UR
    // frames of bytes nobody can open.
    let sealed: Vec<u8> = (0..400u32).map(|i| (i * 37 % 251) as u8).collect();
    let bundle = BackupBundle {
        data: data_encoding::BASE64.encode(&sealed),
        frames: backup::frames(&sealed),
        wallet_count: 2,
        size_bytes: sealed.len() as u32,
    };
    let previews = vec![
        BackupWalletPreview {
            index: 0,
            name: "Savings".to_owned(),
            network: Network::Signet,
            kind: descriptors_kind(),
            already_watched: false,
        },
        BackupWalletPreview {
            index: 1,
            name: "Donations".to_owned(),
            network: Network::Mainnet,
            kind: WalletKind::SingleAddress {
                address: MAINNET_ADDRESS.to_owned(),
            },
            already_watched: true,
        },
    ];
    let backend = BackupBackendPreview {
        network: Network::Mainnet,
        backend: "electrum.example.org".to_owned(),
    };

    vec![
        variants(
            "ExportDirection",
            every!(ExportDirection { Incoming, Outgoing }),
        ),
        fixture(
            "ExportOptions",
            vec![("everything", everything.clone()), ("filtered", filtered)],
        ),
        fixture(
            "ExportResult",
            vec![(
                "two_rows",
                transactions_csv(&[received(), sent()], &everything),
            )],
        ),
        fixture(
            "BackupOptions",
            vec![
                ("everything", BackupOptions::default()),
                (
                    "chosen",
                    BackupOptions {
                        wallet_ids: Some(vec![SAVINGS.to_owned()]),
                        include_settings: true,
                    },
                ),
            ],
        ),
        fixture("BackupBundle", vec![("two_wallets", bundle)]),
        fixture(
            "BackupWalletPreview",
            vec![
                ("new", previews[0].clone()),
                ("already_watched", previews[1].clone()),
            ],
        ),
        fixture("BackupBackendPreview", vec![("electrum", backend.clone())]),
        fixture(
            "BackupPreview",
            vec![
                (
                    "with_settings",
                    BackupPreview {
                        created_at: NOW - 86_400,
                        wallets: previews.clone(),
                        has_settings: true,
                        backends: vec![backend],
                        electrum_hosts: vec!["electrum.example.org:50002".to_owned()],
                    },
                ),
                (
                    "wallets_only",
                    BackupPreview {
                        created_at: NOW - 86_400,
                        wallets: previews,
                        has_settings: false,
                        backends: vec![],
                        electrum_hosts: vec![],
                    },
                ),
            ],
        ),
        fixture(
            "ImportChoices",
            vec![
                ("everything", ImportChoices::default()),
                (
                    "chosen",
                    ImportChoices {
                        indexes: Some(vec![0]),
                        apply_settings: true,
                    },
                ),
            ],
        ),
        fixture(
            "ImportReport",
            vec![(
                "one_restored",
                ImportReport {
                    added: vec![fresh()],
                    skipped: 1,
                    settings_applied: true,
                },
            )],
        ),
    ]
}

// --- broadcast ---------------------------------------------------------

fn script_of(address: &str) -> ScriptBuf {
    Address::from_str(address)
        .expect("a test address")
        .assume_checked()
        .script_pubkey()
}

/// The coin [`spend`] spends: 1,000,000 sats on the first receive
/// address of the BDK tpub.
fn spent_coin() -> TxOut {
    TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: script_of(&address(RECEIVE, 0)),
    }
}

/// The coinbase of block [`TIP`], tagged the way a pool tags its
/// blocks, paying a BIP-173 address.
fn coinbase() -> Transaction {
    let mut script_sig = vec![0x03];
    script_sig.extend_from_slice(&TIP.to_le_bytes()[..3]);
    script_sig.extend_from_slice(b"/Foundry USA Pool #dropgold/");
    let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment.extend([0x5c; 32]);
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(312_500_000),
                script_pubkey: script_of(MAINNET_ADDRESS),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment),
            },
        ],
    }
}

/// A payment of 250,000 sats from the first receive address of the
/// BDK tpub, with change, as a signed raw transaction or as the
/// unsigned skeleton of a PSBT.
fn spend(signed: bool) -> DecodedTx {
    let script = script_of;
    let witness = if signed {
        Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]])
    } else {
        Witness::new()
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(TIP - 1).expect("a height"),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&txid("salary")).expect("a txid"),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(250_000),
                script_pubkey: script(TESTNET_ADDRESS),
            },
            TxOut {
                value: Amount::from_sat(749_660),
                script_pubkey: script(&address(CHANGE, 0)),
            },
        ],
    };
    let prevout = spent_coin();
    DecodedTx {
        source: if signed {
            TxSource::RawTransaction
        } else {
            TxSource::Psbt
        },
        tx,
        inputs: vec![DecodedInput {
            signed,
            prevout: (!signed).then(|| prevout.clone()),
            prevout_proven: false,
            disputed_witness_utxo: None,
            loose_sighash: None,
            finalized: None,
            hints: SigningHints::default(),
        }],
        ready: signed,
    }
}

fn previews() -> Vec<(&'static str, TxPreview)> {
    let prevout = spend(false).inputs[0].prevout.clone();
    let mine = InputFacts {
        prevout: prevout.clone(),
        wallet: Some(wallet_ref(SAVINGS, "Savings")),
        ..InputFacts::default()
    };
    let outputs = [
        OutputFacts::default(),
        OutputFacts {
            wallet: Some(wallet_ref(SAVINGS, "Savings")),
            change: true,
        },
    ];
    let preview = |decoded: DecodedTx, input: InputFacts| {
        broadcast::build_preview(
            &decoded,
            Network::Signet,
            &[input],
            &outputs,
            Some(TIP),
            NOW,
        )
    };
    vec![
        ("ready", preview(spend(true), mine.clone())),
        (
            "unsigned_psbt",
            preview(spend(false), InputFacts::default()),
        ),
        (
            "refused",
            preview(
                spend(true),
                InputFacts {
                    spent: Some(true),
                    spent_by: Some(broadcast::SpentBy {
                        txid: Txid::from_str(&txid("earlier")).expect("a txid"),
                        confirmed: true,
                    }),
                    ..mine
                },
            ),
        ),
    ]
}

fn broadcasts() -> Vec<Fixture> {
    let previews = previews();
    let ready = previews[0].1.clone();
    let unsigned = previews[1].1.clone();
    let refused = previews[2].1.clone();
    let mut warnings: Vec<(String, TxWarning)> = Vec::new();
    for (_, preview) in &previews {
        for warning in &preview.warnings {
            let case = serde_json::to_value(warning.kind).expect("a kind serializes");
            let case = case.as_str().expect("a unit variant").to_owned();
            if !warnings.iter().any(|(seen, _)| *seen == case) {
                warnings.push((case, warning.clone()));
            }
        }
    }
    let warnings: Vec<(&str, TxWarning)> = warnings
        .iter()
        .map(|(case, warning)| (case.as_str(), warning.clone()))
        .collect();
    assert!(
        warnings.iter().any(|(_, w)| w.blocking) && warnings.iter().any(|(_, w)| !w.blocking),
        "the warnings show both a blocking caution and one that is not"
    );
    let found = BroadcastStatus {
        txid: ready.txid.clone(),
        found: true,
        confirmed: true,
        block_height: Some(TIP + 1),
        confirmations: 1,
        backend: "electrum.example.org".to_owned(),
        at: NOW + 700,
    };

    vec![
        variants(
            "TxSource",
            every!(TxSource {
                RawTransaction,
                Psbt
            }),
        ),
        fixture(
            "WalletRef",
            vec![("savings", wallet_ref(SAVINGS, "Savings"))],
        ),
        fixture(
            "TxInputPreview",
            vec![
                ("signed_coin_of_a_wallet", ready.inputs[0].clone()),
                ("unsigned_unknown_coin", unsigned.inputs[0].clone()),
            ],
        ),
        fixture(
            "TxOutputPreview",
            vec![
                ("payment", ready.outputs[0].clone()),
                ("change", ready.outputs[1].clone()),
                (
                    "op_return",
                    TxOutputPreview {
                        index: 2,
                        value_sats: 0,
                        address: None,
                        op_return: Some(op_return(b"Hello from the Gerfaut tests")),
                        wallet: None,
                        change: false,
                    },
                ),
            ],
        ),
        variants(
            "TxWarningKind",
            every!(TxWarningKind {
                Unsigned,
                HighFeeRate,
                HighFeeShare,
                Locked,
                InputUnknown,
                InputSpent,
                InputMismatch,
                FeeUnknown,
                DustOutput,
                SpendsWatched,
                UncommittedOutputs,
            }),
        ),
        variants("TxSeverity", every!(TxSeverity { Alert, Info })),
        fixture("TxWarning", warnings),
        variants(
            "TxReadiness",
            every!(TxReadiness {
                Ready,
                Refused,
                Unsigned,
            }),
        ),
        variants(
            "FeeRateBasis",
            every!(FeeRateBasis {
                Exact,
                Estimated,
                UpperBound,
            }),
        ),
        fixture(
            "TxPreview",
            vec![
                ("ready", ready.clone()),
                ("unsigned_psbt", unsigned),
                ("refused", refused),
            ],
        ),
        fixture(
            "BroadcastReport",
            vec![(
                "sent",
                BroadcastReport {
                    txid: ready.txid.clone(),
                    backend: "electrum.example.org".to_owned(),
                    at: NOW,
                },
            )],
        ),
        fixture(
            "BroadcastStatus",
            vec![
                ("confirmed", found.clone()),
                (
                    "in_mempool",
                    BroadcastStatus {
                        confirmed: false,
                        block_height: None,
                        confirmations: 0,
                        ..found.clone()
                    },
                ),
                (
                    "not_found",
                    BroadcastStatus {
                        found: false,
                        confirmed: false,
                        block_height: None,
                        confirmations: 0,
                        ..found
                    },
                ),
            ],
        ),
        fixture(
            "RecentBroadcast",
            vec![(
                "sent",
                RecentBroadcast {
                    txid: ready.txid.clone(),
                    network: Network::Signet,
                    hex: ready.hex.clone().expect("a ready preview has its hex"),
                    backend: "electrum.example.org".to_owned(),
                    at: NOW,
                },
            )],
        ),
    ]
}

// --- settings, lock, preferences, updates --------------------------------

fn settings() -> Vec<Fixture> {
    let chosen = Preferences {
        unit: Unit::Sats,
        masked: true,
        fiat: true,
        fiat_currency: FiatCurrency::Chf,
        price_source: PriceSource::Kraken,
        notify_new_tx: true,
        explorer_ack: true,
    };
    let pin = AppLock {
        kind: LockKind::Pin,
        biometric: true,
        secret: None,
    };
    let configured = Settings {
        active_network: Network::Signet,
        backends: BTreeMap::from([
            (
                Network::Mainnet,
                BackendConfig::CustomElectrum {
                    url: "tcp://umbrel.local:50001".to_owned(),
                    own_node: true,
                },
            ),
            (Network::Signet, BackendConfig::Public { server: None }),
        ]),
        gap_limit: 50,
        app_prefs: BTreeMap::from([("theme".to_owned(), "dark".to_owned())]),
        electrum_certs: BTreeMap::from([(
            "electrum.example.org:50002".to_owned(),
            fingerprint_of(b"the certificate the user accepted"),
        )]),
        app_lock: Some(pin.clone()),
        tor: TorSettings {
            mode: TorMode::System,
            socks_proxy: Some("127.0.0.1:9150".to_owned()),
        },
        preferences: chosen,
    };
    let status = UpdateStatus {
        automatic: true,
        announce: None,
        available: None,
        tor_unavailable: false,
    };

    vec![
        variants("LockKind", every!(LockKind { Pin, Password })),
        fixture(
            "AppLock",
            vec![
                ("pin_with_biometrics", pin),
                (
                    "password",
                    AppLock {
                        kind: LockKind::Password,
                        biometric: false,
                        secret: None,
                    },
                ),
            ],
        ),
        fixture(
            "LockVerdict",
            vec![
                (
                    "unlocked",
                    LockVerdict {
                        unlocked: true,
                        failures: 0,
                        retry_after_secs: 0,
                    },
                ),
                (
                    "refused_with_delay",
                    LockVerdict {
                        unlocked: false,
                        failures: 5,
                        retry_after_secs: 30,
                    },
                ),
            ],
        ),
        fixture(
            "Settings",
            vec![("fresh", Settings::default()), ("configured", configured)],
        ),
        variants(
            "TxStage",
            every!(TxStage {
                Mempool,
                Confirmed,
                Dropped,
            }),
        ),
        variants("Unit", every!(Unit { Btc, Sats })),
        fixture(
            "Preferences",
            vec![("default", Preferences::default()), ("chosen", chosen)],
        ),
        fixture(
            "PreferencesChange",
            vec![
                ("nothing", PreferencesChange::default()),
                (
                    "currency",
                    PreferencesChange {
                        fiat_currency: Some(FiatCurrency::Usd),
                        ..PreferencesChange::default()
                    },
                ),
                (
                    "everything",
                    PreferencesChange {
                        unit: Some(Unit::Sats),
                        masked: Some(true),
                        fiat: Some(true),
                        fiat_currency: Some(FiatCurrency::Chf),
                        price_source: Some(PriceSource::Kraken),
                        notify_new_tx: Some(true),
                        explorer_ack: Some(true),
                    },
                ),
            ],
        ),
        fixture(
            "UpdateStatus",
            vec![
                ("up_to_date", status.clone()),
                (
                    "announce",
                    UpdateStatus {
                        announce: Some("0.2.0".to_owned()),
                        available: Some("0.2.0".to_owned()),
                        ..status.clone()
                    },
                ),
                (
                    "closed",
                    UpdateStatus {
                        available: Some("0.2.0".to_owned()),
                        ..status.clone()
                    },
                ),
                (
                    "tor_unavailable",
                    UpdateStatus {
                        tor_unavailable: true,
                        ..status.clone()
                    },
                ),
                (
                    "off",
                    UpdateStatus {
                        automatic: false,
                        ..status
                    },
                ),
            ],
        ),
    ]
}

// --- price -------------------------------------------------------------

fn prices() -> Vec<Fixture> {
    let table = price_table();
    let entry = |currency: FiatCurrency| -> CurrencyEntry {
        table
            .currencies
            .iter()
            .find(|entry| entry.currency == currency)
            .expect("a currency of the table")
            .clone()
    };
    let sources: Vec<(String, SourceEntry)> = table
        .sources
        .iter()
        .map(|entry| {
            let case = serde_json::to_value(entry.source).expect("a source serializes");
            (
                case.as_str().expect("a unit variant").to_owned(),
                entry.clone(),
            )
        })
        .collect();
    let sources: Vec<(&str, SourceEntry)> = sources
        .iter()
        .map(|(case, entry)| (case.as_str(), entry.clone()))
        .collect();
    let points = vec![
        PricePoint {
            t: NOW - 7_200,
            rate: 91_250.5,
        },
        PricePoint {
            t: NOW - 3_600,
            rate: 91_810.0,
        },
        PricePoint {
            t: NOW,
            rate: 92_034.25,
        },
    ];

    vec![
        variants(
            "PriceSource",
            every!(PriceSource {
                Coingecko,
                Kraken,
                MempoolSpace,
            }),
        ),
        variants(
            "CurrencyReach",
            every!(CurrencyReach {
                Every,
                CoingeckoOnly,
            }),
        ),
        variants("FiatCurrency", FiatCurrency::ALL.to_vec()),
        fixture(
            "CurrencyEntry",
            vec![
                ("every_source", entry(FiatCurrency::Eur)),
                ("coingecko_only", entry(FiatCurrency::Inr)),
            ],
        ),
        fixture("SourceEntry", sources),
        fixture("PriceTable", vec![("table", table.clone())]),
        fixture(
            "PriceQuote",
            vec![(
                "eur",
                PriceQuote {
                    rate: 92_034.25,
                    currency: FiatCurrency::Eur,
                    source: PriceSource::Coingecko,
                    at: NOW,
                },
            )],
        ),
        variants(
            "PriceRange",
            every!(PriceRange {
                Day,
                Week,
                Month,
                Year,
                Max,
            }),
        ),
        fixture("PricePoint", vec![("point", points[0])]),
        fixture(
            "PriceHistory",
            vec![(
                "day",
                PriceHistory {
                    points,
                    currency: FiatCurrency::Eur,
                    source: PriceSource::Kraken,
                    range: PriceRange::Day,
                    at: NOW,
                },
            )],
        ),
    ]
}

// --- live --------------------------------------------------------------

fn live_tx(stage: TxStage) -> LiveTx {
    LiveTx {
        wallet_id: SAVINGS.to_owned(),
        txid: txid("rent"),
        net_sats: 84_000,
        stage,
        replaces: None,
    }
}

fn live() -> Vec<Fixture> {
    let any = WatchLimits::DEFAULT;
    let own = WatchLimits::OWN_NODE;
    let remedies = vec![
        ("own_node", Remedy::OwnNode { limits: own }),
        (
            "raise_fulcrum",
            Remedy::RaiseServerLimit {
                server: Some(ServerSoftware::Fulcrum),
                settings: vec!["max_subs_per_ip".to_owned()],
            },
        ),
        (
            "raise_unknown_server",
            Remedy::RaiseServerLimit {
                server: None,
                settings: vec![],
            },
        ),
    ];
    reaches_every("Remedy", &remedies, 2, |remedy| match remedy {
        Remedy::OwnNode { .. } => 0,
        Remedy::RaiseServerLimit { .. } => 1,
    });
    let past_limit = LeftOut {
        reason: LeftOutReason::LiveLimit,
        limits: any,
        own_node: false,
        remedy: Some(Remedy::OwnNode { limits: own }),
    };
    let refused = LeftOut {
        reason: LeftOutReason::ServerRefused,
        limits: own,
        own_node: true,
        remedy: Some(Remedy::RaiseServerLimit {
            server: Some(ServerSoftware::Fulcrum),
            settings: vec!["max_subs_per_ip".to_owned()],
        }),
    };
    let coverage = vec![
        WalletCoverage {
            wallet_id: SAVINGS.to_owned(),
            coverage: Coverage::Live,
            watched_scripts: 46,
            left_out_scripts: 0,
            refused_scripts: 0,
        },
        WalletCoverage {
            wallet_id: COLD.to_owned(),
            coverage: Coverage::Partial,
            watched_scripts: 200,
            left_out_scripts: 64,
            refused_scripts: 0,
        },
        WalletCoverage {
            wallet_id: DONATIONS.to_owned(),
            coverage: Coverage::SyncOnly,
            watched_scripts: 0,
            left_out_scripts: 1,
            refused_scripts: 1,
        },
    ];
    let connected = WatchStatus {
        state: WatchState::Connected,
        transport: Some(WatchTransport::Electrum),
        server: Some("electrum.example.org".to_owned()),
        detail: None,
        watched_scripts: 246,
        pushed_scripts: 246,
        left_out_scripts: 65,
        left_out_wallets: 2,
        wallets: coverage.clone(),
        server_software: Some("Fulcrum 1.12.0".to_owned()),
        left_out: Some(refused.clone()),
    };
    let polling = WatchStatus {
        state: WatchState::Polling,
        transport: Some(WatchTransport::EsploraPolling),
        server: Some("esplora.example.org".to_owned()),
        detail: None,
        watched_scripts: 46,
        pushed_scripts: 0,
        left_out_scripts: 0,
        left_out_wallets: 0,
        wallets: vec![coverage[0].clone()],
        server_software: None,
        left_out: None,
    };
    let reconnecting = WatchStatus {
        state: WatchState::Reconnecting,
        detail: Some("connection reset by the server".to_owned()),
        left_out: Some(past_limit.clone()),
        ..connected.clone()
    };
    let events = vec![
        (
            "transaction",
            LiveEvent::Transaction(live_tx(TxStage::Mempool)),
        ),
        (
            "wallet_synced",
            LiveEvent::WalletSynced {
                report: sync_report(),
            },
        ),
        (
            "sync_failed",
            LiveEvent::SyncFailed {
                wallet_id: COLD.to_owned(),
                message: "sync failed via electrum.example.org: connection refused".to_owned(),
            },
        ),
        ("new_block", LiveEvent::NewBlock { height: TIP + 1 }),
        ("status", LiveEvent::Status(connected.clone())),
    ];
    reaches_every("LiveEvent", &events, 5, |event| match event {
        LiveEvent::Transaction(_) => 0,
        LiveEvent::WalletSynced { .. } => 1,
        LiveEvent::SyncFailed { .. } => 2,
        LiveEvent::NewBlock { .. } => 3,
        LiveEvent::Status(_) => 4,
    });

    let told = Context {
        names: HashMap::from([(SAVINGS.to_owned(), "Savings".to_owned())]),
        unit: Unit::Btc,
        masked: false,
        details: true,
    };
    let discreet = Context {
        names: HashMap::new(),
        unit: Unit::Sats,
        masked: true,
        details: false,
    };
    let compose = |txs: Vec<LiveTx>, context: &Context| -> Vec<Notice> {
        let held: Held = txs.into_iter().collect();
        notice::compose(SAVINGS, &held, context)
    };
    let first = |txs: Vec<LiveTx>, context: &Context| -> Notice { compose(txs, context).remove(0) };
    let many: Vec<LiveTx> = ["a", "b", "c", "d"]
        .iter()
        .map(|seed| LiveTx {
            txid: txid(seed),
            ..live_tx(TxStage::Mempool)
        })
        .collect();
    let counted = compose(many, &told).pop().expect("a notice for the rest");
    assert!(counted.id.is_none(), "the count names no transaction");

    vec![
        variants(
            "WatchState",
            every!(WatchState {
                Off,
                Connecting,
                Connected,
                Reconnecting,
                Polling,
            }),
        ),
        variants(
            "WatchTransport",
            every!(WatchTransport {
                Electrum,
                MempoolWebsocket,
                EsploraPolling,
            }),
        ),
        fixture("WatchLimits", vec![("any_server", any), ("own_node", own)]),
        fixture(
            "WatchLimitsChoice",
            vec![("current", WatchLimitsChoice::CURRENT)],
        ),
        variants(
            "LeftOutReason",
            every!(LeftOutReason {
                LiveLimit,
                ServerRefused,
            }),
        ),
        variants(
            "ServerSoftware",
            every!(ServerSoftware {
                Fulcrum,
                ElectrumX,
                ElectrsEsplora,
                MempoolElectrs,
            }),
        ),
        fixture("Remedy", remedies),
        fixture(
            "LeftOut",
            vec![
                ("past_live_limit", past_limit),
                ("server_refused", refused),
                (
                    "own_node_at_its_limit",
                    LeftOut {
                        reason: LeftOutReason::LiveLimit,
                        limits: own,
                        own_node: true,
                        remedy: None,
                    },
                ),
            ],
        ),
        variants(
            "Coverage",
            every!(Coverage {
                Live,
                Partial,
                SyncOnly,
            }),
        ),
        fixture(
            "WalletCoverage",
            vec![
                ("live", coverage[0].clone()),
                ("partial", coverage[1].clone()),
                ("refused", coverage[2].clone()),
            ],
        ),
        fixture(
            "WatchStatus",
            vec![
                ("off", WatchStatus::default()),
                ("connected", connected),
                ("reconnecting", reconnecting),
                ("polling", polling),
            ],
        ),
        fixture(
            "LiveTx",
            vec![
                ("mempool", live_tx(TxStage::Mempool)),
                ("confirmed", live_tx(TxStage::Confirmed)),
                ("dropped", live_tx(TxStage::Dropped)),
                (
                    "replacing",
                    LiveTx {
                        txid: txid("rent, bumped"),
                        replaces: Some(txid("rent")),
                        ..live_tx(TxStage::Mempool)
                    },
                ),
            ],
        ),
        fixture("LiveEvent", events),
        variants(
            "NoticeKind",
            every!(NoticeKind {
                Transaction,
                Dropped
            }),
        ),
        fixture(
            "NoticeId",
            vec![("payment", NoticeId::of(&live_tx(TxStage::Mempool)))],
        ),
        fixture(
            "Notice",
            vec![
                ("incoming", first(vec![live_tx(TxStage::Mempool)], &told)),
                ("confirmed", first(vec![live_tx(TxStage::Confirmed)], &told)),
                (
                    "discreet",
                    first(vec![live_tx(TxStage::Mempool)], &discreet),
                ),
                ("dropped", first(vec![live_tx(TxStage::Dropped)], &told)),
                ("the_rest", counted),
                ("test", notice::test_notice()),
            ],
        ),
        fixture("Context", vec![("told", told), ("discreet", discreet)]),
    ]
}

// --- errors ------------------------------------------------------------

/// A failure as both bridges hand it over: the code, and the error's own
/// words. The desktop rejects the command with it; Android wraps it in
/// `{"error": …}`.
#[derive(Serialize)]
struct Failure {
    kind: ErrorCode,
    message: String,
}

fn errors() -> Vec<Fixture> {
    let text = |s: &str| s.to_owned();
    let errors = vec![
        CoreError::UnrecognizedInput(text("expected a descriptor, an extended key or an address")),
        CoreError::PrivateMaterialRejected,
        CoreError::InvalidInput {
            kind: "descriptor",
            detail: text("checksum mismatch"),
        },
        CoreError::TooManyParts(5_001),
        CoreError::NetworkMismatch {
            expected: text("signet"),
            found: text("mainnet"),
        },
        CoreError::WalletNotFound(text(SAVINGS)),
        CoreError::DuplicateWallet(text("Savings")),
        CoreError::Vault(VaultError::WrongKeyOrCorrupted),
        CoreError::Vault(VaultError::AlreadyOpen),
        CoreError::Vault(VaultError::CorruptedPayload(text("truncated"))),
        CoreError::UnreadableBackup(text("not a Gerfaut backup")),
        CoreError::NewerBackup(text("written by a newer Gerfaut")),
        CoreError::Sync {
            backend: text("electrum.example.org"),
            detail: text("connection refused"),
        },
        CoreError::Broadcast {
            backend: text("electrum.example.org"),
            detail: text("bad-txns-inputs-missingorspent"),
        },
        CoreError::BackendUnavailable(text("no public backend for regtest")),
        CoreError::Tor(text("no Tor answers on 127.0.0.1:9050")),
        CoreError::Descriptor(text("the policy lets anyone spend")),
        CoreError::Internal(text("a lock was poisoned")),
    ];
    let failures: Vec<(&str, Failure)> = errors
        .iter()
        .map(|error| {
            let failure = Failure {
                kind: error.code(),
                message: error.to_string(),
            };
            (error.code().as_str(), failure)
        })
        .collect();
    let codes: BTreeSet<&str> = failures.iter().map(|(code, _)| *code).collect();
    assert_eq!(
        codes.len(),
        ErrorCode::ALL.len(),
        "every code has its failure, once"
    );

    vec![
        variants("ErrorCode", ErrorCode::ALL.to_vec()),
        fixture("CoreError", failures),
    ]
}
