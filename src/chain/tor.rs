//! Tor for `.onion` backends: the Tor already running on the device when
//! there is one, the client built into this library when there is not.
//!
//! Both chain backends only ever need a SOCKS5 proxy that resolves names
//! itself; whether it is a system daemon or the embedded client makes no
//! difference to them. So the choice is made here, once per operation
//! that touches an onion host, and the proxy address is handed down.
//! Clearnet-only operations never come through here at all.
//!
//! The embedded client is arti, the Tor Project's Rust implementation,
//! started lazily and kept for the life of the process behind a loopback
//! SOCKS5 listener ([`socks`]) on a port the system picks, guarded by
//! credentials drawn for the process: loopback is shared by every app on
//! Android, and this proxy carries this wallet's traffic only.

#[cfg(feature = "embedded-tor")]
mod embedded;
// Only the embedded client runs the server; it is built and tested in
// every configuration so the feature never drifts from what CI sees.
#[cfg_attr(not(feature = "embedded-tor"), allow(dead_code))]
pub(crate) mod socks;

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{CoreError, CoreResult};

/// Where a Tor daemon, Orbot and the Tor Browser expert bundle listen
/// by default.
pub const DEFAULT_SYSTEM_SOCKS: &str = "127.0.0.1:9050";

/// Whether this build carries the embedded client.
pub const EMBEDDED_AVAILABLE: bool = cfg!(feature = "embedded-tor");

/// Whether a proxy answering on loopback may be taken for the system's
/// Tor without being asked for. On a desktop, loopback belongs to the
/// machine's user: whatever listens at 127.0.0.1:9050 is Tor because
/// they started it. On Android every app holding the INTERNET permission
/// can bind that port and answer the greeting, so nothing found there
/// is trusted on its own: `Auto` goes straight to the built-in client,
/// and the system proxy carries traffic only when the user chose it by
/// name in the settings.
pub const TRUST_LOOPBACK_SOCKS: bool = !cfg!(target_os = "android");

/// How long the system proxy gets to answer the greeting. A proxy on
/// loopback answers within a millisecond; the budget only bounds what
/// a dead port costs, once per onion operation.
const PROBE_BUDGET: Duration = Duration::from_millis(300);

/// How `.onion` hosts are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorMode {
    /// The system proxy when it answers, the embedded client otherwise.
    /// Users who run their own Tor keep their own guards and circuits;
    /// everyone else gets Tor without installing anything. Where
    /// loopback is shared ([`TRUST_LOOPBACK_SOCKS`] is false) the system
    /// proxy is not even looked for, and this is the embedded client.
    #[default]
    Auto,
    /// The system proxy only; the embedded client is never started.
    System,
    /// The embedded client only; the system proxy is never looked for.
    Embedded,
}

/// The Tor part of the settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TorSettings {
    #[serde(default)]
    pub mode: TorMode,
    /// The system proxy, `host:port`. `None` is [`DEFAULT_SYSTEM_SOCKS`].
    #[serde(default)]
    pub socks_proxy: Option<String>,
}

impl TorSettings {
    /// The system proxy address in effect.
    pub fn system_socks(&self) -> &str {
        self.socks_proxy.as_deref().unwrap_or(DEFAULT_SYSTEM_SOCKS)
    }
}

/// Which Tor a route goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorVia {
    System,
    Embedded,
}

/// A SOCKS5 proxy ready to carry onion traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorRoute {
    /// `host:port` of the proxy: what a settings screen may show.
    pub socks: String,
    pub via: TorVia,
    /// What the embedded proxy asks a client for. Kept out of the
    /// serialized form, so the apps never see or show them; the chain
    /// layer gets them through [`TorRoute::proxy`].
    #[serde(skip)]
    credentials: Option<socks::Credentials>,
}

impl TorRoute {
    /// The proxy as the chain layer takes it: `user:password@host:port`
    /// when the proxy asks for credentials, `host:port` otherwise. Never
    /// for display; [`Self::socks`] is.
    pub(crate) fn proxy(&self) -> String {
        match &self.credentials {
            Some(credentials) => format!(
                "{}:{}@{}",
                credentials.username(),
                credentials.password(),
                self.socks
            ),
            None => self.socks.clone(),
        }
    }
}

/// Splits a proxy string the chain layer was handed into its
/// credentials, if any, and its `host:port`. The inverse of
/// [`TorRoute::proxy`], for the client that takes them apart rather than
/// as a URL.
pub(crate) fn split_proxy(proxy: &str) -> (Option<(&str, &str)>, &str) {
    match proxy.rsplit_once('@') {
        Some((userinfo, address)) => match userinfo.split_once(':') {
            Some((username, password)) => (Some((username, password)), address),
            None => (Some((userinfo, "")), address),
        },
        None => (None, proxy),
    }
}

/// What a settings screen shows about Tor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorStatus {
    pub mode: TorMode,
    /// The system proxy address in effect.
    pub socks_proxy: String,
    /// The Tor the last onion operation went through, if any yet.
    pub via: Option<TorVia>,
    /// The proxy address that operation used.
    pub socks: Option<String>,
    /// The embedded client has been started in this process.
    pub running: bool,
    /// The embedded client has reached the network.
    pub bootstrapped: bool,
    pub bootstrap_percent: u8,
    /// Why the embedded client's last start failed, until the next one.
    pub error: Option<String>,
    pub embedded_available: bool,
    /// Whether `Auto` may use a proxy found on loopback
    /// ([`TRUST_LOOPBACK_SOCKS`]). False on Android, where the System
    /// option is worth a word of caution: any app can answer there.
    pub system_socks_trusted: bool,
}

/// The last route taken, for the settings screen to name. Process-wide,
/// like the embedded client.
static LAST_ROUTE: Mutex<Option<TorRoute>> = Mutex::new(None);

/// Where the embedded client stands, updated as it bootstraps.
#[derive(Debug, Clone, Default)]
struct Progress {
    running: bool,
    bootstrapped: bool,
    percent: u8,
    error: Option<String>,
}

static PROGRESS: Mutex<Progress> = Mutex::new(Progress {
    running: false,
    bootstrapped: false,
    percent: 0,
    error: None,
});

fn progress() -> Progress {
    PROGRESS
        .lock()
        .map(|progress| progress.clone())
        .unwrap_or_default()
}

#[cfg(feature = "embedded-tor")]
fn update(change: impl FnOnce(&mut Progress)) {
    if let Ok(mut progress) = PROGRESS.lock() {
        change(&mut progress);
    }
}

/// The proxy to reach onion hosts through, per the settings.
///
/// `System` probes the system proxy and refuses when nothing answers.
/// `Auto` probes it too where loopback is trusted
/// ([`TRUST_LOOPBACK_SOCKS`]) and falls back to the embedded client;
/// where it is not, `Auto` is the embedded client. `Embedded` never
/// probes and starts the client if it is not running: up to about 90
/// seconds on a first run, a few on later ones. Call it only when an
/// onion host is about to be reached.
pub async fn resolve(settings: &TorSettings, data_dir: &Path) -> CoreResult<TorRoute> {
    #[cfg(feature = "embedded-tor")]
    let embedded = Some(async || embedded::socks_access(data_dir).await);
    #[cfg(not(feature = "embedded-tor"))]
    let embedded = {
        let _ = data_dir;
        None::<NoEmbedded>
    };
    let route = resolve_with(settings, TRUST_LOOPBACK_SOCKS, probe, embedded).await?;
    if let Ok(mut last) = LAST_ROUTE.lock() {
        *last = Some(route.clone());
    }
    Ok(route)
}

/// The type of a starter this build does not have.
#[cfg(not(feature = "embedded-tor"))]
type NoEmbedded = fn() -> std::future::Ready<CoreResult<socks::Access>>;

/// The policy on its own: `trust_loopback_socks` says whether `Auto` may
/// take a proxy found on loopback for Tor, `probe` says whether a proxy
/// answers at an address, `embedded` starts the built-in client and
/// returns how to reach its proxy, or is `None` in a build without one.
async fn resolve_with(
    settings: &TorSettings,
    trust_loopback_socks: bool,
    probe: impl AsyncFn(&str) -> bool,
    embedded: Option<impl AsyncFnOnce() -> CoreResult<socks::Access>>,
) -> CoreResult<TorRoute> {
    let system = settings.system_socks();
    let via_system = || TorRoute {
        socks: system.to_owned(),
        via: TorVia::System,
        credentials: None,
    };
    let via_embedded = |access: socks::Access| TorRoute {
        socks: access.address,
        via: TorVia::Embedded,
        credentials: Some(access.credentials),
    };
    match settings.mode {
        TorMode::System => {
            if probe(system).await {
                Ok(via_system())
            } else {
                Err(CoreError::Tor(format!(
                    "no Tor proxy answers at {system}; start Tor, or let Gerfaut use its \
                     built-in one"
                )))
            }
        }
        TorMode::Auto => {
            // Where loopback is shared, a proxy found there is anyone's:
            // it is not probed, let alone used, unless chosen by name.
            if trust_loopback_socks && probe(system).await {
                return Ok(via_system());
            }
            match embedded {
                Some(start) => start().await.map(via_embedded),
                None if trust_loopback_socks => Err(CoreError::Tor(format!(
                    "Tor is not running on this device ({system} does not answer) and this \
                     build has no built-in Tor"
                ))),
                None => Err(CoreError::Tor(format!(
                    "this build has no built-in Tor; to use a Tor app running on this device, \
                     choose it in the settings ({system})"
                ))),
            }
        }
        TorMode::Embedded => match embedded {
            Some(start) => start().await.map(via_embedded),
            None => Err(CoreError::Tor(
                "this build has no built-in Tor; use the Tor running on this device instead"
                    .to_owned(),
            )),
        },
    }
}

/// Whether a SOCKS5 proxy answers at `address`: connect, offer "no
/// authentication", expect it accepted. Anything else, silence past the
/// budget included, is a no.
pub(crate) async fn probe(address: &str) -> bool {
    let greeting = async {
        let mut stream = TcpStream::connect(address).await.ok()?;
        stream
            .write_all(&[socks::VERSION, 1, socks::NO_AUTH])
            .await
            .ok()?;
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.ok()?;
        Some(answer == [socks::VERSION, socks::NO_AUTH])
    };
    matches!(
        tokio::time::timeout(PROBE_BUDGET, greeting).await,
        Ok(Some(true))
    )
}

/// Where Tor stands, for a settings screen. Reads only: nothing is
/// probed or started.
pub async fn status(settings: &TorSettings) -> TorStatus {
    let last = LAST_ROUTE.lock().ok().and_then(|route| route.clone());
    let embedded = progress();
    TorStatus {
        mode: settings.mode,
        socks_proxy: settings.system_socks().to_owned(),
        via: last.as_ref().map(|route| route.via),
        socks: last.map(|route| route.socks),
        running: embedded.running,
        bootstrapped: embedded.bootstrapped,
        bootstrap_percent: embedded.percent,
        error: embedded.error,
        embedded_available: EMBEDDED_AVAILABLE,
        system_socks_trusted: TRUST_LOOPBACK_SOCKS,
    }
}

/// Checks a proxy address the user typed, `host:port` with the port in
/// range, and returns it trimmed. A typo fails here, at the settings
/// screen, not at the next sync.
pub fn parse_socks_address(value: &str) -> CoreResult<String> {
    let invalid = |detail: &str| CoreError::InvalidInput {
        kind: "tor proxy",
        detail: detail.to_owned(),
    };
    let value = value.trim();
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected host:port"))?;
    if host.trim_matches(['[', ']']).is_empty() {
        return Err(invalid("the address has no host"));
    }
    match port.parse::<u16>() {
        Ok(port) if port > 0 => Ok(value.to_owned()),
        _ => Err(invalid("the port must be between 1 and 65535")),
    }
}

/// What a backend reports when handed an onion host and no proxy. The
/// manager resolves a route before any onion operation, so this is a
/// bug when it shows; it must still never turn into a lookup of the
/// onion name.
pub(crate) fn no_route(url: &str) -> String {
    let host = super::host_of(url).unwrap_or_else(|| url.to_owned());
    CoreError::Tor(format!("no Tor proxy to reach {host} through")).to_string()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::Ready;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use tokio::net::TcpListener;

    use super::*;

    /// A loopback port nothing listens on.
    async fn closed_port() -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address.to_string()
    }

    /// A server that answers the SOCKS5 greeting the way Tor does.
    async fn fake_tor() -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut greeting = [0u8; 3];
                if stream.read_exact(&mut greeting).await.is_ok() {
                    let _ = stream.write_all(&[socks::VERSION, socks::NO_AUTH]).await;
                }
            }
        });
        address
    }

    fn settings(mode: TorMode, socks_proxy: Option<&str>) -> TorSettings {
        TorSettings {
            mode,
            socks_proxy: socks_proxy.map(str::to_owned),
        }
    }

    /// A starter that records being called and hands out a fixed
    /// address; the real one is never run by these tests.
    fn starter(called: &Cell<bool>) -> Option<impl AsyncFnOnce() -> CoreResult<socks::Access>> {
        Some(async || {
            called.set(true);
            Ok(socks::Access {
                address: "127.0.0.1:1".to_owned(),
                credentials: socks::Credentials::new("user", "pass"),
            })
        })
    }

    const NO_STARTER: Option<fn() -> Ready<CoreResult<socks::Access>>> = None;

    #[tokio::test]
    async fn the_probe_says_no_quickly_on_a_closed_port() {
        let address = closed_port().await;
        let started = Instant::now();
        assert!(!probe(&address).await);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn the_probe_says_yes_to_a_socks5_greeting_only() {
        assert!(probe(&fake_tor().await).await);

        // Something listening that speaks no SOCKS is not a proxy.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request").await;
            }
        });
        assert!(!probe(&address).await);
    }

    #[tokio::test]
    async fn auto_takes_the_system_proxy_when_it_answers() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, Some("127.0.0.1:9150")),
            true,
            async |address: &str| address == "127.0.0.1:9150",
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(
            route,
            TorRoute {
                socks: "127.0.0.1:9150".to_owned(),
                via: TorVia::System,
                credentials: None,
            }
        );
        // A system proxy takes no credentials: the string is the address.
        assert_eq!(route.proxy(), "127.0.0.1:9150");
        assert!(!called.get(), "the embedded client stays off");
    }

    #[tokio::test]
    async fn auto_falls_back_to_the_embedded_client() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| false,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert_eq!(route.socks, "127.0.0.1:1");
        assert!(called.get());
    }

    /// The embedded proxy's credentials reach the chain layer and
    /// nothing else: not the serialized route the apps receive, not a
    /// debug print, not the address shown in the settings.
    #[tokio::test]
    async fn the_embedded_credentials_never_leave_the_process() {
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| false,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.proxy(), "user:pass@127.0.0.1:1");
        assert_eq!(route.socks, "127.0.0.1:1");
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(json, r#"{"socks":"127.0.0.1:1","via":"embedded"}"#);
        let shown = format!("{route:?}");
        assert!(!shown.contains("pass"), "{shown}");
        // What the apps send back reads without the field.
        let back: TorRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(back.socks, route.socks);
        assert_eq!(back.proxy(), "127.0.0.1:1");

        // And the chain layer takes the string apart again.
        assert_eq!(
            split_proxy("user:pass@127.0.0.1:1"),
            (Some(("user", "pass")), "127.0.0.1:1")
        );
        assert_eq!(split_proxy("127.0.0.1:9050"), (None, "127.0.0.1:9050"));
        assert_eq!(split_proxy("[::1]:9050"), (None, "[::1]:9050"));
    }

    #[tokio::test]
    async fn auto_without_an_embedded_client_says_what_is_missing() {
        let error = resolve_with(
            &settings(TorMode::Auto, None),
            true,
            async |_: &str| false,
            NO_STARTER,
        )
        .await
        .unwrap_err();
        match error {
            CoreError::Tor(detail) => {
                assert!(detail.contains(DEFAULT_SYSTEM_SOCKS), "{detail}");
                assert!(detail.contains("no built-in Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn system_never_starts_the_embedded_client() {
        let called = Cell::new(false);
        let error = resolve_with(
            &settings(TorMode::System, Some("localhost:9050")),
            true,
            async |_: &str| false,
            starter(&called),
        )
        .await
        .unwrap_err();
        assert!(matches!(&error, CoreError::Tor(detail) if detail.contains("localhost:9050")));
        assert!(!called.get());

        let route = resolve_with(
            &settings(TorMode::System, None),
            true,
            async |_: &str| true,
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert_eq!(route.socks, DEFAULT_SYSTEM_SOCKS);
        assert!(!called.get());
    }

    /// Android: loopback is every app's. `Auto` does not ask what is
    /// listening there, and goes straight to the built-in client.
    #[tokio::test]
    async fn auto_on_a_shared_loopback_never_probes() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Auto, None),
            false,
            async |_: &str| {
                probed.set(true);
                true
            },
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert!(!probed.get(), "whatever answers on loopback is not asked");
        assert!(called.get());

        // Without a built-in client there is no automatic route at all;
        // the error points at the explicit choice.
        let error = resolve_with(
            &settings(TorMode::Auto, None),
            false,
            async |_: &str| {
                probed.set(true);
                true
            },
            NO_STARTER,
        )
        .await
        .unwrap_err();
        match error {
            CoreError::Tor(detail) => {
                assert!(detail.contains("settings"), "{detail}");
                assert!(detail.contains("no built-in Tor"), "{detail}");
            }
            other => panic!("expected a tor error, got {other:?}"),
        }
        assert!(!probed.get());
    }

    /// The explicit choice stands wherever it is made: `System` probes
    /// the proxy the user named, shared loopback or not.
    #[tokio::test]
    async fn system_still_probes_on_a_shared_loopback() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::System, Some("127.0.0.1:9050")),
            false,
            async |address: &str| {
                probed.set(true);
                address == "127.0.0.1:9050"
            },
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::System);
        assert!(probed.get());
        assert!(!called.get());
    }

    #[test]
    fn loopback_is_trusted_everywhere_but_android() {
        assert_eq!(TRUST_LOOPBACK_SOCKS, !cfg!(target_os = "android"));
    }

    #[tokio::test]
    async fn embedded_never_probes() {
        let probed = Cell::new(false);
        let called = Cell::new(false);
        let route = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| {
                probed.set(true);
                true
            },
            starter(&called),
        )
        .await
        .unwrap();
        assert_eq!(route.via, TorVia::Embedded);
        assert!(!probed.get());
        assert!(called.get());

        let error = resolve_with(
            &settings(TorMode::Embedded, None),
            true,
            async |_: &str| true,
            NO_STARTER,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CoreError::Tor(_)));
        assert!(!probed.get());
    }

    #[test]
    fn a_proxy_address_is_host_and_port() {
        assert_eq!(
            parse_socks_address(" 127.0.0.1:9150 ").unwrap(),
            "127.0.0.1:9150"
        );
        assert_eq!(parse_socks_address("[::1]:9050").unwrap(), "[::1]:9050");
        assert_eq!(parse_socks_address("orbot:9050").unwrap(), "orbot:9050");
        for wrong in [
            "",
            "9050",
            ":9050",
            "[]:9050",
            "host:",
            "host:0",
            "host:65536",
            "host:tor",
        ] {
            assert!(
                matches!(
                    parse_socks_address(wrong),
                    Err(CoreError::InvalidInput {
                        kind: "tor proxy",
                        ..
                    })
                ),
                "{wrong:?} must be refused"
            );
        }
    }

    #[test]
    fn settings_read_and_write_as_snake_case() {
        let stored: TorSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(stored, TorSettings::default());
        assert_eq!(stored.mode, TorMode::Auto);
        assert_eq!(stored.system_socks(), DEFAULT_SYSTEM_SOCKS);

        let chosen = TorSettings {
            mode: TorMode::Embedded,
            socks_proxy: Some("127.0.0.1:9150".to_owned()),
        };
        let json = serde_json::to_string(&chosen).unwrap();
        assert_eq!(
            json,
            r#"{"mode":"embedded","socks_proxy":"127.0.0.1:9150"}"#
        );
        assert_eq!(serde_json::from_str::<TorSettings>(&json).unwrap(), chosen);
    }

    #[tokio::test]
    async fn status_reads_without_touching_anything() {
        let status = status(&settings(TorMode::System, Some("127.0.0.1:9150"))).await;
        assert_eq!(status.mode, TorMode::System);
        assert_eq!(status.socks_proxy, "127.0.0.1:9150");
        assert_eq!(status.embedded_available, cfg!(feature = "embedded-tor"));
        assert_eq!(status.system_socks_trusted, TRUST_LOOPBACK_SOCKS);
        assert!(!status.bootstrapped);
    }

    #[test]
    fn a_missing_route_is_a_tor_error_naming_the_host() {
        let detail = no_route("http://abc.onion/api");
        assert!(detail.starts_with("tor: "), "{detail}");
        assert!(detail.contains("abc.onion"), "{detail}");
    }

    /// Live. Bootstraps the embedded client for real and reads the tip
    /// height of a public onion Esplora through its proxy, the way a
    /// sync would. Ignored: it needs the network, and a first bootstrap
    /// takes up to a minute.
    #[cfg(feature = "embedded-tor")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "bootstraps Tor and talks to an onion service"]
    async fn the_embedded_client_reaches_an_onion_esplora() {
        const MEMPOOL_ONION: &str =
            "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api";
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(TorMode::Embedded, None);
        let route = resolve(&settings, dir.path())
            .await
            .expect("the embedded client bootstraps");
        assert_eq!(route.via, TorVia::Embedded);
        assert!(route.socks.starts_with("127.0.0.1:"));

        let client = crate::chain::esplora::client(MEMPOOL_ONION, Some(&route.proxy())).unwrap();
        let height = client
            .get_height()
            .await
            .expect("the onion Esplora answers over Tor");
        assert!(height > 900_000, "{height}");

        let after = status(&settings).await;
        assert!(after.running && after.bootstrapped);
        assert_eq!(after.bootstrap_percent, 100);
        assert_eq!(after.via, Some(TorVia::Embedded));
        assert_eq!(after.socks, Some(route.socks.clone()));
        assert!(std::fs::read_dir(dir.path().join("tor").join("cache")).is_ok());

        // A second resolution reuses the running client.
        assert_eq!(resolve(&settings, dir.path()).await.unwrap(), route);
    }
}
