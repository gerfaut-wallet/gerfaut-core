//! The embedded client: arti, bootstrapped once per process and kept
//! behind a loopback SOCKS5 listener for the life of the process.
//!
//! Guards and the network directory live under the data directory, next
//! to the vault: a later start reuses them and reaches the network in
//! seconds instead of downloading it again.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient, TorClientConfig};
use futures_util::StreamExt;
use tokio::sync::OnceCell;
use tor_rtcompat::tokio::TokioRustlsRuntime;

use super::{Progress, attempts, socks, update};
use crate::error::{CoreError, CoreResult};

/// How long a bootstrap may take. A first run downloads the network
/// directory, a few megabytes even compressed, and builds the first
/// circuits; on a poor connection that runs to a minute. Past this the
/// attempt is given up, and the next onion operation tries again.
const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(90);

/// What is kept for the life of the process.
struct Embedded {
    /// Where the proxy listens and what it asks for.
    access: socks::Access,
    /// Dropping the client would tear down the circuits behind the
    /// listener; it is held for that reason alone.
    _client: Arc<TorClient<TokioRustlsRuntime>>,
}

/// The one client of the process. Left empty when a start fails, so
/// the next caller starts it again rather than inheriting the failure.
static CLIENT: OnceCell<Embedded> = OnceCell::const_new();

/// How to reach the running client's proxy, starting it if needed.
/// Concurrent callers wait for the same start.
pub(super) async fn socks_access(data_dir: &Path) -> CoreResult<socks::Access> {
    CLIENT
        .get_or_try_init(|| start(data_dir))
        .await
        .map(|embedded| embedded.access.clone())
}

/// How to reach the client's proxy when it already runs; `None` before
/// it was started, and while a start is still on its way. Never starts
/// it.
pub(super) fn running_access() -> Option<socks::Access> {
    CLIENT.get().map(|embedded| embedded.access.clone())
}

async fn start(data_dir: &Path) -> CoreResult<Embedded> {
    update(|progress| {
        *progress = Progress {
            running: true,
            ..Progress::default()
        }
    });
    match bootstrap(data_dir).await {
        Ok(embedded) => {
            update(|progress| {
                progress.bootstrapped = true;
                progress.percent = 100;
            });
            Ok(embedded)
        }
        Err(error) => {
            update(|progress| {
                progress.running = false;
                progress.error = Some(error.to_string());
            });
            Err(error)
        }
    }
}

async fn bootstrap(data_dir: &Path) -> CoreResult<Embedded> {
    // arti's TLS to relays goes through rustls, which wants a
    // process-level crypto provider before anything is built: the same
    // ring provider the Electrum connections use.
    let _ = crate::chain::tls::provider();
    let runtime = TokioRustlsRuntime::current()
        .map_err(|error| tor(format!("no async runtime to run Tor on: {error}")))?;
    let client = TorClient::with_runtime(runtime)
        .config(config(data_dir)?)
        .create_unbootstrapped_async()
        .await
        .map_err(|error| tor(format!("Tor could not start: {error}")))?;

    // arti's own estimate, capped below 100 until the bootstrap call
    // itself returns: that is what "ready" means.
    let mut events = client.bootstrap_events();
    let reporter = tokio::spawn(async move {
        while let Some(status) = events.next().await {
            let percent = (status.as_frac() * 100.0).clamp(0.0, 99.0) as u8;
            update(|progress| progress.percent = progress.percent.max(percent));
        }
    });
    let outcome = tokio::time::timeout(BOOTSTRAP_BUDGET, client.bootstrap()).await;
    reporter.abort();
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(tor(format!("Tor could not reach the network: {error}"))),
        Err(_) => {
            return Err(tor(format!(
                "Tor did not reach the network within {} seconds",
                BOOTSTRAP_BUDGET.as_secs()
            )));
        }
    }

    let (listener, address) = socks::bind()
        .await
        .map_err(|error| tor(format!("cannot listen on loopback for Tor: {error}")))?;
    let connect = {
        let streams = Arc::new(Streams {
            current: std::sync::Mutex::new(client.clone()),
        });
        move |host: String, port: u16| {
            let streams = streams.clone();
            async move { streams.connect(host, port).await }
        }
    };
    // Fresh for every start: nothing outside this process ever holds
    // them, and a restart owes nothing to the previous run.
    let credentials = socks::Credentials::random();
    tokio::spawn(socks::serve(listener, credentials.clone(), connect));
    Ok(Embedded {
        access: socks::Access {
            address: address.to_string(),
            credentials,
        },
        _client: client,
    })
}

type Client = Arc<TorClient<TokioRustlsRuntime>>;

/// The client the streams of the proxy go out on: the one bootstrapped,
/// until the second attempt at an onion connection connects through a
/// client of its own ([`attempts`]). That client then takes its place:
/// its circuit to the service is the one known to answer, where the
/// streams of the first would still join the attempt that hangs. Every
/// stream shares one isolation either way, as before any second
/// attempt.
struct Streams {
    current: std::sync::Mutex<Client>,
}

impl Streams {
    fn current(&self) -> Client {
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The client of a second attempt beside one made through `first`:
    /// the one another stream put in its place meanwhile, if one did,
    /// else one of a new isolation.
    fn successor(&self, first: &Client) -> Client {
        let current = self.current();
        if Arc::ptr_eq(&current, first) {
            first.isolated_client()
        } else {
            current
        }
    }

    /// `used` in the place of `first`, unless another stream replaced
    /// `first` already; nothing when `used` is `first`.
    fn adopt(&self, first: &Client, used: &Client) {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if Arc::ptr_eq(&current, first) {
            *current = used.clone();
        }
    }

    /// The upstream side of a `CONNECT`: a host in the clear in one
    /// attempt, an onion service in two ([`attempts::two`]).
    async fn connect(&self, host: String, port: u16) -> io::Result<DataStream> {
        let first = self.current();
        if !crate::chain::is_onion_host(&host) {
            return first.connect((host, port)).await.map_err(io::Error::other);
        }
        let through = |client: Client, host: String| async move {
            match client.connect((host, port)).await {
                Ok(stream) => Ok((stream, client)),
                Err(error) => Err(io::Error::other(error)),
            }
        };
        let (stream, used) = attempts::two(
            through(first.clone(), host.clone()),
            || through(self.successor(&first), host),
            attempts::TRY,
        )
        .await?;
        self.adopt(&first, &used);
        Ok(stream)
    }
}

fn config(data_dir: &Path) -> CoreResult<TorClientConfig> {
    let tor_dir = data_dir.join("tor");
    let mut builder =
        TorClientConfigBuilder::from_directories(tor_dir.join("state"), tor_dir.join("cache"));
    builder.address_filter().allow_onion_addrs(true);
    // On a phone, reduced channel padding, the level arti names "for
    // mobile": a cell every 9 to 14 s, client to relay only, where the
    // normal level sends one every 1.5 to 9.5 s both ways. A live watch
    // holds a circuit open for hours, and at the normal level the radio
    // never gets to sleep. The price is somewhat less cover against an
    // observer of the link who counts cells. A desktop keeps the normal
    // level.
    if cfg!(any(target_os = "android", target_os = "ios")) {
        builder.channel().padding(tor_config::PaddingLevel::Reduced);
    }
    // On a phone the data directory already holds the encrypted vault,
    // in the storage the platform keeps private to the app, and arti's
    // own walk up the Unix permissions of every ancestor would refuse
    // Android's group-writable `/data`. A desktop keeps the check: on a
    // machine shared with other accounts, a directory one of them can
    // write to would let it swap the guards and the directory the client
    // trusts.
    if cfg!(any(target_os = "android", target_os = "ios")) {
        builder.storage().permissions().dangerously_trust_everyone();
    }
    builder
        .build()
        .map_err(|error| tor(format!("invalid Tor configuration: {error}")))
}

fn tor(detail: String) -> CoreError {
    CoreError::Tor(detail)
}
