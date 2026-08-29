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
use arti_client::{TorClient, TorClientConfig};
use futures_util::StreamExt;
use tokio::sync::OnceCell;
use tor_rtcompat::tokio::TokioRustlsRuntime;

use super::{Progress, socks, update};
use crate::error::{CoreError, CoreResult};

/// How long a bootstrap may take. A first run downloads the network
/// directory, a few megabytes even compressed, and builds the first
/// circuits; on a poor connection that runs to a minute. Past this the
/// attempt is given up, and the next onion operation tries again.
const BOOTSTRAP_BUDGET: Duration = Duration::from_secs(90);

/// What is kept for the life of the process.
struct Embedded {
    /// Where the proxy listens.
    socks: String,
    /// Dropping the client would tear down the circuits behind the
    /// listener; it is held for that reason alone.
    _client: Arc<TorClient<TokioRustlsRuntime>>,
}

/// The one client of the process. Left empty when a start fails, so
/// the next caller starts it again rather than inheriting the failure.
static CLIENT: OnceCell<Embedded> = OnceCell::const_new();

/// The proxy address of the running client, starting it if needed.
/// Concurrent callers wait for the same start.
pub(super) async fn socks_address(data_dir: &Path) -> CoreResult<String> {
    CLIENT
        .get_or_try_init(|| start(data_dir))
        .await
        .map(|embedded| embedded.socks.clone())
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
        let client = client.clone();
        move |host: String, port: u16| {
            let client = client.clone();
            async move { client.connect((host, port)).await.map_err(io::Error::other) }
        }
    };
    tokio::spawn(socks::serve(listener, connect));
    Ok(Embedded {
        socks: address.to_string(),
        _client: client,
    })
}

fn config(data_dir: &Path) -> CoreResult<TorClientConfig> {
    let tor_dir = data_dir.join("tor");
    let mut builder =
        TorClientConfigBuilder::from_directories(tor_dir.join("state"), tor_dir.join("cache"));
    builder.address_filter().allow_onion_addrs(true);
    // The data directory already holds the encrypted vault, in the
    // storage the platform keeps private to the app. arti's own walk up
    // the Unix permissions of every ancestor would refuse Android's
    // group-writable `/data`, the very platform this client is for.
    builder.storage().permissions().dangerously_trust_everyone();
    builder
        .build()
        .map_err(|error| tor(format!("invalid Tor configuration: {error}")))
}

fn tor(detail: String) -> CoreError {
    CoreError::Tor(detail)
}
