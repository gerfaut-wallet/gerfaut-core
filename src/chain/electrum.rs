//! Electrum backend: descriptor wallet sync over the user's own server.
//!
//! The Electrum client of BDK is blocking. Each operation runs on a
//! thread of its own, never on the runtime's blocking pool: a call
//! waiting on a server there would hold a runtime shutdown, and with it
//! the exit of the app, for as long as the server takes. The caller
//! awaits the thread under a deadline, and the moment it stops waiting,
//! the deadline passed or its future dropped, the socket is shut down
//! and the thread ends at its next read.
//!
//! Every socket is opened here: TCP, the Tor proxy in front of it for a
//! hidden service, and TLS by [`crate::chain::tls`], so the certificate
//! a self-hosted server presents goes through Gerfaut's own verifier: a
//! public authority, or the fingerprint the user accepted for that
//! host. What the client reads goes through [`Guarded`], which cuts off
//! a line longer than [`MAX_LINE`].

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bdk_electrum::BdkElectrumClient;
use bdk_electrum::electrum_client::raw_client::RawClient;
use bdk_electrum::electrum_client::socks::Socks5Stream;
use bdk_electrum::electrum_client::{self, ElectrumApi, Param};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};

use super::tls::{self, ConnectError, Verdict};

pub(crate) mod address;
pub(crate) mod rpc;

/// Requests per Electrum batch call.
const BATCH_SIZE: usize = 10;
/// Socket timeout, each read and each write. Without it a stalled
/// server holds a call until its deadline.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(20);
/// Onion endpoints get more room: Tor circuits are slow to build.
pub(crate) const TOR_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest an operation of a few calls may take, all of them
/// together: a broadcast, a lookup, a certificate check.
const CALL_DEADLINE: Duration = Duration::from_secs(90);
const TOR_CALL_DEADLINE: Duration = Duration::from_secs(4 * 60);
/// The longest line read from a server. A whole transaction, hex
/// encoded, fits with room to spare, and so does a history as long as
/// the public servers hand out. A server that sends more without a
/// line end is not speaking the protocol, and is cut off rather than
/// buffered.
pub(crate) const MAX_LINE: usize = 16 << 20;
/// Name Gerfaut announces in `server.version`.
pub(crate) const CLIENT_NAME: &str = "gerfaut";
/// Protocol version asked for, as an exact range. `electrum-client`
/// reads block headers in the 1.4 shape unless it negotiated the version
/// itself, which it cannot do on a stream Gerfaut opened: pinning both
/// sides to 1.4 keeps the wire and the parser in agreement.
pub(crate) const PROTOCOL: &str = "1.4";

/// Default ports of the Electrum protocol.
const SSL_PORT: u16 = 50002;
const TCP_PORT: u16 = 50001;

/// One Electrum server, with the certificate fingerprint the user
/// accepted for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub url: String,
    pub pin: Option<String>,
}

impl Target {
    pub(crate) fn new(url: impl Into<String>, pin: Option<String>) -> Self {
        Target {
            url: url.into(),
            pin,
        }
    }
}

/// What a settings screen needs to know about a server's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Inspection {
    /// Plain TCP: there is no certificate, and anything on the path
    /// reads the traffic.
    NotTls,
    /// A Tor hidden service: the onion address is the server's identity.
    Tor,
    /// A TLS server, and what its certificate amounts to.
    Tls(Verdict),
}

/// Splits `ssl://host:port` into its parts. A bare `host:port` is TLS,
/// the way every Electrum client has always read it.
pub(crate) fn parse(url: &str) -> Result<(bool, String, u16), String> {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("ssl".to_owned(), url),
    };
    let tls = match scheme.as_str() {
        "ssl" | "tls" => true,
        "tcp" => false,
        other => return Err(format!("{other}:// is not an Electrum address")),
    };
    let rest = rest.split(['/', '?']).next().unwrap_or_default();
    let default_port = if tls { SSL_PORT } else { TCP_PORT };
    let port_of = |port: &str| {
        port.parse::<u16>()
            .map_err(|_| format!("{port} is not a port number"))
    };
    // An IPv6 literal is bracketed precisely so its own colons are not
    // read as a port separator.
    let (host, port) = match rest.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| "the address opens a bracket it never closes".to_owned())?;
            match tail.strip_prefix(':') {
                Some(port) => (host, port_of(port)?),
                None => (host, default_port),
            }
        }
        None => match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port_of(port)?),
            _ => (rest, default_port),
        },
    };
    if host.is_empty() {
        return Err("the address has no host".to_owned());
    }
    Ok((tls, host.to_owned(), port))
}

/// The key a trusted fingerprint is stored under: the host and port
/// that identify the socket, scheme and path stripped. The host is
/// read the way the settings store it, in lower case and without the
/// trailing dot of a fully qualified name, so a certificate accepted
/// under one spelling of the address is found under every other. A
/// host the URL standard cannot read keys as written.
pub fn certificate_key(url: &str) -> String {
    match parse(url) {
        Ok((_, host, port)) => {
            let host = crate::chain::canonical_host(&host).unwrap_or(host);
            format!("{host}:{port}")
        }
        Err(_) => url.to_owned(),
    }
}

/// What abandons a connection from outside the thread that uses it: a
/// flag every read and write checks, and a handle on the socket, shut
/// down so that a read waiting on the server returns at once.
#[derive(Debug, Default)]
pub(crate) struct Cancel {
    cancelled: AtomicBool,
    socket: Mutex<Option<TcpStream>>,
}

impl Cancel {
    /// Keeps a handle on the socket a connection was opened on. One
    /// abandoned before this point is shut down here.
    fn hold(&self, socket: &TcpStream) -> Result<(), ConnectError> {
        let handle = socket
            .try_clone()
            .map_err(|e| ConnectError::Io(e.to_string()))?;
        if let Ok(mut held) = self.socket.lock() {
            *held = Some(handle);
        }
        if self.is_cancelled() {
            self.abort();
            return Err(ConnectError::Io(ABANDONED.to_owned()));
        }
        Ok(())
    }

    pub(crate) fn abort(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(held) = self.socket.lock()
            && let Some(socket) = held.as_ref()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

const ABANDONED: &str = "the call was abandoned";

/// Aborts the connection it guards when dropped. The future awaiting a
/// thread holds one, so a caller that stops waiting, for whatever
/// reason, never leaves a thread talking to the server.
struct AbortOnDrop(Arc<Cancel>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A stream the blocking client can read and write.
trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// The stream every blocking connection is read through: it refuses to
/// go on once the call is abandoned, cuts off a server that sends a
/// line longer than `limit`, which the client would otherwise buffer
/// whole, and one that sends more than [`MAX_READ`] in all: the client
/// queues every notification a server pushes, unbounded.
pub(crate) struct Guarded {
    inner: Box<dyn Stream>,
    cancel: Arc<Cancel>,
    /// Bytes read since the last line end.
    unended: usize,
    limit: usize,
    /// Bytes read since the connection opened.
    total: usize,
}

/// The most one connection reads, every answer together: far past the
/// full scan of any wallet a phone holds.
const MAX_READ: usize = 256 << 20;

impl Guarded {
    fn new(inner: Box<dyn Stream>, cancel: Arc<Cancel>, limit: usize) -> Self {
        Guarded {
            inner,
            cancel,
            unended: 0,
            limit,
            total: 0,
        }
    }

    fn check(&self) -> std::io::Result<()> {
        if self.cancel.is_cancelled() {
            // Not `Interrupted`: a reader retries that one.
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                ABANDONED,
            ));
        }
        Ok(())
    }
}

impl Read for Guarded {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.check()?;
        let read = self.inner.read(buf)?;
        match buf[..read].iter().rposition(|byte| *byte == b'\n') {
            Some(end) => self.unended = read - end - 1,
            None => self.unended = self.unended.saturating_add(read),
        }
        if self.unended > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                too_long(self.limit),
            ));
        }
        self.total = self.total.saturating_add(read);
        if self.total > MAX_READ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the server sent more than {} MiB on one connection",
                    MAX_READ >> 20
                ),
            ));
        }
        Ok(read)
    }
}

impl Write for Guarded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}

/// What a server that sent more than a line may hold is told it did.
pub(crate) fn too_long(limit: usize) -> String {
    format!("the server sent an answer longer than {} MiB", limit >> 20)
}

/// A connected client.
pub(crate) type Connection = RawClient<Guarded>;

/// Opens the connection. `proxy` is the Tor SOCKS proxy the caller
/// resolved for onion servers; an onion address without one is refused
/// before anything could look the name up.
fn connect(
    target: &Target,
    proxy: Option<&str>,
    cancel: &Arc<Cancel>,
) -> Result<Connection, ConnectError> {
    let (tls_wanted, host, port) = parse(&target.url).map_err(ConnectError::Io)?;
    let timeout = timeout_for(target);

    // Tor: the .onion address is the server's public key, and the
    // circuit proves the endpoint holds it. A certificate on top adds
    // encryption inside an encrypted tunnel and authenticates nothing,
    // so it is not what is trusted here — the address is.
    let stream: Box<dyn Stream> = if crate::chain::is_onion(&target.url) {
        let proxy =
            proxy.ok_or_else(|| ConnectError::Io(crate::chain::tor::no_route(&target.url)))?;
        // The embedded proxy asks for credentials; the SOCKS client
        // takes them apart from the address. The name goes to the proxy
        // as spelled, and is resolved inside Tor.
        let (credentials, address) = crate::chain::tor::split_proxy(proxy);
        let opened = match credentials {
            Some((username, password)) => Socks5Stream::connect_with_password(
                address,
                (host.as_str(), port),
                username,
                password,
                Some(timeout),
            ),
            None => Socks5Stream::connect(address, (host.as_str(), port), Some(timeout)),
        };
        let socket = opened
            .map_err(|e| {
                ConnectError::Io(format!(
                    "could not connect through Tor: {}",
                    describe_io(&e, timeout)
                ))
            })?
            .into_inner();
        cancel.hold(&socket)?;
        if tls_wanted {
            Box::new(tls::onion_handshake(&host, socket)?)
        } else {
            Box::new(socket)
        }
    } else {
        let socket = tls::tcp_connect(&host, port, timeout)?;
        cancel.hold(&socket)?;
        if tls_wanted {
            Box::new(tls::handshake(&host, target.pin.as_deref(), socket)?)
        } else {
            Box::new(socket)
        }
    };
    let raw = RawClient::from(Guarded::new(stream, cancel.clone(), MAX_LINE));
    negotiate(&raw, timeout)?;
    Ok(raw)
}

/// `server.version` is the first call an Electrum server expects, and
/// the one that fixes the protocol version.
fn negotiate(raw: &Connection, timeout: Duration) -> Result<(), ConnectError> {
    raw.raw_call(
        "server.version",
        vec![
            Param::String(CLIENT_NAME.to_owned()),
            Param::StringVec(vec![PROTOCOL.to_owned(), PROTOCOL.to_owned()]),
        ],
    )
    .map(|_| ())
    .map_err(|e| ConnectError::Io(describe(&e, timeout)))
}

/// A connected client, as BDK drives it.
type Client = BdkElectrumClient<Connection>;

/// Runs `operation` against `target` on a thread of its own, and waits
/// for it at most `deadline`. Past it, or as soon as the future is
/// dropped, the connection is shut down: the thread's next read fails
/// and it ends, whatever the server does.
async fn run<T: Send + 'static>(
    target: &Target,
    proxy: Option<&str>,
    deadline: Duration,
    operation: impl FnOnce(&Client) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let cancel = Arc::new(Cancel::default());
    let _abort = AbortOnDrop(cancel.clone());
    let (done, outcome) = tokio::sync::oneshot::channel();
    let target = target.clone();
    let proxy = proxy.map(str::to_owned);
    std::thread::Builder::new()
        .name("gerfaut-electrum".to_owned())
        .spawn(move || {
            let result = connect(&target, proxy.as_deref(), &cancel)
                .map_err(|e| e.to_string())
                .and_then(|raw| operation(&BdkElectrumClient::new(raw)));
            let _ = done.send(result);
        })
        .map_err(|e| format!("could not start the connection: {e}"))?;
    match tokio::time::timeout(deadline, outcome).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("the connection ended unexpectedly".to_owned()),
        Err(_) => Err(format!("no answer within {} s", deadline.as_secs())),
    }
}

/// The deadline of an operation of a few calls against this server.
fn call_deadline(target: &Target) -> Duration {
    if crate::chain::is_onion(&target.url) {
        TOR_CALL_DEADLINE
    } else {
        CALL_DEADLINE
    }
}

/// What the settings screen shows about this server's certificate.
pub(crate) fn inspect_blocking(target: &Target) -> Result<Inspection, String> {
    let (tls_wanted, host, port) = parse(&target.url)?;
    if crate::chain::is_onion(&target.url) {
        return Ok(Inspection::Tor);
    }
    if !tls_wanted {
        return Ok(Inspection::NotTls);
    }
    tls::inspect(&host, port, target.pin.as_deref(), TIMEOUT)
        .map(Inspection::Tls)
        .map_err(|e| e.to_string())
}

/// The same, on a thread of its own and within a deadline. The check
/// opens a connection and closes it: nothing to abort on the way.
pub(crate) async fn inspect(target: &Target) -> Result<Inspection, String> {
    let deadline = call_deadline(target);
    let target = target.clone();
    let (done, outcome) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("gerfaut-electrum".to_owned())
        .spawn(move || {
            let _ = done.send(inspect_blocking(&target));
        })
        .map_err(|e| format!("could not start the connection: {e}"))?;
    match tokio::time::timeout(deadline, outcome).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("the connection ended unexpectedly".to_owned()),
        Err(_) => Err(format!("no answer within {} s", deadline.as_secs())),
    }
}

/// A full scan, within `deadline`.
pub(crate) async fn full_scan(
    target: &Target,
    request: FullScanRequest<KeychainKind>,
    stop_gap: u32,
    proxy: Option<&str>,
    deadline: Duration,
) -> Result<FullScanResponse<KeychainKind>, String> {
    let fail = failed(target);
    run(target, proxy, deadline, move |client| {
        client
            .full_scan(request, stop_gap as usize, BATCH_SIZE, true)
            .map_err(fail)
    })
    .await
}

/// A sync of the revealed scripts, within `deadline`.
pub(crate) async fn sync(
    target: &Target,
    request: SyncRequest<(KeychainKind, u32)>,
    proxy: Option<&str>,
    deadline: Duration,
) -> Result<SyncResponse, String> {
    let fail = failed(target);
    run(target, proxy, deadline, move |client| {
        client.sync(request, BATCH_SIZE, true).map_err(fail)
    })
    .await
}

// --- errors ---------------------------------------------------------------

/// The budget a server gets: onion hosts the longer one.
fn timeout_for(target: &Target) -> Duration {
    if crate::chain::is_onion(&target.url) {
        TOR_TIMEOUT
    } else {
        TIMEOUT
    }
}

/// The error of a call to `target`, as a sentence.
fn failed(target: &Target) -> impl Fn(electrum_client::Error) -> String + use<> {
    let timeout = timeout_for(target);
    move |error| describe(&error, timeout)
}

/// The error as a sentence a person can act on. The crate reports every
/// failed call as "made one or multiple attempts, all errored" over a
/// bulleted list, and an I/O failure in the operating system's words,
/// error number included.
fn describe(error: &electrum_client::Error, timeout: Duration) -> String {
    use electrum_client::Error;
    match error {
        // The client is left at its default of one attempt, so the list
        // holds the one failure; the last entry is the freshest anyway.
        Error::AllAttemptsErrored(errors) => match errors.last() {
            Some(inner) => describe(inner, timeout),
            None => "request failed".to_owned(),
        },
        Error::IOError(io) => describe_io(io, timeout),
        Error::SharedIOError(io) => describe_io(io, timeout),
        Error::Protocol(value) => {
            let message = value
                .get("message")
                .and_then(|m| m.as_str())
                .map_or_else(|| value.to_string(), str::to_owned);
            format!("the server refused the request: {message}")
        }
        Error::Message(text) => text.clone(),
        Error::InvalidDNSNameError(host) => format!("{host} is not a valid TLS host name"),
        Error::CouldNotCreateConnection(_) => "TLS handshake failed".to_owned(),
        Error::JSON(_) | Error::Hex(_) | Error::Bitcoin(_) | Error::InvalidResponse(_) => {
            "unexpected response".to_owned()
        }
        _ => "request failed".to_owned(),
    }
}

fn describe_io(error: &std::io::Error, timeout: Duration) -> String {
    use std::io::ErrorKind;
    match error.kind() {
        // A socket read timeout is `WouldBlock` on Unix and `TimedOut`
        // on Windows.
        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
            format!("timed out after {} s", timeout.as_secs())
        }
        ErrorKind::ConnectionRefused
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown => "could not connect".to_owned(),
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof
        | ErrorKind::NotConnected => "the connection was closed".to_owned(),
        // What [`Guarded`] says of a line too long: its own words.
        ErrorKind::InvalidData => error.to_string(),
        _ => {
            // Name resolution has no kind of its own, and each platform
            // words it differently.
            let text = error.to_string();
            let lower = text.to_ascii_lowercase();
            if [
                "lookup",
                "host is known",
                "name or service",
                "nodename nor servname",
            ]
            .iter()
            .any(|phrase| lower.contains(phrase))
            {
                "host not found".to_owned()
            } else {
                format!("connection failed: {text}")
            }
        }
    }
}

// --- broadcast ------------------------------------------------------------

pub(crate) async fn broadcast(
    target: &Target,
    tx: &Transaction,
    proxy: Option<&str>,
) -> Result<Txid, String> {
    let tx = tx.clone();
    let timeout = timeout_for(target);
    run(target, proxy, call_deadline(target), move |client| {
        client
            .inner
            .transaction_broadcast(&tx)
            .map_err(|e| broadcast_error(timeout, &e))
    })
    .await
}

/// Electrum returns the node's refusal as a protocol error whose
/// message is the reason; keep that. Anything else is a failure to
/// reach the node, described as such.
fn broadcast_error(timeout: Duration, error: &electrum_client::Error) -> String {
    match error {
        electrum_client::Error::Protocol(value) => {
            let text = value
                .get("message")
                .and_then(|m| m.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            crate::chain::esplora::node_message(&text)
        }
        other => describe(other, timeout),
    }
}

/// The output an input spends. Electrum has no "is it spent" call
/// without the script's whole history, which is more than a preview
/// needs: spent-ness stays unknown here and the node says so on
/// broadcast.
pub(crate) async fn fetch_prevout(
    target: &Target,
    outpoint: OutPoint,
    proxy: Option<&str>,
) -> Result<Option<TxOut>, String> {
    let fail = failed(target);
    run(
        target,
        proxy,
        call_deadline(target),
        move |client| match client.inner.transaction_get(&outpoint.txid) {
            Ok(tx) => Ok(tx.output.get(outpoint.vout as usize).cloned()),
            Err(electrum_client::Error::Protocol(_)) => Ok(None),
            Err(error) => Err(fail(error)),
        },
    )
    .await
}

/// Where a transaction stands, read off the history of one of its
/// output scripts: height 0 means mempool, a height means confirmed,
/// absence means the server does not have it.
pub(crate) async fn tx_standing(
    target: &Target,
    txid: Txid,
    script: ScriptBuf,
    proxy: Option<&str>,
) -> Result<(bool, Option<u32>, u32), String> {
    let fail = failed(target);
    run(target, proxy, call_deadline(target), move |client| {
        let tip = client
            .inner
            .block_headers_subscribe()
            .map_err(&fail)?
            .height as u32;
        let history = client.inner.script_get_history(&script).map_err(&fail)?;
        let entry = history.iter().find(|entry| entry.tx_hash == txid);
        Ok(match entry {
            None => (false, None, tip),
            Some(entry) if entry.height > 0 => (true, Some(entry.height as u32), tip),
            Some(_) => (true, None, tip),
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Cursor};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    /// A server that answers `server.version`, then starts its answer
    /// to the next request and never finishes it. It says when that
    /// request arrived, and when the client closed the connection.
    ///
    /// Only a client that opens with the `server.version` of this crate
    /// counts: the port may be one another test just closed, and a
    /// client of that test, still trying it, is turned away.
    fn stalling_server() -> (String, mpsc::Receiver<&'static str>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let (seen, heard) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut writer, mut lines) = loop {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let writer = stream.try_clone().unwrap();
                let mut lines = BufReader::new(stream);
                let mut hello = String::new();
                let _ = lines.read_line(&mut hello);
                if hello.contains("server.version") && hello.contains(CLIENT_NAME) {
                    let _ = lines.get_ref().set_read_timeout(None);
                    break (writer, lines);
                }
            };
            let _ =
                writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":[\"fake\",\"1.4\"]}\n");
            let mut line = String::new();
            let _ = lines.read_line(&mut line);
            let _ = seen.send("asked");
            let _ = writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"height\":");
            // Held until the client goes: a read then ends one way or
            // the other.
            let mut rest = [0u8; 64];
            while matches!(lines.get_mut().read(&mut rest), Ok(n) if n > 0) {}
            let _ = seen.send("closed");
        });
        (url, heard)
    }

    /// What the server says next. It runs on a thread of its own, which
    /// a machine busy with the rest of the suite may be slow to wake:
    /// the bounds that matter are asserted on the client side.
    fn within(heard: &mpsc::Receiver<&'static str>, what: &'static str) {
        assert_eq!(
            heard.recv_timeout(Duration::from_secs(10)).ok(),
            Some(what),
            "the server never saw the client {what}"
        );
    }

    /// A call is held to its deadline however the server stalls, and
    /// the connection is shut down when it runs out: the thread does
    /// not go on reading.
    #[tokio::test]
    async fn a_stalled_call_is_abandoned_at_its_deadline() {
        let (url, heard) = stalling_server();
        let started = Instant::now();
        let outcome = run(
            &Target::new(url, None),
            None,
            Duration::from_millis(500),
            |client| {
                client
                    .inner
                    .block_headers_subscribe()
                    .map_err(|e| e.to_string())
            },
        )
        .await;
        assert_eq!(outcome.err().as_deref(), Some("no answer within 0 s"));
        assert!(started.elapsed() < Duration::from_secs(2));
        within(&heard, "asked");
        within(&heard, "closed");
    }

    /// The call runs on a thread of its own, not on the blocking pool: a
    /// runtime dropped while it waits on a server does not wait with it,
    /// and dropping its future closes the connection.
    #[test]
    fn a_runtime_shutdown_never_waits_on_an_electrum_call() {
        let (url, heard) = stalling_server();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(async move {
            let _ = run(
                &Target::new(url, None),
                None,
                Duration::from_secs(3600),
                |client| {
                    client
                        .inner
                        .block_headers_subscribe()
                        .map_err(|e| e.to_string())
                },
            )
            .await;
        });
        within(&heard, "asked");
        let dropped = Instant::now();
        drop(runtime);
        assert!(
            dropped.elapsed() < Duration::from_secs(2),
            "the runtime waited {:?}",
            dropped.elapsed()
        );
        within(&heard, "closed");
    }

    /// Against a server that answers, the same path carries a call.
    #[tokio::test]
    async fn a_call_goes_through_the_guarded_connection() {
        let server = crate::testkit::FakeElectrum::start().await;
        let target = Target::new(format!("tcp://{}", server.address), None);
        run(&target, None, Duration::from_secs(10), |client| {
            client.inner.ping().map_err(|e| e.to_string())
        })
        .await
        .unwrap();
    }

    /// An onion server is reached through the proxy, by name, with the
    /// proxy's credentials; nothing looks the name up on the way.
    #[tokio::test]
    async fn an_onion_server_is_reached_through_the_proxy_by_name() {
        use crate::chain::tor::socks;
        const ONION: &str = "gerfautexample000000000000000000000000000000000000000.onion";
        let server = crate::testkit::FakeElectrum::start().await;
        let upstream = server.address;
        let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
        let (listener, address) = socks::bind().await.unwrap();
        let seen = asked.clone();
        tokio::spawn(socks::serve(
            listener,
            socks::Credentials::new("user", "pass"),
            move |host, port| {
                seen.lock().unwrap().push((host, port));
                async move { tokio::net::TcpStream::connect(upstream).await }
            },
        ));
        let target = Target::new(format!("tcp://{ONION}:50001"), None);
        let proxy = format!("user:pass@{address}");
        run(&target, Some(&proxy), Duration::from_secs(10), |client| {
            client.inner.ping().map_err(|e| e.to_string())
        })
        .await
        .unwrap();
        assert_eq!(*asked.lock().unwrap(), vec![(ONION.to_owned(), 50001)]);
        // Without a route, nothing is opened at all.
        let refused = run(&target, None, Duration::from_secs(10), |_| Ok(())).await;
        assert!(refused.unwrap_err().starts_with("tor: "));
    }

    /// An in-memory stream, for the reader on its own.
    struct Memory(Cursor<Vec<u8>>);

    impl Read for Memory {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Memory {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A line past the limit is refused as it arrives, not buffered
    /// whole; lines within it go through; an abandoned call reads
    /// nothing more.
    #[test]
    fn a_line_past_the_limit_is_cut_off() {
        let mut data = b"short\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', 64 * 1024));
        let cancel = Arc::new(Cancel::default());
        let guarded = Guarded::new(
            Box::new(Memory(Cursor::new(data))),
            cancel.clone(),
            16 * 1024,
        );
        let mut reader = BufReader::with_capacity(1024, guarded);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "short\n");
        line.clear();
        let error = reader.read_line(&mut line).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            describe_io(&error, TIMEOUT),
            "the server sent an answer longer than 0 MiB"
        );
        assert!(line.len() <= 16 * 1024 + 1024, "{} bytes held", line.len());

        let cancel = Arc::new(Cancel::default());
        let mut guarded = Guarded::new(
            Box::new(Memory(Cursor::new(b"line\n".to_vec()))),
            cancel.clone(),
            MAX_LINE,
        );
        cancel.abort();
        let error = guarded.read(&mut [0u8; 8]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(guarded.write(b"x").is_err());
    }

    #[test]
    fn an_address_splits_into_transport_host_and_port() {
        assert_eq!(
            parse("ssl://electrum.example:50002").unwrap(),
            (true, "electrum.example".to_owned(), 50002)
        );
        assert_eq!(
            parse("tcp://192.168.1.10:50001").unwrap(),
            (false, "192.168.1.10".to_owned(), 50001)
        );
        // No scheme means TLS, the Electrum convention.
        assert_eq!(
            parse("electrum.example:51002").unwrap(),
            (true, "electrum.example".to_owned(), 51002)
        );
        // No port means the protocol default, per transport.
        assert_eq!(parse("ssl://host").unwrap().2, SSL_PORT);
        assert_eq!(parse("tcp://host").unwrap().2, TCP_PORT);
        // An IPv6 literal keeps its own colons.
        assert_eq!(
            parse("ssl://[2001:db8::1]:50002").unwrap(),
            (true, "2001:db8::1".to_owned(), 50002)
        );
        assert!(parse("http://host:50002").is_err());
        assert!(parse("ssl://host:not-a-port").is_err());
    }

    /// Live. The whole trust-on-first-use path against real servers:
    /// a certificate a public authority signs needs no acceptance, one a
    /// server signed itself is described precisely and refused until it
    /// is accepted, then it carries real data, and a different
    /// certificate on the same host is refused again.
    #[tokio::test]
    #[ignore = "talks to public Electrum servers"]
    async fn a_self_signed_server_asks_once_and_then_serves() {
        let vouched = Target::new("ssl://electrum.blockstream.info:50002", None);
        assert_eq!(
            inspect_blocking(&vouched).unwrap(),
            Inspection::Tls(Verdict::Trusted),
            "blockstream's certificate is signed by a public authority"
        );

        // One of the servers Sparrow ships that signs its own.
        let url = "ssl://electrum.emzy.de:50002";
        let Inspection::Tls(Verdict::Unknown {
            fingerprint,
            reason,
            subject,
            expires,
        }) = inspect_blocking(&Target::new(url, None)).unwrap()
        else {
            panic!("emzy's Electrum server is expected to sign its own certificate");
        };
        assert!(tls::is_fingerprint(&fingerprint), "{fingerprint}");
        assert!(!reason.is_empty());
        // The certificate says who it is and until when, even the one
        // written in a version webpki refuses to read.
        assert!(subject.is_some_and(|s| !s.is_empty()));
        assert!(expires.is_some_and(|at| at > 1_700_000_000));

        // Accepted once: the connection opens, and the server answers
        // with real chain data over it.
        let accepted = Target::new(url, Some(fingerprint.clone()));
        assert_eq!(
            inspect_blocking(&accepted).unwrap(),
            Inspection::Tls(Verdict::Pinned)
        );
        let pizza: Txid = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
            .parse()
            .unwrap();
        let txout = fetch_prevout(&accepted, OutPoint::new(pizza, 0), None)
            .await
            .expect("an accepted certificate carries Electrum traffic")
            .expect("the server knows that transaction");
        assert_eq!(txout.value.to_sat(), 1_000_000_000_000);

        // Any other certificate on that host is refused, and named.
        let elsewhere = Target::new(url, Some(["AA"; 32].join(":")));
        match inspect_blocking(&elsewhere).unwrap() {
            Inspection::Tls(Verdict::Changed { presented, stored }) => {
                assert_eq!(presented, fingerprint);
                assert_eq!(stored, ["AA"; 32].join(":"));
            }
            other => panic!("a changed certificate must be refused, got {other:?}"),
        }
    }

    #[test]
    fn errors_read_as_sentences_not_as_the_crate_spells_them() {
        use electrum_client::Error;
        let refused = Error::IOError(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(describe(&refused, TIMEOUT), "could not connect");
        // Every call the crate's client makes is reported as a list of
        // attempts; the sentence is the failure inside.
        let attempts = Error::AllAttemptsErrored(vec![Error::IOError(std::io::Error::from(
            std::io::ErrorKind::TimedOut,
        ))]);
        assert_eq!(describe(&attempts, TIMEOUT), "timed out after 20 s");
        assert_eq!(describe(&attempts, TOR_TIMEOUT), "timed out after 60 s");
        let unix_read_timeout =
            Error::IOError(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        assert_eq!(
            describe(&unix_read_timeout, TIMEOUT),
            "timed out after 20 s"
        );
        let lookup = Error::IOError(std::io::Error::other(
            "failed to lookup address information: Name or service not known",
        ));
        assert_eq!(describe(&lookup, TIMEOUT), "host not found");
        let refusal = Error::Protocol(serde_json::json!({
            "code": 1,
            "message": "unknown method"
        }));
        assert_eq!(
            describe(&refusal, TIMEOUT),
            "the server refused the request: unknown method"
        );
        let garbled = Error::JSON(serde_json::from_str::<u32>("x").unwrap_err());
        assert_eq!(describe(&garbled, TIMEOUT), "unexpected response");
        assert_eq!(
            timeout_for(&Target::new(
                "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001",
                None
            )),
            TOR_TIMEOUT
        );
        assert_eq!(
            timeout_for(&Target::new("ssl://electrum.example:50002", None)),
            TIMEOUT
        );
    }

    /// The inspection of an onion server is decided before any socket
    /// exists, and in whatever case the address was stored: a `.ONION`
    /// is a hidden service, not a plain TCP host to be looked up.
    #[test]
    fn an_onion_is_inspected_as_tor_in_any_case() {
        const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567";
        let shouted = format!("tcp://{}.ONION:50001", ONION.to_ascii_uppercase());
        assert_eq!(
            inspect_blocking(&Target::new(format!("tcp://{ONION}.onion:50001"), None)).unwrap(),
            Inspection::Tor
        );
        assert_eq!(
            inspect_blocking(&Target::new(shouted.clone(), None)).unwrap(),
            Inspection::Tor
        );
        // And without a route, the connection is refused before the
        // name could reach a resolver, whatever the case.
        let error = connect(&Target::new(shouted, None), None, &Arc::default())
            .err()
            .map(|e| e.to_string())
            .expect("no route, no connection");
        assert!(error.starts_with("tor: "), "{error}");
    }

    #[test]
    fn the_trust_key_is_the_socket_scheme_and_path_stripped() {
        assert_eq!(
            certificate_key("ssl://electrum.example:50002"),
            "electrum.example:50002"
        );
        // Two spellings of the same server share one accepted certificate.
        assert_eq!(
            certificate_key("electrum.example:50002"),
            certificate_key("ssl://electrum.example:50002")
        );
        // A default port is spelled out, so the key never depends on how
        // the user typed the address.
        assert_eq!(certificate_key("ssl://host"), "host:50002");
    }

    /// The settings store the address in canonical form. The key has
    /// to read the host the same way, or a certificate accepted from
    /// the address as typed is looked up under another key and asked
    /// for a second time.
    #[test]
    fn the_trust_key_reads_the_host_the_way_the_store_does() {
        let canonical = certificate_key("ssl://node.example.org:50002");
        assert_eq!(canonical, "node.example.org:50002");
        assert_eq!(certificate_key("SSL://Node.Example.ORG.:50002"), canonical);
        assert_eq!(certificate_key("node.example.org.:50002"), canonical);
        assert_eq!(certificate_key("ssl://NODE.EXAMPLE.ORG:50002"), canonical);
        // An IPv6 literal in its canonical spelling, keyed as before.
        assert_eq!(
            certificate_key("ssl://[2001:DB8:0:0::1]:50002"),
            "2001:db8::1:50002"
        );
        assert_eq!(certificate_key("[2001:db8::1]:50002"), "2001:db8::1:50002");
    }
}
