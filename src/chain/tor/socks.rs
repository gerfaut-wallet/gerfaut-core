//! The smallest SOCKS5 server that satisfies `reqwest` (`socks5h://`)
//! and `electrum-client`: username/password authentication (RFC 1929),
//! `CONNECT` only, the target given as a domain name, an IPv4 or an
//! IPv6 address. It listens on loopback only and hands every stream to
//! the connect function it is given, which is where Tor comes in. Names
//! are passed through as spelled and never resolved here: an onion name
//! has nowhere to be resolved but inside Tor.
//!
//! Loopback is not private everywhere. On Android every app holding the
//! INTERNET permission shares it, and a proxy that took anyone's
//! `CONNECT` would carry anyone's traffic through this wallet's Tor
//! client. So each process draws its own [`Credentials`], and a client
//! that does not present them gets nothing, not even a refusal it can
//! learn from.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::distr::{Alphanumeric, SampleString};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) const VERSION: u8 = 5;
/// The "no authentication" method: what a system Tor answers the probe
/// with, never what this server accepts.
pub(crate) const NO_AUTH: u8 = 0;
/// The username/password method, RFC 1929.
const USER_PASS: u8 = 2;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
/// The one version of the username/password subnegotiation.
const AUTH_VERSION: u8 = 1;
const AUTH_SUCCEEDED: u8 = 0;
const AUTH_FAILED: u8 = 1;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Reply codes, RFC 1928 section 6.
const REPLY_SUCCEEDED: u8 = 0;
const REPLY_GENERAL_FAILURE: u8 = 1;
const REPLY_NETWORK_UNREACHABLE: u8 = 3;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_CONNECTION_REFUSED: u8 = 5;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

/// How long a client has to get from its greeting to its request. A
/// client of ours sends them back to back; a neighbour on loopback that
/// connects and says nothing, or stops halfway, would otherwise hold a
/// task for as long as it keeps the socket open.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a client must present to use the proxy. Drawn at random for the
/// process, handed to the HTTP and Electrum clients in memory, and
/// never written, shown or logged: the `Debug` form says nothing.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credentials {
    username: String,
    password: String,
}

/// Length of each credential, in characters. Alphanumeric, so they ride
/// in a proxy URL without escaping; 32 of them is about 190 bits, well
/// past what a neighbour on loopback could try.
const CREDENTIAL_CHARS: usize = 32;

impl Credentials {
    /// Fresh credentials from the process CSPRNG.
    pub(crate) fn random() -> Self {
        let mut rng = rand::rng();
        Credentials {
            username: Alphanumeric.sample_string(&mut rng, CREDENTIAL_CHARS),
            password: Alphanumeric.sample_string(&mut rng, CREDENTIAL_CHARS),
        }
    }

    /// Known credentials, for tests that play both sides.
    #[cfg(test)]
    pub(crate) fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Credentials {
            username: username.into(),
            password: password.into(),
        }
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }

    /// Whether a client presented exactly these, compared in constant
    /// time over both fields whatever their lengths.
    fn accept(&self, username: &[u8], password: &[u8]) -> bool {
        let same_username = username.len() == self.username.len()
            && bool::from(username.ct_eq(self.username.as_bytes()));
        let same_password = password.len() == self.password.len()
            && bool::from(password.ct_eq(self.password.as_bytes()));
        same_username & same_password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(redacted)")
    }
}

/// Where a proxy listens and what it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Access {
    /// `host:port`.
    pub address: String,
    pub credentials: Credentials,
}

/// Listens on loopback, on a port the system picks: nothing to clash
/// with, nothing reachable from outside the machine.
pub(crate) async fn bind() -> io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

/// Accepts connections for as long as the task lives, one session per
/// connection. `credentials` are what every client must present;
/// `connect` opens the upstream side of each `CONNECT`.
pub(crate) async fn serve<C, F, U>(listener: TcpListener, credentials: Credentials, connect: C)
where
    C: Fn(String, u16) -> F + Clone + Send + 'static,
    F: Future<Output = io::Result<U>> + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_within(listener, credentials, connect, HANDSHAKE_TIMEOUT).await
}

/// [`serve`] with the handshake budget given, so a test can shorten it.
async fn serve_within<C, F, U>(
    listener: TcpListener,
    credentials: Credentials,
    connect: C,
    handshake_timeout: Duration,
) where
    C: Fn(String, u16) -> F + Clone + Send + 'static,
    F: Future<Output = io::Result<U>> + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            // Out of descriptors, or a peer gone before the accept: the
            // listener itself is fine, so pause rather than spin.
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let connect = connect.clone();
        let credentials = credentials.clone();
        // A session's failure is the client's to notice: it got the
        // reply code, and the proxy has nothing to add.
        tokio::spawn(async move {
            let _ = session(stream, &credentials, connect, handshake_timeout).await;
        });
    }
}

/// The handshake: method negotiation, the credentials, then the request
/// down to its target. Every refusal is answered with the reply code
/// the protocol has for it before the stream is dropped.
async fn handshake<S>(stream: &mut S, credentials: &Credentials) -> io::Result<(String, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let [version, method_count] = greeting;
    if version != VERSION {
        return Err(invalid("not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; method_count as usize];
    stream.read_exact(&mut methods).await?;
    // Username/password only: a client that offers nothing but "no
    // authentication" is not one of ours.
    if !methods.contains(&USER_PASS) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHODS]).await?;
        return Err(invalid(
            "the client offers no authentication this proxy accepts",
        ));
    }
    stream.write_all(&[VERSION, USER_PASS]).await?;

    // RFC 1929: the version, then the username and the password, each
    // behind its own length byte.
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let [auth_version, username_len] = head;
    if auth_version != AUTH_VERSION {
        stream.write_all(&[AUTH_VERSION, AUTH_FAILED]).await?;
        return Err(invalid("not a username/password request"));
    }
    let mut username = vec![0u8; username_len as usize];
    stream.read_exact(&mut username).await?;
    let mut password_len = [0u8; 1];
    stream.read_exact(&mut password_len).await?;
    let mut password = vec![0u8; password_len[0] as usize];
    stream.read_exact(&mut password).await?;
    if !credentials.accept(&username, &password) {
        // The failure code, then the stream is dropped: RFC 1929
        // section 2 has the server close the connection.
        stream.write_all(&[AUTH_VERSION, AUTH_FAILED]).await?;
        return Err(invalid("wrong proxy credentials"));
    }
    stream.write_all(&[AUTH_VERSION, AUTH_SUCCEEDED]).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [version, command, _reserved, address_type] = head;
    if version != VERSION {
        reply(stream, REPLY_GENERAL_FAILURE).await?;
        return Err(invalid("not a SOCKS5 request"));
    }
    let host = match address_type {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; length[0] as usize];
            stream.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(name) => name,
                Err(_) => {
                    reply(stream, REPLY_GENERAL_FAILURE).await?;
                    return Err(invalid("the host name is not text"));
                }
            }
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => {
            reply(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(invalid("unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if command != CMD_CONNECT {
        reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(invalid("only CONNECT is supported"));
    }
    Ok((host, port))
}

/// One session: the handshake, given `handshake_timeout` to complete,
/// then the upstream connection, the reply, and bytes both ways until
/// either side closes. A client that runs out of time is dropped
/// without a word, the way one with the wrong credentials is.
pub(crate) async fn session<S, C, F, U>(
    mut stream: S,
    credentials: &Credentials,
    connect: C,
    handshake_timeout: Duration,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnOnce(String, u16) -> F,
    F: Future<Output = io::Result<U>>,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (host, port) = tokio::time::timeout(handshake_timeout, handshake(&mut stream, credentials))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "the client did not finish its handshake in time",
            )
        })??;

    let mut upstream = match connect(host, port).await {
        Ok(upstream) => upstream,
        Err(error) => {
            reply(&mut stream, reply_code(&error)).await?;
            return Err(error);
        }
    };
    reply(&mut stream, REPLY_SUCCEEDED).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// The reply, with an unspecified bound address: clients never use it
/// for `CONNECT`, and the real one would be a Tor circuit anyway.
async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> io::Result<()> {
    stream
        .write_all(&[VERSION, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// The closest reply code to why the upstream connection failed.
fn reply_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => REPLY_HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => REPLY_NETWORK_UNREACHABLE,
        _ => REPLY_GENERAL_FAILURE,
    }
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpStream;

    use super::*;

    /// An upstream that repeats what it hears: one relayed byte proves
    /// the whole path, negotiation to copy.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    /// The credentials every proxy under test expects.
    fn credentials() -> Credentials {
        Credentials::new("gerfaut-test-user", "gerfaut-test-pass")
    }

    /// The proxy under test, on loopback, with the connect function
    /// injected: the same accept loop the embedded client runs.
    async fn proxy<C, F, U>(connect: C) -> SocketAddr
    where
        C: Fn(String, u16) -> F + Clone + Send + 'static,
        F: Future<Output = io::Result<U>> + Send + 'static,
        U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (listener, address) = bind().await.unwrap();
        tokio::spawn(serve(listener, credentials(), connect));
        address
    }

    /// The RFC 1929 request for a username and a password.
    fn auth_request(username: &str, password: &str) -> Vec<u8> {
        let mut request = vec![AUTH_VERSION, username.len() as u8];
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        request
    }

    /// A proxy that connects everything to an echo server and records
    /// what it was asked for.
    async fn echo_proxy(seen: Arc<Mutex<Vec<(String, u16)>>>) -> SocketAddr {
        let echo = echo_server().await;
        proxy(move |host, port| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push((host, port));
                TcpStream::connect(echo).await
            }
        })
        .await
    }

    /// Connects, offers both methods the way `reqwest` does, and
    /// presents the right credentials.
    async fn greet(proxy: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(&[VERSION, 2, NO_AUTH, USER_PASS])
            .await
            .unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, USER_PASS]);
        let expected = credentials();
        stream
            .write_all(&auth_request(expected.username(), expected.password()))
            .await
            .unwrap();
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [AUTH_VERSION, AUTH_SUCCEEDED]);
        stream
    }

    async fn request(stream: &mut TcpStream, command: u8, target: &[u8], port: u16) -> [u8; 10] {
        let mut request = vec![VERSION, command, 0];
        request.extend_from_slice(target);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

    fn domain(name: &str) -> Vec<u8> {
        let mut target = vec![ATYP_DOMAIN, name.len() as u8];
        target.extend_from_slice(name.as_bytes());
        target
    }

    #[tokio::test]
    async fn a_connect_to_a_domain_is_relayed() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = echo_proxy(seen.clone()).await;
        let mut stream = greet(proxy).await;

        let reply = request(&mut stream, CMD_CONNECT, &domain("mempool.onion"), 443).await;
        assert_eq!(
            reply,
            [VERSION, REPLY_SUCCEEDED, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
        );
        // The name reaches the connect function as spelled, unresolved.
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("mempool.onion".to_owned(), 443)]
        );

        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }

    #[tokio::test]
    async fn ip_targets_are_spelled_out_for_the_connect_function() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = echo_proxy(seen.clone()).await;

        let mut v4 = greet(proxy).await;
        let mut target = vec![ATYP_IPV4];
        target.extend_from_slice(&[10, 0, 0, 7]);
        assert_eq!(
            request(&mut v4, CMD_CONNECT, &target, 80).await[1],
            REPLY_SUCCEEDED
        );

        let mut v6 = greet(proxy).await;
        let mut target = vec![ATYP_IPV6];
        target.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert_eq!(
            request(&mut v6, CMD_CONNECT, &target, 8333).await[1],
            REPLY_SUCCEEDED
        );

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("10.0.0.7".to_owned(), 80), ("::1".to_owned(), 8333)]
        );
    }

    #[tokio::test]
    async fn bind_is_refused_as_unsupported() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = echo_proxy(seen.clone()).await;
        let mut stream = greet(proxy).await;
        let reply = request(&mut stream, 2, &domain("example.onion"), 80).await;
        assert_eq!(reply[1], REPLY_COMMAND_NOT_SUPPORTED);
        assert!(seen.lock().unwrap().is_empty(), "nothing is connected");
        // The proxy closed the stream after the reply.
        let mut rest = [0u8; 1];
        assert_eq!(stream.read(&mut rest).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_unknown_address_type_is_refused() {
        let proxy = echo_proxy(Arc::new(Mutex::new(Vec::new()))).await;
        let mut stream = greet(proxy).await;
        // The reply comes before the address, whose length is unknown.
        stream
            .write_all(&[VERSION, CMD_CONNECT, 0, 9])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
    }

    /// Another app on the same loopback, or a scanner: it offers "no
    /// authentication", the only method an open proxy would take, and
    /// is told there is nothing here for it.
    #[tokio::test]
    async fn a_client_that_offers_no_authentication_is_turned_away() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = echo_proxy(seen.clone()).await;
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&[VERSION, 1, NO_AUTH]).await.unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, NO_ACCEPTABLE_METHODS]);
        // The proxy closed the stream after the refusal.
        let mut rest = [0u8; 1];
        assert_eq!(stream.read(&mut rest).await.unwrap(), 0);
        assert!(seen.lock().unwrap().is_empty(), "nothing is connected");
    }

    #[tokio::test]
    async fn wrong_credentials_are_refused_and_the_stream_closed() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = echo_proxy(seen.clone()).await;
        for (username, password) in [
            ("gerfaut-test-user", "not-the-password"),
            ("someone-else", "gerfaut-test-pass"),
            ("", ""),
            ("gerfaut-test-user", "gerfaut-test-pass-and-more"),
        ] {
            let mut stream = TcpStream::connect(proxy).await.unwrap();
            stream.write_all(&[VERSION, 1, USER_PASS]).await.unwrap();
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, [VERSION, USER_PASS]);
            stream
                .write_all(&auth_request(username, password))
                .await
                .unwrap();
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(
                answer,
                [AUTH_VERSION, AUTH_FAILED],
                "{username:?}/{password:?}"
            );
            let mut rest = [0u8; 1];
            assert_eq!(
                stream.read(&mut rest).await.unwrap(),
                0,
                "closed after the refusal"
            );
        }
        assert!(seen.lock().unwrap().is_empty(), "nothing is connected");

        // A subnegotiation of a version nobody wrote is refused too. The
        // refusal comes as soon as the version is read: only the head
        // is sent, so nothing unread makes the close a reset.
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&[VERSION, 1, USER_PASS]).await.unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.unwrap();
        stream.write_all(&[7, 1]).await.unwrap();
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [AUTH_VERSION, AUTH_FAILED]);
    }

    /// `reqwest`, which the Esplora backend runs on, reads the
    /// credentials out of a `socks5h://user:pass@host:port` URL and
    /// presents them: the whole path, greeting to relayed response.
    /// Without them the same client gets nowhere.
    #[tokio::test]
    async fn reqwest_presents_the_credentials_from_the_proxy_url() {
        // An upstream speaking just enough HTTP for one request.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = {
            let seen = seen.clone();
            proxy(move |host, port| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push((host, port));
                    TcpStream::connect(upstream).await
                }
            })
            .await
        };
        let http = |proxy_url: String| {
            reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(proxy_url).unwrap())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap()
        };

        let expected = credentials();
        let with_credentials = http(format!(
            "socks5h://{}:{}@{proxy}",
            expected.username(),
            expected.password()
        ));
        let body = with_credentials
            .get("http://gerfaut.onion/ping")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
        // The name went through unresolved, to the port HTTP implies.
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("gerfaut.onion".to_owned(), 80)]
        );

        let without = http(format!("socks5h://{proxy}"));
        assert!(
            without
                .get("http://gerfaut.onion/ping")
                .send()
                .await
                .is_err()
        );
        let wrong = http(format!("socks5h://{}:nope@{proxy}", expected.username()));
        assert!(wrong.get("http://gerfaut.onion/ping").send().await.is_err());
        assert_eq!(seen.lock().unwrap().len(), 1, "nothing else was connected");
    }

    #[test]
    fn random_credentials_are_long_alphanumeric_and_never_shown() {
        let a = Credentials::random();
        let b = Credentials::random();
        for text in [a.username(), a.password(), b.username(), b.password()] {
            assert_eq!(text.len(), CREDENTIAL_CHARS);
            assert!(text.chars().all(|c| c.is_ascii_alphanumeric()), "{text}");
        }
        assert_ne!(a, b);
        assert_ne!(a.username(), a.password());
        let shown = format!("{a:?}");
        assert!(!shown.contains(a.username()) && !shown.contains(a.password()));
        assert!(a.accept(a.username().as_bytes(), a.password().as_bytes()));
        assert!(!a.accept(b.username().as_bytes(), a.password().as_bytes()));
    }

    #[tokio::test]
    async fn an_upstream_failure_becomes_its_reply_code() {
        let refusing = proxy(|_host, _port| async {
            Err::<TcpStream, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
        })
        .await;
        let mut stream = greet(refusing).await;
        let reply = request(&mut stream, CMD_CONNECT, &domain("down.onion"), 80).await;
        assert_eq!(reply[1], REPLY_CONNECTION_REFUSED);

        let unreachable = proxy(|_host, _port| async {
            Err::<TcpStream, _>(io::Error::from(io::ErrorKind::HostUnreachable))
        })
        .await;
        let mut stream = greet(unreachable).await;
        let reply = request(&mut stream, CMD_CONNECT, &domain("gone.onion"), 80).await;
        assert_eq!(reply[1], REPLY_HOST_UNREACHABLE);

        // Anything Tor itself reports is a general failure.
        let failing =
            proxy(|_host, _port| async { Err::<TcpStream, _>(io::Error::other("no circuit")) })
                .await;
        let mut stream = greet(failing).await;
        let reply = request(&mut stream, CMD_CONNECT, &domain("far.onion"), 80).await;
        assert_eq!(reply[1], REPLY_GENERAL_FAILURE);
    }

    /// A neighbour that connects and says nothing, or greets and then
    /// falls silent, is dropped once its time is up rather than kept on
    /// a task for as long as it holds the socket.
    #[tokio::test]
    async fn a_silent_client_is_dropped_once_its_time_is_up() {
        let (listener, address) = bind().await.unwrap();
        tokio::spawn(serve_within(
            listener,
            credentials(),
            |_host: String, _port: u16| async {
                Err::<TcpStream, _>(io::Error::other("nothing to connect for"))
            },
            Duration::from_millis(200),
        ));
        let closed = |read: &io::Result<usize>| matches!(read, Ok(0) | Err(_));

        // Not a byte sent.
        let mut silent = TcpStream::connect(address).await.unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut byte))
            .await
            .expect("the proxy closes the stream instead of waiting");
        assert!(closed(&read), "{read:?}");

        // Greeted, then nothing where the credentials should follow.
        let mut halfway = TcpStream::connect(address).await.unwrap();
        halfway.write_all(&[VERSION, 1, USER_PASS]).await.unwrap();
        let mut answer = [0u8; 2];
        halfway.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, USER_PASS]);
        let read = tokio::time::timeout(Duration::from_secs(5), halfway.read(&mut byte))
            .await
            .expect("the proxy closes the stream instead of waiting");
        assert!(closed(&read), "{read:?}");
    }

    #[tokio::test]
    async fn a_session_over_any_stream_is_the_same_protocol() {
        // The session logic on its own, over an in-memory pipe.
        let (mut client, server) = tokio::io::duplex(256);
        let (mut upstream_end, upstream) = tokio::io::duplex(256);
        let expected = credentials();
        let session = tokio::spawn(async move {
            session(
                server,
                &expected,
                move |host, port| async move {
                    assert_eq!((host.as_str(), port), ("pipe.onion", 50001));
                    Ok::<_, io::Error>(upstream)
                },
                HANDSHAKE_TIMEOUT,
            )
            .await
        });
        client.write_all(&[VERSION, 1, USER_PASS]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, USER_PASS]);
        client
            .write_all(&auth_request("gerfaut-test-user", "gerfaut-test-pass"))
            .await
            .unwrap();
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [AUTH_VERSION, AUTH_SUCCEEDED]);
        let mut request = vec![VERSION, CMD_CONNECT, 0];
        request.extend_from_slice(&domain("pipe.onion"));
        request.extend_from_slice(&50001u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REPLY_SUCCEEDED);
        upstream_end.write_all(b"tip").await.unwrap();
        let mut heard = [0u8; 3];
        client.read_exact(&mut heard).await.unwrap();
        assert_eq!(&heard, b"tip");
        drop(client);
        drop(upstream_end);
        assert!(session.await.unwrap().is_ok());
    }
}
