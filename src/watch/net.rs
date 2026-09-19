//! The sockets of the live watcher: TCP, the Tor proxy in front of it
//! when the host is a hidden service, and TLS on top when the address
//! asks for it.
//!
//! A sync opens its connections through `reqwest` and `electrum-client`.
//! Neither can hold a socket open and wait on it, so the watcher opens
//! its own, under the same three rules. An onion host is reached
//! through the SOCKS proxy the caller resolved, by name, and refused
//! when there is none: nothing here ever resolves one. An Electrum
//! server presents its certificate to the verifier of
//! [`crate::chain::tls`], pin included. An HTTPS server is checked
//! against the public authorities, as the HTTP client checks it.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::chain::tls;
use crate::chain::tor::socks::{NO_AUTH, VERSION};

/// Anything a session can read from and write to.
pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub(crate) type BoxStream = Box<dyn Stream>;

/// What is laid over the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security<'a> {
    /// Nothing: `tcp://` and `http://`.
    Plain,
    /// TLS checked against the public authorities: `https://`.
    Public,
    /// TLS checked the Electrum way: the public authorities, or the
    /// fingerprint the user accepted for this host.
    Electrum { pin: Option<&'a str> },
}

/// Opens a connection to `host:port`. `proxy` is the Tor SOCKS proxy
/// the caller resolved, `user:password@host:port` or `host:port`, and
/// is what the connection goes through when given. The whole opening,
/// TLS included, gets `budget`.
pub(crate) async fn open(
    host: &str,
    port: u16,
    security: Security<'_>,
    proxy: Option<&str>,
    budget: Duration,
) -> Result<BoxStream, String> {
    let onion = crate::chain::is_onion_host(host);
    // Checked here again, below whatever the caller decided: the one
    // place a name turns into a connection is the one place an onion
    // without a route must stop.
    if onion && proxy.is_none() {
        return Err(crate::chain::tor::no_route(host));
    }
    let opening = async {
        let socket = match proxy {
            Some(proxy) => through_socks(proxy, host, port).await?,
            None => TcpStream::connect((host, port))
                .await
                .map_err(|e| describe_io(&e))?,
        };
        let _ = socket.set_nodelay(true);
        let config = match security {
            Security::Plain => return Ok(Box::new(socket) as BoxStream),
            Security::Public => tls::public_config().map_err(|e| e.to_string())?,
            Security::Electrum { .. } if onion => tls::onion_config().map_err(|e| e.to_string())?,
            Security::Electrum { pin } => {
                let handshake = tls::Handshake::new(pin).map_err(|e| e.to_string())?;
                let name = tls::server_name(host).map_err(|e| e.to_string())?;
                return match TlsConnector::from(handshake.config.clone())
                    .connect(name, socket)
                    .await
                {
                    Ok(stream) => Ok(Box::new(stream) as BoxStream),
                    Err(error) => Err(handshake.refusal(&error).to_string()),
                };
            }
        };
        let name = tls::server_name(host).map_err(|e| e.to_string())?;
        TlsConnector::from(config)
            .connect(name, socket)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
            .map_err(|e| format!("TLS handshake failed: {e}"))
    };
    match tokio::time::timeout(budget, opening).await {
        Ok(result) => result,
        Err(_) => Err(format!("could not connect within {} s", budget.as_secs())),
    }
}

/// A SOCKS5 `CONNECT` to `host:port` by name, RFC 1928, with the
/// username and password of RFC 1929 when the proxy string carries
/// them. The name goes to the proxy as spelled: an onion has nowhere
/// to be resolved but inside Tor.
async fn through_socks(proxy: &str, host: &str, port: u16) -> Result<TcpStream, String> {
    const USER_PASS: u8 = 2;
    const CONNECT: u8 = 1;
    const DOMAIN: u8 = 3;
    let fail = |what: &str| format!("could not connect through Tor: {what}");
    let (credentials, address) = crate::chain::tor::split_proxy(proxy);
    let name = host.as_bytes();
    if name.is_empty() || name.len() > 255 {
        return Err(fail("the host name does not fit a SOCKS request"));
    }
    let mut socket = TcpStream::connect(address)
        .await
        .map_err(|_| fail("the proxy does not answer"))?;
    let io = |_| fail("the proxy closed the connection");

    let greeting: &[u8] = match credentials {
        Some(_) => &[VERSION, 2, NO_AUTH, USER_PASS],
        None => &[VERSION, 1, NO_AUTH],
    };
    socket.write_all(greeting).await.map_err(io)?;
    let mut choice = [0u8; 2];
    socket.read_exact(&mut choice).await.map_err(io)?;
    match (choice, credentials) {
        ([VERSION, NO_AUTH], _) => {}
        ([VERSION, USER_PASS], Some((username, password))) => {
            if username.len() > 255 || password.len() > 255 {
                return Err(fail("the proxy credentials do not fit a SOCKS request"));
            }
            let mut auth = vec![1u8, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            socket.write_all(&auth).await.map_err(io)?;
            let mut verdict = [0u8; 2];
            socket.read_exact(&mut verdict).await.map_err(io)?;
            if verdict[1] != 0 {
                return Err(fail("the proxy refused the credentials"));
            }
        }
        _ => return Err(fail("the proxy offers no usable authentication")),
    }

    let mut request = vec![VERSION, CONNECT, 0, DOMAIN, name.len() as u8];
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await.map_err(io)?;
    let mut reply = [0u8; 4];
    socket.read_exact(&mut reply).await.map_err(io)?;
    if reply[0] != VERSION {
        return Err(fail("the proxy does not speak SOCKS5"));
    }
    if reply[1] != 0 {
        return Err(fail(match reply[1] {
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "the circuit timed out",
            _ => "the proxy could not reach the host",
        }));
    }
    // The bound address, which nothing here needs: read and dropped.
    let rest = match reply[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        DOMAIN => {
            let mut length = [0u8; 1];
            socket.read_exact(&mut length).await.map_err(io)?;
            usize::from(length[0]) + 2
        }
        _ => return Err(fail("the proxy answered with an unknown address type")),
    };
    let mut bound = [0u8; 257];
    socket.read_exact(&mut bound[..rest]).await.map_err(io)?;
    Ok(socket)
}

fn describe_io(error: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown => "could not connect".to_owned(),
        ErrorKind::TimedOut => "timed out".to_owned(),
        _ => {
            let lower = error.to_string().to_ascii_lowercase();
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
                format!("connection failed: {error}")
            }
        }
    }
}

/// Reads lines off a stream, never holding more than `limit` bytes of
/// one: a server that sends a line without an end is cut off, not
/// buffered. Cancel safe: what was read stays here between calls.
pub(crate) struct LineReader<R> {
    inner: R,
    buffer: Vec<u8>,
    scanned: usize,
    limit: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub(crate) fn new(inner: R, limit: usize) -> Self {
        LineReader {
            inner,
            buffer: Vec::new(),
            scanned: 0,
            limit,
        }
    }

    /// The next line without its end, `None` once the stream is closed.
    pub(crate) async fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(offset) = self.buffer[self.scanned..].iter().position(|b| *b == b'\n') {
                let end = self.scanned + offset;
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.scanned = 0;
                return Ok(Some(line));
            }
            self.scanned = self.buffer.len();
            if self.buffer.len() > self.limit {
                return Err(std::io::Error::other(
                    "the server sent a line without an end",
                ));
            }
            let mut chunk = [0u8; 4096];
            let read = self.inner.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpListener;

    use super::*;
    use crate::chain::tor::socks;

    const ONION: &str = "gerfautexample000000000000000000000000000000000000000.onion";
    const BUDGET: Duration = Duration::from_secs(5);

    /// An onion host with no proxy never becomes a connection, and so
    /// never a lookup: the refusal comes before any socket exists.
    #[tokio::test]
    async fn an_onion_without_a_route_is_refused_before_any_socket() {
        for security in [
            Security::Plain,
            Security::Public,
            Security::Electrum { pin: None },
        ] {
            let error = open(ONION, 50001, security, None, BUDGET)
                .await
                .err()
                .expect("no route, no connection");
            assert!(error.starts_with("tor: "), "{error}");
        }
        let shouted = ONION.to_ascii_uppercase();
        let error = open(&shouted, 50001, Security::Plain, None, BUDGET)
            .await
            .err()
            .expect("an onion in capitals is an onion");
        assert!(error.starts_with("tor: "), "{error}");
    }

    /// Through the proxy, the name reaches it as spelled, with the
    /// credentials it asks for, and the stream carries bytes both ways.
    #[tokio::test]
    async fn an_onion_goes_through_the_proxy_by_name() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = upstream.accept().await {
                let mut hello = [0u8; 5];
                if stream.read_exact(&mut hello).await.is_ok() {
                    let _ = stream.write_all(b"world").await;
                }
            }
        });
        let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
        let (listener, address) = socks::bind().await.unwrap();
        let credentials = socks::Credentials::new("user", "pass");
        let seen = asked.clone();
        tokio::spawn(socks::serve(listener, credentials, move |host, port| {
            seen.lock().unwrap().push((host, port));
            async move { TcpStream::connect(upstream_address).await }
        }));

        let proxy = format!("user:pass@{address}");
        let mut stream = open(ONION, 50001, Security::Plain, Some(&proxy), BUDGET)
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut answer = [0u8; 5];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"world");
        assert_eq!(*asked.lock().unwrap(), vec![(ONION.to_owned(), 50001)]);

        // The wrong credentials get nothing.
        let wrong = format!("user:nope@{address}");
        assert!(
            open(ONION, 50001, Security::Plain, Some(&wrong), BUDGET)
                .await
                .is_err()
        );
        assert_eq!(asked.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_line_without_an_end_is_cut_off() {
        let (mut writer, reader) = tokio::io::duplex(1 << 16);
        let mut lines = LineReader::new(reader, 1024);
        writer.write_all(b"one\r\ntwo\nthr").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), b"one");
        assert_eq!(lines.next_line().await.unwrap().unwrap(), b"two");
        writer.write_all(b"ee\n").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap().unwrap(), b"three");
        writer.write_all(&vec![b'x'; 8192]).await.unwrap();
        assert!(lines.next_line().await.is_err());
    }
}
