//! The smallest SOCKS5 server that satisfies `reqwest` (`socks5h://`)
//! and `electrum-client`: no authentication, `CONNECT` only, the target
//! given as a domain name, an IPv4 or an IPv6 address. It listens on
//! loopback only and hands every stream to the connect function it is
//! given, which is where Tor comes in. Names are passed through as
//! spelled and never resolved here: an onion name has nowhere to be
//! resolved but inside Tor.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) const VERSION: u8 = 5;
pub(crate) const NO_AUTH: u8 = 0;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
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

/// Listens on loopback, on a port the system picks: nothing to clash
/// with, nothing reachable from outside the machine.
pub(crate) async fn bind() -> io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

/// Accepts connections for as long as the task lives, one session per
/// connection. `connect` opens the upstream side of each `CONNECT`.
pub(crate) async fn serve<C, F, U>(listener: TcpListener, connect: C)
where
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
        // A session's failure is the client's to notice: it got the
        // reply code, and the proxy has nothing to add.
        tokio::spawn(async move {
            let _ = session(stream, connect).await;
        });
    }
}

/// One session: method negotiation, the request, the reply, then bytes
/// both ways until either side closes. Every refusal is answered with
/// the reply code the protocol has for it before the stream is dropped.
pub(crate) async fn session<S, C, F, U>(mut stream: S, connect: C) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnOnce(String, u16) -> F,
    F: Future<Output = io::Result<U>>,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let [version, method_count] = greeting;
    if version != VERSION {
        return Err(invalid("not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; method_count as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHODS]).await?;
        return Err(invalid("the client offers no method this proxy speaks"));
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [version, command, _reserved, address_type] = head;
    if version != VERSION {
        reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
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
                    reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
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
            reply(&mut stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(invalid("unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if command != CMD_CONNECT {
        reply(&mut stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(invalid("only CONNECT is supported"));
    }

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

    /// The proxy under test, on loopback, with the connect function
    /// injected: the same accept loop the embedded client runs.
    async fn proxy<C, F, U>(connect: C) -> SocketAddr
    where
        C: Fn(String, u16) -> F + Clone + Send + 'static,
        F: Future<Output = io::Result<U>> + Send + 'static,
        U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (listener, address) = bind().await.unwrap();
        tokio::spawn(serve(listener, connect));
        address
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

    /// Connects and negotiates "no authentication".
    async fn greet(proxy: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&[VERSION, 1, NO_AUTH]).await.unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, NO_AUTH]);
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

    #[tokio::test]
    async fn a_client_that_insists_on_authentication_is_turned_away() {
        let proxy = echo_proxy(Arc::new(Mutex::new(Vec::new()))).await;
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        // Username/password only.
        stream.write_all(&[VERSION, 1, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, NO_ACCEPTABLE_METHODS]);
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

    #[tokio::test]
    async fn a_session_over_any_stream_is_the_same_protocol() {
        // The session logic on its own, over an in-memory pipe.
        let (mut client, server) = tokio::io::duplex(256);
        let (mut upstream_end, upstream) = tokio::io::duplex(256);
        let session = tokio::spawn(session(server, move |host, port| async move {
            assert_eq!((host.as_str(), port), ("pipe.onion", 50001));
            Ok::<_, io::Error>(upstream)
        }));
        client.write_all(&[VERSION, 1, NO_AUTH]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
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
