//! A direct TCP connection to a host that resolves to several addresses,
//! opened the way RFC 8305 (Happy Eyeballs) opens it.
//!
//! The addresses are tried in the resolver's order, IPv6 and IPv4
//! alternating from the family of the first one. The next attempt starts
//! once the one before has gone [`STAGGER`] without connecting, or at
//! once when it fails; the first that connects is kept and the others
//! are closed. An address that ignores the connection, as one or two
//! behind a public server's name often do, no longer holds the next one
//! back for the whole timeout.
//!
//! Someone else's server is not hit harder for it: [`AT_ONCE`] attempts
//! at most are in flight, a new one starts only while none has
//! connected, and a connection that loses the race is closed the moment
//! it exists. The whole opening gets the one timeout, whatever the
//! number of addresses, and fails as a timeout when it runs out.
//!
//! Only direct connections come here. A host reached through Tor is
//! named to the proxy and never resolved on this machine.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;

/// How long an attempt runs alone before the next address is tried
/// beside it: the delay RFC 8305 recommends.
pub(crate) const STAGGER: Duration = Duration::from_millis(250);

/// The most attempts in flight at once. An address that ignores the
/// connection keeps its place until the timeout, so the opening gets
/// past one silent address fewer than this: four, as many as trying
/// them one after the other, twenty seconds each, got past within the
/// ninety seconds of a call.
pub(crate) const AT_ONCE: usize = 5;

/// The longest an opening is given, whatever the caller asks: a day
/// keeps the deadline within what the clock can count.
const LONGEST: Duration = Duration::from_secs(24 * 3600);

/// The order the addresses are tried in: the resolver's, which already
/// puts the preferred family first, with the two families alternating
/// from the family of its first address.
fn ordered(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let addresses: Vec<SocketAddr> = addresses.into_iter().collect();
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let leading = first.is_ipv6();
    let (lead, other): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == leading);
    let (mut lead, mut other) = (lead.into_iter(), other.into_iter());
    let mut order = Vec::with_capacity(lead.len() + other.len());
    loop {
        match (lead.next(), other.next()) {
            (None, None) => return order,
            (one, two) => order.extend(one.into_iter().chain(two)),
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection timed out")
}

fn nowhere() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any address",
    )
}

/// Connects to whichever of `addresses` connects first, within
/// `timeout` for the whole opening. When none does, the error is a
/// timeout if an attempt was still waiting, the last failure otherwise.
pub(crate) fn connect(
    addresses: Vec<SocketAddr>,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    race(addresses, timeout, |address, left| {
        std::net::TcpStream::connect_timeout(&address, left)
    })
}

/// [`connect`] with the attempt given: `attempt(address, left)` gets the
/// time left before the deadline. Each runs on a thread of its own, as a
/// blocking connection cannot be called off: one that connects after
/// the race is over is dropped where it is handed back, and closed.
fn race<T: Send + 'static>(
    addresses: Vec<SocketAddr>,
    timeout: Duration,
    attempt: impl Fn(SocketAddr, Duration) -> io::Result<T> + Send + Sync + 'static,
) -> io::Result<T> {
    let start = Instant::now();
    let deadline = start + timeout.min(LONGEST);
    let attempt = Arc::new(attempt);
    let (sender, results) = mpsc::channel();
    let mut queue = ordered(addresses).into_iter().peekable();
    let (mut running, mut next, mut last) = (0usize, start, None);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if running < AT_ONCE
            && now >= next
            && let Some(address) = queue.next()
        {
            let (sender, attempt, left) = (sender.clone(), Arc::clone(&attempt), deadline - now);
            let spawned = std::thread::Builder::new()
                .name("gerfaut-dial".to_owned())
                .spawn(move || {
                    let _ = sender.send(attempt(address, left));
                });
            match spawned {
                Ok(_) => {
                    running += 1;
                    next = now + STAGGER;
                }
                // This device's shortage, not the server's silence.
                Err(error) => {
                    last = Some(io::Error::other(format!(
                        "could not start a connection attempt: {error}"
                    )))
                }
            }
            continue;
        }
        let more = queue.peek().is_some();
        if running == 0 && !more {
            break;
        }
        let wake = if running < AT_ONCE && more {
            next.min(deadline)
        } else {
            deadline
        };
        // Past `wake`: time for the next address, or the deadline.
        if let Ok(result) = results.recv_timeout(wake.saturating_duration_since(now)) {
            running -= 1;
            match result {
                Ok(connected) => return Ok(connected),
                Err(error) => {
                    last = Some(error);
                    next = Instant::now();
                }
            }
        }
    }
    Err(if running > 0 || queue.peek().is_some() {
        timed_out()
    } else {
        last.unwrap_or_else(nowhere)
    })
}

/// [`connect`] for the runtime: `host` is resolved by the system, then
/// raced the same way. The attempts still waiting when one connects, or
/// when the future is dropped, are dropped with their sockets.
pub(crate) async fn connect_async(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    // An onion is only ever named to Tor; the caller sends it there.
    if crate::chain::is_onion_host(host) {
        return Err(io::Error::other(format!(
            "{host} is an onion address and needs Tor"
        )));
    }
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    race_async(addresses, timeout, tokio::net::TcpStream::connect).await
}

async fn race_async<T, F, A>(
    addresses: Vec<SocketAddr>,
    timeout: Duration,
    attempt: A,
) -> io::Result<T>
where
    A: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    use tokio::time::{Instant, sleep_until};
    let start = Instant::now();
    let deadline = start + timeout.min(LONGEST);
    let mut queue = ordered(addresses).into_iter().peekable();
    let mut running = FuturesUnordered::new();
    let (mut next, mut last) = (start, None);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if running.len() < AT_ONCE
            && now >= next
            && let Some(address) = queue.next()
        {
            running.push(attempt(address));
            next = now + STAGGER;
            continue;
        }
        let more = running.len() < AT_ONCE && queue.peek().is_some();
        if running.is_empty() && !more {
            break;
        }
        tokio::select! {
            Some(result) = running.next(), if !running.is_empty() => match result {
                Ok(connected) => return Ok(connected),
                Err(error) => {
                    last = Some(error);
                    next = Instant::now();
                }
            },
            () = sleep_until(next), if more => {}
            () = sleep_until(deadline) => {}
        }
    }
    Err(if running.is_empty() && queue.peek().is_none() {
        last.unwrap_or_else(nowhere)
    } else {
        timed_out()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], 50002))
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 50002))
    }

    /// What an address does with a connection.
    #[derive(Debug, Clone, Copy)]
    enum Peer {
        /// Ignores it, until the caller gives up.
        Silent,
        /// Turns it down at once.
        Refuses,
        /// Takes it after this long.
        Answers(Duration),
    }

    /// What the attempts did: when each started, and how many were in
    /// flight at most.
    #[derive(Default)]
    struct Log {
        started: Mutex<Vec<(SocketAddr, Duration)>>,
        in_flight: AtomicUsize,
        most: AtomicUsize,
        dropped: AtomicUsize,
    }

    /// One attempt in flight, until dropped.
    struct Flight(Arc<Log>);

    impl Drop for Flight {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, SeqCst);
        }
    }

    impl Log {
        fn start(self: &Arc<Self>, address: SocketAddr, at: Duration) -> Flight {
            self.started.lock().unwrap().push((address, at));
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.most.fetch_max(now, SeqCst);
            Flight(Arc::clone(self))
        }

        fn order(&self) -> Vec<SocketAddr> {
            self.started
                .lock()
                .unwrap()
                .iter()
                .map(|(a, _)| *a)
                .collect()
        }
    }

    /// A connection that counts itself closed.
    struct Connection(SocketAddr, Arc<Log>);

    impl Drop for Connection {
        fn drop(&mut self) {
            self.1.dropped.fetch_add(1, SeqCst);
        }
    }

    fn peer(peers: &[(SocketAddr, Peer)], address: SocketAddr) -> Peer {
        peers.iter().find(|(a, _)| *a == address).unwrap().1
    }

    /// The blocking race over simulated addresses: what it connected
    /// to, how long it took, and what the attempts did.
    fn dial(
        peers: &[(SocketAddr, Peer)],
        timeout: Duration,
    ) -> (io::Result<SocketAddr>, Duration, Arc<Log>) {
        let log = Arc::new(Log::default());
        let start = Instant::now();
        let (table, attempts) = (peers.to_vec(), Arc::clone(&log));
        let result = race(
            peers.iter().map(|(a, _)| *a).collect(),
            timeout,
            move |address, left| {
                let _flight = attempts.start(address, start.elapsed());
                match peer(&table, address) {
                    Peer::Silent => {
                        std::thread::sleep(left);
                        Err(timed_out())
                    }
                    Peer::Refuses => Err(io::ErrorKind::ConnectionRefused.into()),
                    Peer::Answers(after) => {
                        std::thread::sleep(after);
                        Ok(Connection(address, Arc::clone(&attempts)))
                    }
                }
            },
        );
        let elapsed = start.elapsed();
        (result.map(|c| c.0), elapsed, log)
    }

    /// The same race on the runtime, its clock paused: the times are
    /// exact.
    async fn dial_async(
        peers: &[(SocketAddr, Peer)],
        timeout: Duration,
    ) -> (io::Result<SocketAddr>, Duration, Arc<Log>) {
        let log = Arc::new(Log::default());
        let start = tokio::time::Instant::now();
        let addresses = peers.iter().map(|(a, _)| *a).collect();
        let result = race_async(addresses, timeout, |address| {
            let flight = log.start(address, start.elapsed());
            let peer = peer(peers, address);
            async move {
                let _flight = flight;
                match peer {
                    Peer::Silent => {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Err(timed_out())
                    }
                    Peer::Refuses => Err(io::ErrorKind::ConnectionRefused.into()),
                    Peer::Answers(after) => {
                        tokio::time::sleep(after).await;
                        Ok(address)
                    }
                }
            }
        })
        .await;
        (result, start.elapsed(), log)
    }

    const ANSWER: Peer = Peer::Answers(Duration::from_millis(10));

    #[test]
    fn the_families_alternate_from_the_first_address() {
        assert_eq!(
            ordered([v6(1), v6(2), v6(3), v4(1), v4(2)]),
            [v6(1), v4(1), v6(2), v4(2), v6(3)]
        );
        assert_eq!(ordered([v4(1), v4(2), v6(1)]), [v4(1), v6(1), v4(2)]);
        // One family keeps the resolver's order.
        assert_eq!(ordered([v4(3), v4(1), v4(2)]), [v4(3), v4(1), v4(2)]);
        assert!(ordered([]).is_empty());
    }

    /// The defect this module was written for: a silent address in
    /// front of one that answers cost the whole timeout.
    #[test]
    fn a_silent_address_costs_the_stagger_not_the_timeout() {
        let peers = [(v4(1), Peer::Silent), (v4(2), ANSWER)];
        let (connected, took, _) = dial(&peers, Duration::from_secs(20));
        assert_eq!(connected.unwrap(), v4(2));
        assert!(took >= STAGGER && took < Duration::from_secs(2), "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_address_costs_the_stagger_not_the_timeout_on_the_runtime() {
        let peers = [(v4(1), Peer::Silent), (v4(2), ANSWER)];
        let (connected, took, log) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap(), v4(2));
        assert_eq!(took, STAGGER + Duration::from_millis(10));
        // The silent attempt is called off with the race.
        assert_eq!(log.in_flight.load(SeqCst), 0);
    }

    /// Nothing answers: a timeout, after the one timeout of the whole
    /// opening, however many addresses there are.
    #[test]
    fn silent_addresses_time_out_once() {
        let peers = [
            (v4(1), Peer::Silent),
            (v4(2), Peer::Silent),
            (v6(1), Peer::Silent),
        ];
        let timeout = Duration::from_millis(800);
        let (connected, took, log) = dial(&peers, timeout);
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(took >= timeout && took < timeout * 2, "{took:?}");
        assert_eq!(log.order().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_addresses_time_out_once_on_the_runtime() {
        let peers = [(v4(1), Peer::Silent), (v4(2), Peer::Silent)];
        let (connected, took, _) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(took, Duration::from_secs(20));
    }

    /// A refusal starts the next attempt at once, without the stagger.
    #[test]
    fn a_refusal_moves_on_at_once() {
        let peers = [(v4(1), Peer::Refuses), (v4(2), ANSWER)];
        let (connected, _, log) = dial(&peers, Duration::from_secs(20));
        assert_eq!(connected.unwrap(), v4(2));
        let second = log.started.lock().unwrap()[1].1;
        assert!(second < STAGGER, "{second:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_moves_on_at_once_on_the_runtime() {
        let peers = [(v4(1), Peer::Refuses), (v4(2), ANSWER)];
        let (connected, took, _) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap(), v4(2));
        assert_eq!(took, Duration::from_millis(10));
    }

    /// Every address refusing is the refusal, told by its kind.
    #[test]
    fn refusals_everywhere_are_a_refusal() {
        let peers = [(v4(1), Peer::Refuses), (v6(1), Peer::Refuses)];
        let (connected, took, _) = dial(&peers, Duration::from_secs(20));
        assert_eq!(
            connected.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn refusals_everywhere_are_a_refusal_on_the_runtime() {
        let peers = [(v4(1), Peer::Refuses), (v6(1), Peer::Refuses)];
        let (connected, _, _) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(
            connected.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
    }

    #[test]
    fn an_ipv6_only_host_gets_the_same_race() {
        let peers = [(v6(1), Peer::Silent), (v6(2), ANSWER)];
        let (connected, took, _) = dial(&peers, Duration::from_secs(20));
        assert_eq!(connected.unwrap(), v6(2));
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    /// The attempts start one stagger apart, the families alternating.
    #[tokio::test(start_paused = true)]
    async fn attempts_start_a_stagger_apart_in_alternating_families() {
        let peers = [
            (v6(1), Peer::Silent),
            (v6(2), Peer::Silent),
            (v4(1), Peer::Silent),
            (v4(2), ANSWER),
        ];
        let (connected, _, log) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap(), v4(2));
        let started = log.started.lock().unwrap().clone();
        assert_eq!(
            started,
            [
                (v6(1), Duration::ZERO),
                (v4(1), STAGGER),
                (v6(2), STAGGER * 2),
                (v4(2), STAGGER * 3),
            ]
        );
    }

    /// However many addresses ignore it, no more than [`AT_ONCE`]
    /// connections are tried at the same time, and none is started
    /// past the deadline.
    #[test]
    fn attempts_in_flight_are_bounded() {
        let peers: Vec<_> = (1..=9).map(|n| (v4(n), Peer::Silent)).collect();
        let (connected, _, log) = dial(&peers, Duration::from_millis(2500));
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(log.most.load(SeqCst), AT_ONCE);
        assert_eq!(log.order(), &[v4(1), v4(2), v4(3), v4(4), v4(5)]);
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_in_flight_are_bounded_on_the_runtime() {
        let peers: Vec<_> = (1..=9).map(|n| (v4(n), Peer::Silent)).collect();
        let (connected, _, log) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(log.most.load(SeqCst), AT_ONCE);
        assert_eq!(log.order().len(), AT_ONCE);
    }

    /// A slot freed by a failure goes to the next address.
    #[tokio::test(start_paused = true)]
    async fn a_failure_frees_its_place() {
        let mut peers: Vec<_> = (1..=4).map(|n| (v4(n), Peer::Silent)).collect();
        peers.push((v4(5), Peer::Refuses));
        peers.push((v4(6), ANSWER));
        let (connected, _, log) = dial_async(&peers, Duration::from_secs(20)).await;
        assert_eq!(connected.unwrap(), v4(6));
        assert_eq!(log.most.load(SeqCst), AT_ONCE);
    }

    /// A blocking attempt that connects after another won is closed as
    /// soon as it is handed back.
    #[test]
    fn a_connection_that_loses_is_closed() {
        let log = Arc::new(Log::default());
        let attempts = Arc::clone(&log);
        let slow = Duration::from_millis(600);
        let won = race(
            vec![v4(1), v4(2)],
            Duration::from_secs(5),
            move |address, _| {
                std::thread::sleep(if address == v4(1) {
                    slow
                } else {
                    Duration::ZERO
                });
                Ok(Connection(address, Arc::clone(&attempts)))
            },
        )
        .unwrap();
        assert_eq!(won.0, v4(2));
        std::thread::sleep(slow + Duration::from_millis(300));
        assert_eq!(log.dropped.load(SeqCst), 1, "the loser is closed");
        drop(won);
    }

    #[test]
    fn no_address_is_no_connection() {
        let (connected, _, _) = dial(&[], Duration::from_secs(1));
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    /// No time at all is a timeout, not an address missing; no limit
    /// at all is a long one, not none.
    #[test]
    fn the_timeout_is_read_whatever_its_size() {
        let (connected, _, log) = dial(&[(v4(1), ANSWER)], Duration::ZERO);
        assert_eq!(connected.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(log.order().is_empty());
        let (connected, _, _) = dial(&[(v4(1), ANSWER)], Duration::MAX);
        assert_eq!(connected.unwrap(), v4(1));
    }

    #[tokio::test]
    async fn an_onion_never_reaches_the_resolver() {
        let error = connect_async("abcdef.onion", 80, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("needs Tor"), "{error}");
    }

    /// Real sockets. A listening socket whose queue of one is full
    /// drops every new connection without a word on Linux, as the
    /// silent addresses of a public server do.
    #[cfg(target_os = "linux")]
    mod sockets {
        use super::*;
        use crate::chain::tls::{ConnectError, tcp_connect};

        /// A silent address, and the connections that fill its queue:
        /// a backlog of one takes two, and drops every SYN after them.
        fn silent() -> Silent {
            silent_at("127.0.0.1:0".parse().unwrap())
        }

        type Silent = (
            tokio::net::TcpListener,
            Vec<std::net::TcpStream>,
            SocketAddr,
        );

        fn silent_at(address: SocketAddr) -> Silent {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(address).unwrap();
            let listener = socket.listen(1).unwrap();
            let address = listener.local_addr().unwrap();
            let fillers = (0..2)
                .map(|_| {
                    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap()
                })
                .collect();
            (listener, fillers, address)
        }

        #[tokio::test]
        async fn a_silent_socket_does_not_hold_back_one_that_answers() {
            let (_silent, _fillers, quiet) = silent();
            let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let answers = open.local_addr().unwrap();
            let start = Instant::now();
            let socket = tokio::task::spawn_blocking(move || {
                connect(vec![quiet, answers], Duration::from_secs(20))
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(socket.peer_addr().unwrap(), answers);
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "{:?}",
                start.elapsed()
            );

            let start = Instant::now();
            let addresses = vec![quiet, answers];
            let socket = race_async(
                addresses,
                Duration::from_secs(20),
                tokio::net::TcpStream::connect,
            )
            .await
            .unwrap();
            assert_eq!(socket.peer_addr().unwrap(), answers);
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "{:?}",
                start.elapsed()
            );
        }

        /// A host that never answers is still a server out of reach, as
        /// the rest of the core reads it, after the timeout it was given.
        #[tokio::test]
        async fn a_silent_host_is_unreachable_after_its_timeout() {
            let (_silent, _fillers, quiet) = silent();
            let timeout = Duration::from_millis(700);
            let start = Instant::now();
            let error = tokio::task::spawn_blocking(move || {
                tcp_connect("127.0.0.1", quiet.port(), timeout)
            })
            .await
            .unwrap()
            .unwrap_err();
            assert!(matches!(error, ConnectError::Unreachable(_)), "{error}");
            assert!(crate::chain::Fault::from(error).is_outage());
            assert!(start.elapsed() >= timeout, "{:?}", start.elapsed());

            let fault = crate::chain::net::open(
                "127.0.0.1",
                quiet.port(),
                crate::chain::net::Security::Plain,
                None,
                timeout,
            )
            .await
            .err()
            .unwrap();
            assert!(fault.is_outage(), "{fault:?}");
        }

        /// A request of the price or update checks gets past an address
        /// that ignores it, at the cost of its share of the connect
        /// timeout, where it used to wait out the request's whole time
        /// and fail.
        #[tokio::test]
        async fn an_http_request_gets_past_a_silent_address() {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // One port on two addresses: the client takes the port from
            // the URL, whatever the addresses carry.
            let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let answers = live.local_addr().unwrap();
            let (_silent, _fillers, quiet) =
                silent_at(SocketAddr::from(([127, 0, 0, 2], answers.port())));
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = live.accept().await {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                }
            });
            let builder = crate::chain::http_client().timeout(Duration::from_secs(15));
            let client = crate::chain::route(builder, None)
                .unwrap()
                .resolve_to_addrs("gerfaut.test", &[quiet, answers])
                .build()
                .unwrap();
            let start = Instant::now();
            let url = format!("http://gerfaut.test:{}/", answers.port());
            let body = client.get(url).send().await.unwrap().text().await.unwrap();
            assert_eq!(body, "ok");
            let took = start.elapsed();
            assert!(took < crate::chain::CONNECT_TIMEOUT, "{took:?}");
        }
    }
}
