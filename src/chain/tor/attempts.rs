//! Two attempts at a connection to an onion service, the second beside
//! the first.
//!
//! arti gives a rendezvous point that never answers longer than the
//! minute a client of the core waits for its connection (arti issue
//! #2482), and a stream to a service, with the isolation of a stream
//! already on its way there, joins that attempt instead of starting one:
//! asking again through the same client waits on the same rendezvous
//! point. So once [`TRY`] has passed, the embedded client starts a
//! second attempt through a client of an isolation of its own, which
//! arti starts from nothing, with a rendezvous point of its own. The
//! first goes on meanwhile, and whichever connects first is used.
//!
//! [`Routes`] keeps, for each onion service, the client its streams go
//! through: the one that last connected to it, so that later streams go
//! where the service answered rather than back to a rendezvous that
//! hangs.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

/// How long an attempt runs alone, and how long both then get: the
/// whole is the minute the clients of the core give a connection to an
/// onion host.
pub(super) const TRY: Duration = Duration::from_secs(30);

/// Connects with `first`, given `try_for`; past it, with `second()` as
/// well, and both get `try_for` more. The stream of whichever connects
/// first. When one fails, the other is waited for; when neither
/// connects, the error is the last failure, or a timeout when both were
/// silent. A failure of `first` within
/// `try_for` is returned as it is: arti has already tried the
/// rendezvous points it would try, and the service is down or gone.
pub(super) async fn two<S, F, G>(
    first: F,
    second: impl FnOnce() -> G,
    try_for: Duration,
) -> io::Result<S>
where
    F: Future<Output = io::Result<S>>,
    G: Future<Output = io::Result<S>>,
{
    let mut first = std::pin::pin!(first);
    if let Ok(connected) = tokio::time::timeout(try_for, first.as_mut()).await {
        return connected;
    }
    let mut second = std::pin::pin!(second());
    let mut failed = None;
    let both = async {
        let (mut first_done, mut second_done) = (false, false);
        while !(first_done && second_done) {
            let outcome = tokio::select! {
                connected = first.as_mut(), if !first_done => {
                    first_done = true;
                    connected
                }
                connected = second.as_mut(), if !second_done => {
                    second_done = true;
                    connected
                }
            };
            match outcome {
                Ok(stream) => return Some(stream),
                Err(error) => failed = Some(error),
            }
        }
        None
    };
    let connected = tokio::time::timeout(try_for, both).await;
    match connected {
        Ok(Some(stream)) => Ok(stream),
        // A failure is worth more than the silence of the other attempt.
        _ => Err(failed.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the onion service did not answer within {} s",
                    (try_for * 2).as_secs()
                ),
            )
        })),
    }
}

/// A Tor client as [`Routes`] handles it: one of a new isolation can be
/// made from it, and two handles tell whether they are the same client.
pub(super) trait Isolate: Clone {
    fn isolated(&self) -> Self;
    fn same(&self, other: &Self) -> bool;
}

/// The client each onion service is reached through, by host. A service
/// starts on the client the routes were made with. A second attempt
/// that connects puts its client in that place for that service alone;
/// so does a new isolation, when neither attempt connected. The streams
/// to one service that wait on the same client share one second
/// client, so that they build one new way to the service rather than
/// one each. One entry per onion host the process reached: a few.
pub(super) struct Routes<C> {
    base: C,
    hosts: Mutex<HashMap<String, Route<C>>>,
}

struct Route<C> {
    current: C,
    next: Option<C>,
    /// `current` was put in place because nothing connected, and gives
    /// way to the first client that does.
    untried: bool,
}

impl<C: Clone> Route<C> {
    fn on(base: &C) -> Self {
        Route {
            current: base.clone(),
            next: None,
            untried: false,
        }
    }
}

impl<C: Isolate> Routes<C> {
    pub(super) fn new(base: C) -> Self {
        Routes {
            base,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    fn hosts(&self) -> std::sync::MutexGuard<'_, HashMap<String, Route<C>>> {
        self.hosts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The client a stream to `host` goes through first.
    fn first(&self, host: &str) -> C {
        self.hosts()
            .get(host)
            .map_or_else(|| self.base.clone(), |route| route.current.clone())
    }

    /// The client of a second attempt beside one made through `first`:
    /// the one another stream put in its place meanwhile, if one did,
    /// else the one the second attempts beside `first` share.
    fn second(&self, host: &str, first: &C) -> C {
        let mut hosts = self.hosts();
        let route = hosts
            .entry(host.to_owned())
            .or_insert_with(|| Route::on(&self.base));
        if !route.current.same(first) {
            return route.current.clone();
        }
        route.next.get_or_insert_with(|| first.isolated()).clone()
    }

    /// After a second attempt beside `first`, unless another stream
    /// moved the service on already: the client that connected, or one
    /// of a new isolation when none did, in the place of `first`. The
    /// next stream then never waits again on what hung. A client that
    /// connected also replaces one put in place because nothing had: a
    /// stream that gave up a moment before another connected through
    /// the same second client does not send the service elsewhere.
    fn settle(&self, host: &str, first: &C, used: Option<&C>) {
        let mut hosts = self.hosts();
        let route = hosts
            .entry(host.to_owned())
            .or_insert_with(|| Route::on(&self.base));
        if route.current.same(first) || (route.untried && used.is_some()) {
            route.current = used.map_or_else(|| first.isolated(), C::clone);
            route.untried = used.is_none();
            route.next = None;
        }
    }

    /// A stream to the onion service `host`, in two attempts
    /// ([`two`]) opened by `open`, each through its client.
    pub(super) async fn connect<S, F, O>(&self, host: String, port: u16, open: O) -> io::Result<S>
    where
        O: Fn(C, String, u16) -> F,
        F: Future<Output = io::Result<S>>,
    {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let first = self.first(&key);
        let seconded = std::sync::atomic::AtomicBool::new(false);
        let through = |client: C, host: String| {
            let opened = open(client.clone(), host, port);
            async move { opened.await.map(|stream| (stream, client)) }
        };
        let connected = two(
            through(first.clone(), host.clone()),
            || {
                seconded.store(true, std::sync::atomic::Ordering::Relaxed);
                through(self.second(&key, &first), host)
            },
            TRY,
        )
        .await;
        if seconded.load(std::sync::atomic::Ordering::Relaxed) {
            let used = connected.as_ref().ok().map(|(_, used)| used);
            self.settle(&key, &first, used);
        }
        connected.map(|(stream, _)| stream)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    const TRY_FOR: Duration = Duration::from_secs(30);

    /// An attempt that connects, or fails, after `after`.
    async fn attempt(
        after: Duration,
        outcome: Result<&'static str, &'static str>,
    ) -> io::Result<&'static str> {
        tokio::time::sleep(after).await;
        outcome.map_err(io::Error::other)
    }

    fn never() -> impl Future<Output = io::Result<&'static str>> {
        std::future::pending()
    }

    /// The second attempt, which says when it was started.
    fn second(
        started: &Arc<AtomicBool>,
        after: Duration,
        outcome: Result<&'static str, &'static str>,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn Future<Output = io::Result<&'static str>>>> {
        let started = started.clone();
        move || {
            started.store(true, Ordering::SeqCst);
            Box::pin(attempt(after, outcome))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_attempt_in_time_is_the_only_one() {
        let started = Arc::new(AtomicBool::new(false));
        let begun = tokio::time::Instant::now();
        let stream = two(
            attempt(Duration::from_secs(29), Ok("first")),
            second(&started, Duration::ZERO, Ok("second")),
            TRY_FOR,
        )
        .await
        .unwrap();
        assert_eq!(stream, "first");
        assert_eq!(begun.elapsed(), Duration::from_secs(29));
        assert!(!started.load(Ordering::SeqCst));
    }

    /// A service that turns the first attempt down is not asked again.
    #[tokio::test(start_paused = true)]
    async fn a_first_attempt_that_fails_in_time_is_the_only_one() {
        let started = Arc::new(AtomicBool::new(false));
        let error = two(
            attempt(Duration::from_secs(5), Err("not found")),
            second(&started, Duration::ZERO, Ok("second")),
            TRY_FOR,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "not found");
        assert!(!started.load(Ordering::SeqCst));
    }

    /// The case of arti issue #2482: a rendezvous point that never
    /// answers, and a second one that does.
    #[tokio::test(start_paused = true)]
    async fn a_silent_first_attempt_gets_a_second_one_after_thirty_seconds() {
        let started = Arc::new(AtomicBool::new(false));
        let begun = tokio::time::Instant::now();
        let stream = two(
            never(),
            second(&started, Duration::from_secs(8), Ok("second")),
            TRY_FOR,
        )
        .await
        .unwrap();
        assert_eq!(stream, "second");
        assert_eq!(begun.elapsed(), Duration::from_secs(38));
    }

    /// The first attempt is still heard once the second has started.
    #[tokio::test(start_paused = true)]
    async fn a_late_first_attempt_still_counts() {
        let started = Arc::new(AtomicBool::new(false));
        let begun = tokio::time::Instant::now();
        let stream = two(
            attempt(Duration::from_secs(35), Ok("first")),
            second(&started, Duration::from_secs(20), Ok("second")),
            TRY_FOR,
        )
        .await
        .unwrap();
        assert_eq!(stream, "first");
        assert_eq!(begun.elapsed(), Duration::from_secs(35));
        assert!(started.load(Ordering::SeqCst));
    }

    /// One attempt failing leaves the other to finish, and both failing
    /// gives the error that came last.
    #[tokio::test(start_paused = true)]
    async fn a_failed_attempt_waits_for_the_other() {
        let started = Arc::new(AtomicBool::new(false));
        let stream = two(
            attempt(Duration::from_secs(40), Err("first failed")),
            second(&started, Duration::from_secs(20), Ok("second")),
            TRY_FOR,
        )
        .await
        .unwrap();
        assert_eq!(stream, "second");

        let stream = two(
            attempt(Duration::from_secs(50), Ok("first")),
            second(&started, Duration::from_secs(1), Err("second failed")),
            TRY_FOR,
        )
        .await
        .unwrap();
        assert_eq!(stream, "first");

        let error = two(
            attempt(Duration::from_secs(40), Err("first failed")),
            second(&started, Duration::from_secs(15), Err("second failed")),
            TRY_FOR,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "second failed");
    }

    /// A failure is told, rather than the silence of the other attempt.
    #[tokio::test(start_paused = true)]
    async fn a_failure_beside_a_silent_attempt_is_told() {
        let started = Arc::new(AtomicBool::new(false));
        let begun = tokio::time::Instant::now();
        let error = two(
            attempt(Duration::from_secs(40), Err("descriptor not found")),
            second(&started, Duration::from_secs(300), Ok("late")),
            TRY_FOR,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "descriptor not found");
        assert_eq!(begun.elapsed(), Duration::from_secs(60));
    }

    /// Neither attempt in time: the connection fails at the minute, when
    /// the clients give up anyway.
    #[tokio::test(start_paused = true)]
    async fn two_silent_attempts_fail_at_the_minute() {
        let started = Arc::new(AtomicBool::new(false));
        let begun = tokio::time::Instant::now();
        let error = two(
            never(),
            second(&started, Duration::from_secs(31), Ok("late")),
            TRY_FOR,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(begun.elapsed(), Duration::from_secs(60));
        assert!(started.load(Ordering::SeqCst));
    }

    /// A client of the tests: its number, and the count of clients made.
    #[derive(Clone)]
    struct Fake {
        id: usize,
        made: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Isolate for Fake {
        fn isolated(&self) -> Self {
            Fake {
                id: self.made.fetch_add(1, Ordering::SeqCst) + 1,
                made: self.made.clone(),
            }
        }

        fn same(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    fn routes() -> Routes<Fake> {
        Routes::new(Fake {
            id: 0,
            made: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// A stream to `host`: the number of the client it went through.
    async fn stream(
        routes: &Routes<Fake>,
        host: &str,
        behave: impl Fn(usize, &str) -> Option<(Duration, bool)>,
    ) -> io::Result<usize> {
        routes
            .connect(host.to_owned(), 80, |client: Fake, host, _| {
                let outcome = behave(client.id, &host);
                async move {
                    match outcome {
                        Some((after, true)) => {
                            tokio::time::sleep(after).await;
                            Ok(client.id)
                        }
                        Some((after, false)) => {
                            tokio::time::sleep(after).await;
                            Err(io::Error::other(format!("refused by {}", client.id)))
                        }
                        None => std::future::pending().await,
                    }
                }
            })
            .await
    }

    /// The bootstrapped client hangs on the service, any other answers.
    fn first_hangs(id: usize, _: &str) -> Option<(Duration, bool)> {
        (id != 0).then_some((Duration::from_secs(5), true))
    }

    /// Streams that wait together on a hung service share one second
    /// client, and the streams after them go straight through it; the
    /// other services stay where they were.
    #[tokio::test(start_paused = true)]
    async fn streams_that_hang_together_share_one_second_route() {
        let routes = routes();
        let host = "x.onion";
        let (a, b, c, d) = tokio::join!(
            stream(&routes, host, first_hangs),
            stream(&routes, host, first_hangs),
            stream(&routes, host, first_hangs),
            stream(&routes, host, first_hangs),
        );
        assert_eq!([a.unwrap(), b.unwrap(), c.unwrap(), d.unwrap()], [1; 4]);
        assert_eq!(routes.base.made.load(Ordering::SeqCst), 1);

        let begun = tokio::time::Instant::now();
        assert_eq!(stream(&routes, "X.ONION.", first_hangs).await.unwrap(), 1);
        assert_eq!(begun.elapsed(), Duration::from_secs(5));

        let answers = |_: usize, _: &str| Some((Duration::from_secs(1), true));
        assert_eq!(stream(&routes, "y.onion", answers).await.unwrap(), 0);
        assert_eq!(routes.base.made.load(Ordering::SeqCst), 1);
    }

    /// Neither attempt connected: the next stream starts on a client of
    /// a new isolation, rather than wait again on what hung.
    #[tokio::test(start_paused = true)]
    async fn a_service_silent_twice_is_tried_next_on_a_new_route() {
        let routes = routes();
        let silent = |_: usize, _: &str| None;
        let error = stream(&routes, "x.onion", silent).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let answers_third =
            |id: usize, _: &str| (id == 2).then_some((Duration::from_secs(1), true));
        let begun = tokio::time::Instant::now();
        assert_eq!(stream(&routes, "x.onion", answers_third).await.unwrap(), 2);
        assert_eq!(begun.elapsed(), Duration::from_secs(1));
    }

    /// A service that refuses at once leaves its route as it was, and
    /// no client is made for it.
    #[tokio::test(start_paused = true)]
    async fn a_quick_refusal_moves_nothing() {
        let routes = routes();
        let refuses = |_: usize, _: &str| Some((Duration::from_secs(2), false));
        let error = stream(&routes, "x.onion", refuses).await.unwrap_err();
        assert_eq!(error.to_string(), "refused by 0");
        assert_eq!(routes.base.made.load(Ordering::SeqCst), 0);
        assert_eq!(routes.first("x.onion").id, 0);
    }

    /// The first attempt winning after the second started keeps the
    /// service on it, and the next hang gets a second client of its own
    /// rather than the one left behind.
    #[tokio::test(start_paused = true)]
    async fn a_late_first_keeps_its_route() {
        let routes = routes();
        let late = |id: usize, _: &str| match id {
            0 => Some((Duration::from_secs(35), true)),
            _ => None,
        };
        assert_eq!(stream(&routes, "x.onion", late).await.unwrap(), 0);
        assert_eq!(routes.first("x.onion").id, 0);
        assert_eq!(stream(&routes, "x.onion", first_hangs).await.unwrap(), 2);
    }

    /// A stream that gives up just before the shared second client
    /// connects leaves the service on that client, once another stream
    /// connected through it.
    #[tokio::test(start_paused = true)]
    async fn a_success_right_after_a_give_up_still_counts() {
        let routes = routes();
        let begun = tokio::time::Instant::now();
        // The second client connects at 62 s, whoever asks it.
        let at_62 = |id: usize, _: &str| {
            (id == 1).then(|| {
                let at = begun + Duration::from_secs(62);
                (
                    at.saturating_duration_since(tokio::time::Instant::now()),
                    true,
                )
            })
        };
        let late = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            stream(&routes, "x.onion", at_62).await
        };
        let (a, b) = tokio::join!(stream(&routes, "x.onion", at_62), late);
        assert_eq!(a.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(b.unwrap(), 1);
        assert_eq!(routes.first("x.onion").id, 1);
    }
}
