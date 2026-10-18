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

use std::future::Future;
use std::io;
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
}
