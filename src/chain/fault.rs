//! What a request to one server failed with: its words, for the logs
//! and the screens, and what kind of failure they tell of, set where the
//! core writes them. A relegation and the code of a sync that failed are
//! decided on the kind, never on the words: those of the core stay what
//! they were, and those of a server, quoted after "refused the request",
//! choose nothing.
//!
//! Where a failure comes from `electrum_client` or `reqwest`, its kind is
//! read from the error's variant and what it wraps (an I/O error's kind,
//! a timeout, a connection that failed), not from its text. A failure the
//! core writes as words of its own, or that reaches it as a plain string,
//! is [`FaultKind::Other`]: one that is not marked counts for nothing,
//! the safe side of both decisions.

/// What a failed request says of the server that failed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultKind {
    /// The server is down, or asks for less, whatever was asked: the
    /// connection could not be opened or was cut, it or one request timed
    /// out, its certificate would not do, the name of its host does not
    /// resolve, it answered HTTP 429 or a 5xx, or it was out of memory
    /// for its answers ([`crate::chain::electrum::out_of_budget`]). What
    /// relegates a server when a later one answers. The deadline of a
    /// whole sync is not one, nor is what this device says: a Tor that is
    /// starting or missing, or the words of its system, a firewall for
    /// instance ("connection failed").
    Outage,
    /// The server sent a proof that does not hold: a confirmation its
    /// header or its branch does not back
    /// ([`crate::chain::proof::FALSE_PROOF`]), a coin its own
    /// transaction does not pay ([`crate::chain::proof::COIN_NOT_PAID`]),
    /// or a chain that takes back a confirmation the wallet proved
    /// without proving its own blocks
    /// ([`crate::chain::proof::UNPROVEN_REORGANISATION`]).
    /// What makes a sync fail under [`crate::error::ErrorCode::FalseProof`].
    FalseProof,
    /// Anything else: a refusal of what was asked, in the server's words
    /// or the core's, an answer that is not the protocol, the deadline of
    /// a sync.
    Other,
}

/// A failed request: its words and their kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fault {
    kind: FaultKind,
    detail: String,
}

impl Fault {
    /// A failure of the server itself: see [`FaultKind::Outage`].
    pub(crate) fn outage(detail: impl Into<String>) -> Fault {
        Fault {
            kind: FaultKind::Outage,
            detail: detail.into(),
        }
    }

    /// Any other failure: see [`FaultKind::Other`].
    pub(crate) fn other(detail: impl Into<String>) -> Fault {
        Fault {
            kind: FaultKind::Other,
            detail: detail.into(),
        }
    }

    /// A proof of a confirmation that does not hold.
    pub(crate) fn false_proof() -> Fault {
        Fault {
            kind: FaultKind::FalseProof,
            detail: crate::chain::proof::FALSE_PROOF.to_owned(),
        }
    }

    /// A coin its own transaction does not pay.
    pub(crate) fn coin_not_paid() -> Fault {
        Fault {
            kind: FaultKind::FalseProof,
            detail: crate::chain::proof::COIN_NOT_PAID.to_owned(),
        }
    }

    /// A chain that takes back a proven confirmation without proof.
    pub(crate) fn unproven_reorganisation() -> Fault {
        Fault {
            kind: FaultKind::FalseProof,
            detail: crate::chain::proof::UNPROVEN_REORGANISATION.to_owned(),
        }
    }

    pub(crate) fn kind(&self) -> FaultKind {
        self.kind
    }

    /// Whether the server is down: see [`FaultKind::Outage`].
    pub(crate) fn is_outage(&self) -> bool {
        self.kind == FaultKind::Outage
    }

    /// The words, as the logs and the screens read them.
    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Fault {}

/// What an I/O error says of the server by its kind alone, the one list
/// every socket of the core reads: the Electrum client of a sync, the
/// sockets of the live watcher, the connection a TLS handshake goes
/// over, and the HTTP client of an Esplora sync for a connection cut.
/// Each is an outage; any other kind says nothing of the server by
/// itself (see [`Fault::of_io`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoOutage {
    /// The connection would not open: refused, or no route to the host
    /// or its network.
    Unreachable,
    /// A time limit passed: a socket read timeout is `WouldBlock` on
    /// Unix and `TimedOut` on Windows.
    TimedOut,
    /// The connection was cut, by the server or on the way.
    Closed,
}

impl IoOutage {
    /// The class of an I/O error's kind, `None` when it is not one.
    pub(crate) fn of(kind: std::io::ErrorKind) -> Option<IoOutage> {
        use std::io::ErrorKind;
        match kind {
            ErrorKind::ConnectionRefused
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown => Some(IoOutage::Unreachable),
            ErrorKind::TimedOut | ErrorKind::WouldBlock => Some(IoOutage::TimedOut),
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
            | ErrorKind::NotConnected => Some(IoOutage::Closed),
            _ => None,
        }
    }
}

impl Fault {
    /// An I/O failure of a connection to a server, of the kind its error
    /// has ([`IoOutage`]), with `timeout` the time limit it was held to,
    /// when one was and the error can only have come from it.
    /// A failure the core raised inside the I/O comes out as the fault
    /// it is; a name that does not resolve, which has no kind of its own,
    /// is told by the words of this device's system, never a server's;
    /// `InvalidData` keeps its own words, those of a reader that cut off
    /// what the server sent.
    pub(crate) fn of_io(error: &std::io::Error, timeout: Option<std::time::Duration>) -> Fault {
        if let Some(fault) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Fault>())
        {
            return fault.clone();
        }
        match IoOutage::of(error.kind()) {
            Some(IoOutage::Unreachable) => Fault::outage("could not connect"),
            Some(IoOutage::TimedOut) => Fault::outage(match timeout {
                Some(timeout) => format!("timed out after {} s", timeout.as_secs()),
                None => "timed out".to_owned(),
            }),
            Some(IoOutage::Closed) => Fault::outage("the connection was closed"),
            None if error.kind() == std::io::ErrorKind::InvalidData => {
                Fault::other(error.to_string())
            }
            None => {
                // Each platform words it differently.
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
                    Fault::outage("host not found")
                } else {
                    Fault::other(format!("connection failed: {text}"))
                }
            }
        }
    }
}

/// Words of the core's own that tell of nothing more than what they say.
impl From<String> for Fault {
    fn from(detail: String) -> Fault {
        Fault::other(detail)
    }
}

/// What the tests compare a failure's words with.
#[cfg(test)]
impl PartialEq<&str> for Fault {
    fn eq(&self, words: &&str) -> bool {
        self.detail == *words
    }
}

#[cfg(test)]
impl PartialEq<str> for Fault {
    fn eq(&self, words: &str) -> bool {
        self.detail == words
    }
}

#[cfg(test)]
impl Fault {
    /// Whether the server sent a proof that does not hold.
    pub(crate) fn is_false_proof(&self) -> bool {
        self.kind == FaultKind::FalseProof
    }

    /// Whether the words hold `part`, for the tests that read them.
    pub(crate) fn contains(&self, part: &str) -> bool {
        self.detail.contains(part)
    }

    pub(crate) fn starts_with(&self, part: &str) -> bool {
        self.detail.starts_with(part)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

    use super::{Fault, IoOutage};

    /// The one list: each kind that says the server is out of reach, in
    /// its class, and a few that say nothing of it.
    #[test]
    fn each_io_kind_of_an_outage_has_its_class() {
        for (kind, class) in [
            (ErrorKind::ConnectionRefused, IoOutage::Unreachable),
            (ErrorKind::HostUnreachable, IoOutage::Unreachable),
            (ErrorKind::NetworkUnreachable, IoOutage::Unreachable),
            (ErrorKind::NetworkDown, IoOutage::Unreachable),
            (ErrorKind::TimedOut, IoOutage::TimedOut),
            (ErrorKind::WouldBlock, IoOutage::TimedOut),
            (ErrorKind::ConnectionReset, IoOutage::Closed),
            (ErrorKind::ConnectionAborted, IoOutage::Closed),
            (ErrorKind::BrokenPipe, IoOutage::Closed),
            (ErrorKind::UnexpectedEof, IoOutage::Closed),
            (ErrorKind::NotConnected, IoOutage::Closed),
        ] {
            assert_eq!(IoOutage::of(kind), Some(class), "{kind:?}");
            assert!(
                Fault::of_io(&Error::from(kind), None).is_outage(),
                "{kind:?}"
            );
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotFound,
            ErrorKind::AddrNotAvailable,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
            ErrorKind::Other,
        ] {
            assert_eq!(IoOutage::of(kind), None, "{kind:?}");
        }
    }

    /// The words of each class, and of what is not one.
    #[test]
    fn an_io_failure_is_told_in_the_words_of_its_class() {
        let of = |error: Error| Fault::of_io(&error, Some(Duration::from_secs(20)));
        assert_eq!(of(ErrorKind::ConnectionRefused.into()), "could not connect");
        assert_eq!(of(ErrorKind::WouldBlock.into()), "timed out after 20 s");
        // A limit of the system's own, not one the core set.
        assert_eq!(Fault::of_io(&ErrorKind::TimedOut.into(), None), "timed out");
        assert_eq!(
            of(ErrorKind::BrokenPipe.into()),
            "the connection was closed"
        );
        let unresolved = of(Error::other(
            "failed to lookup address information: Name or service not known",
        ));
        assert_eq!(unresolved, "host not found");
        assert!(unresolved.is_outage());
        let cut_off = of(Error::new(ErrorKind::InvalidData, "an answer too long"));
        assert_eq!(cut_off, "an answer too long");
        assert!(!cut_off.is_outage());
        let local = of(ErrorKind::PermissionDenied.into());
        assert!(local.starts_with("connection failed: "), "{local}");
        assert!(!local.is_outage());
        let raised = of(Error::other(Fault::false_proof()));
        assert!(raised.is_false_proof());
    }
}
