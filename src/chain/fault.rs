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
