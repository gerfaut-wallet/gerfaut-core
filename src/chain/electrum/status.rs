//! The status an Electrum server gives a script: the hash of its
//! history, in the order the server lists it.
//!
//! A sync reads the history of a script, and the live watch hears the
//! status of the same script from the same server. A history that does
//! not hash to the status that server announced is not the one it
//! stands by: a server behind its own word, or a reply out of step with
//! it. Such a history is set aside unread when it leaves out a
//! transaction the wallet holds there ([`verdict`]): read, it would have
//! the wallet take a payment it holds for one that vanished. The script
//! waits for the next sync, which the watch asks for when the status
//! moves again. One that leaves out nothing is read: it takes nothing
//! from the wallet, and it is most likely newer than the status heard,
//! the server's notice on its way, or from another machine behind the
//! same address that heard of a transaction first. Setting it aside
//! would only hide that transaction from the sync that found it.
//!
//! Before protocol 1.6 the order of the mempool in a status is the
//! server's own. Read in their sources: ElectrumX of spesmilo sorts it
//! by unconfirmed inputs, then by txid as it is written; electrs of
//! romanz by unconfirmed inputs, then by the txid's bytes, the other
//! way round; Fulcrum by unconfirmed parents, then by hash; the electrs
//! of Blockstream and of mempool keep the order transactions came in;
//! the ElectrumX of kyuupichan takes them from a set, which may come out
//! in another order once it changed. Each lists a history in the order
//! its status hashes, from the same code, but a status and a history
//! read at two moments may still differ in that order alone. So the same
//! transactions in another order agree, a disagreement over several
//! transactions waiting is asked about once more, and past what can be
//! tried in every order the history is read as it then comes: an honest
//! server is never refused for an order the protocol left to it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use bdk_wallet::bitcoin::{Script, Txid};

use crate::chain::Endpoint;

/// One transaction of a history: its txid and height, 0 or -1 for the
/// mempool.
pub(crate) type Entry = (Txid, i32);

/// Transactions of a mempool tried in every order, at most: 720 orders.
const REORDERED_MAX: usize = 6;

/// The Electrum status of a history: SHA-256 of `txid:height:` for each
/// transaction, in the order given, in hex.
pub(crate) fn history_status(history: &[(Txid, i32)]) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, HashEngine, sha256};
    use bdk_wallet::bitcoin::hex::DisplayHex;
    let mut engine = sha256::Hash::engine();
    for (txid, height) in history {
        engine.input(format!("{txid}:{height}:").as_bytes());
    }
    sha256::Hash::from_engine(engine)
        .to_byte_array()
        .to_lower_hex_string()
}

/// Whether a history a server listed is the one its status hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Agreement {
    /// As listed, or with its mempool in another order.
    Holds,
    /// In no order of its mempool.
    Differs,
    /// Not as listed, and its mempool is too long to try in every
    /// order.
    Undecided,
}

impl Agreement {
    /// Whether the server is worth asking for the history again before
    /// it is set aside or read as it comes: an order not tried, or one
    /// of several transactions waiting, which the server may have
    /// listed at another moment than its status.
    pub(crate) fn asks_again(self, history: &[Entry]) -> bool {
        match self {
            Agreement::Holds => false,
            Agreement::Undecided => true,
            Agreement::Differs => waiting(history) >= 2,
        }
    }
}

/// How many transactions of a history wait in the mempool.
fn waiting(history: &[Entry]) -> usize {
    history.iter().filter(|(_, height)| *height <= 0).count()
}

/// What a sync does with a history a server listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Read,
    /// Ask the server for it once more, and decide on that answer.
    AskAgain,
    SetAside,
}

/// The histories of one script a sync reads, checked against what a
/// live watch heard of it from the same server: the first one, then the
/// one read again when the first asks for it. Both sync paths, a
/// descriptor wallet's and a watched address's, go through it.
pub(crate) struct Check<'a> {
    told: Option<&'a Told>,
    script: &'a Script,
    /// What the wallet holds on the script.
    expected: &'a HashSet<Txid>,
    asked_again: bool,
}

impl<'a> Check<'a> {
    pub(crate) fn new(
        told: Option<&'a Told>,
        script: &'a Script,
        expected: &'a HashSet<Txid>,
    ) -> Self {
        Check {
            told,
            script,
            expected,
            asked_again: false,
        }
    }

    /// What to do with the history the server listed: read when no
    /// status was heard for the script, or when it cannot be spelled as
    /// one (`None`, a height past what a status holds); otherwise see
    /// [`verdict`]. [`Verdict::AskAgain`] comes once at most: the answer
    /// to it is read or set aside.
    pub(crate) fn verdict(&mut self, listed: Option<&[Entry]>) -> Verdict {
        let status = self.told.and_then(|told| told.status_of(self.script));
        let (Some(status), Some(listed)) = (status, listed) else {
            return Verdict::Read;
        };
        let verdict = verdict(listed, status.as_deref(), self.expected, self.asked_again);
        self.asked_again = true;
        verdict
    }
}

/// What a sync does with `history`, listed by a server that announced
/// `status` for the script, the wallet holding `expected` there. Read
/// when it hashes to the status ([`agreement`]), or leaves out nothing
/// the wallet holds; otherwise asked for once more when the order may be
/// at fault ([`Agreement::asks_again`]), then, `asked_again`, read when
/// no order can be told for it, and set aside when it still disagrees.
fn verdict(
    history: &[Entry],
    status: Option<&str>,
    expected: &HashSet<Txid>,
    asked_again: bool,
) -> Verdict {
    let agreed = agreement(history, status);
    if agreed == Agreement::Holds {
        return Verdict::Read;
    }
    let listed: HashSet<&Txid> = history.iter().map(|(txid, _)| txid).collect();
    if expected.iter().all(|txid| listed.contains(txid)) {
        return Verdict::Read;
    }
    if asked_again {
        return if agreed == Agreement::Undecided {
            Verdict::Read
        } else {
            Verdict::SetAside
        };
    }
    if agreed.asks_again(history) {
        Verdict::AskAgain
    } else {
        Verdict::SetAside
    }
}

/// Whether `history`, as a server listed it, hashes to `status`, the
/// one it announced, `None` for a script it holds nothing for: as
/// listed, or with the transactions of its mempool after its
/// confirmed ones in any order.
pub(crate) fn agreement(history: &[Entry], status: Option<&str>) -> Agreement {
    let Some(status) = status else {
        return if history.is_empty() {
            Agreement::Holds
        } else {
            Agreement::Differs
        };
    };
    if history.is_empty() {
        return Agreement::Differs;
    }
    if history_status(history) == status {
        return Agreement::Holds;
    }
    let (mut confirmed, mut mempool): (Vec<Entry>, Vec<Entry>) =
        history.iter().partition(|(_, height)| *height > 0);
    if mempool.len() < 2 {
        return Agreement::Differs;
    }
    if mempool.len() > REORDERED_MAX {
        return Agreement::Undecided;
    }
    if in_some_order(&mut confirmed, &mut mempool, status) {
        Agreement::Holds
    } else {
        Agreement::Differs
    }
}

/// Whether `head` followed by `left` in some order hashes to `status`.
/// Both come back as they were.
fn in_some_order(head: &mut Vec<Entry>, left: &mut Vec<Entry>, status: &str) -> bool {
    if left.is_empty() {
        return history_status(head) == status;
    }
    for at in 0..left.len() {
        let next = left.remove(at);
        head.push(next);
        let found = in_some_order(head, left, status);
        head.pop();
        left.insert(at, next);
        if found {
            return true;
        }
    }
    false
}

/// What the server of a live watch announced of each script, while a
/// session with it is open: the status it gave last, by script hash.
/// The watch writes it; a sync on that same server reads it, and on any
/// other finds nothing there.
#[derive(Debug, Clone, Default)]
pub(crate) struct Announced(Arc<Mutex<Heard>>);

#[derive(Debug, Default)]
struct Heard {
    server: Option<Endpoint>,
    statuses: HashMap<String, Option<String>>,
}

impl Announced {
    fn heard(&self) -> std::sync::MutexGuard<'_, Heard> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A session opened with `server`: nothing heard before it holds.
    pub(crate) fn open(&self, server: &Endpoint) {
        let mut heard = self.heard();
        heard.server = Some(server.clone());
        heard.statuses.clear();
    }

    /// The session ended: what it heard says nothing of what the server
    /// holds from now on.
    pub(crate) fn close(&self) {
        let mut heard = self.heard();
        heard.server = None;
        heard.statuses.clear();
    }

    /// The server gave `status` for the script hash `scripthash`.
    pub(crate) fn set(&self, scripthash: &str, status: Option<String>) {
        self.heard().statuses.insert(scripthash.to_owned(), status);
    }

    /// The script hash left the list: its status is no longer heard.
    pub(crate) fn forget(&self, scripthash: &str) {
        self.heard().statuses.remove(scripthash);
    }

    /// The status `server` last gave `script`, while a session with it
    /// is open: `None` when none is, or it gave none; `Some(None)` when
    /// it said the script has no history.
    pub(crate) fn status_of(&self, server: &Endpoint, script: &Script) -> Option<Option<String>> {
        let heard = self.heard();
        if heard.server.as_ref() != Some(server) {
            return None;
        }
        heard.statuses.get(&scripthash(script)).cloned()
    }
}

/// The Electrum script hash of a script: SHA-256, reversed, in hex.
pub(crate) fn scripthash(script: &Script) -> String {
    use bdk_wallet::bitcoin::hashes::{Hash, sha256};
    use bdk_wallet::bitcoin::hex::DisplayHex;
    let mut digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    digest.reverse();
    digest.to_lower_hex_string()
}

/// What a sync on `server` checks the histories it reads against.
#[derive(Debug, Clone)]
pub(crate) struct Told {
    pub announced: Announced,
    pub server: Endpoint,
}

impl Told {
    /// The status the server announced for `script`, if a watch heard
    /// one from it: see [`Announced::status_of`].
    pub(crate) fn status_of(&self, script: &Script) -> Option<Option<String>> {
        self.announced.status_of(&self.server, script)
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::ScriptBuf;
    use bdk_wallet::bitcoin::hashes::Hash;

    use super::*;

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    /// A history agrees with its status as listed, or with its mempool,
    /// 0 and -1 alike, in another order after the confirmed part; not
    /// with its confirmed part in another order, nor with another
    /// transaction, nor past the orders it can try.
    #[test]
    fn a_history_agrees_with_its_status_in_any_mempool_order() {
        let (a, b, c) = (txid(1), txid(2), txid(3));
        let status = history_status(&[(a, 90), (b, 0), (c, -1)]);
        let agree = |history: &[Entry]| agreement(history, Some(&status));
        assert_eq!(agree(&[(a, 90), (b, 0), (c, -1)]), Agreement::Holds);
        assert_eq!(agree(&[(a, 90), (c, -1), (b, 0)]), Agreement::Holds);
        assert_eq!(agree(&[(a, 90), (b, 0)]), Agreement::Differs);
        assert_eq!(agree(&[(a, 90), (b, 0), (c, 0)]), Agreement::Differs);
        let status = history_status(&[(a, 90), (b, 91)]);
        assert_eq!(
            agreement(&[(b, 91), (a, 90)], Some(&status)),
            Agreement::Differs
        );
        assert_eq!(agreement(&[], None), Agreement::Holds);
        assert_eq!(agreement(&[], Some(&status)), Agreement::Differs);
        assert_eq!(agreement(&[(a, 90)], None), Agreement::Differs);
        let many: Vec<Entry> = (0..7).map(|n| (txid(n), 0)).collect();
        let reversed: Vec<Entry> = many.iter().rev().copied().collect();
        assert_eq!(
            agreement(&reversed, Some(&history_status(&many))),
            Agreement::Undecided
        );
    }

    /// What a session heard holds only while it is open, and only for
    /// the server it was heard from.
    #[test]
    fn a_status_is_heard_from_one_server_while_its_session_lasts() {
        let script = ScriptBuf::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let ours = Endpoint::Esplora("http://ours".to_owned());
        let theirs = Endpoint::Esplora("http://theirs".to_owned());
        let announced = Announced::default();
        announced.open(&ours);
        announced.set(&scripthash(&script), Some("ab".to_owned()));
        assert_eq!(
            announced.status_of(&ours, &script),
            Some(Some("ab".to_owned()))
        );
        assert_eq!(announced.status_of(&theirs, &script), None);
        announced.close();
        assert_eq!(announced.status_of(&ours, &script), None);
        announced.open(&ours);
        assert_eq!(announced.status_of(&ours, &script), None);
    }
}
