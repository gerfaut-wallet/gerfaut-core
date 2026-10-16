//! What a notification of Live says, on every platform.
//!
//! The words are the same on the desktop and on Android, so they are
//! composed here and the apps post what they get: a title, a text, and
//! the payment each one is about. Pure: the same transactions, names,
//! unit, mask and choice of details always read the same. The budget
//! that caps how many go out is the one piece of state, and the manager
//! holds it ([`crate::WalletManager::notices`]).
//!
//! Four rules hold the text:
//!
//! - A balance change is stated, never celebrated: an amount, a
//!   direction, and whether the chain has it yet.
//! - While balances are masked, no amount.
//! - Without details, no amount and no wallet name either. The desktop
//!   says neither behind its lock screen, since a notification must not
//!   say what the window refuses to; Android leaves it to a setting of
//!   its own, whatever the lock.
//! - A pending payment that is no longer coming is always said, one
//!   notification each: it takes back what an earlier one promised,
//!   and folding it into a count would leave the promise standing.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::LiveTx;
use crate::format::{format_btc, group_thousands};
use crate::store::TxStage;

/// Transactions said one by one for a wallet in one sync; the rest are
/// counted in a single line.
pub const NOTICES_PER_WALLET: usize = 3;

/// The longest title a notification carries, in characters, the mark
/// that says a name was cut included.
const MAX_TITLE_CHARS: usize = 64;

/// The title of a notification that must not name a wallet.
pub const APP_TITLE: &str = "Gerfaut";

/// Payments no longer coming held for one sync. Far above what a real
/// wallet sees; the rest are counted in a line that says the same.
const MAX_DROPPED_HELD: usize = 64;

/// Notifications let through in one window of time, whatever the
/// backend says. A server can make a wallet look busy; it cannot make
/// the device ring without end. Payments no longer coming draw on a
/// budget of the same size of their own.
///
/// The window is a minute of the wall clock. A monotonic clock stops
/// while a phone sleeps, which is most of the time under Live: one
/// burst would then hold the budget shut for hours, and what it
/// silenced is already claimed, so never said.
pub(crate) const BUDGET: u32 = 20;
pub(crate) const BUDGET_WINDOW: Duration = Duration::from_secs(60);

/// The unit amounts are shown in, as the display setting has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    #[default]
    Btc,
    Sats,
}

/// Everything the text depends on besides the transactions: what the
/// app lets a notification say, read at the moment of posting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// The name of each wallet, by id.
    pub names: HashMap<String, String>,
    pub unit: Unit,
    /// Balances are masked: no amount.
    pub masked: bool,
    /// Whether a notification may name the wallet and state the amount.
    /// Off, the title is the app's and the text says only what happened.
    /// The desktop turns it off behind its lock screen; on Android it is
    /// the "Show wallet and amount" setting, lock or not.
    pub details: bool,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            names: HashMap::new(),
            unit: Unit::Btc,
            masked: false,
            details: true,
        }
    }
}

/// Which flood budget a notification draws on. A payment that is no
/// longer coming has one of its own, so a burst of new transactions
/// can never silence it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    Transaction,
    Dropped,
}

/// Which payment a notification is about: the id the core asks a host
/// to post it under, `replaces.unwrap_or(txid)`, for the wallet it is
/// posted for. A fee bump confirms under a txid of its own and names in
/// `replaces` the one first announced, so its confirmation shares the
/// id of the pending notice. The wallet is part of the id because a
/// payment between two watched wallets is announced for each of them,
/// and one must not take the other's place.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoticeId {
    pub wallet_id: String,
    pub txid: String,
}

impl NoticeId {
    pub fn of(tx: &LiveTx) -> Self {
        NoticeId {
            wallet_id: tx.wallet_id.clone(),
            txid: payment(tx).to_owned(),
        }
    }
}

/// The txid a transaction's payment was first announced under.
fn payment(tx: &LiveTx) -> &str {
    tx.replaces.as_deref().unwrap_or(&tx.txid)
}

/// One notification, ready to post.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub title: String,
    pub body: String,
    pub kind: NoticeKind,
    /// The payment it is about. A later notice with the same id takes
    /// its place where the system lets one notification replace
    /// another. `None` for a line that counts the rest or sums up.
    pub id: Option<NoticeId>,
    /// The wallet it is about, a line that counts the rest of a sync
    /// included; `None` for the line that says more is waiting.
    pub wallet_id: Option<String>,
}

/// What one sync of one wallet has to announce: the first few
/// transactions and how many came after them, and every pending
/// payment that is no longer coming.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Held {
    pub first: Vec<LiveTx>,
    pub more: u32,
    pub dropped: Vec<LiveTx>,
    pub dropped_more: u32,
}

impl Held {
    pub fn push(&mut self, tx: LiveTx) {
        // A payment held as pending is said once. What comes next for it
        // in the same sync takes the place of the pending notice rather
        // than showing beside it: its confirmation, a fee bump's
        // included, stands where it stood. A payment no longer coming
        // has nothing to take back from a notice never posted, so
        // neither is said, as the core does with news still waiting.
        let pending = self.first.iter().position(|held| {
            held.stage == TxStage::Mempool
                && held.wallet_id == tx.wallet_id
                && payment(held) == payment(&tx)
        });
        if let Some(at) = pending {
            match tx.stage {
                TxStage::Mempool => {}
                TxStage::Confirmed => self.first[at] = tx,
                TxStage::Dropped => {
                    self.first.remove(at);
                }
            }
            return;
        }
        if tx.stage == TxStage::Dropped {
            if self.dropped.len() < MAX_DROPPED_HELD {
                self.dropped.push(tx);
            } else {
                self.dropped_more = self.dropped_more.saturating_add(1);
            }
        } else if self.first.len() < NOTICES_PER_WALLET {
            self.first.push(tx);
        } else {
            self.more = self.more.saturating_add(1);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_empty() && self.more == 0 && self.dropped.is_empty()
    }
}

impl FromIterator<LiveTx> for Held {
    fn from_iter<I: IntoIterator<Item = LiveTx>>(txs: I) -> Self {
        let mut held = Held::default();
        for tx in txs {
            held.push(tx);
        }
        held
    }
}

/// A batch of any wallets, held wallet by wallet in the order each one
/// first appears.
pub(crate) fn by_wallet(txs: impl IntoIterator<Item = LiveTx>) -> Vec<(String, Held)> {
    let mut wallets: Vec<(String, Held)> = Vec::new();
    for tx in txs {
        match wallets
            .iter_mut()
            .find(|(wallet_id, _)| *wallet_id == tx.wallet_id)
        {
            Some((_, held)) => held.push(tx),
            None => {
                let wallet_id = tx.wallet_id.clone();
                wallets.push((wallet_id, std::iter::once(tx).collect()));
            }
        }
    }
    wallets
}

fn amount(sats: u64, unit: Unit) -> String {
    match unit {
        Unit::Btc => format!("{} BTC", group_thousands(&format_btc(sats))),
        Unit::Sats => format!("{} sats", group_thousands(&sats.to_string())),
    }
}

fn describe(tx: &LiveTx, context: &Context) -> String {
    let hidden = context.masked || !context.details || tx.net_sats == 0;
    let outgoing = tx.net_sats < 0;
    let sats = || amount(tx.net_sats.unsigned_abs(), context.unit);
    let moved = || {
        if outgoing {
            format!("{} left this wallet", sats())
        } else {
            format!("Received {}", sats())
        }
    };
    match (hidden, tx.stage) {
        (true, TxStage::Mempool) if outgoing => "New outgoing transaction · pending".to_owned(),
        (true, TxStage::Mempool) => "New transaction · pending".to_owned(),
        (true, TxStage::Confirmed) if outgoing => "Outgoing transaction confirmed".to_owned(),
        (true, TxStage::Confirmed) => "Transaction confirmed".to_owned(),
        (true, TxStage::Dropped) => "A pending payment is no longer coming".to_owned(),
        (false, TxStage::Mempool) => format!("{} · pending", moved()),
        (false, TxStage::Confirmed) => format!("{} · confirmed", moved()),
        (false, TxStage::Dropped) => {
            format!("A pending payment of {} is no longer coming", sats())
        }
    }
}

/// Characters that draw nothing yet reorder or hide what is around
/// them: the bidirectional overrides, embeddings, isolates and marks,
/// and the zero-width space, word joiner and byte order mark. The two
/// zero-width joiners stay: some scripts and emoji need them.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// A wallet name as a notification may carry it. The name is the one
/// piece of free text that reaches the system: it comes from the
/// person, or from a backup someone handed them. The invisible
/// characters that turn text around go; a control character, a line
/// break among them, is a space, and runs of blanks become one; a name
/// too long is cut, and the cut is shown.
pub fn safe_title(name: &str) -> String {
    let spaced: String = name
        .chars()
        .filter(|&c| !invisible(c))
        .map(|c| {
            if c.is_whitespace() || c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let joined = spaced
        .split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return APP_TITLE.to_owned();
    }
    if joined.chars().count() <= MAX_TITLE_CHARS {
        return joined;
    }
    let cut: String = joined.chars().take(MAX_TITLE_CHARS - 1).collect();
    format!("{}…", cut.trim_end())
}

fn plural(count: u32, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// What one wallet's sync amounts to: one notice per transaction up to
/// [`NOTICES_PER_WALLET`], then one line counting the rest, then one
/// notice for each payment no longer coming. Those come last, so they
/// sit on top of the pile the system keeps.
pub fn compose(wallet_id: &str, held: &Held, context: &Context) -> Vec<Notice> {
    let title = if context.details {
        context
            .names
            .get(wallet_id)
            .map(|name| safe_title(name))
            .unwrap_or_else(|| APP_TITLE.to_owned())
    } else {
        APP_TITLE.to_owned()
    };
    let notice = |body: String, kind: NoticeKind, id: Option<NoticeId>| Notice {
        title: title.clone(),
        body,
        kind,
        id,
        wallet_id: Some(wallet_id.to_owned()),
    };
    let mut notices: Vec<Notice> = held
        .first
        .iter()
        .map(|tx| {
            notice(
                describe(tx, context),
                NoticeKind::Transaction,
                Some(NoticeId::of(tx)),
            )
        })
        .collect();
    if held.more > 0 {
        notices.push(notice(
            plural(held.more, "more transaction"),
            NoticeKind::Transaction,
            None,
        ));
    }
    notices.extend(held.dropped.iter().map(|tx| {
        notice(
            describe(tx, context),
            NoticeKind::Dropped,
            Some(NoticeId::of(tx)),
        )
    }));
    if held.dropped_more > 0 {
        let count = held.dropped_more;
        notices.push(notice(
            format!(
                "{count} more pending payment{} no longer coming",
                if count == 1 { " is" } else { "s are" }
            ),
            NoticeKind::Dropped,
            None,
        ));
    }
    notices
}

/// The notification that shows the person what an alert looks like.
pub(crate) fn test_notice() -> Notice {
    Notice {
        title: APP_TITLE.to_owned(),
        body: "This is a test. Alerts about your wallets appear like this one.".to_owned(),
        kind: NoticeKind::Transaction,
        id: None,
        wallet_id: None,
    }
}

/// A cap on what is posted per minute.
#[derive(Debug)]
pub(crate) struct Budget {
    started: Option<SystemTime>,
    spent: u32,
}

/// What the budget says about one more notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Allowance {
    Post,
    /// The last one of the window: say that more is waiting instead.
    LastCall,
    Silent,
}

impl Budget {
    pub(crate) const fn new() -> Self {
        Budget {
            started: None,
            spent: 0,
        }
    }

    /// A clock set back starts a new window: the budget errs towards
    /// saying more, never towards a silence longer than a minute.
    pub(crate) fn allow(&mut self, now: SystemTime) -> Allowance {
        let fresh = self.started.is_none_or(|started| {
            now.duration_since(started)
                .map_or(true, |elapsed| elapsed >= BUDGET_WINDOW)
        });
        if fresh {
            self.started = Some(now);
            self.spent = 0;
        }
        self.spent = self.spent.saturating_add(1);
        match self.spent {
            n if n < BUDGET => Allowance::Post,
            n if n == BUDGET => Allowance::LastCall,
            _ => Allowance::Silent,
        }
    }
}

/// One budget per kind of notification: a burst of new transactions
/// never silences a payment that is no longer coming.
#[derive(Debug)]
pub(crate) struct Budgets {
    pub(crate) transactions: Budget,
    dropped: Budget,
}

impl Budgets {
    pub(crate) const fn new() -> Self {
        Budgets {
            transactions: Budget::new(),
            dropped: Budget::new(),
        }
    }
}

/// The notices the budgets let through, the last one of each kind
/// replaced by a line saying more is waiting.
pub(crate) fn within_budget(
    budgets: &mut Budgets,
    notices: Vec<Notice>,
    now: SystemTime,
) -> Vec<Notice> {
    let mut out = Vec::new();
    for notice in notices {
        let (budget, last_call) = match notice.kind {
            NoticeKind::Transaction => (
                &mut budgets.transactions,
                "More transactions are coming in. Open Gerfaut to see them.",
            ),
            NoticeKind::Dropped => (
                &mut budgets.dropped,
                "More pending payments are no longer coming. Open Gerfaut to see them.",
            ),
        };
        match budget.allow(now) {
            Allowance::Post => out.push(notice),
            Allowance::LastCall => out.push(Notice {
                title: APP_TITLE.to_owned(),
                body: last_call.to_owned(),
                kind: notice.kind,
                id: None,
                wallet_id: None,
            }),
            Allowance::Silent => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(txid: &str, net_sats: i64, stage: TxStage) -> LiveTx {
        LiveTx {
            wallet_id: "w1".to_owned(),
            txid: txid.to_owned(),
            net_sats,
            stage,
            replaces: None,
        }
    }

    fn id(txid: &str) -> Option<NoticeId> {
        Some(NoticeId {
            wallet_id: "w1".to_owned(),
            txid: txid.to_owned(),
        })
    }

    fn context() -> Context {
        Context {
            names: HashMap::from([("w1".to_owned(), "Cold storage".to_owned())]),
            ..Context::default()
        }
    }

    fn w1() -> Option<String> {
        Some("w1".to_owned())
    }

    #[test]
    fn an_amount_a_direction_and_where_the_chain_has_it() {
        let held: Held = [
            tx("a", 150_000, TxStage::Mempool),
            tx("b", -2_100_000_000, TxStage::Mempool),
            tx("c", 150_000, TxStage::Confirmed),
        ]
        .into_iter()
        .collect();
        let notices = compose("w1", &held, &context());
        assert_eq!(notices.len(), 3);
        assert!(notices.iter().all(|notice| notice.title == "Cold storage"));
        assert_eq!(notices[0].body, "Received 0.00150000 BTC · pending");
        assert_eq!(
            notices[1].body,
            "21.00000000 BTC left this wallet · pending"
        );
        assert_eq!(notices[2].body, "Received 0.00150000 BTC · confirmed");
    }

    #[test]
    fn amounts_follow_the_unit() {
        let held: Held = [tx("a", 1_234_567, TxStage::Mempool)].into_iter().collect();
        let sats = Context {
            unit: Unit::Sats,
            ..context()
        };
        assert_eq!(
            compose("w1", &held, &sats)[0].body,
            "Received 1\u{202f}234\u{202f}567 sats · pending"
        );
    }

    #[test]
    fn masked_says_the_direction_and_never_the_amount() {
        let held: Held = [
            tx("a", 150_000, TxStage::Mempool),
            tx("b", -150_000, TxStage::Mempool),
            tx("c", -150_000, TxStage::Confirmed),
        ]
        .into_iter()
        .collect();
        let masked = Context {
            masked: true,
            ..context()
        };
        let notices = compose("w1", &held, &masked);
        assert_eq!(notices[0].title, "Cold storage");
        assert_eq!(notices[0].body, "New transaction · pending");
        assert_eq!(notices[1].body, "New outgoing transaction · pending");
        assert_eq!(notices[2].body, "Outgoing transaction confirmed");
        assert!(notices.iter().all(|notice| !notice.body.contains("150")));
    }

    /// Without details a notification names no wallet and no amount,
    /// masked or not: what the desktop posts over its lock screen, and
    /// what Android posts once the person asks for it.
    #[test]
    fn without_details_no_wallet_and_no_amount() {
        let held: Held = [
            tx("a", 150_000, TxStage::Mempool),
            tx("b", -150_000, TxStage::Mempool),
            tx("c", 150_000, TxStage::Confirmed),
            tx("d", 9, TxStage::Mempool),
            tx("e", 9, TxStage::Mempool),
        ]
        .into_iter()
        .collect();
        let generic = Context {
            details: false,
            ..context()
        };
        let notices = compose("w1", &held, &generic);
        let notice = |body: &str, id: Option<NoticeId>| Notice {
            title: "Gerfaut".to_owned(),
            body: body.to_owned(),
            kind: NoticeKind::Transaction,
            id,
            wallet_id: w1(),
        };
        assert_eq!(
            notices,
            vec![
                notice("New transaction · pending", id("a")),
                notice("New outgoing transaction · pending", id("b")),
                notice("Transaction confirmed", id("c")),
                notice("2 more transactions", None),
            ]
        );
        for notice in &notices {
            assert!(!notice.title.contains("Cold"));
            assert!(!notice.body.contains("150"));
            assert!(!notice.body.contains("BTC"));
        }
    }

    /// A payment that vanished takes back an earlier notification:
    /// with its amount when amounts show, without it when they are
    /// masked, and naming nothing without details.
    #[test]
    fn a_payment_no_longer_coming_is_said_in_every_state() {
        let held: Held = [tx("a", 150_000, TxStage::Dropped)].into_iter().collect();
        let plain = compose("w1", &held, &context());
        assert_eq!(
            plain,
            vec![Notice {
                title: "Cold storage".to_owned(),
                body: "A pending payment of 0.00150000 BTC is no longer coming".to_owned(),
                kind: NoticeKind::Dropped,
                id: id("a"),
                wallet_id: w1(),
            }]
        );

        let sats = Context {
            unit: Unit::Sats,
            ..context()
        };
        assert_eq!(
            compose("w1", &held, &sats)[0].body,
            "A pending payment of 150\u{202f}000 sats is no longer coming"
        );

        let masked = Context {
            masked: true,
            ..context()
        };
        let shown = compose("w1", &held, &masked);
        assert_eq!(shown[0].title, "Cold storage");
        assert_eq!(shown[0].body, "A pending payment is no longer coming");

        let generic = Context {
            details: false,
            ..context()
        };
        let shown = compose("w1", &held, &generic);
        assert_eq!(shown[0].title, "Gerfaut");
        assert_eq!(shown[0].body, "A pending payment is no longer coming");
    }

    /// However many transactions a sync found, each payment that is no
    /// longer coming gets its own notification, after them.
    #[test]
    fn a_payment_no_longer_coming_is_never_folded_into_a_count() {
        let mut held: Held = (0..9)
            .map(|i| tx(&format!("t{i}"), 1_000, TxStage::Mempool))
            .collect();
        held.push(tx("gone1", 5_000, TxStage::Dropped));
        held.push(tx("t9", 1_000, TxStage::Confirmed));
        held.push(tx("gone2", 7_000, TxStage::Dropped));
        let notices = compose("w1", &held, &context());
        let bodies: Vec<&str> = notices.iter().map(|n| n.body.as_str()).collect();
        assert_eq!(bodies[3], "7 more transactions");
        assert_eq!(
            &bodies[4..],
            [
                "A pending payment of 0.00005000 BTC is no longer coming",
                "A pending payment of 0.00007000 BTC is no longer coming",
            ]
        );
        assert!(notices[4..].iter().all(|n| n.kind == NoticeKind::Dropped));
        assert!(
            notices[..4]
                .iter()
                .all(|n| n.kind == NoticeKind::Transaction)
        );

        // Past what is held one by one, the rest still say what they are.
        let flood: Held = (0..(MAX_DROPPED_HELD + 2))
            .map(|i| tx(&format!("d{i}"), 1, TxStage::Dropped))
            .collect();
        let notices = compose("w1", &flood, &context());
        assert_eq!(notices.len(), MAX_DROPPED_HELD + 1);
        assert_eq!(
            notices.last().map(|n| n.body.as_str()),
            Some("2 more pending payments are no longer coming")
        );
    }

    /// A fee bump confirms under a txid of its own and names the first
    /// one: its notice carries the id of the pending notice, so it can
    /// take that notice's place. A payment that was not bumped keeps its
    /// own txid, and the same payment in another wallet an id of its own.
    #[test]
    fn a_bumps_confirmation_uses_the_first_txids_id() {
        let pending: Held = [tx("a", 50_000, TxStage::Mempool)].into_iter().collect();
        let bump = LiveTx {
            replaces: Some("a".to_owned()),
            ..tx("c", 49_600, TxStage::Confirmed)
        };
        let confirmed: Held = [bump.clone()].into_iter().collect();
        assert_eq!(compose("w1", &pending, &context())[0].id, id("a"));
        let said = compose("w1", &confirmed, &context());
        assert_eq!(said[0].id, id("a"));
        assert_eq!(said[0].body, "Received 0.00049600 BTC · confirmed");

        let plain: Held = [tx("b", 1, TxStage::Confirmed)].into_iter().collect();
        assert_eq!(compose("w1", &plain, &context())[0].id, id("b"));

        let elsewhere = LiveTx {
            wallet_id: "w2".to_owned(),
            ..bump
        };
        assert_eq!(
            NoticeId::of(&elsewhere),
            NoticeId {
                wallet_id: "w2".to_owned(),
                txid: "a".to_owned(),
            }
        );
    }

    /// What a sync says next about a payment it holds as pending takes
    /// the place of the pending notice: none is left beside its own
    /// confirmation, a bump's included, a second arrival adds nothing,
    /// and a payment gone before its notice was posted is not said.
    #[test]
    fn a_held_pending_notice_gives_way_to_what_follows_it() {
        let bump = LiveTx {
            replaces: Some("a".to_owned()),
            ..tx("c", 49_600, TxStage::Confirmed)
        };
        let held: Held = [
            tx("a", 50_000, TxStage::Mempool),
            tx("b", 1, TxStage::Mempool),
            tx("a", 50_000, TxStage::Mempool),
            bump.clone(),
        ]
        .into_iter()
        .collect();
        assert_eq!(held.first, vec![bump, tx("b", 1, TxStage::Mempool)]);
        assert_eq!(held.more, 0);

        let gone: Held = [
            tx("a", 50_000, TxStage::Mempool),
            tx("a", 50_000, TxStage::Dropped),
        ]
        .into_iter()
        .collect();
        assert!(gone.is_empty());

        // The same txid in another wallet is another notice.
        let elsewhere = LiveTx {
            wallet_id: "w2".to_owned(),
            ..tx("a", 1, TxStage::Confirmed)
        };
        let both: Held = [tx("a", 1, TxStage::Mempool), elsewhere]
            .into_iter()
            .collect();
        assert_eq!(both.first.len(), 2);
    }

    #[test]
    fn three_are_said_and_the_rest_counted() {
        let held: Held = (0..7)
            .map(|i| tx(&format!("t{i}"), 1_000, TxStage::Mempool))
            .collect();
        assert_eq!(held.first.len(), NOTICES_PER_WALLET);
        assert_eq!(held.more, 4);
        let notices = compose("w1", &held, &context());
        assert_eq!(notices.len(), 4);
        assert_eq!(notices[3].body, "4 more transactions");
        assert_eq!(notices[3].id, None);
        assert_eq!(notices[3].wallet_id, w1());

        let one_more: Held = (0..4)
            .map(|i| tx(&format!("t{i}"), 1_000, TxStage::Mempool))
            .collect();
        assert_eq!(
            compose("w1", &one_more, &context())[3].body,
            "1 more transaction"
        );
    }

    /// A batch of several wallets is said wallet by wallet, in the order
    /// each first appears, each under its own name.
    #[test]
    fn a_batch_of_several_wallets_is_said_wallet_by_wallet() {
        let mut w2 = tx("move", 50_000, TxStage::Mempool);
        w2.wallet_id = "w2".to_owned();
        let batch = vec![
            tx("a", 1_000, TxStage::Mempool),
            w2.clone(),
            tx("a", 1_000, TxStage::Confirmed),
            tx("b", 2_000, TxStage::Mempool),
        ];
        let wallets = by_wallet(batch);
        assert_eq!(
            wallets
                .iter()
                .map(|(wallet_id, _)| wallet_id.as_str())
                .collect::<Vec<_>>(),
            ["w1", "w2"]
        );
        assert_eq!(
            wallets[0].1.first,
            vec![
                tx("a", 1_000, TxStage::Confirmed),
                tx("b", 2_000, TxStage::Mempool)
            ]
        );
        assert_eq!(wallets[1].1.first, vec![w2]);
    }

    /// A name is free text, and may come from a backup someone else
    /// wrote: nothing in it shapes the notification.
    #[test]
    fn a_wallet_name_cannot_shape_the_notification() {
        assert_eq!(
            safe_title("Savings\r\nReceived 5 BTC\u{0}\u{1b}[31m"),
            "Savings Received 5 BTC [31m"
        );
        assert_eq!(safe_title("  a \t\n  b  "), "a b");
        assert_eq!(safe_title("\u{7}\n"), "Gerfaut");
        // An override would draw the rest of the line backwards, and an
        // isolate or a mark would move it around: none of them stays.
        assert_eq!(
            safe_title("Savings \u{202E}CTB 5 devieceR\u{202C}"),
            "Savings CTB 5 devieceR"
        );
        assert_eq!(
            safe_title("\u{2067}a\u{2069}\u{200F}b\u{200B}c\u{FEFF}\u{2060}d\u{061C}"),
            "abcd"
        );
        assert_eq!(safe_title("\u{202E}\u{200B}"), "Gerfaut");
        // What joins letters or emoji is kept.
        assert_eq!(
            safe_title("\u{1F468}\u{200D}\u{1F469}\u{200C}"),
            "\u{1F468}\u{200D}\u{1F469}\u{200C}"
        );
        // Markup is text: the platform layer escapes it, and it stays
        // one line either way.
        assert_eq!(
            safe_title("<toast launch='x'>"),
            "<toast launch='x'>".to_owned()
        );
        // A wallet nobody can name falls back on the app.
        let held: Held = [tx("a", 1, TxStage::Mempool)].into_iter().collect();
        assert_eq!(
            compose("unknown", &held, &Context::default())[0].title,
            "Gerfaut"
        );
    }

    /// A control character is a space, never a joint between two words:
    /// "Cold\u{7}storage" does not read "Coldstorage".
    #[test]
    fn a_control_character_is_a_space() {
        assert_eq!(safe_title("Cold\u{7}storage"), "Cold storage");
        assert_eq!(safe_title("Cold\u{0}\u{1b}storage"), "Cold storage");
        assert_eq!(safe_title("Cold\u{85}storage\u{9f}"), "Cold storage");
    }

    /// A name that fits is kept whole; a longer one is cut to 63
    /// characters and the cut is shown, with no blank before the mark.
    #[test]
    fn a_long_name_is_cut_and_says_so() {
        let fits = "x".repeat(MAX_TITLE_CHARS);
        assert_eq!(safe_title(&fits), fits);
        let long = safe_title(&"x".repeat(500));
        assert_eq!(long.chars().count(), MAX_TITLE_CHARS);
        assert_eq!(long, format!("{}…", "x".repeat(MAX_TITLE_CHARS - 1)));
        assert_eq!(
            safe_title(&"Savings for the long run ".repeat(5)),
            "Savings for the long run Savings for the long run Savings for t…"
        );
        let on_a_blank = format!("{} tail", "x".repeat(MAX_TITLE_CHARS - 2));
        assert_eq!(
            safe_title(&on_a_blank),
            format!("{}…", "x".repeat(MAX_TITLE_CHARS - 2))
        );
        // Characters past the basic plane count as one each.
        let eagles = safe_title(&"\u{1F985}".repeat(70));
        assert_eq!(eagles.chars().count(), MAX_TITLE_CHARS);
    }

    /// What crosses the bridge to Android: the context the app sends and
    /// the notices it gets back, field by field.
    #[test]
    fn the_context_and_the_notices_cross_the_bridge_as_json() {
        let context: Context = serde_json::from_str(
            r#"{"names":{"w1":"Cold storage"},"unit":"sats","masked":true,"details":false}"#,
        )
        .unwrap();
        assert_eq!(
            context,
            Context {
                unit: Unit::Sats,
                masked: true,
                details: false,
                ..self::context()
            }
        );
        // A context without its choice of details is refused, never
        // read as one that may say everything.
        assert!(
            serde_json::from_str::<Context>(r#"{"names":{},"unit":"btc","masked":false}"#).is_err()
        );
        let held: Held = [tx("a", 1, TxStage::Dropped)].into_iter().collect();
        let json = serde_json::to_value(compose("w1", &held, &self::context())).unwrap();
        assert_eq!(
            json,
            serde_json::json!([{
                "title": "Cold storage",
                "body": "A pending payment of 0.00000001 BTC is no longer coming",
                "kind": "dropped",
                "id": {"wallet_id": "w1", "txid": "a"},
                "wallet_id": "w1",
            }])
        );
    }

    fn notices(kind: NoticeKind, count: usize) -> Vec<Notice> {
        (0..count)
            .map(|i| Notice {
                title: "w".to_owned(),
                body: format!("n{i}"),
                kind,
                id: Some(NoticeId {
                    wallet_id: "w".to_owned(),
                    txid: format!("t{i}"),
                }),
                wallet_id: Some("w".to_owned()),
            })
            .collect()
    }

    #[test]
    fn the_budget_caps_a_minute_and_says_more_is_waiting() {
        let mut budget = Budgets::new();
        let start = SystemTime::now();
        let notices = notices(NoticeKind::Transaction, 50);
        let posted = within_budget(&mut budget, notices.clone(), start);
        assert_eq!(posted.len(), BUDGET as usize);
        assert_eq!(posted[0].body, "n0");
        assert_eq!(
            posted.last().map(|notice| notice.body.as_str()),
            Some("More transactions are coming in. Open Gerfaut to see them.")
        );
        // That line is about no payment: it must not take one's place.
        assert_eq!(posted.last().and_then(|notice| notice.id.clone()), None);
        assert_eq!(
            posted.last().and_then(|notice| notice.wallet_id.clone()),
            None
        );
        // Nothing more inside the window, everything again after it.
        assert!(
            within_budget(
                &mut budget,
                notices.clone(),
                start + Duration::from_secs(30)
            )
            .is_empty()
        );
        let later = within_budget(&mut budget, notices.clone(), start + BUDGET_WINDOW);
        assert_eq!(later.len(), BUDGET as usize);

        // A clock set back opens a new window rather than a long silence.
        let spent = within_budget(&mut budget, notices.clone(), start + BUDGET_WINDOW);
        assert!(spent.is_empty());
        let set_back = within_budget(&mut budget, notices, start);
        assert_eq!(set_back.len(), BUDGET as usize);
    }

    /// A minute spent on new transactions leaves the payments no longer
    /// coming untouched, and their own flood line says what they are.
    #[test]
    fn a_burst_of_transactions_never_silences_a_payment_no_longer_coming() {
        let mut budgets = Budgets::new();
        let start = SystemTime::now();
        let mut all = notices(NoticeKind::Transaction, 50);
        all.push(Notice {
            title: "Cold storage".to_owned(),
            body: "A pending payment is no longer coming".to_owned(),
            kind: NoticeKind::Dropped,
            id: None,
            wallet_id: w1(),
        });
        let posted = within_budget(&mut budgets, all, start);
        assert_eq!(posted.len(), BUDGET as usize + 1);
        assert_eq!(
            posted.last().map(|notice| notice.body.as_str()),
            Some("A pending payment is no longer coming")
        );

        let flood = within_budget(&mut budgets, notices(NoticeKind::Dropped, 50), start);
        assert_eq!(flood.len(), BUDGET as usize - 1);
        assert_eq!(
            flood.last().map(|notice| notice.body.as_str()),
            Some("More pending payments are no longer coming. Open Gerfaut to see them.")
        );
    }
}
