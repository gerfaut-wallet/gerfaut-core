//! What a sync found worth announcing, kept in the vault until a caller
//! claims it.
//!
//! A sync compares a wallet before and after: what it sees for the
//! first time, and what it sees confirm, is news. The news is written
//! to the vault in the same save as the sync itself, whoever ran the
//! sync, and it is not handed to that caller. A caller takes it with a
//! claim, and the first to claim takes it all: whoever claims
//! announces. So a sync whose caller announces nothing, or a caller
//! that arrives while another sync of the wallet runs and gets that
//! sync's result with nothing listed as new, never swallows a
//! transaction. It waits in the vault for the next claim.
//!
//! News is kept by wallet, and so is the record of what was announced:
//! a payment from one watched wallet to another is said for each, going
//! out of the first and coming into the second, once per wallet and
//! stage. Everything below is read wallet by wallet.
//!
//! # Replacements
//!
//! A sender who bumps the fee of a payment replaces it with another
//! transaction spending the same coins. Announced as it arrives, each
//! replacement would be one more identical notification. So a new
//! unconfirmed transaction that spends an output a pending transaction
//! of the wallet spent, one already announced at the mempool stage,
//! and that moves the wallet the same way (in, or out) and by nearly as
//! much, is recorded as announced and not said. Whichever of them
//! confirms is said once, as confirmed. A replacement that moves the
//! wallet by much less, or sends much more out, is no fee bump: it is
//! said as a transaction of its own.
//!
//! An incoming payment announced at the mempool stage that leaves the
//! wallet with nothing paying it nearly as much in its place, replaced
//! by one that pays elsewhere, one that pays the wallet a few sats, or
//! evicted, is news of its own: [`TxStage::Dropped`], said once.
//!
//! Every function here works on the payload, under the lock of the
//! caller, and does no I/O.

use std::collections::HashMap;

use crate::live::{ANNOUNCED_MAX, LiveTx};
use crate::store::{Announced, TxStage, Unclaimed, VaultPayload};
use crate::wallet::snapshot::NewTx;

/// A transaction as a sync saw it: enough to tell a replacement from a
/// new payment, and a payment that vanished from one replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    pub txid: String,
    /// Net effect on the wallet, in satoshis.
    pub net_sats: i64,
    pub confirmed: bool,
    /// The outputs it spends, txid and index.
    pub spends: Vec<(String, u32)>,
}

impl Seen {
    fn line(&self) -> NewTx {
        NewTx {
            txid: self.txid.clone(),
            net_sats: self.net_sats,
            confirmed: self.confirmed,
        }
    }

    /// Whether this transaction, which spends what `old` spent, is a fee
    /// bump of it: it moves the wallet the same way, and by nearly as
    /// much. A sender who pays the fee out of the amount takes a little
    /// from it with each bump, a tenth at most and never more than
    /// [`BUMP_ALLOWANCE_SATS`]. One who cuts a payment down to a few
    /// sats, so that something still pays the wallet, has not bumped a
    /// fee, and neither has a replacement that sends much more out.
    fn bumps(&self, old: &Seen) -> bool {
        let allowance = (old.net_sats.unsigned_abs() / 10).min(BUMP_ALLOWANCE_SATS);
        self.net_sats.signum() == old.net_sats.signum()
            && i128::from(self.net_sats) >= i128::from(old.net_sats) - i128::from(allowance)
    }
}

/// The most a fee bump may take from what a transaction moves, in
/// satoshis: well past the fee of a replacement, and far short of what
/// is worth stealing.
const BUMP_ALLOWANCE_SATS: u64 = 10_000;

/// What one sync of a wallet moved.
#[derive(Debug, Clone, Default)]
pub(crate) struct Moves {
    /// Transactions seen for the first time.
    pub new: Vec<Seen>,
    /// Transactions pending before the sync and in a block now.
    pub confirmed: Vec<Seen>,
    /// Transactions pending before the sync, as they were then.
    pub pending_before: Vec<Seen>,
    /// Of those, the ones the wallet no longer holds: replaced by a
    /// conflicting transaction, or evicted from the mempool.
    pub gone: Vec<Seen>,
}

impl Moves {
    /// The two lists of a sync report: the transactions seen for the
    /// first time, and those seen confirm.
    pub(crate) fn lines(&self) -> (Vec<NewTx>, Vec<NewTx>) {
        (
            self.new.iter().map(Seen::line).collect(),
            self.confirmed.iter().map(Seen::line).collect(),
        )
    }
}

/// The transactions of `txs` by each output they spend: who conflicts
/// with whom, read in one pass however many inputs a server lists.
fn by_spent(txs: &[Seen]) -> HashMap<(&str, u32), Vec<&Seen>> {
    let mut spenders: HashMap<(&str, u32), Vec<&Seen>> = HashMap::new();
    for tx in txs {
        for (txid, vout) in &tx.spends {
            spenders.entry((txid.as_str(), *vout)).or_default().push(tx);
        }
    }
    spenders
}

/// The transactions of `spenders` that spend an output `tx` spends:
/// the ones it replaces, or that replace it. No more than one of them
/// can ever be in a block.
fn conflicting<'a>(
    spenders: &'a HashMap<(&str, u32), Vec<&'a Seen>>,
    tx: &'a Seen,
) -> impl Iterator<Item = &'a Seen> + 'a {
    tx.spends
        .iter()
        .filter_map(|(txid, vout)| spenders.get(&(txid.as_str(), *vout)))
        .flatten()
        .copied()
        .filter(move |other| other.txid != tx.txid)
}

/// Unclaimed news kept, at most. Past this the oldest goes: it is news
/// no caller took for hundreds of transactions.
pub(crate) const UNCLAIMED_MAX: usize = 500;
/// How long news waits for a claim, in seconds. Longer and it is not
/// news any more: whoever syncs with alerts off and claims nothing
/// would have it all said the day the alerts are turned on.
pub(crate) const UNCLAIMED_FOR: u64 = 12 * 3600;

/// Whether this transaction was announced for this wallet at exactly
/// this stage.
fn announced_as(payload: &VaultPayload, wallet_id: &str, txid: &str, stage: TxStage) -> bool {
    payload
        .announced
        .iter()
        .any(|entry| entry.covers(wallet_id) && entry.txid == txid && entry.stage == stage)
}

/// Whether this transaction is announced at the mempool stage, or
/// waiting to be, for this wallet.
fn pending_said(payload: &VaultPayload, wallet_id: &str, txid: &str) -> bool {
    announced_as(payload, wallet_id, txid, TxStage::Mempool)
        || payload.unclaimed.iter().any(|entry| {
            entry.wallet_id == wallet_id && entry.txid == txid && entry.stage == TxStage::Mempool
        })
}

/// Takes the arrival of a transaction out of the news still waiting.
/// True when there was one.
fn unsay_arrival(payload: &mut VaultPayload, wallet_id: &str, txid: &str) -> bool {
    let before = payload.unclaimed.len();
    payload.unclaimed.retain(|entry| {
        !(entry.wallet_id == wallet_id && entry.txid == txid && entry.stage == TxStage::Mempool)
    });
    payload.unclaimed.len() < before
}

/// A replacement takes the place of what it replaces: in the news still
/// waiting, where the arrival of the one it replaces is, so the
/// notification names the transaction that is there; in the record
/// otherwise, so it is never said.
fn replace(payload: &mut VaultPayload, wallet_id: &str, replaced: &Seen, by: &Seen) {
    let waiting = payload.unclaimed.iter_mut().find(|entry| {
        entry.wallet_id == wallet_id
            && entry.txid == replaced.txid
            && entry.stage == TxStage::Mempool
    });
    match waiting {
        Some(entry) => {
            entry.txid = by.txid.clone();
            entry.net_sats = by.net_sats;
        }
        None => remember(
            payload,
            [Announced {
                wallet_id: wallet_id.to_owned(),
                txid: by.txid.clone(),
                stage: TxStage::Mempool,
            }],
        ),
    }
}

/// Whether this transaction was announced for this wallet at this stage
/// already. A confirmation announced covers its arrival too: nobody is
/// told a transaction is pending after being told it confirmed.
pub(crate) fn told(payload: &VaultPayload, wallet_id: &str, txid: &str, stage: TxStage) -> bool {
    payload.announced.iter().any(|entry| {
        entry.covers(wallet_id)
            && entry.txid == txid
            && (entry.stage == stage
                || (stage == TxStage::Mempool && entry.stage == TxStage::Confirmed))
    })
}

/// Forgets news older than [`UNCLAIMED_FOR`]. A clock set back leaves
/// it be.
fn expire(payload: &mut VaultPayload, now: u64) {
    payload
        .unclaimed
        .retain(|entry| entry.found_at.saturating_add(UNCLAIMED_FOR) >= now);
}

/// Records one piece of news for a wallet, unless it was announced or
/// is waiting already. A confirmation replaces the arrival of the same
/// transaction still waiting: it is said once, as confirmed.
pub(crate) fn push(
    payload: &mut VaultPayload,
    wallet_id: &str,
    txid: &str,
    net_sats: i64,
    stage: TxStage,
    now: u64,
) {
    if told(payload, wallet_id, txid, stage) {
        return;
    }
    let waiting = payload.unclaimed.iter().any(|entry| {
        entry.wallet_id == wallet_id
            && entry.txid == txid
            && (entry.stage == stage
                || (stage == TxStage::Mempool && entry.stage == TxStage::Confirmed))
    });
    if waiting {
        return;
    }
    if stage == TxStage::Confirmed {
        payload.unclaimed.retain(|entry| {
            !(entry.wallet_id == wallet_id && entry.txid == txid && entry.stage == TxStage::Mempool)
        });
    }
    payload.unclaimed.push(Unclaimed {
        wallet_id: wallet_id.to_owned(),
        txid: txid.to_owned(),
        net_sats,
        stage,
        found_at: now,
    });
    let excess = payload.unclaimed.len().saturating_sub(UNCLAIMED_MAX);
    payload.unclaimed.drain(..excess);
}

/// Records what one sync of a wallet found: what it saw for the first
/// time, what it saw confirm, and the payments it saw vanish. A
/// wallet's first sync records nothing: its whole history is "new",
/// and that is an import, not news.
pub(crate) fn record(
    payload: &mut VaultPayload,
    wallet_id: &str,
    first_sync: bool,
    moves: &Moves,
    now: u64,
) {
    expire(payload, now);
    if first_sync {
        return;
    }
    for tx in &moves.confirmed {
        push(
            payload,
            wallet_id,
            &tx.txid,
            tx.net_sats,
            TxStage::Confirmed,
            now,
        );
    }
    let before = by_spent(&moves.pending_before);
    for tx in &moves.new {
        if tx.confirmed {
            push(
                payload,
                wallet_id,
                &tx.txid,
                tx.net_sats,
                TxStage::Confirmed,
                now,
            );
            continue;
        }
        // A fee bump of what was announced: said.
        let replaced = conflicting(&before, tx)
            .find(|old| tx.bumps(old) && pending_said(payload, wallet_id, &old.txid));
        match replaced {
            Some(old) => replace(payload, wallet_id, old, tx),
            None => push(
                payload,
                wallet_id,
                &tx.txid,
                tx.net_sats,
                TxStage::Mempool,
                now,
            ),
        }
    }
    let arrived = by_spent(&moves.new);
    for old in &moves.gone {
        // Never said: nothing to take back.
        if unsay_arrival(payload, wallet_id, &old.txid) {
            continue;
        }
        let said_pending = announced_as(payload, wallet_id, &old.txid, TxStage::Mempool)
            && !announced_as(payload, wallet_id, &old.txid, TxStage::Confirmed);
        if !said_pending || old.net_sats <= 0 {
            continue;
        }
        let paid_instead = conflicting(&arrived, old).any(|tx| tx.bumps(old));
        if !paid_instead {
            push(
                payload,
                wallet_id,
                &old.txid,
                old.net_sats,
                TxStage::Dropped,
                now,
            );
        }
    }
}

/// How much news waits for a wallet.
pub(crate) fn waiting(payload: &VaultPayload, wallet_id: &str, now: u64) -> usize {
    payload
        .unclaimed
        .iter()
        .filter(|entry| entry.wallet_id == wallet_id)
        .filter(|entry| entry.found_at.saturating_add(UNCLAIMED_FOR) >= now)
        .count()
}

/// Takes up to `max` pieces of news waiting for a wallet, oldest first,
/// and records them as announced.
pub(crate) fn claim(
    payload: &mut VaultPayload,
    wallet_id: &str,
    max: usize,
    now: u64,
) -> Vec<LiveTx> {
    expire(payload, now);
    let mut claimed: Vec<LiveTx> = Vec::new();
    let announced = &payload.announced;
    payload.unclaimed.retain(|entry| {
        if entry.wallet_id != wallet_id || claimed.len() >= max {
            return true;
        }
        let already = announced.iter().any(|told| {
            told.covers(wallet_id)
                && told.txid == entry.txid
                && (told.stage == entry.stage
                    || (entry.stage == TxStage::Mempool && told.stage == TxStage::Confirmed))
        });
        if !already {
            claimed.push(LiveTx {
                wallet_id: entry.wallet_id.clone(),
                txid: entry.txid.clone(),
                net_sats: entry.net_sats,
                stage: entry.stage,
            });
        }
        false
    });
    remember(
        payload,
        claimed.iter().map(|tx| Announced {
            wallet_id: tx.wallet_id.clone(),
            txid: tx.txid.clone(),
            stage: tx.stage,
        }),
    );
    claimed
}

/// Adds to the record of what was announced, the oldest forgotten past
/// [`ANNOUNCED_MAX`].
pub(crate) fn remember(payload: &mut VaultPayload, told: impl IntoIterator<Item = Announced>) {
    payload.announced.extend(told);
    let excess = payload.announced.len().saturating_sub(ANNOUNCED_MAX);
    payload.announced.drain(..excess);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn seen(txid: &str, net_sats: i64, confirmed: bool) -> Seen {
        Seen {
            txid: txid.to_owned(),
            net_sats,
            confirmed,
            spends: vec![(format!("parent-of-{txid}"), 0)],
        }
    }

    /// Spending the same output as `other`.
    fn replacing(other: &Seen, txid: &str, net_sats: i64, confirmed: bool) -> Seen {
        Seen {
            txid: txid.to_owned(),
            net_sats,
            confirmed,
            spends: other.spends.clone(),
        }
    }

    fn arrived(new: &[Seen]) -> Moves {
        Moves {
            new: new.to_vec(),
            ..Moves::default()
        }
    }

    fn confirmed(txs: &[Seen]) -> Moves {
        Moves {
            confirmed: txs.to_vec(),
            ..Moves::default()
        }
    }

    fn stages(claimed: &[LiveTx]) -> Vec<(&str, TxStage)> {
        claimed
            .iter()
            .map(|tx| (tx.txid.as_str(), tx.stage))
            .collect()
    }

    #[test]
    fn news_is_claimed_once_by_whoever_asks_first() {
        let mut payload = VaultPayload::default();
        record(
            &mut payload,
            "w",
            false,
            &arrived(&[seen("a", 5, false)]),
            NOW,
        );
        assert_eq!(waiting(&payload, "w", NOW), 1);
        assert!(claim(&mut payload, "other", 10, NOW).is_empty());
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("a", TxStage::Mempool)]);
        assert_eq!(claimed[0].net_sats, 5);
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
        // Seen again, by another sync: said already.
        record(
            &mut payload,
            "w",
            false,
            &arrived(&[seen("a", 5, false)]),
            NOW,
        );
        assert_eq!(waiting(&payload, "w", NOW), 0);
        // Its confirmation is news of its own, once.
        record(
            &mut payload,
            "w",
            false,
            &confirmed(&[seen("a", 5, true)]),
            NOW,
        );
        record(
            &mut payload,
            "w",
            false,
            &confirmed(&[seen("a", 5, true)]),
            NOW,
        );
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("a", TxStage::Confirmed)]
        );
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
    }

    #[test]
    fn a_first_sync_is_an_import_and_records_nothing() {
        let mut payload = VaultPayload::default();
        record(
            &mut payload,
            "w",
            true,
            &arrived(&[seen("old", 1, true), seen("pending", 2, false)]),
            NOW,
        );
        assert_eq!(waiting(&payload, "w", NOW), 0);
        // What was pending then is news when it confirms.
        record(
            &mut payload,
            "w",
            false,
            &confirmed(&[seen("pending", 2, true)]),
            NOW,
        );
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("pending", TxStage::Confirmed)]
        );
    }

    /// One watched wallet pays another: the transaction is news for
    /// each, going out of one and coming into the other, at each stage,
    /// once per wallet, whichever claims first. If it vanishes, the
    /// wallet it was paying is told, and only that one.
    #[test]
    fn a_transfer_between_two_wallets_is_said_for_each() {
        let mut payload = VaultPayload::default();
        let out = seen("t", -40_500, false);
        let into = seen("t", 40_000, false);
        record(
            &mut payload,
            "a",
            false,
            &arrived(std::slice::from_ref(&out)),
            NOW,
        );
        record(
            &mut payload,
            "b",
            false,
            &arrived(std::slice::from_ref(&into)),
            NOW,
        );
        let said_b = claim(&mut payload, "b", 10, NOW);
        let said_a = claim(&mut payload, "a", 10, NOW);
        assert_eq!(stages(&said_a), [("t", TxStage::Mempool)]);
        assert_eq!(stages(&said_b), [("t", TxStage::Mempool)]);
        assert_eq!((said_a[0].net_sats, said_b[0].net_sats), (-40_500, 40_000));
        // Seen again by either: said already, for each.
        record(
            &mut payload,
            "a",
            false,
            &arrived(std::slice::from_ref(&out)),
            NOW,
        );
        record(
            &mut payload,
            "b",
            false,
            &arrived(std::slice::from_ref(&into)),
            NOW,
        );
        assert!(claim(&mut payload, "a", 10, NOW).is_empty());
        assert!(claim(&mut payload, "b", 10, NOW).is_empty());

        let confirm = |tx: &Seen| Seen {
            confirmed: true,
            ..tx.clone()
        };
        record(&mut payload, "a", false, &confirmed(&[confirm(&out)]), NOW);
        assert_eq!(
            stages(&claim(&mut payload, "a", 10, NOW)),
            [("t", TxStage::Confirmed)]
        );
        record(&mut payload, "b", false, &confirmed(&[confirm(&into)]), NOW);
        assert_eq!(
            stages(&claim(&mut payload, "b", 10, NOW)),
            [("t", TxStage::Confirmed)]
        );
        for wallet in ["a", "b"] {
            record(
                &mut payload,
                wallet,
                false,
                &confirmed(&[confirm(&out)]),
                NOW,
            );
            assert!(claim(&mut payload, wallet, 10, NOW).is_empty(), "{wallet}");
        }

        // Another transfer, evicted before it confirms.
        let mut payload = VaultPayload::default();
        let out = seen("u", -10_500, false);
        let into = seen("u", 10_000, false);
        record(
            &mut payload,
            "a",
            false,
            &arrived(std::slice::from_ref(&out)),
            NOW,
        );
        record(
            &mut payload,
            "b",
            false,
            &arrived(std::slice::from_ref(&into)),
            NOW,
        );
        claim(&mut payload, "a", 10, NOW);
        claim(&mut payload, "b", 10, NOW);
        let gone = |tx: &Seen| Moves {
            pending_before: vec![tx.clone()],
            gone: vec![tx.clone()],
            ..Moves::default()
        };
        record(&mut payload, "a", false, &gone(&out), NOW);
        record(&mut payload, "b", false, &gone(&into), NOW);
        assert!(claim(&mut payload, "a", 10, NOW).is_empty());
        assert_eq!(
            stages(&claim(&mut payload, "b", 10, NOW)),
            [("u", TxStage::Dropped)]
        );
    }

    /// A record written before announcements were kept by wallet names
    /// none: it covers every wallet, and nothing it covered is said
    /// again.
    #[test]
    fn a_record_from_before_wallets_covers_every_wallet() {
        let mut stored = serde_json::to_value(VaultPayload::default()).unwrap();
        stored["announced"] = serde_json::json!([{ "txid": "old", "stage": "mempool" }]);
        let mut payload: VaultPayload = serde_json::from_value(stored).unwrap();
        assert_eq!(payload.announced[0].wallet_id, "");
        for wallet in ["a", "b"] {
            record(
                &mut payload,
                wallet,
                false,
                &arrived(&[seen("old", 1, false)]),
                NOW,
            );
            assert!(claim(&mut payload, wallet, 10, NOW).is_empty(), "{wallet}");
        }
    }

    /// Arrived and confirmed before anyone claimed: said once, as
    /// confirmed. And a claim takes no more than it is allowed.
    #[test]
    fn a_confirmation_replaces_an_arrival_nobody_claimed() {
        let mut payload = VaultPayload::default();
        record(
            &mut payload,
            "w",
            false,
            &arrived(&[seen("a", 1, false), seen("b", 2, false)]),
            NOW,
        );
        record(
            &mut payload,
            "w",
            false,
            &confirmed(&[seen("a", 1, true)]),
            NOW,
        );
        let first = claim(&mut payload, "w", 1, NOW);
        assert_eq!(stages(&first), [("b", TxStage::Mempool)]);
        let rest = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&rest), [("a", TxStage::Confirmed)]);
    }

    /// A sender bumps the fee again and again: every replacement pays
    /// the wallet as the first did, none is said again, and the one
    /// that confirms is said once.
    #[test]
    fn a_fee_bump_is_not_said_again() {
        let mut payload = VaultPayload::default();
        let a = seen("a", 50_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&a)),
            NOW,
        );
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("a", TxStage::Mempool)]
        );
        let mut current = a;
        for (txid, sats) in [("b", 49_800), ("c", 49_600), ("d", 49_400)] {
            let bump = replacing(&current, txid, sats, false);
            let moves = Moves {
                new: vec![bump.clone()],
                pending_before: vec![current.clone()],
                gone: vec![current.clone()],
                ..Moves::default()
            };
            record(&mut payload, "w", false, &moves, NOW);
            assert!(claim(&mut payload, "w", 10, NOW).is_empty(), "{txid}");
            current = bump;
        }
        let mined = Seen {
            confirmed: true,
            ..current.clone()
        };
        record(&mut payload, "w", false, &confirmed(&[mined]), NOW);
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("d", TxStage::Confirmed)]
        );
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
    }

    /// Replaced before anyone claimed the first: one notice, naming the
    /// transaction that is there.
    #[test]
    fn a_replacement_takes_the_place_of_an_arrival_nobody_claimed() {
        let mut payload = VaultPayload::default();
        let a = seen("a", 50_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&a)),
            NOW,
        );
        let b = replacing(&a, "b", 49_800, false);
        let moves = Moves {
            new: vec![b],
            pending_before: vec![a.clone()],
            gone: vec![a],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &moves, NOW);
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("b", TxStage::Mempool)]);
        assert_eq!(claimed[0].net_sats, 49_800);
    }

    /// The sender replaces the payment with one that pays elsewhere, or
    /// it is evicted: the wallet holds nothing that pays it instead.
    /// Said once, as dropped. Nothing is taken back that was never said,
    /// and a spend that vanishes is no loss to warn about.
    #[test]
    fn a_payment_that_vanishes_is_said_once() {
        let mut payload = VaultPayload::default();
        let a = seen("a", 50_000, false);
        let out = seen("out", -10_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(&[a.clone(), out.clone()]),
            NOW,
        );
        assert_eq!(claim(&mut payload, "w", 10, NOW).len(), 2);
        let vanished = Moves {
            pending_before: vec![a.clone(), out.clone()],
            gone: vec![a.clone(), out],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &vanished, NOW);
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("a", TxStage::Dropped)]);
        assert_eq!(claimed[0].net_sats, 50_000);
        record(&mut payload, "w", false, &vanished, NOW);
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());

        let x = seen("x", 1_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&x)),
            NOW,
        );
        let unsaid = Moves {
            pending_before: vec![x.clone()],
            gone: vec![x],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &unsaid, NOW);
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
    }

    /// The sender replaces a payment with one that still pays the
    /// wallet, but a few sats: that is no fee bump. The replacement is
    /// said for what it pays, and the payment announced is said to be
    /// dropped. So is a cut past what a fee bump takes, even when most
    /// of the payment is left.
    #[test]
    fn a_replacement_that_cuts_a_payment_is_said() {
        for (kept, cut_to) in [(1_000_000, 1), (1_000_000, 985_000), (50_000, 44_000)] {
            let mut payload = VaultPayload::default();
            let a = seen("a", kept, false);
            record(
                &mut payload,
                "w",
                false,
                &arrived(std::slice::from_ref(&a)),
                NOW,
            );
            assert_eq!(
                stages(&claim(&mut payload, "w", 10, NOW)),
                [("a", TxStage::Mempool)]
            );
            let cut = replacing(&a, "b", cut_to, false);
            let moves = Moves {
                new: vec![cut],
                pending_before: vec![a.clone()],
                gone: vec![a],
                ..Moves::default()
            };
            record(&mut payload, "w", false, &moves, NOW);
            let claimed = claim(&mut payload, "w", 10, NOW);
            assert_eq!(
                stages(&claimed),
                [("b", TxStage::Mempool), ("a", TxStage::Dropped)],
                "{kept} cut to {cut_to}"
            );
            assert_eq!(claimed[0].net_sats, cut_to);
            assert_eq!(claimed[1].net_sats, kept);
        }
    }

    /// Cut before anyone claimed the payment: one notice, for what the
    /// replacement pays, and nothing to take back.
    #[test]
    fn a_cut_before_the_payment_was_said_is_said_once() {
        let mut payload = VaultPayload::default();
        let a = seen("a", 1_000_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&a)),
            NOW,
        );
        let moves = Moves {
            new: vec![replacing(&a, "b", 1, false)],
            pending_before: vec![a.clone()],
            gone: vec![a],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &moves, NOW);
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("b", TxStage::Mempool)]);
        assert_eq!(claimed[0].net_sats, 1);
    }

    /// A spend bumped from the change is not said again. One replaced
    /// by a transaction that sends far more out is said: whoever holds
    /// the keys redirected it.
    #[test]
    fn a_spend_replaced_by_a_larger_one_is_said() {
        let mut payload = VaultPayload::default();
        let out = seen("out", -20_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&out)),
            NOW,
        );
        assert_eq!(claim(&mut payload, "w", 10, NOW).len(), 1);
        let bumped = replacing(&out, "bumped", -21_000, false);
        let moves = Moves {
            new: vec![bumped.clone()],
            pending_before: vec![out.clone()],
            gone: vec![out],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &moves, NOW);
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
        let drained = replacing(&bumped, "drained", -900_000, false);
        let moves = Moves {
            new: vec![drained.clone()],
            pending_before: vec![bumped.clone()],
            gone: vec![bumped],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &moves, NOW);
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("drained", TxStage::Mempool)]);
        assert_eq!(claimed[0].net_sats, -900_000);
    }

    /// Replaced by a transaction that pays the wallet and is already in
    /// a block: its confirmation is said, and nothing vanished.
    #[test]
    fn a_replacement_that_confirms_is_said_once() {
        let mut payload = VaultPayload::default();
        let a = seen("a", 50_000, false);
        record(
            &mut payload,
            "w",
            false,
            &arrived(std::slice::from_ref(&a)),
            NOW,
        );
        claim(&mut payload, "w", 10, NOW);
        let mined = replacing(&a, "b", 49_800, true);
        let moves = Moves {
            new: vec![mined],
            pending_before: vec![a.clone()],
            gone: vec![a],
            ..Moves::default()
        };
        record(&mut payload, "w", false, &moves, NOW);
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("b", TxStage::Confirmed)]
        );
    }

    #[test]
    fn news_nobody_claims_is_forgotten_in_time_and_in_number() {
        let mut payload = VaultPayload::default();
        record(
            &mut payload,
            "w",
            false,
            &arrived(&[seen("a", 1, false)]),
            NOW,
        );
        let later = NOW + UNCLAIMED_FOR + 1;
        assert_eq!(waiting(&payload, "w", later), 0);
        assert!(claim(&mut payload, "w", 10, later).is_empty());

        let many: Vec<Seen> = (0..UNCLAIMED_MAX + 20)
            .map(|n| seen(&format!("t{n}"), 1, false))
            .collect();
        record(&mut payload, "w", false, &arrived(&many), NOW);
        assert_eq!(payload.unclaimed.len(), UNCLAIMED_MAX);
        assert_eq!(payload.unclaimed[0].txid, "t20", "the oldest went first");
    }
}
