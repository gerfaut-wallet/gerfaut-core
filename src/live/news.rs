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
//! Every function here works on the payload, under the lock of the
//! caller, and does no I/O.

use crate::live::{ANNOUNCED_MAX, LiveTx};
use crate::store::{Announced, TxStage, Unclaimed, VaultPayload};
use crate::wallet::snapshot::NewTx;

/// Unclaimed news kept, at most. Past this the oldest goes: it is news
/// no caller took for hundreds of transactions.
pub(crate) const UNCLAIMED_MAX: usize = 500;
/// How long news waits for a claim, in seconds. Longer and it is not
/// news any more: whoever syncs with alerts off and claims nothing
/// would have it all said the day the alerts are turned on.
pub(crate) const UNCLAIMED_FOR: u64 = 12 * 3600;

/// Whether this transaction was announced at this stage already. A
/// confirmation announced covers its arrival too: nobody is told a
/// transaction is pending after being told it confirmed.
pub(crate) fn told(payload: &VaultPayload, txid: &str, stage: TxStage) -> bool {
    payload.announced.iter().any(|entry| {
        entry.txid == txid
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
    if told(payload, txid, stage) {
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
/// time, and what it saw confirm. A wallet's first sync records
/// nothing: its whole history is "new", and that is an import, not
/// news.
pub(crate) fn record(
    payload: &mut VaultPayload,
    wallet_id: &str,
    first_sync: bool,
    new: &[NewTx],
    confirmed: &[NewTx],
    now: u64,
) {
    expire(payload, now);
    if first_sync {
        return;
    }
    for tx in confirmed {
        push(
            payload,
            wallet_id,
            &tx.txid,
            tx.net_sats,
            TxStage::Confirmed,
            now,
        );
    }
    for tx in new {
        let stage = if tx.confirmed {
            TxStage::Confirmed
        } else {
            TxStage::Mempool
        };
        push(payload, wallet_id, &tx.txid, tx.net_sats, stage, now);
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
            told.txid == entry.txid
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

    fn seen(txid: &str, net_sats: i64, confirmed: bool) -> NewTx {
        NewTx {
            txid: txid.to_owned(),
            net_sats,
            confirmed,
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
        record(&mut payload, "w", false, &[seen("a", 5, false)], &[], NOW);
        assert_eq!(waiting(&payload, "w", NOW), 1);
        assert!(claim(&mut payload, "other", 10, NOW).is_empty());
        let claimed = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&claimed), [("a", TxStage::Mempool)]);
        assert_eq!(claimed[0].net_sats, 5);
        assert!(claim(&mut payload, "w", 10, NOW).is_empty());
        // Seen again, by another sync: said already.
        record(&mut payload, "w", false, &[seen("a", 5, false)], &[], NOW);
        assert_eq!(waiting(&payload, "w", NOW), 0);
        // Its confirmation is news of its own, once.
        record(&mut payload, "w", false, &[], &[seen("a", 5, true)], NOW);
        record(&mut payload, "w", false, &[], &[seen("a", 5, true)], NOW);
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
            &[seen("old", 1, true), seen("pending", 2, false)],
            &[],
            NOW,
        );
        assert_eq!(waiting(&payload, "w", NOW), 0);
        // What was pending then is news when it confirms.
        record(
            &mut payload,
            "w",
            false,
            &[],
            &[seen("pending", 2, true)],
            NOW,
        );
        assert_eq!(
            stages(&claim(&mut payload, "w", 10, NOW)),
            [("pending", TxStage::Confirmed)]
        );
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
            &[seen("a", 1, false), seen("b", 2, false)],
            &[],
            NOW,
        );
        record(&mut payload, "w", false, &[], &[seen("a", 1, true)], NOW);
        let first = claim(&mut payload, "w", 1, NOW);
        assert_eq!(stages(&first), [("b", TxStage::Mempool)]);
        let rest = claim(&mut payload, "w", 10, NOW);
        assert_eq!(stages(&rest), [("a", TxStage::Confirmed)]);
    }

    #[test]
    fn news_nobody_claims_is_forgotten_in_time_and_in_number() {
        let mut payload = VaultPayload::default();
        record(&mut payload, "w", false, &[seen("a", 1, false)], &[], NOW);
        let later = NOW + UNCLAIMED_FOR + 1;
        assert_eq!(waiting(&payload, "w", later), 0);
        assert!(claim(&mut payload, "w", 10, later).is_empty());

        let many: Vec<NewTx> = (0..UNCLAIMED_MAX + 20)
            .map(|n| seen(&format!("t{n}"), 1, false))
            .collect();
        record(&mut payload, "w", false, &many, &[], NOW);
        assert_eq!(payload.unclaimed.len(), UNCLAIMED_MAX);
        assert_eq!(payload.unclaimed[0].txid, "t20", "the oldest went first");
    }
}
