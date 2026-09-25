//! A descriptor wallet read from an Esplora server, asking for no more
//! than the wallet lacks.
//!
//! An Esplora server lists the history of a script in pages, newest
//! first: every unconfirmed transaction and the 25 latest confirmed ones,
//! then 25 at a time. Each comes whole, with the coins it spends, so a
//! page weighs tens of kilobytes where the list of its txids would weigh
//! one. Read from the top every time, as the engine of BDK reads it, the
//! history of a busy wallet cost megabytes at each sync.
//!
//! Here each script is read the way the plan asks:
//!
//! - Its counters first (`/scripthash/:hash`, a few hundred bytes). A
//!   [`Reading::Checked`] plan compares them with what the wallet holds
//!   for the script and reads nothing more when they agree: nothing
//!   arrived, left the mempool or confirmed there.
//! - Then its pages, down to the first transaction the wallet already
//!   holds confirmed in the same block, and no further once what the
//!   wallet holds and what was read together make up the count the
//!   server gave: nothing older is missing. The first page lists every
//!   unconfirmed transaction, so a replacement or an eviction is seen
//!   whatever page the reading stops at.
//!
//! A transaction the wallet holds is not taken again, only where it now
//! stands. The keychains walked past what the wallet knows are read
//! whole, as before: those scripts are empty, or new to the wallet.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use bdk_esplora::esplora_client::api::{ScriptHashStats, TxStatus};
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use futures_util::future::try_join_all;

use super::page::PageTx;
use super::{Client, Counts, PARALLEL_REQUESTS};
use crate::chain::{Held, Plan, Reading, Scan, ScriptFacts};

/// Confirmed transactions an Esplora server lists per page.
const PAGE: usize = 25;
/// Pages read of one script at most: 10,000 confirmed transactions. A
/// server that keeps listing new ones past that is refused rather than
/// read on until the deadline, holding every page in memory.
const MAX_PAGES: usize = 400;

/// The part of a block summary that is read.
#[derive(serde::Deserialize)]
struct Block {
    id: BlockHash,
    height: u32,
}

/// A transaction a history lists: where it stands, and, when the wallet
/// lacks it, the transaction and the coins it spends. What the wallet
/// holds already is not kept.
struct Listed {
    txid: Txid,
    status: TxStatus,
    whole: Option<(Transaction, Vec<(OutPoint, TxOut)>)>,
}

/// A page as the engine keeps it: see [`Listed`].
fn listed(page: Vec<PageTx>, held: &Held) -> Result<Vec<Listed>, String> {
    page.into_iter()
        .map(|tx| {
            let whole = if held.txs.contains_key(&tx.txid) {
                None
            } else {
                let whole = tx.to_tx();
                // The txid commits to the transaction: one that does not
                // hash to it is not the one listed.
                if whole.compute_txid() != tx.txid {
                    return Err(
                        "the server answered with another transaction than the one it listed"
                            .to_owned(),
                    );
                }
                Some((whole, tx.prevouts().collect()))
            };
            Ok(Listed {
                txid: tx.txid,
                status: tx.status,
                whole,
            })
        })
        .collect()
}

/// What was read of one script.
#[derive(Default)]
struct Read {
    txs: Vec<Listed>,
    /// Transactions the wallet expected there that the server no longer
    /// lists.
    evicted: Vec<Txid>,
    /// Whether the script has any history at all, read or not.
    used: bool,
}

/// Runs a plan against one instance.
pub(crate) async fn run(client: &Client, plan: Plan) -> Result<bdk_wallet::Update, String> {
    let Plan {
        tip,
        start_time,
        scripts,
        scans,
        stop_gap,
        reading,
        held,
    } = plan;
    // Before any history, and so never past it: the tip of the answer
    // is what the wallet counts itself synced up to.
    let latest = latest_blocks(client).await?;
    let meeting = Meeting::find(client, &latest, &tip).await?;
    let mut found = Found::new(start_time);

    let mut covered: HashSet<ScriptBuf> = scripts.iter().cloned().collect();
    for batch in scripts.chunks(PARALLEL_REQUESTS) {
        let mut reads = Vec::with_capacity(batch.len());
        for script in batch {
            reads.push(read_script(client, script, &held, reading, meeting.height));
        }
        for read in try_join_all(reads).await? {
            found.take(read)?;
        }
    }

    let mut last_active = BTreeMap::new();
    for Scan { keychain, mut spks } in scans {
        let mut unused = 0usize;
        loop {
            let batch: Vec<(u32, ScriptBuf)> = spks.by_ref().take(PARALLEL_REQUESTS).collect();
            if batch.is_empty() {
                break;
            }
            let mut reads = Vec::with_capacity(batch.len());
            for (_, script) in &batch {
                reads.push(read_scanned(client, script, &held, meeting.height));
                covered.insert(script.clone());
            }
            for ((index, _), read) in batch.iter().zip(try_join_all(reads).await?) {
                if !read.used {
                    unused = unused.saturating_add(1);
                } else {
                    unused = 0;
                    last_active.insert(keychain, *index);
                }
                found.take(read)?;
            }
            if unused >= (stop_gap as usize).max(1) {
                break;
            }
        }
    }

    // The scripts of the confirmations a reorganisation moved, read
    // whatever the plan: see [`Held::reorganised`].
    let moved = held.reorganised(meeting.height, &covered);
    for batch in moved.chunks(PARALLEL_REQUESTS) {
        let mut reads = Vec::with_capacity(batch.len());
        for script in batch {
            reads.push(read_script(
                client,
                script,
                &held,
                Reading::Complete,
                meeting.height,
            ));
        }
        for read in try_join_all(reads).await? {
            found.take(read)?;
        }
    }

    let update = found.update;
    let chain = meeting.chain(client, &latest, &update.anchors).await?;
    Ok(bdk_wallet::Update {
        last_active_indices: last_active,
        tx_update: update,
        chain: Some(chain),
    })
}

/// The path of a script on the server: SHA-256 of the script, in the
/// order it was computed (Electrum reverses it, Esplora does not).
pub(crate) fn script_path(script: &ScriptBuf) -> String {
    format!("/scripthash/{:x}", sha256::Hash::hash(script.as_bytes()))
}

/// One script of the plan: its counters, then what they call for.
///
/// Counters that agree with what the wallet holds say nothing arrived,
/// left or confirmed there, and nothing more is read, with two
/// exceptions. A script holding a confirmation in a block the server no
/// longer has is read, a reorganisation having moved it; and a
/// [`Reading::Complete`] plan lists the unconfirmed transactions of a
/// script that has some, a replacement paying the same amount to the
/// same script leaving the counters as they were.
async fn read_script(
    client: &Client,
    script: &ScriptBuf,
    held: &Held,
    reading: Reading,
    agreed_up_to: u32,
) -> Result<Read, String> {
    let stats: ScriptHashStats = client.get_json(&script_path(script)).await?;
    let used = stats.chain_stats.tx_count > 0 || stats.mempool_stats.tx_count > 0;
    let facts = held.scripts.get(script).cloned().unwrap_or_default();
    let reorganised = facts.confirmed.iter().any(|txid| {
        held.anchors
            .get(txid)
            .is_some_and(|anchor| anchor.block_id.height > agreed_up_to)
    });
    if Counts::of(&stats) == facts.counts && !reorganised {
        if reading == Reading::Checked || stats.mempool_stats.tx_count == 0 {
            return Ok(Read {
                used,
                ..Read::default()
            });
        }
        let path = format!("{}/txs/mempool", script_path(script));
        let txs = listed(client.get_page(&path).await?, held)?;
        let listed_mempool = txs.len();
        let mut read = Read {
            txs,
            evicted: Vec::new(),
            used,
        };
        read.evicted = evicted(&read, &facts, &stats, listed_mempool, false);
        return Ok(read);
    }
    let (mut read, listed_mempool, whole) =
        read_pages_down_to(client, script, held, Some((&facts, &stats))).await?;
    read.evicted = evicted(&read, &facts, &stats, listed_mempool, whole);
    read.used |= used;
    Ok(read)
}

/// A script of a keychain walked past what the wallet knows: one the
/// wallet already holds, in a rescan, as a script of the plan is read;
/// any other, every page, it being empty or new to the wallet.
async fn read_scanned(
    client: &Client,
    script: &ScriptBuf,
    held: &Held,
    agreed_up_to: u32,
) -> Result<Read, String> {
    if held.scripts.contains_key(script) {
        return read_script(client, script, held, Reading::Complete, agreed_up_to).await;
    }
    read_pages_down_to(client, script, held, None)
        .await
        .map(|(read, _, _)| read)
}

/// Reads the pages of a script, newest first: every page, or with
/// `known`, down to what the wallet holds, as [`enough`] decides. Also
/// says how many unconfirmed transactions the first page listed, and
/// whether the pages were read to the end.
async fn read_pages_down_to(
    client: &Client,
    script: &ScriptBuf,
    held: &Held,
    known: Option<(&ScriptFacts, &ScriptHashStats)>,
) -> Result<(Read, usize, bool), String> {
    let base = format!("{}/txs", script_path(script));
    let mut txs: Vec<Listed> = Vec::new();
    let mut after: Option<Txid> = None;
    let mut listed_mempool = 0usize;
    let mut whole = false;
    for pages in 1.. {
        if pages > MAX_PAGES {
            return Err(format!(
                "the server lists more than {} transactions for one address",
                MAX_PAGES * PAGE
            ));
        }
        let path = match after {
            Some(txid) => format!("{base}/chain/{txid}"),
            None => base.clone(),
        };
        let page = listed(client.get_page(&path).await?, held)?;
        let confirmed = page.iter().filter(|tx| tx.status.confirmed).count();
        if after.is_none() {
            listed_mempool = page.len() - confirmed;
        }
        let next = page
            .iter()
            .rev()
            .find(|tx| tx.status.confirmed)
            .map(|tx| tx.txid);
        txs.extend(page);
        if confirmed < PAGE || next.is_none() || next == after {
            whole = true;
            break;
        }
        if let Some((facts, stats)) = known
            && enough(&txs, facts, held, stats)
        {
            break;
        }
        after = next;
    }
    Ok((
        Read {
            used: !txs.is_empty(),
            txs,
            evicted: Vec::new(),
        },
        listed_mempool,
        whole,
    ))
}

/// The transactions the wallet expected on a script that the server no
/// longer lists: they left the mempool, or a reorganisation took them
/// out of the chain.
fn evicted(
    read: &Read,
    facts: &ScriptFacts,
    stats: &ScriptHashStats,
    listed_mempool: usize,
    whole: bool,
) -> Vec<Txid> {
    // A server lists 50 unconfirmed transactions at most: past that, one
    // missing from the list may only have been left off it.
    if (listed_mempool as u64) < u64::from(stats.mempool_stats.tx_count) {
        return Vec::new();
    }
    let listed: HashSet<Txid> = read.txs.iter().map(|tx| tx.txid).collect();
    facts
        .expected
        .iter()
        // Read to the end, the whole history is there. Otherwise only
        // what the wallet holds unconfirmed must be: the rest sits
        // below where the reading stopped.
        .filter(|txid| whole || !facts.confirmed.contains(*txid))
        .filter(|txid| !listed.contains(*txid))
        .copied()
        .collect()
}

/// Whether the pages read so far leave nothing out: every transaction
/// the wallet holds unconfirmed on the script is listed, the reading has
/// reached one it holds confirmed in the same block, and what it holds
/// and what was read together make up the server's count.
fn enough(txs: &[Listed], facts: &ScriptFacts, held: &Held, stats: &ScriptHashStats) -> bool {
    let listed: HashSet<Txid> = txs.iter().map(|tx| tx.txid).collect();
    let pending = facts
        .expected
        .iter()
        .filter(|txid| !facts.confirmed.contains(*txid));
    if pending.clone().any(|txid| !listed.contains(txid)) {
        return false;
    }
    let reached = txs.iter().any(|tx| {
        tx.status.confirmed
            && facts.confirmed.contains(&tx.txid)
            && held
                .anchors
                .get(&tx.txid)
                .is_some_and(|anchor| Some(anchor.block_id.hash) == tx.status.block_hash)
    });
    if !reached {
        return false;
    }
    let read_confirmed: HashSet<Txid> = txs
        .iter()
        .filter(|tx| tx.status.confirmed)
        .map(|tx| tx.txid)
        .collect();
    let covered = facts.confirmed.union(&read_confirmed).count();
    covered as u64 >= u64::from(stats.chain_stats.tx_count)
}

/// The update being put together.
struct Found {
    start_time: u64,
    update: TxUpdate<ConfirmationBlockTime>,
    taken: HashSet<Txid>,
}

impl Found {
    fn new(start_time: u64) -> Self {
        Found {
            start_time,
            update: TxUpdate::default(),
            taken: HashSet::new(),
        }
    }

    /// Takes what was read of one script: where each transaction stands,
    /// the ones the wallet lacks with the coins they spend, and what left
    /// the mempool.
    fn take(&mut self, read: Read) -> Result<(), String> {
        for tx in read.txs {
            let txid = tx.txid;
            if !self.taken.insert(txid) {
                continue;
            }
            match (
                tx.status.block_height,
                tx.status.block_hash,
                tx.status.block_time,
            ) {
                (Some(height), Some(hash), Some(time)) if tx.status.confirmed => {
                    self.update.anchors.insert((
                        ConfirmationBlockTime {
                            block_id: BlockId { height, hash },
                            confirmation_time: time,
                        },
                        txid,
                    ));
                }
                _ => {
                    self.update.seen_ats.insert((txid, self.start_time));
                }
            }
            let Some((whole, prevouts)) = tx.whole else {
                continue;
            };
            self.update.txouts.extend(prevouts);
            self.update.txs.push(Arc::new(whole));
        }
        self.update
            .evicted_ats
            .extend(read.evicted.into_iter().map(|txid| (txid, self.start_time)));
        Ok(())
    }
}

/// The latest blocks, by height: ten on the instances there are.
async fn latest_blocks(client: &Client) -> Result<BTreeMap<u32, BlockHash>, String> {
    let blocks: Vec<Block> = client.get_json("/blocks").await?;
    if blocks.is_empty() {
        return Err("unexpected response".to_owned());
    }
    Ok(blocks
        .into_iter()
        .map(|block| (block.height, block.id))
        .collect())
}

/// The hash of the block at `height`: from the latest blocks when it is
/// one of them, asked for otherwise, and `None` above the latest tip.
async fn block_at(
    client: &Client,
    latest: &BTreeMap<u32, BlockHash>,
    height: u32,
) -> Result<Option<BlockHash>, String> {
    if let Some(hash) = latest.get(&height) {
        return Ok(Some(*hash));
    }
    if latest
        .keys()
        .next_back()
        .is_none_or(|&tip_height| height > tip_height)
    {
        return Ok(None);
    }
    let text = client.get_bytes(&format!("/block-height/{height}")).await?;
    std::str::from_utf8(&text)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .map(Some)
        .ok_or_else(|| "unexpected response".to_owned())
}

/// Where the wallet's chain and the server's meet: the last block both
/// have, and the server's blocks at the heights of the wallet's above it.
struct Meeting {
    agreement: CheckPoint,
    /// The height of `agreement`: a confirmation the wallet holds above
    /// it sits in a block the server no longer has.
    height: u32,
    conflicts: Vec<BlockId>,
}

impl Meeting {
    /// Walks the wallet's chain down from its tip to a block the server
    /// has too.
    async fn find(
        client: &Client,
        latest: &BTreeMap<u32, BlockHash>,
        local_tip: &CheckPoint,
    ) -> Result<Self, String> {
        let mut conflicts = Vec::new();
        for local in local_tip.iter() {
            let Some(remote) = block_at(client, latest, local.height()).await? else {
                continue;
            };
            if remote == local.hash() {
                return Ok(Meeting {
                    height: local.height(),
                    agreement: local,
                    conflicts,
                });
            }
            conflicts.push(BlockId {
                height: local.height(),
                hash: remote,
            });
        }
        Err("the server's chain never meets the wallet's".to_owned())
    }

    /// The wallet's chain as the server sees it: from the meeting point,
    /// the server's blocks where the wallet's differ, one per height a
    /// transaction confirmed at, and the latest ones. The engine of BDK
    /// builds it this way.
    async fn chain(
        self,
        client: &Client,
        latest: &BTreeMap<u32, BlockHash>,
        anchors: &BTreeSet<(ConfirmationBlockTime, Txid)>,
    ) -> Result<CheckPoint, String> {
        let meeting = self.height;
        let mut tip = self
            .agreement
            .extend(self.conflicts.into_iter().rev())
            .map_err(|_| "the server's chain never meets the wallet's".to_owned())?;
        for (anchor, _) in anchors {
            let height = anchor.block_id.height;
            if tip.get(height).is_none()
                && let Some(hash) = block_at(client, latest, height).await?
            {
                tip = tip.insert(BlockId { height, hash });
            }
        }
        for (&height, &hash) in latest {
            // Below the meeting point the two chains are one: a latest
            // block that says otherwise is a server contradicting itself,
            // refused, since putting it in would replace the wallet's
            // genesis block, or blocks both agreed on.
            if height <= meeting {
                if tip.get(height).is_some_and(|held| held.hash() != hash) {
                    return Err("the server's chain contradicts itself".to_owned());
                }
                if tip.get(height).is_some() {
                    continue;
                }
            }
            tip = tip.insert(BlockId { height, hash });
        }
        Ok(tip)
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::hashes::Hash;

    use super::*;

    /// A server whose latest blocks contradict, below the meeting point,
    /// the chain it agreed on: a genesis block of its own among them. The
    /// sync fails; it neither panics nor replaces the wallet's genesis.
    #[tokio::test]
    async fn latest_blocks_that_contradict_the_meeting_are_refused() {
        let hash = |byte: u8| BlockHash::from_byte_array([byte; 32]);
        let local = CheckPoint::new(BlockId {
            height: 0,
            hash: hash(0),
        })
        .push(BlockId {
            height: 1,
            hash: hash(1),
        })
        .unwrap();
        let meeting = || Meeting {
            agreement: local.clone(),
            height: 1,
            conflicts: Vec::new(),
        };
        // Never asked anything: every height it needs is in the latest.
        let client = super::super::client("http://127.0.0.1:9", None).unwrap();
        let lying = BTreeMap::from([(0, hash(9)), (1, hash(1)), (2, hash(2))]);
        let refused = meeting()
            .chain(&client, &lying, &BTreeSet::new())
            .await
            .unwrap_err();
        assert!(refused.contains("contradicts"), "{refused}");

        let honest = BTreeMap::from([(0, hash(0)), (1, hash(1)), (2, hash(2))]);
        let tip = meeting()
            .chain(&client, &honest, &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(tip.height(), 2);
        assert_eq!(tip.get(0).unwrap().hash(), hash(0));
    }
}
