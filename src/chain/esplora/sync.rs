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
//!
//! A confirmation the wallet does not hold in the same block is proven
//! before it is taken ([`prove`]): its merkle branch, and the header of
//! its block, both from the server that listed it, as an Electrum
//! server's are. Two requests for the first confirmation of a block, one
//! for each other one in it; none for a confirmation the wallet holds.
//! One in the first years of the chain is chained to its checkpoint too
//! ([`read_chains`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use super::api::{ScriptHashStats, TxStatus};
use bdk_wallet::bitcoin::block::{Header, Version};
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::{
    BlockHash, CompactTarget, OutPoint, ScriptBuf, Transaction, TxMerkleNode, TxOut, Txid,
};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use electrum_client::GetMerkleRes;
use futures_util::future::try_join_all;

use super::page::PageTx;
use super::{Client, Counts, PAGE, PARALLEL_REQUESTS};
use crate::chain::proof::{
    Proof, above_the_tip, chain_to_checkpoint, chained, chains_to_read, check_confirmation,
    esplora_chains, recheck,
};
use crate::chain::{
    Fault, Held, IMPOSSIBLE_TIP, Plan, Reading, Scan, ScriptFacts, Synced, TIP_LAG_MAX,
    has_proof_of_work, height_limit,
};
use crate::network::Network;
/// Pages read of one script at most: 10,000 confirmed transactions. A
/// server that keeps listing new ones past that is refused rather than
/// read on until the deadline, holding every page in memory.
const MAX_PAGES: usize = 400;

/// Latest blocks kept of what a server lists: the ten Esplora lists.
const LATEST: usize = 10;

/// Blocks Esplora lists a request, down from the height asked
/// (`/blocks/:height`): ten on Blockstream's electrs and on mempool's,
/// whose limit an operator may lower.
const BLOCKS_PER_REQUEST: u32 = 10;

/// Requests one proving of confirmations may spend chaining them to
/// their checkpoints ([`crate::chain::proof::esplora_chains`]): two
/// periods at worst, four on average, about what the first sync of a
/// wallet of a few dozen addresses costs. A confirmation whose period
/// does not fit is left unconfirmed, and the next sync goes on, the
/// periods chained being kept for the session.
const CHAIN_REQUESTS_MAX: u32 = 404;

/// A block as Esplora sums it up: its height, and every field of its
/// header, which make its hash.
#[derive(serde::Deserialize)]
struct Block {
    id: BlockHash,
    height: u32,
    version: u32,
    timestamp: u32,
    bits: u32,
    nonce: u32,
    merkle_root: TxMerkleNode,
    /// `None` for the genesis block alone.
    #[serde(default)]
    previousblockhash: Option<BlockHash>,
}

impl Block {
    /// The header the summary spells out. Its hash is the block's only
    /// if the summary told the truth: [`Block::id`] is a claim.
    fn header(&self) -> Header {
        Header {
            version: Version::from_consensus(self.version as i32),
            prev_blockhash: self.previousblockhash.unwrap_or_else(BlockHash::all_zeros),
            merkle_root: self.merkle_root,
            time: self.timestamp,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
        }
    }
}

/// A transaction a history lists: where it stands, and, when the wallet
/// lacks it, the transaction and the coins it spends. What the wallet
/// holds already is not kept.
struct Listed {
    txid: Txid,
    status: TxStatus,
    whole: Option<(Transaction, Vec<(OutPoint, TxOut)>)>,
}

/// A page as the engine keeps it: see [`Listed`]. What it keeps counts
/// against what the sync may keep.
fn listed(client: &Client, page: Vec<PageTx>, held: &Held) -> Result<Vec<Listed>, Fault> {
    page.into_iter()
        .map(|tx| {
            let whole = if held.txs.contains_key(&tx.txid) {
                None
            } else {
                let whole = tx.to_tx();
                // The txid commits to the transaction: one that does not
                // hash to it is not the one listed.
                if whole.compute_txid() != tx.txid {
                    return Err(Fault::other(
                        "the server answered with another transaction than the one it listed",
                    ));
                }
                let prevouts: Vec<(OutPoint, TxOut)> = tx.prevouts().collect();
                let spent: usize = prevouts
                    .iter()
                    .map(|(_, out)| 44 + out.script_pubkey.len())
                    .sum();
                client.keep(whole.total_size().saturating_add(spent))?;
                Some((whole, prevouts))
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
pub(crate) async fn run(client: &Client, plan: Plan) -> Result<Synced, Fault> {
    let Plan {
        network,
        tip,
        start_time,
        scripts,
        scans,
        stop_gap,
        reading,
        held,
        // Esplora gives no status to check a history against.
        told: _,
    } = plan;
    // Before any history, and so never past it: the tip of the answer
    // is what the wallet counts itself synced up to.
    let limit = height_limit(network, start_time);
    let latest = latest_blocks(client, network, limit).await?;
    let server_tip = latest.keys().next_back().copied().unwrap_or_default();
    // The wallet's blocks far above the server's tip, or past any height
    // a chain can have reached, came from a server that made them up:
    // left out of the walk, and dropped (see [`Synced::drop_above`]).
    let (tip, dropped) =
        if tip.height() > server_tip.saturating_add(TIP_LAG_MAX) || tip.height() > limit {
            let kept = tip
                .iter()
                .find(|checkpoint| checkpoint.height() <= server_tip)
                .unwrap_or_else(|| tip.clone());
            (kept, Some(server_tip))
        } else {
            (tip, None)
        };
    let meeting = Meeting::find(client, network, &latest, &tip).await?;
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

    let mut update = found.update;
    check_spent(&held, &update)?;
    prove(client, network, server_tip, &held, start_time, &mut update).await?;
    let chain = meeting.chain(client, &latest, &update.anchors).await?;
    Ok(Synced {
        update: bdk_wallet::Update {
            last_active_indices: last_active,
            tx_update: update,
            chain: Some(chain),
        },
        orders: Vec::new(),
        drop_above: dropped,
        set_aside: false,
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
) -> Result<Read, Fault> {
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
        let txs = listed(client, client.get_page(&path).await?, held)?;
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
) -> Result<Read, Fault> {
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
) -> Result<(Read, usize, bool), Fault> {
    let base = format!("{}/txs", script_path(script));
    let mut txs: Vec<Listed> = Vec::new();
    let mut after: Option<Txid> = None;
    let mut listed_mempool = 0usize;
    let mut whole = false;
    for pages in 1.. {
        if pages > MAX_PAGES {
            return Err(Fault::other(format!(
                "the server lists more than {} transactions for one address",
                MAX_PAGES * PAGE
            )));
        }
        let path = match after {
            Some(txid) => format!("{base}/chain/{txid}"),
            None => base.clone(),
        };
        let page = listed(client, client.get_page(&path).await?, held)?;
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

/// Refuses a server that says a coin a new transaction spends is other
/// than what the transaction that pays it pays, when the wallet holds
/// that transaction or this sync read it ([`COIN_NOT_PAID`]): those
/// hash to their txids, the coins Esplora attaches to each input do
/// not. A coin of the wallet's is one of them once the history of its
/// script is read, as long as the server lists there the transaction
/// that paid it: what a transaction spends of the wallet, and so what it
/// sends, is then the transaction's word and not the server's. A server
/// that leaves that transaction out of the history, its counters
/// lowered to match, still has its word taken for the coin, which moves
/// what the transaction shows sent, never the balance, made of the
/// wallet's own outputs. The coins of others whose transaction neither
/// holds are the server's word still, as they are for a watched
/// address: they make the fee shown, and the facts read of an input.
/// Reading each of their transactions would prove them: a request for
/// each payer's transaction, a third more requests for the first sync of
/// a wallet of twenty addresses paid twice each (122 requests, measured
/// against a server of the tests), 42 per cent more for one of a hundred
/// addresses paid five times each (1,202), as much again for each other
/// coin a payer spends, and every byte of those transactions, for
/// figures that do not move the balance.
fn check_spent(held: &Held, update: &TxUpdate<ConfirmationBlockTime>) -> Result<(), Fault> {
    let read: HashMap<Txid, &Transaction> = update
        .txs
        .iter()
        .map(|tx| (tx.compute_txid(), tx.as_ref()))
        .collect();
    for (outpoint, said) in &update.txouts {
        let paying = held
            .txs
            .get(&outpoint.txid)
            .map(|tx| tx.as_ref())
            .or_else(|| read.get(&outpoint.txid).copied());
        let Some(paying) = paying else {
            continue;
        };
        if paying.output.get(outpoint.vout as usize) != Some(said) {
            return Err(Fault::coin_not_paid());
        }
    }
    Ok(())
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
    fn take(&mut self, read: Read) -> Result<(), Fault> {
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

/// Proves the confirmations of `update` the wallet does not hold in the
/// same block ([`prove_confirmations`]). One proven takes the time of its
/// block's header; one unsure is taken as unconfirmed, as the server's
/// word alone is; a false one refuses the server.
async fn prove(
    client: &Client,
    network: Network,
    tip: u32,
    held: &Held,
    start_time: u64,
    update: &mut TxUpdate<ConfirmationBlockTime>,
) -> Result<(), Fault> {
    let new: Vec<(ConfirmationBlockTime, Txid)> = update
        .anchors
        .iter()
        .filter(|(anchor, txid)| {
            held.anchors
                .get(txid)
                .is_none_or(|held| held.block_id != anchor.block_id)
        })
        .copied()
        .collect();
    let claimed: Vec<(Txid, BlockId)> = new
        .iter()
        .map(|(anchor, txid)| (*txid, anchor.block_id))
        .collect();
    let times = prove_confirmations(client, network, tip, &claimed).await?;
    for ((anchor, txid), time) in new.into_iter().zip(times) {
        update.anchors.remove(&(anchor, txid));
        match time {
            Some(time) => {
                update.anchors.insert((
                    ConfirmationBlockTime {
                        confirmation_time: time,
                        ..anchor
                    },
                    txid,
                ));
            }
            None => {
                update.seen_ats.insert((txid, start_time));
            }
        }
    }
    Ok(())
}

/// Proves that each transaction of `claimed` confirmed in the block it
/// names: its merkle branch (`/tx/:txid/merkle-proof`) against the header
/// of that block (`/block/:hash/header`), which must be the block named
/// and is read once however many of them it holds
/// ([`check_confirmation`]). Gives, for each, the time of its block once
/// proven, `None` when the proof is unsure, or when the server has no
/// branch or no header for it, as when a block came in since it listed
/// it. A proof that does not hold refuses the server ([`crate::chain::proof::FALSE_PROOF`]),
/// and so does a header that is not the block named. A sound branch into
/// another block has the block at its height read again ([`recheck`]):
/// one that replaced the block named leaves the confirmation unsure. One
/// above `tip`, the tip the server gave before, is weighed by
/// [`above_the_tip`] without a request.
///
/// A confirmation in one of the first periods of the chain, whose
/// header costs next to nothing to forge, is chained to the checkpoint
/// that ends its period ([`read_chains`]); one later on stands on its
/// header's work, as Esplora sends headers ten at a time and chaining
/// them all would cost more requests than the rest of the sync (see
/// [`crate::chain::proof`]).
pub(crate) async fn prove_confirmations(
    client: &Client,
    network: Network,
    tip: u32,
    claimed: &[(Txid, BlockId)],
) -> Result<Vec<Option<u64>>, Fault> {
    let too_high = |tip: u32| {
        claimed
            .iter()
            .any(|(_, block)| above_the_tip(block.height, tip) == Some(Proof::False))
    };
    // A long sync may have seen blocks come in since the tip was read:
    // the tip is read again before anything is refused for it.
    let mut tip = tip;
    // Proven as the first one was: a height alone would let a server
    // raise the bound it is held to.
    if too_high(tip) {
        tip = tip.max(proven_tip(client, network).await?);
    }
    if too_high(tip) {
        return Err(Fault::false_proof());
    }
    let below: Vec<(Txid, BlockId)> = claimed
        .iter()
        .copied()
        .filter(|(_, block)| block.height <= tip)
        .collect();
    let mut proven = prove_below_the_tip(client, network, &below)
        .await?
        .into_iter();
    Ok(claimed
        .iter()
        .map(|(_, block)| {
            if block.height <= tip {
                proven.next().flatten()
            } else {
                None
            }
        })
        .collect())
}

/// [`prove_confirmations`], for confirmations at the tip or below it.
async fn prove_below_the_tip(
    client: &Client,
    network: Network,
    claimed: &[(Txid, BlockId)],
) -> Result<Vec<Option<u64>>, Fault> {
    let mut blocks: Vec<BlockHash> = claimed.iter().map(|(_, block)| block.hash).collect();
    blocks.sort_unstable();
    blocks.dedup();
    let mut headers: HashMap<BlockHash, Header> = HashMap::with_capacity(blocks.len());
    for chunk in blocks.chunks(PARALLEL_REQUESTS) {
        let read = try_join_all(chunk.iter().map(|hash| block_header(client, *hash))).await?;
        for (hash, header) in chunk.iter().zip(read) {
            if let Some(header) = header {
                headers.insert(*hash, header);
            }
        }
    }
    let mut times = Vec::with_capacity(claimed.len());
    // The confirmations proven in a period whose header costs little to
    // forge: where each sits in `times`, its height and its block.
    let mut early: Vec<(usize, u32, BlockHash)> = Vec::new();
    for chunk in claimed.chunks(PARALLEL_REQUESTS) {
        let branches = try_join_all(chunk.iter().map(|(txid, _)| async move {
            let path = format!("/tx/{txid}/merkle-proof");
            client.get_json_opt::<GetMerkleRes>(&path).await
        }))
        .await?;
        for ((txid, block), branch) in chunk.iter().zip(branches) {
            let proof = match (branch, headers.get(&block.hash)) {
                (Some(branch), Some(header)) => {
                    match check_confirmation(network, block.height, header, *txid, &branch) {
                        Proof::Elsewhere => match block_at_height(client, block.height).await? {
                            Some(again) => {
                                recheck(network, block.height, header, &again, *txid, &branch)
                            }
                            None => Proof::Unsure,
                        },
                        verdict => verdict,
                    }
                }
                _ => Proof::Unsure,
            };
            match proof {
                Proof::Holds => {
                    if esplora_chains(network, block.height) {
                        early.push((times.len(), block.height, block.hash));
                    }
                    times.push(Some(u64::from(headers[&block.hash].time)));
                }
                Proof::Unsure => times.push(None),
                Proof::False | Proof::Elsewhere => return Err(Fault::false_proof()),
            }
        }
    }
    if !early.is_empty() {
        let blocks: Vec<(u32, BlockHash)> = early
            .iter()
            .map(|(_, height, hash)| (*height, *hash))
            .collect();
        let read = read_chains(client, network, &blocks).await?;
        for (at, height, hash) in early {
            match chained(network, height, hash, &read) {
                Proof::Holds => {}
                Proof::Unsure => times[at] = None,
                Proof::False | Proof::Elsewhere => return Err(Fault::false_proof()),
            }
        }
    }
    Ok(times)
}

/// The chains to their checkpoints that `blocks`, proven at their
/// heights in periods Esplora chains, need and this session has not
/// read: by the height each starts at, as [`chained`] takes them. Each
/// is read down from the end of its period, as many requests as
/// [`CHAIN_REQUESTS_MAX`] leaves, the periods that do not fit left out:
/// their confirmations are unsure. A chain that does not end at its
/// checkpoint refuses the server ([`FALSE_PROOF`]).
async fn read_chains(
    client: &Client,
    network: Network,
    blocks: &[(u32, BlockHash)],
) -> Result<HashMap<u32, Vec<BlockHash>>, Fault> {
    let mut budget = CHAIN_REQUESTS_MAX;
    let mut read = HashMap::new();
    for (from, count) in chains_to_read(network, blocks) {
        let cost = count.div_ceil(BLOCKS_PER_REQUEST);
        if cost > budget {
            continue;
        }
        let Some(headers) = read_down_to(client, from, count, &mut budget).await? else {
            continue;
        };
        let hashes = chain_to_checkpoint(network, from, &headers).ok_or_else(Fault::false_proof)?;
        read.insert(from, hashes);
    }
    Ok(read)
}

/// The `count` headers from `from` up, read down from the highest of
/// them ten at a time, each request taken from `budget`. `None` when
/// the budget runs out first, or when the server stops listing blocks,
/// as one whose limit is lower, or one that is lying, may: a chain not
/// read proves nothing either way.
async fn read_down_to(
    client: &Client,
    from: u32,
    count: u32,
    budget: &mut u32,
) -> Result<Option<Vec<Header>>, Fault> {
    let end = from + count - 1;
    let mut headers: BTreeMap<u32, Header> = BTreeMap::new();
    let mut next = end;
    loop {
        if *budget == 0 {
            return Ok(None);
        }
        *budget -= 1;
        let Some(listed) = client
            .get_json_opt::<Vec<Block>>(&format!("/blocks/{next}"))
            .await?
        else {
            return Ok(None);
        };
        let lowest = listed
            .iter()
            .map(|block| block.height)
            .filter(|height| (from..=next).contains(height))
            .min();
        for block in &listed {
            if (from..=next).contains(&block.height) {
                headers.insert(block.height, block.header());
            }
        }
        match lowest {
            Some(lowest) if lowest <= from => break,
            Some(lowest) => next = lowest - 1,
            None => return Ok(None),
        }
    }
    let headers: Option<Vec<Header>> = (from..=end)
        .map(|height| headers.get(&height).copied())
        .collect();
    Ok(headers)
}

/// The header of the block `hash`, which must hash to it; `None` when
/// the server has no such block, one a reorganisation left behind.
async fn block_header(client: &Client, hash: BlockHash) -> Result<Option<Header>, Fault> {
    let Some(text) = client
        .fetch(&format!("/block/{hash}/header"), 1 << 10)
        .await?
    else {
        return Ok(None);
    };
    std::str::from_utf8(&text)
        .ok()
        .and_then(|text| deserialize_hex::<Header>(text.trim()).ok())
        .filter(|header| header.block_hash() == hash)
        .map(Some)
        .ok_or_else(Fault::false_proof)
}

/// The header of the block the server has at `height` now; `None` when
/// it has none there.
async fn block_at_height(client: &Client, height: u32) -> Result<Option<Header>, Fault> {
    let Some(text) = client
        .fetch(&format!("/block-height/{height}"), 1 << 10)
        .await?
    else {
        return Ok(None);
    };
    let hash: BlockHash = std::str::from_utf8(&text)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .ok_or_else(|| Fault::other("unexpected response"))?;
    block_header(client, hash).await
}

/// The latest blocks, by height: ten on the instances there are,
/// checked ([`checked_latest`]).
async fn latest_blocks(
    client: &Client,
    network: Network,
    limit: u32,
) -> Result<BTreeMap<u32, BlockHash>, Fault> {
    checked_latest(network, client.get_json("/blocks").await?, limit)
}

/// The server's tip, proven as a descriptor wallet's sync proves it
/// ([`checked_latest`]): what a watched address counts its
/// confirmations from. One request, the one that read the height alone.
pub(crate) async fn proven_tip(client: &Client, network: Network) -> Result<u32, Fault> {
    let limit = height_limit(network, crate::now_secs());
    let latest = latest_blocks(client, network, limit).await?;
    latest
        .keys()
        .next_back()
        .copied()
        .ok_or_else(|| Fault::other("unexpected response"))
}

/// What a server whose latest blocks do not make a chain, with the
/// work of their heights, is refused with.
const UNCHAINED: &str = "the server's latest blocks do not chain";

/// The latest blocks a server listed, checked, as they go into the
/// wallet's chain: the highest [`LATEST`] kept, one for each height down
/// from the tip, each the parent of the one above it, each with the
/// work `network` asks for at its height ([`has_proof_of_work`]), the
/// hash a summary names the hash of the header it spells out, and the
/// tip no higher than `limit`, the most a chain can have reached
/// ([`height_limit`]). A server that lists blocks that do not chain, or
/// a tip no one mined, is refused, and so is one past the limit: a tip
/// made up costs what mining a block of its height costs, as over
/// Electrum.
fn checked_latest(
    network: Network,
    mut blocks: Vec<Block>,
    limit: u32,
) -> Result<BTreeMap<u32, BlockHash>, Fault> {
    blocks.sort_by_key(|block| std::cmp::Reverse(block.height));
    blocks.truncate(LATEST);
    let tip = blocks
        .first()
        .ok_or_else(|| Fault::other("unexpected response"))?;
    if tip.height > limit {
        return Err(Fault::other(IMPOSSIBLE_TIP));
    }
    let chained = blocks.windows(2).all(|pair| {
        pair[1].height.checked_add(1) == Some(pair[0].height)
            && pair[0].previousblockhash == Some(pair[1].id)
    });
    let worked = blocks.iter().all(|block| {
        let header = block.header();
        header.block_hash() == block.id && has_proof_of_work(network, block.height, &header)
    });
    if !chained || !worked {
        return Err(Fault::other(UNCHAINED));
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
) -> Result<Option<BlockHash>, Fault> {
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
        .ok_or_else(|| Fault::other("unexpected response"))
}

/// Where the wallet's chain and the server's meet: the last block both
/// have, and the server's blocks at the heights of the wallet's above it.
struct Meeting {
    agreement: CheckPoint,
    /// The height of `agreement`: a confirmation the wallet holds above
    /// it sits in a block the server no longer has.
    height: u32,
    conflicts: Vec<BlockId>,
    /// The wallet's tip, when the server is behind it and agrees with it
    /// on every block both have: a server that lags, whose answer keeps
    /// the wallet's chain as it is.
    ahead: Option<CheckPoint>,
}

impl Meeting {
    /// Walks the wallet's chain down from its tip to a block the server
    /// has too. The first block they disagree on has the server's
    /// genesis block checked: one of another network would otherwise
    /// cost a request for every block the wallet holds.
    async fn find(
        client: &Client,
        network: Network,
        latest: &BTreeMap<u32, BlockHash>,
        local_tip: &CheckPoint,
    ) -> Result<Self, Fault> {
        let mut conflicts = Vec::new();
        for local in local_tip.iter() {
            let Some(remote) = block_at(client, latest, local.height()).await? else {
                continue;
            };
            if remote == local.hash() {
                let behind = latest
                    .keys()
                    .next_back()
                    .is_some_and(|&tip| tip < local_tip.height());
                return Ok(Meeting {
                    height: local.height(),
                    ahead: (behind && conflicts.is_empty()).then(|| local_tip.clone()),
                    agreement: local,
                    conflicts,
                });
            }
            if conflicts.is_empty() {
                super::check_network(client, network).await?;
            }
            conflicts.push(BlockId {
                height: local.height(),
                hash: remote,
            });
        }
        Err(Fault::other("the server's chain never meets the wallet's"))
    }

    /// The wallet's chain as the server sees it: from the meeting point,
    /// the server's blocks where the wallet's differ, one per height a
    /// transaction confirmed at, and the latest ones. The engine of BDK
    /// builds it this way. A server behind the wallet leaves the
    /// wallet's blocks above its tip where they are, which an update
    /// built from the meeting point could not.
    async fn chain(
        self,
        client: &Client,
        latest: &BTreeMap<u32, BlockHash>,
        anchors: &BTreeSet<(ConfirmationBlockTime, Txid)>,
    ) -> Result<CheckPoint, Fault> {
        let meeting = self.height;
        let mut tip = match self.ahead {
            Some(local) => local,
            None => self
                .agreement
                .extend(self.conflicts.into_iter().rev())
                .map_err(|_| "the server's chain never meets the wallet's".to_owned())?,
        };
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
                    return Err(Fault::other("the server's chain contradicts itself"));
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
            ahead: None,
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

    /// A block summed up as Esplora sums it up, from its header.
    fn summary(height: u32, header: &Header) -> Block {
        Block {
            id: header.block_hash(),
            height,
            version: header.version.to_consensus() as u32,
            timestamp: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
            merkle_root: header.merkle_root,
            previousblockhash: (height > 0).then_some(header.prev_blockhash),
        }
    }

    /// The latest blocks go into the wallet's chain only as a chain: the
    /// highest ten, one per height, each the parent of the one above it,
    /// each the block its header makes, under a tip a chain can have
    /// reached.
    #[test]
    fn the_latest_blocks_must_chain() {
        let mut headers: Vec<Header> = Vec::new();
        for height in 0..=100u32 {
            headers.push(Header {
                version: Version::TWO,
                prev_blockhash: headers
                    .last()
                    .map_or_else(BlockHash::all_zeros, Header::block_hash),
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            });
        }
        let block = |height: u32| summary(height, &headers[height as usize]);
        let latest = |range: std::ops::RangeInclusive<u32>| range.rev().map(block).collect();
        let checked =
            |blocks: Vec<Block>, limit: u32| checked_latest(Network::Signet, blocks, limit);
        let read = checked(latest(91..=100), 1_000).unwrap();
        assert_eq!(
            read.keys().copied().collect::<Vec<_>>(),
            (91..=100).collect::<Vec<_>>()
        );
        assert_eq!(read[&100], headers[100].block_hash());
        // More than ten: the highest ten are read, in any order given.
        let mut many: Vec<Block> = latest(0..=100);
        many.reverse();
        assert_eq!(checked(many, 1_000).unwrap(), read);
        // A tip past what a chain can have reached.
        assert_eq!(checked(latest(91..=100), 99).unwrap_err(), IMPOSSIBLE_TIP);
        // A gap, a block twice, a parent that is not the block below.
        let mut gap: Vec<Block> = latest(91..=100);
        gap.remove(3);
        assert!(checked(gap, 1_000).is_err());
        let mut twice: Vec<Block> = latest(91..=100);
        twice.push(block(95));
        assert!(checked(twice, 1_000).is_err());
        let mut forged: Vec<Block> = latest(91..=100);
        forged[0].previousblockhash = Some(headers[7].block_hash());
        assert!(checked(forged, 1_000).is_err());
        // A summary whose fields make another block than the one named.
        let mut renamed: Vec<Block> = latest(91..=100);
        renamed[0].nonce ^= 1;
        assert_eq!(checked(renamed, 1_000).unwrap_err(), UNCHAINED);
        // A lone tip of four billion, once refused for its height alone.
        assert!(checked(vec![summary(4_000_000_000, &headers[0])], 1_000).is_err());
        assert!(checked(Vec::new(), 1_000).is_err());
    }
}
