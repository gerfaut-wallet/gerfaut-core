//! A descriptor wallet read from an Electrum server, asking for no more
//! than the wallet lacks.
//!
//! The history of a script is a list of txids and heights, a few dozen
//! bytes each, and it is read for every script of the plan. What costs is
//! what follows, and the engine of BDK asked for all of it at every sync:
//! each transaction again, the transaction behind every coin each one
//! spends, and a header and a merkle proof per confirmation. Here:
//!
//! - A transaction the wallet holds is not asked for again. One it lacks
//!   is asked for once, and refused unless it hashes to its txid.
//! - A confirmation the wallet holds is taken as proven when the server
//!   puts the transaction at the same height and that block is still
//!   the one the server has there: below the last block both chains
//!   agree on, or among the latest blocks with the same hash. Anything
//!   else, a new confirmation or one moved by a reorganisation, is
//!   proven again, header and merkle branch.
//! - The coins a transaction spends are asked for only for a
//!   transaction the wallet lacked, and only those it cannot find in
//!   what it holds: they are what its fee is counted from.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use bdk_electrum::electrum_client::{self, ElectrumApi, GetHistoryRes};
use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};

use crate::chain::{Held, Plan, Scan, Synced};

/// Requests per batch.
const BATCH: usize = 10;
/// The latest blocks read with the tip, as the engine of BDK reads them:
/// a reorganisation that deep is met without a request per block.
const CHAIN_SUFFIX: u32 = 8;

type Error = electrum_client::Error;

/// Runs a plan on an open connection.
pub(crate) fn run(client: &impl ElectrumApi, plan: Plan) -> Result<Synced, Error> {
    let Plan {
        tip,
        start_time,
        scripts,
        scans,
        stop_gap,
        held,
        ..
    } = plan;
    let mut chain = Chain::read(client, &tip)?;
    let mut pass = Pass {
        held: &held,
        start_time,
        update: TxUpdate::default(),
        wanted: Vec::new(),
        fetched: HashMap::new(),
        to_prove: Vec::new(),
        taken: HashSet::new(),
        orders: Vec::new(),
    };

    for batch in scripts.chunks(BATCH) {
        let histories = client.batch_script_get_history(batch.iter().map(|s| s.as_script()))?;
        for (script, history) in batch.iter().zip(histories) {
            pass.take(script, &history, &chain);
        }
    }

    let mut last_active = BTreeMap::new();
    for Scan { keychain, mut spks } in scans {
        let mut unused = 0usize;
        'scan: loop {
            let batch: Vec<(u32, ScriptBuf)> = spks.by_ref().take(BATCH).collect();
            if batch.is_empty() {
                break;
            }
            let histories =
                client.batch_script_get_history(batch.iter().map(|(_, s)| s.as_script()))?;
            for ((index, script), history) in batch.iter().zip(histories) {
                if history.is_empty() {
                    unused = unused.saturating_add(1);
                    if unused >= (stop_gap as usize).max(1) {
                        break 'scan;
                    }
                } else {
                    unused = 0;
                    last_active.insert(keychain, *index);
                }
                pass.take(script, &history, &chain);
            }
        }
    }

    pass.fetch_missing(client)?;
    pass.prove(client, &mut chain)?;
    pass.fetch_prevouts(client)?;
    let tip = chain.update(&pass.update);
    Ok(Synced {
        update: bdk_wallet::Update {
            last_active_indices: last_active,
            tx_update: pass.update,
            chain: Some(tip),
        },
        orders: pass.orders,
    })
}

/// The server's chain against the wallet's.
struct Chain {
    /// The wallet's chain up to the last block both agree on, then the
    /// server's latest blocks.
    tip: CheckPoint,
    /// The server's hash at each height read: the latest blocks, and the
    /// ones read on the way down to the agreement.
    hashes: BTreeMap<u32, BlockHash>,
    /// Headers read, by height.
    headers: HashMap<u32, Header>,
    /// The height of the last block both chains agree on.
    agreement: u32,
}

impl Chain {
    /// The tip and the latest blocks, then the wallet's chain walked down
    /// to a block the server has too. A server behind the wallet leaves
    /// the wallet's chain as it is.
    fn read(client: &impl ElectrumApi, local: &CheckPoint) -> Result<Self, Error> {
        let height = client.block_headers_subscribe()?.height as u32;
        if height < local.height() {
            return Ok(Chain {
                tip: local.clone(),
                hashes: BTreeMap::new(),
                headers: HashMap::new(),
                agreement: local.height(),
            });
        }
        let start = height.saturating_sub(CHAIN_SUFFIX - 1);
        let latest = client.block_headers(start as usize, CHAIN_SUFFIX as usize)?;
        let mut headers = HashMap::new();
        let mut hashes = BTreeMap::new();
        for (at, header) in (start..).zip(latest.headers) {
            hashes.insert(at, header.block_hash());
            headers.insert(at, header);
        }
        let mut agreement = None;
        for checkpoint in local.iter() {
            let at = checkpoint.height();
            let hash = match hashes.get(&at) {
                Some(hash) => *hash,
                None => {
                    let header = client.block_header(at as usize)?;
                    let hash = header.block_hash();
                    hashes.insert(at, hash);
                    headers.insert(at, header);
                    hash
                }
            };
            if hash == checkpoint.hash() {
                agreement = Some(checkpoint);
                break;
            }
        }
        let agreement = agreement.ok_or_else(|| {
            Error::Message("the server's chain never meets the wallet's".to_owned())
        })?;
        let tip = agreement
            .clone()
            .extend(
                hashes
                    .range(agreement.height() + 1..)
                    .map(|(&height, &hash)| BlockId { height, hash }),
            )
            .map_err(|_| {
                Error::Message("the server's chain never meets the wallet's".to_owned())
            })?;
        Ok(Chain {
            tip,
            hashes,
            headers,
            agreement: agreement.height(),
        })
    }

    /// Whether a confirmation the wallet holds still stands where the
    /// server puts the transaction.
    fn still_holds(&self, anchor: &ConfirmationBlockTime, height: u32) -> bool {
        if anchor.block_id.height != height {
            return false;
        }
        match self.hashes.get(&height) {
            Some(hash) => *hash == anchor.block_id.hash,
            None => height <= self.agreement,
        }
    }

    /// The chain of the update: a block per height a transaction
    /// confirmed at, below the tip, as the engine of BDK builds it.
    fn update(&self, update: &TxUpdate<ConfirmationBlockTime>) -> CheckPoint {
        let mut tip = self.tip.clone();
        for (anchor, _) in &update.anchors {
            let height = anchor.block_id.height;
            if tip.get(height).is_none() && height <= tip.height() {
                let hash = self
                    .hashes
                    .get(&height)
                    .copied()
                    .unwrap_or(anchor.block_id.hash);
                tip = tip.insert(BlockId { height, hash });
            }
        }
        tip
    }
}

/// The update being put together.
struct Pass<'h> {
    held: &'h Held,
    start_time: u64,
    update: TxUpdate<ConfirmationBlockTime>,
    /// Transactions the wallet lacks, in the order they were met.
    wanted: Vec<Txid>,
    fetched: HashMap<Txid, Arc<Transaction>>,
    /// Confirmations to prove: txid and height.
    to_prove: Vec<(Txid, u32)>,
    /// Transactions already taken from another script.
    taken: HashSet<Txid>,
    /// Each history as the server listed it.
    orders: Vec<(ScriptBuf, Vec<(Txid, i32)>)>,
}

impl Pass<'_> {
    /// Takes the history of one script.
    fn take(&mut self, script: &ScriptBuf, history: &[GetHistoryRes], chain: &Chain) {
        self.orders.push((
            script.clone(),
            history
                .iter()
                .map(|entry| (entry.tx_hash, entry.height))
                .collect(),
        ));
        if let Some(facts) = self.held.scripts.get(script) {
            let listed: HashSet<Txid> = history.iter().map(|entry| entry.tx_hash).collect();
            self.update.evicted_ats.extend(
                facts
                    .expected
                    .iter()
                    .filter(|txid| !listed.contains(*txid))
                    .map(|txid| (*txid, self.start_time)),
            );
        }
        for entry in history {
            let txid = entry.tx_hash;
            if !self.taken.insert(txid) {
                continue;
            }
            if !self.held.txs.contains_key(&txid) {
                self.wanted.push(txid);
            }
            match u32::try_from(entry.height) {
                // 0 and -1 are the mempool.
                Ok(height) if height > 0 => match self.held.anchors.get(&txid) {
                    Some(anchor) if chain.still_holds(anchor, height) => {}
                    _ => self.to_prove.push((txid, height)),
                },
                _ => {
                    self.update.seen_ats.insert((txid, self.start_time));
                }
            }
        }
    }

    /// Asks for the transactions the wallet lacks.
    fn fetch_missing(&mut self, client: &impl ElectrumApi) -> Result<(), Error> {
        let wanted = std::mem::take(&mut self.wanted);
        for (txid, tx) in fetch_txs(client, &wanted)? {
            self.update.txs.push(tx.clone());
            self.fetched.insert(txid, tx);
        }
        Ok(())
    }

    /// Proves the confirmations the wallet does not hold: the header of
    /// each block, then the merkle branch of each transaction in it. A
    /// branch that does not lead to the header's root proves nothing,
    /// and the transaction is left unconfirmed, as the engine of BDK
    /// leaves it.
    fn prove(&mut self, client: &impl ElectrumApi, chain: &mut Chain) -> Result<(), Error> {
        let to_prove = std::mem::take(&mut self.to_prove);
        let mut missing: Vec<u32> = to_prove
            .iter()
            .map(|(_, height)| *height)
            .filter(|height| !chain.headers.contains_key(height))
            .collect();
        missing.sort_unstable();
        missing.dedup();
        for heights in missing.chunks(BATCH) {
            let headers = client.batch_block_header(heights.iter().copied())?;
            for (height, header) in heights.iter().zip(headers) {
                chain.headers.insert(*height, header);
            }
        }
        for batch in to_prove.chunks(BATCH) {
            let proofs = client
                .batch_transaction_get_merkle(batch.iter().map(|(txid, h)| (*txid, *h as usize)))?;
            for ((txid, height), proof) in batch.iter().zip(proofs) {
                let Some(header) = chain.headers.get(height) else {
                    continue;
                };
                if electrum_client::utils::validate_merkle_proof(txid, &header.merkle_root, &proof)
                {
                    self.update.anchors.insert((
                        ConfirmationBlockTime {
                            block_id: BlockId {
                                height: *height,
                                hash: header.block_hash(),
                            },
                            confirmation_time: u64::from(header.time),
                        },
                        *txid,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Asks for the coins the new transactions spend that the wallet
    /// cannot find in what it holds.
    fn fetch_prevouts(&mut self, client: &impl ElectrumApi) -> Result<(), Error> {
        let mut spent = Vec::new();
        let mut wanted = Vec::new();
        let mut asked = HashSet::new();
        for tx in self.fetched.values() {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.input {
                let outpoint = input.previous_output;
                if self.held.txs.contains_key(&outpoint.txid)
                    || self.fetched.contains_key(&outpoint.txid)
                    || self.held.txouts.contains(&outpoint)
                {
                    continue;
                }
                spent.push(outpoint);
                if asked.insert(outpoint.txid) {
                    wanted.push(outpoint.txid);
                }
            }
        }
        let previous = fetch_txs(client, &wanted)?;
        for outpoint in spent {
            let txout = previous
                .get(&outpoint.txid)
                .and_then(|tx| tx.output.get(outpoint.vout as usize))
                .ok_or_else(|| Error::Message(format!("the coin {outpoint} does not exist")))?;
            self.update.txouts.insert(outpoint, txout.clone());
        }
        Ok(())
    }
}

/// Asks for transactions by txid, a batch at a time, and refuses one
/// that does not hash to the txid it was asked for.
fn fetch_txs(
    client: &impl ElectrumApi,
    txids: &[Txid],
) -> Result<HashMap<Txid, Arc<Transaction>>, Error> {
    let mut found = HashMap::new();
    for batch in txids.chunks(BATCH) {
        let txs = client.batch_transaction_get(batch.iter())?;
        for (txid, tx) in batch.iter().zip(txs) {
            if tx.compute_txid() != *txid {
                return Err(Error::Message(
                    "the server answered with another transaction than the one asked for"
                        .to_owned(),
                ));
            }
            found.insert(*txid, Arc::new(tx));
        }
    }
    Ok(found)
}
