//! What proves that a transaction confirmed: a header with the work its
//! network asks for at its height, and a merkle branch that leads from
//! the transaction to the root that header commits to. Every path of the
//! core that takes a confirmation from a server goes through
//! [`check_confirmation`], and every header it takes for the chain alone
//! through [`has_proof_of_work`].
//!
//! Without the work, a server makes a confirmation up for nothing: a
//! header that commits to its transaction, mined by no one. A mainnet
//! header is held to the target of its retarget period, read from the
//! checkpoints Electrum ships ([`targets`]). Past the last of them, the
//! target may grow four times easier a period, as consensus lets it, for
//! [`PAST_THE_TABLE`] periods and no more: the height is the server's
//! word, and a bound that kept loosening with it would reach the easiest
//! target two dozen periods on, a height any server can claim. A header
//! for a recent block then costs what a block costs a miner, a sixteenth
//! of it at least.
//!
//! A header alone costs only its period's work, and a server picks the
//! height it claims: in the first years of the chain that work is close
//! to nothing. So over Electrum, a confirmation in a period whose forged
//! header would cost less than [`CHAIN_BELOW_DIFFICULTY`] is chained: the
//! headers from its block to the end of its period, 2,016 at most, in
//! one request unless a server sends fewer at a time, must follow one
//! another up to the hash the checkpoints give for that block
//! ([`chain_to_checkpoint`]). The periods
//! read are kept for the session. Esplora has no way to send a run of
//! headers short of one request per block: over Esplora, a confirmation
//! is taken on its header's work alone, and one claimed in an early
//! period costs what forging a header of that period costs. Past the last
//! checkpoint, there is no hash to chain to either way, and the work of a
//! recent block is the price of a forged confirmation, as it is for any
//! wallet that reads headers.
//!
//! The table is written again before each release, from the checkpoints
//! of the latest Electrum release:
//!
//! ```text
//! curl -sSfLo /tmp/checkpoints.json https://raw.githubusercontent.com/spesmilo/electrum/<commit>/electrum/chains/mainnet/checkpoints.json
//! GERFAUT_WRITE_TARGETS=/tmp/checkpoints.json GERFAUT_TARGETS_COMMIT=<commit> cargo test --lib the_target_table
//! cargo test --lib chain::proof
//! ```
//!
//! Confirmations a wallet stored before these checks are kept as they
//! are, never proven again: no release read them the old way, only the
//! testers' vaults of the unpublished 0.1.0.
//!
//! Testnet4 and signet keep the check they had, the easiest target of
//! the network: a testnet4 block may be mined at that target twenty
//! minutes after the one before it, and a signet block is made valid by
//! a signature, so on neither does work prove more. Regtest blocks are
//! made at will.
//!
//! The branch is read the way Electrum reads it. The position must fit
//! in the branch, and no node may be the right copy of its left sibling:
//! that is the copy an odd row makes of its last node, which stands for
//! no transaction (CVE-2012-2459). No inner node may read as a
//! transaction either: a transaction of 64 bytes is also two hashes, and
//! a branch through it passes off one of its halves as a transaction of
//! the block (CVE-2017-12842). Two hashes read as a transaction by
//! chance too, about once in a million branches, and every server sends
//! the same branch for a transaction: such a branch proves nothing, and
//! refuses no server ([`Proof::Unsure`]).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::deserialize;
use bdk_wallet::bitcoin::hashes::{Hash, sha256d};
use bdk_wallet::bitcoin::params::Params;
use bdk_wallet::bitcoin::{
    BlockHash, CompactTarget, OutPoint, Script, ScriptBuf, Target, Transaction, TxMerkleNode, Txid,
};
use electrum_client::GetMerkleRes;

use crate::network::Network;

mod targets;
#[cfg(test)]
mod tests;

/// What a server whose proof of a confirmation does not hold is refused
/// with: a header without the work of its height, or a branch that does
/// not lead to its root.
pub(crate) const FALSE_PROOF: &str = "the server sent a false proof of a confirmation";

/// What a server that lists a coin its own transaction does not pay is
/// refused with.
pub(crate) const COIN_NOT_PAID: &str = "the server listed a coin its transaction does not pay";

/// Whether a server was refused, in `detail`, for a proof that does not
/// hold: [`FALSE_PROOF`] or [`COIN_NOT_PAID`].
pub(crate) fn is_false_proof(detail: &str) -> bool {
    detail.contains(FALSE_PROOF) || detail.contains(COIN_NOT_PAID)
}

/// Blocks between two retargets.
const RETARGET_PERIOD: u32 = 2_016;

/// Periods past the table over which the target may grow four times
/// easier each: sixteen times easier in all. The difficulty of mainnet
/// never fell to half of what it was in any year of its history.
const PAST_THE_TABLE: usize = 2;

/// The longest branch read: a block of more than four billion
/// transactions is past what any block can hold.
const BRANCH_MAX: usize = 32;

/// Whether a header at `height` carries the work `network` asks for
/// there: its hash meets its own target, and that target is no easier
/// than the network allows at that height ([`easiest_target`]). A
/// header of a network whose blocks work does not prove passes.
pub(crate) fn has_proof_of_work(network: Network, height: u32, header: &Header) -> bool {
    let Some(easiest) = easiest_target(network, height) else {
        return true;
    };
    let target = header.target();
    target <= easiest && target.is_met_by(header.block_hash())
}

/// The easiest target a header of `network` at `height` may carry, or
/// `None` where work proves nothing. On mainnet, the target of its
/// period in the table, and past the table, the last one four times
/// easier for each period since, [`PAST_THE_TABLE`] times at most, never
/// easier than the easiest target of the network.
fn easiest_target(network: Network, height: u32) -> Option<Target> {
    match network {
        Network::Mainnet => {
            let params = Params::new(network.to_bitcoin());
            let table = targets::MAINNET_BITS;
            let period = (height / RETARGET_PERIOD) as usize;
            let last = table.len() - 1;
            let bits = table[period.min(last)];
            let mut easiest = Target::from_compact(CompactTarget::from_consensus(bits));
            for _ in last..period.min(last + PAST_THE_TABLE) {
                let looser = easiest.max_transition_threshold(&params);
                if looser == easiest {
                    break;
                }
                easiest = looser;
            }
            Some(easiest)
        }
        Network::Testnet4 => Some(Params::new(network.to_bitcoin()).max_attainable_target),
        Network::Signet | Network::Regtest => None,
    }
}

/// What a branch and a header make of a confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proof {
    /// The branch leads from the transaction to the root of a header
    /// with the work of its height: the transaction confirmed there.
    Holds,
    /// A header without the work of its height, or a branch that is no
    /// branch of any block: a position past it, a node paired with a copy
    /// of itself, more hashes than any block needs. The server is to be
    /// refused.
    False,
    /// Not proven, and no lie either: a branch for another height than
    /// the one asked about, as a server answers when a block came in
    /// between, or one through an inner node that reads as a transaction.
    /// The transaction is left unconfirmed, as it was.
    Unsure,
    /// A sound branch that leads to another root than the header's: the
    /// block at that height may have changed since the header was read,
    /// a reorganisation in between. Read the header again, once, and ask
    /// [`recheck`].
    Elsewhere,
}

/// What `branch` proves of `txid` in the block of `header`, at `height`:
/// see [`Proof`]. Every path that takes a confirmation from a server
/// asks it here.
pub(crate) fn check_confirmation(
    network: Network,
    height: u32,
    header: &Header,
    txid: Txid,
    branch: &GetMerkleRes,
) -> Proof {
    if u32::try_from(branch.block_height) != Ok(height) {
        return Proof::Unsure;
    }
    if !has_proof_of_work(network, height, header) {
        return Proof::False;
    }
    match merkle_root(txid, branch.pos, &branch.merkle) {
        Ok(root) if root == header.merkle_root => Proof::Holds,
        Ok(_) => Proof::Elsewhere,
        Err(Fault::Transaction) => Proof::Unsure,
        Err(Fault::Shape) => Proof::False,
    }
}

/// Blocks a confirmation may sit above the tip the same server gave a
/// moment before: blocks that came in since.
pub(crate) const ABOVE_THE_TIP: u32 = 3;

/// What a confirmation claimed at `height` is worth against `tip`, the
/// tip the same server gave just before: above it by more than
/// [`ABOVE_THE_TIP`], a false proof whatever header comes with it; above
/// it within that, unsure, a block that came in since and that the next
/// sync reads. `None` at the tip or below it.
pub(crate) fn above_the_tip(height: u32, tip: u32) -> Option<Proof> {
    if height > tip.saturating_add(ABOVE_THE_TIP) {
        Some(Proof::False)
    } else if height > tip {
        Some(Proof::Unsure)
    } else {
        None
    }
}

/// What a branch that led elsewhere ([`Proof::Elsewhere`]) proves once
/// the header at its height is read `again`: a block that is not the one
/// first read, which the branch proves the transaction in, says a
/// reorganisation came in between, and the confirmation is unsure. The
/// same block, or a branch that proves nothing in the new one, is a
/// false proof.
pub(crate) fn recheck(
    network: Network,
    height: u32,
    first: &Header,
    again: &Header,
    txid: Txid,
    branch: &GetMerkleRes,
) -> Proof {
    let moved = again.block_hash() != first.block_hash();
    if moved && check_confirmation(network, height, again, txid, branch) == Proof::Holds {
        Proof::Unsure
    } else {
        Proof::False
    }
}

/// Why a branch leads to no root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// It is no branch of a block: longer than any block needs, a
    /// position past what it holds, or a node paired with a copy of
    /// itself on its left.
    Shape,
    /// An inner node reads as a transaction.
    Transaction,
}

/// The root a branch leads to from `txid` at position `pos`, or why it
/// leads to none ([`Fault`]). The hashes of the branch are spelled the
/// way servers send them, as a txid is shown: byte for byte reversed.
fn merkle_root(txid: Txid, pos: usize, branch: &[[u8; 32]]) -> Result<TxMerkleNode, Fault> {
    if branch.len() > BRANCH_MAX {
        return Err(Fault::Shape);
    }
    let mut index = pos;
    let mut node = txid.to_byte_array();
    for sibling in branch {
        let mut sibling = *sibling;
        sibling.reverse();
        let right = index & 1 == 1;
        if right && sibling == node {
            return Err(Fault::Shape);
        }
        let (left, right) = if right {
            (sibling, node)
        } else {
            (node, sibling)
        };
        let mut inner = [0u8; 64];
        inner[..32].copy_from_slice(&left);
        inner[32..].copy_from_slice(&right);
        if deserialize::<Transaction>(&inner).is_ok() {
            return Err(Fault::Transaction);
        }
        node = sha256d::Hash::hash(&inner).to_byte_array();
        index >>= 1;
    }
    if index != 0 {
        return Err(Fault::Shape);
    }
    Ok(TxMerkleNode::from_byte_array(node))
}

/// Whether output `vout` of `tx` pays `ours` `value` sats: what a coin of
/// it a server lists must be.
pub(crate) fn pays(tx: &Transaction, vout: u32, ours: &Script, value: u64) -> bool {
    tx.output
        .get(vout as usize)
        .is_some_and(|output| output.script_pubkey == *ours && output.value.to_sat() == value)
}

/// A coin past the round of a watched address, proven: what its
/// transaction pays, where it confirmed, and the time of its block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvenCoin {
    pub script: ScriptBuf,
    pub value: u64,
    pub height: u32,
    pub time: Option<u64>,
}

/// Where a coin was proven: its network, the server, its outpoint.
type ProvenAt = (Network, String, OutPoint);

/// The coins past the round proven in this session, by network, server
/// and outpoint: one the same server lists again at the same height,
/// paying the same script as much, is not read and proven again at each
/// sync. Forgotten all at once past [`PROVEN_COINS_MAX`], and with the
/// process.
static PROVEN_COINS: LazyLock<Mutex<HashMap<ProvenAt, ProvenCoin>>> =
    LazyLock::new(Default::default);

/// Coins kept proven at most: a few hundred kilobytes.
const PROVEN_COINS_MAX: usize = 10_000;

/// The time of the block a coin was proven in this session on `server`,
/// when it was proven as `coin` says; `None` when it was not.
pub(crate) fn proven_coin(
    network: Network,
    server: &str,
    outpoint: OutPoint,
    coin: &ProvenCoin,
) -> Option<Option<u64>> {
    let proven = PROVEN_COINS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    proven
        .get(&(network, server.to_owned(), outpoint))
        .filter(|held| {
            held.script == coin.script && held.value == coin.value && held.height == coin.height
        })
        .map(|held| held.time)
}

/// Remembers a coin proven on `server` for the rest of the session.
pub(crate) fn remember_coin(network: Network, server: &str, outpoint: OutPoint, coin: ProvenCoin) {
    let mut proven = PROVEN_COINS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if proven.len() >= PROVEN_COINS_MAX {
        proven.clear();
    }
    proven.insert((network, server.to_owned(), outpoint), coin);
}

/// Forgets what was proven on the servers whose address holds `server`:
/// a server of the tests starts on a port a test before it may have
/// used, and inherits nothing from it.
#[cfg(test)]
pub(crate) fn forget_proven_coins(server: &str) {
    let mut proven = PROVEN_COINS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    proven.retain(|(_, at, _), _| !at.contains(server));
}

/// The difficulty under which a header alone does not prove a
/// confirmation over Electrum, and its block is chained to its period's
/// checkpoint ([`chain_to_checkpoint`]): 4 × 10^14.
///
/// A forged header costs its difficulty times 2^32 hashes. Hashrate rents
/// for about $50 a day per PH/s, what mining earns at the time of writing
/// (October 2026: some 3.2 BTC a block at about $100,000, over some
/// 900 EH/s), which puts 2^32 hashes at about $2.5 × 10^-9, and a header
/// of this difficulty at about $1,000,000. Every period that has a
/// checkpoint is easier than that today, the last at 1.26 × 10^14.
const CHAIN_BELOW_DIFFICULTY: u128 = 400_000_000_000_000;

/// The checkpoint a confirmation at `height` must chain to over
/// Electrum, when one is needed ([`CHAIN_BELOW_DIFFICULTY`]): the height
/// and hash of the last block of its period. None on another network
/// than mainnet, in a period past the checkpoints, or in a period whose
/// work proves enough.
pub(crate) fn checkpoint_for(network: Network, height: u32) -> Option<(u32, BlockHash)> {
    if network != Network::Mainnet {
        return None;
    }
    let period = (height / RETARGET_PERIOD) as usize;
    let end = targets::MAINNET_ENDS.get(period)?.parse().ok()?;
    let bits = CompactTarget::from_consensus(targets::MAINNET_BITS[period]);
    let params = Params::new(network.to_bitcoin());
    (Target::from_compact(bits).difficulty(&params) < CHAIN_BELOW_DIFFICULTY)
        .then_some(((period as u32 + 1) * RETARGET_PERIOD - 1, end))
}

/// The hashes of the blocks from `from` to the end of its period, read
/// from `headers`, when they follow one another up to the hash the
/// checkpoints give for that end ([`checkpoint_for`]): the real blocks,
/// which no amount of work can stand in for. Remembered for the session.
/// `None` when they do not, or when no checkpoint applies.
pub(crate) fn chain_to_checkpoint(
    network: Network,
    from: u32,
    headers: &[Header],
) -> Option<Vec<BlockHash>> {
    let (end, end_hash) = checkpoint_for(network, from)?;
    if u32::try_from(headers.len()).ok()? != end.checked_sub(from)? + 1 {
        return None;
    }
    let hashes: Vec<BlockHash> = headers.iter().map(Header::block_hash).collect();
    let chained = headers
        .windows(2)
        .all(|pair| pair[1].prev_blockhash == pair[0].block_hash());
    if !chained || hashes.last() != Some(&end_hash) {
        return None;
    }
    remember_chained(from, &hashes);
    Some(hashes)
}

/// What chaining says of a confirmation proven in the block `hash` at
/// `height`: [`Proof::Holds`] when no chaining is needed or the block is
/// the one the chain to the checkpoint holds there, [`Proof::False`] when
/// it holds another, [`Proof::Unsure`] when that chain could not be read.
/// `read` holds the chains this sync read, by the height they start at
/// ([`chain_to_checkpoint`]); the session's are asked too.
pub(crate) fn chained(
    network: Network,
    height: u32,
    hash: BlockHash,
    read: &HashMap<u32, Vec<BlockHash>>,
) -> Proof {
    let Some((end, _)) = checkpoint_for(network, height) else {
        return Proof::Holds;
    };
    let in_read = read.iter().find_map(|(from, hashes)| {
        let in_period = *from <= height && from + hashes.len() as u32 - 1 == end;
        in_period.then(|| hashes[(height - from) as usize])
    });
    match in_read.or_else(|| chained_before(height)) {
        Some(real) if real == hash => Proof::Holds,
        Some(_) => Proof::False,
        None => Proof::Unsure,
    }
}

/// The chains to the checkpoints that the confirmations of `proven`,
/// blocks proven at their heights, need and this session has not read:
/// for each period, the lowest height to read from, and how many headers.
pub(crate) fn chains_to_read(network: Network, proven: &[(u32, BlockHash)]) -> Vec<(u32, u32)> {
    let mut lowest: HashMap<u32, (u32, u32)> = HashMap::new();
    for (height, _) in proven {
        let Some((end, _)) = checkpoint_for(network, *height) else {
            continue;
        };
        if chained_before(*height).is_some() {
            continue;
        }
        let entry = lowest.entry(end).or_insert((*height, end));
        entry.0 = entry.0.min(*height);
    }
    let mut reads: Vec<(u32, u32)> = lowest
        .into_values()
        .map(|(from, end)| (from, end - from + 1))
        .collect();
    reads.sort_unstable();
    reads
}

/// A chain to a checkpoint: the height it starts at, and the hashes from
/// there to the end of the period.
type Chain = (u32, Vec<BlockHash>);

/// The chains to the checkpoints read in this session, by period.
static CHAINED: LazyLock<Mutex<HashMap<u32, Chain>>> = LazyLock::new(Default::default);

/// Periods kept chained at most: some 64 KiB each.
const CHAINED_MAX: usize = 64;

/// The block the session's chain to the checkpoints holds at `height`.
fn chained_before(height: u32) -> Option<BlockHash> {
    let chained = CHAINED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (from, hashes) = chained.get(&(height / RETARGET_PERIOD))?;
    hashes.get(height.checked_sub(*from)? as usize).copied()
}

/// Keeps a chain to a checkpoint for the session, unless one that starts
/// lower is kept already.
fn remember_chained(from: u32, hashes: &[BlockHash]) {
    let mut chained = CHAINED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let period = from / RETARGET_PERIOD;
    if chained.get(&period).is_some_and(|(kept, _)| *kept <= from) {
        return;
    }
    if chained.len() >= CHAINED_MAX {
        chained.clear();
    }
    chained.insert(period, (from, hashes.to_vec()));
}
