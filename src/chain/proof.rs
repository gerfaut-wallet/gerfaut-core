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
//! of it at least. The header is not chained to the others, which would
//! take every header of its period: one claimed in a period of the first
//! years of the chain costs that period's work, and no more.
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
    CompactTarget, OutPoint, Script, ScriptBuf, Target, Transaction, TxMerkleNode, Txid,
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
    /// branch of the block: the server is to be refused.
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
