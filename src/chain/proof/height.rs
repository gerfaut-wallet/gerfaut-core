//! What binds a mainnet block to its height. Its work says it was mined,
//! and the `bits` of its period say in which period of the table
//! ([`super::has_proof_of_work`]); neither says at which height in it,
//! nor at which height past the table, where the work of any recent
//! block passes. A server that served the real blocks of the chain at
//! heights of its own, a few or a few million too high, passed every
//! other check: the wallet counted its confirmations against a tip that
//! was never there, and took every honest server after it for one that
//! lags.
//!
//! Since BIP-34, block 227,931, the first transaction of every block,
//! its coinbase, starts its script with the height of the block. Proven
//! in the block by its merkle branch from position 0 under the root of
//! the header, it binds that header to its height: to serve a block
//! elsewhere, a server would have to mine one.
//!
//! A height needs no request when the block is a checkpoint, the block
//! the session's chain to a checkpoint holds there, or one this session
//! proved already ([`known`]): by its coinbase, or chained to a block so
//! proven, as the latest blocks a server sends are to its tip. What is
//! proven is kept by network and hash, whatever server it was read
//! from: a block has one height. An unchanged tip costs nothing at the
//! next sync; a new one costs two requests over Electrum
//! (`blockchain.transaction.id_from_pos`, `blockchain.transaction.get`)
//! and three over Esplora (`/block/:hash/txid/0`, `/tx/:txid/raw`,
//! `/tx/:txid/merkle-proof`), as does the block of a confirmation that
//! nothing else binds, once.
//!
//! Signet, testnet4 and regtest ask for none of it: their work proves
//! nothing, and their chain is repaired when a server made it up.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::script::{self, Instruction};
use bdk_wallet::bitcoin::{BlockHash, Transaction, Txid};

use super::{Fault, Proof, RETARGET_PERIOD, chained_before, merkle_root, targets};
use crate::network::Network;

/// The first mainnet block whose coinbase carries its height.
pub(crate) const BIP34_HEIGHT: u32 = 227_931;

/// What a server whose tip's height it cannot prove is refused with:
/// it may only lack the block's coinbase, and is not taken for a liar,
/// but its tip is not followed either.
pub(crate) const UNPROVEN_TIP: &str = "the server could not prove the height of its tip";

/// The heights proven in this session, by network and block hash.
static PROVEN: LazyLock<Mutex<HashMap<(Network, BlockHash), u32>>> =
    LazyLock::new(Default::default);

/// Heights kept proven at most: a megabyte or two. Forgotten all at once
/// past it, and with the process.
const PROVEN_MAX: usize = 20_000;

/// The checkpoints by hash: the height each one ends its period at.
static CHECKPOINTS: LazyLock<HashMap<BlockHash, u32>> = LazyLock::new(|| {
    targets::MAINNET_ENDS
        .iter()
        .enumerate()
        .filter_map(|(period, hash)| {
            let end = (period as u32 + 1) * RETARGET_PERIOD - 1;
            Some((hash.parse().ok()?, end))
        })
        .collect()
});

/// What is known of the block `hash` at `height` with no request:
/// [`Proof::Holds`] where its height needs no proof, or is proven;
/// [`Proof::False`] where the block is known at another height; `None`
/// where its coinbase is to be read.
pub(crate) fn known(network: Network, height: u32, hash: BlockHash) -> Option<Proof> {
    if network != Network::Mainnet {
        return Some(Proof::Holds);
    }
    let at = CHECKPOINTS.get(&hash).copied().or_else(|| {
        PROVEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(network, hash))
            .copied()
    });
    match at {
        Some(at) if at == height => Some(Proof::Holds),
        Some(_) => Some(Proof::False),
        None if chained_before(height) == Some(hash) => Some(Proof::Holds),
        None => None,
    }
}

/// Keeps `blocks`, each a height and the hash of the block there, as
/// proven for the session: blocks whose coinbase was read, or that chain
/// to one that was.
pub(crate) fn remember(network: Network, blocks: impl IntoIterator<Item = (u32, BlockHash)>) {
    if network != Network::Mainnet {
        return;
    }
    let mut proven = PROVEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (height, hash) in blocks {
        if proven.len() >= PROVEN_MAX {
            proven.clear();
        }
        proven.insert((network, hash), height);
    }
}

/// What `coinbase`, said to be the transaction at position `pos` of the
/// block of `header` with `branch` as its merkle branch, proves of that
/// block's height. The header is one already held to its work.
///
/// [`Proof::Holds`] when the transaction is the one `txid` names, at
/// position 0, a coinbase, the branch leading from it to the header's
/// root, and its script starting with `height` as BIP-34 writes it.
/// [`Proof::Elsewhere`] when a sound branch leads to another root: the
/// block at that height may have changed since the header was read.
/// [`Proof::Unsure`] below BIP-34, where a coinbase says nothing, and
/// for a branch through an inner node that reads as a transaction.
/// Anything else is [`Proof::False`].
pub(crate) fn coinbase_proof(
    height: u32,
    header: &Header,
    coinbase: &Transaction,
    txid: Txid,
    pos: usize,
    branch: &[[u8; 32]],
) -> Proof {
    if height < BIP34_HEIGHT {
        return Proof::Unsure;
    }
    if pos != 0 || coinbase.compute_txid() != txid || !coinbase.is_coinbase() {
        return Proof::False;
    }
    match merkle_root(txid, 0, branch) {
        Ok(root) if root == header.merkle_root => {}
        Ok(_) => return Proof::Elsewhere,
        Err(Fault::Transaction) => return Proof::Unsure,
        Err(Fault::Shape) => return Proof::False,
    }
    if written_height(coinbase) == Some(height) {
        Proof::Holds
    } else {
        Proof::False
    }
}

/// The height a coinbase starts its script with, as BIP-34 has it: the
/// first push, minimally encoded, a number in the minimal form script
/// reads, as `Block::bip34_block_height` of rust-bitcoin reads it.
fn written_height(coinbase: &Transaction) -> Option<u32> {
    let input = coinbase.input.first()?;
    match input.script_sig.instructions_minimal().next()?.ok()? {
        Instruction::PushBytes(bytes) => {
            let height = script::read_scriptint(bytes.as_bytes()).ok()?;
            u32::try_from(height).ok()
        }
        Instruction::Op(_) => None,
    }
}

/// What a tip whose height was asked of its server ([`coinbase_proof`],
/// or [`known`]) is worth: followed when it holds, refused as a false
/// proof when it does not, and refused as [`UNPROVEN_TIP`] when the
/// server could not show it either way.
pub(crate) fn tip_proven(proof: Proof) -> Result<(), crate::chain::Fault> {
    match proof {
        Proof::Holds => Ok(()),
        Proof::Unsure => Err(crate::chain::Fault::other(UNPROVEN_TIP)),
        Proof::False | Proof::Elsewhere => Err(crate::chain::Fault::false_proof()),
    }
}

/// Forgets the height proven for `hash`: a test that counts what a
/// proof costs starts from none.
#[cfg(test)]
pub(crate) fn forget(hash: BlockHash) {
    PROVEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|(_, held), _| *held != hash);
}
