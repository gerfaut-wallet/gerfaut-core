//! A single watched address over Electrum: the state the Esplora path
//! builds ([`crate::chain::esplora::fetch_address_state`]), read from
//! what an Electrum server answers. The history comes whole in one
//! call where Esplora pages it; the rounds are cut the same way, the
//! newest first and at most [`CONFIRMED_PER_ROUND`] confirmed ones, so
//! "load older transactions" goes on from the same cursor on both.
//!
//! Esplora hands every input its previous output. Electrum does not, so
//! they are read here: the transaction that created each one is fetched
//! and only the outputs spent are kept, because the fee, the taproot
//! facts and the sigops of a transaction are read from them. A round is
//! read a few transactions at a time, each turned into what the wallet
//! keeps before the next ones come: what a round holds in memory is its
//! result, not its transactions.

use std::collections::{HashMap, HashSet};

use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::deserialize_hex;
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde::Deserialize;
use serde_json::json;

use super::rpc::{CallError, Connection};
use super::{MAX_LINE, Target};
use crate::chain::esplora::{HISTORY_PAGES_PER_ROUND, HistoryRound, parse_address, script_address};
use crate::network::Network;
use crate::wallet::snapshot::TxIo;
use crate::wallet::{AddressTx, AddressUtxo, AddressWatchState, tx_extras};

/// Unconfirmed transactions in a round: what the first page of an
/// Esplora history holds.
const MEMPOOL_PER_ROUND: usize = 50;
/// Confirmed transactions in a round: as many as Esplora pages hold in
/// one, 25 a page.
pub(crate) const CONFIRMED_PER_ROUND: usize = HISTORY_PAGES_PER_ROUND * 25;
/// Transactions of a round held at once while their inputs are read.
const TXS_AT_ONCE: usize = 10;
/// Blocks whose time is read for one round, at most.
const MAX_HEADERS: usize = 2_000;

#[derive(Deserialize)]
struct Tip {
    height: u32,
}

/// One line of a history: height 0 or -1 is the mempool.
#[derive(Debug, Clone, Deserialize)]
struct Entry {
    tx_hash: Txid,
    height: i64,
}

#[derive(Deserialize)]
struct Unspent {
    tx_hash: Txid,
    tx_pos: u32,
    height: i64,
    value: u64,
}

/// A transaction picked for a round, and its height when confirmed.
type Picked = (Txid, Option<u32>);

/// A height the chain has, from what a server wrote.
fn height_of(height: i64) -> Option<u32> {
    u32::try_from(height).ok().filter(|height| *height > 0)
}

/// The Electrum script hash of a script: SHA-256, reversed, in hex.
fn scripthash(script: &ScriptBuf) -> String {
    let mut digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    digest.reverse();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Fetches the complete state of a single watched address.
pub(crate) async fn fetch_state(
    target: &Target,
    address: &str,
    network: Network,
    proxy: Option<&str>,
) -> Result<AddressWatchState, String> {
    state_in_rounds_of(target, address, network, proxy, CONFIRMED_PER_ROUND).await
}

/// Fetches the next round of older transactions, after `from`.
pub(crate) async fn fetch_history(
    target: &Target,
    address: &str,
    network: Network,
    from: &str,
    proxy: Option<&str>,
) -> Result<HistoryRound, String> {
    history_in_rounds_of(target, address, network, from, proxy, CONFIRMED_PER_ROUND).await
}

async fn state_in_rounds_of(
    target: &Target,
    address: &str,
    network: Network,
    proxy: Option<&str>,
    per_round: usize,
) -> Result<AddressWatchState, String> {
    let ours = parse_address(address, network)?.script_pubkey();
    let hash = scripthash(&ours);
    let mut connection = Connection::open(target, proxy).await?;
    let tip: Tip = connection
        .call("blockchain.headers.subscribe", json!([]))
        .await?;
    let history = history(&mut connection, &hash).await?;
    let unspent: Vec<Unspent> = connection
        .call("blockchain.scripthash.listunspent", json!([hash]))
        .await?;
    let (round, cursor) = round_of(&history, None, per_round)?;
    let mut txs = read(&mut connection, &round, &ours, network).await?;

    let heights = txs
        .iter()
        .filter_map(|tx| tx.height)
        .chain(unspent.iter().filter_map(|coin| height_of(coin.height)));
    let times = block_times(&mut connection, heights).await?;
    for tx in &mut txs {
        tx.timestamp = tx.height.and_then(|height| times.get(&height).copied());
    }
    let utxos = unspent
        .into_iter()
        .map(|coin| {
            let height = height_of(coin.height);
            AddressUtxo {
                txid: coin.tx_hash.to_string(),
                vout: coin.tx_pos,
                value_sats: coin.value,
                height,
                timestamp: height.and_then(|height| times.get(&height).copied()),
            }
        })
        .collect();
    // Esplora counts these over the whole history. Here they cover the
    // transactions read, which is all of them unless the history is
    // longer than a round.
    let funded_sats = sum_of(&txs, |tx| &tx.outputs);
    let spent_sats = sum_of(&txs, |tx| &tx.inputs);
    Ok(AddressWatchState {
        txs,
        utxos,
        tip_height: tip.height,
        funded_sats,
        spent_sats,
        truncated: cursor.is_some(),
        history_cursor: cursor,
    })
}

async fn history_in_rounds_of(
    target: &Target,
    address: &str,
    network: Network,
    from: &str,
    proxy: Option<&str>,
    per_round: usize,
) -> Result<HistoryRound, String> {
    let ours = parse_address(address, network)?.script_pubkey();
    let from: Txid = from
        .parse()
        .map_err(|_| format!("invalid history cursor: {from}"))?;
    let mut connection = Connection::open(target, proxy).await?;
    let history = history(&mut connection, &scripthash(&ours)).await?;
    let (round, cursor) = round_of(&history, Some(from), per_round)?;
    let mut txs = read(&mut connection, &round, &ours, network).await?;
    let heights: Vec<u32> = txs.iter().filter_map(|tx| tx.height).collect();
    let times = block_times(&mut connection, heights).await?;
    for tx in &mut txs {
        tx.timestamp = tx.height.and_then(|height| times.get(&height).copied());
    }
    Ok(HistoryRound { txs, cursor })
}

fn sum_of(txs: &[AddressTx], side: impl Fn(&AddressTx) -> &Vec<TxIo>) -> u64 {
    txs.iter()
        .flat_map(|tx| side(tx).iter())
        .filter(|io| io.is_mine)
        .filter_map(|io| io.value_sats)
        .fold(0u64, u64::saturating_add)
}

/// The whole history of a script. A server that will not send one this
/// long says so in its own words, and the message says what reads it.
async fn history(connection: &mut Connection, hash: &str) -> Result<Vec<Entry>, String> {
    match connection
        .call::<Vec<Entry>>("blockchain.scripthash.get_history", json!([hash]))
        .await
    {
        Ok(history) => Ok(history),
        Err(CallError::Refused(words)) => {
            let lower = words.to_ascii_lowercase();
            let about_size = [
                "too large",
                "too long",
                "too many",
                "exceed",
                "limit",
                "max",
            ]
            .iter()
            .any(|phrase| lower.contains(phrase));
            Err(if about_size {
                format!(
                    "the server will not send the history of this address, too long for it \
                     ({words}); an Esplora backend, or an Electrum server that allows longer \
                     histories, can read it"
                )
            } else {
                format!("the server refused the history of this address: {words}")
            })
        }
        Err(CallError::TooLong) => Err(format!(
            "the history of this address is longer than an Electrum answer read here may be \
             ({} MiB); an Esplora backend can read it",
            MAX_LINE >> 20
        )),
        Err(other) => Err(other.into()),
    }
}

/// The transactions of one round, newest first: the unconfirmed ones
/// on the first round only, then up to `per_round` confirmed ones after
/// `from`. The cursor names the oldest one taken when older ones remain.
fn round_of(
    history: &[Entry],
    from: Option<Txid>,
    per_round: usize,
) -> Result<(Vec<Picked>, Option<String>), String> {
    // A server may list a transaction twice; it is read once.
    let mut seen = HashSet::new();
    let unique: Vec<&Entry> = history
        .iter()
        .filter(|entry| seen.insert(entry.tx_hash))
        .collect();
    // Servers list a history oldest first. Reversed, then sorted by
    // height with a stable sort, it reads newest first, and in reverse
    // block order within a block, the way Esplora lists it.
    let mut confirmed: Vec<&Entry> = unique
        .iter()
        .copied()
        .filter(|entry| height_of(entry.height).is_some())
        .collect();
    confirmed.reverse();
    confirmed.sort_by_key(|entry| std::cmp::Reverse(entry.height));
    let start = match from {
        None => 0,
        Some(from) => {
            confirmed
                .iter()
                .position(|entry| entry.tx_hash == from)
                .ok_or_else(|| {
                    "the history of this address changed since the last sync; sync the wallet \
                     and try again"
                        .to_owned()
                })?
                + 1
        }
    };
    let rest = &confirmed[start..];
    let taken = &rest[..rest.len().min(per_round)];
    let cursor = (rest.len() > taken.len())
        .then(|| taken.last().map(|entry| entry.tx_hash.to_string()))
        .flatten();
    let mut round: Vec<Picked> = Vec::new();
    if from.is_none() {
        round.extend(
            unique
                .iter()
                .filter(|entry| height_of(entry.height).is_none())
                .take(MEMPOOL_PER_ROUND)
                .map(|entry| (entry.tx_hash, None)),
        );
    }
    round.extend(
        taken
            .iter()
            .map(|entry| (entry.tx_hash, height_of(entry.height))),
    );
    Ok((round, cursor))
}

/// A transaction as the server sent it, refused unless it is the one
/// asked for: its hash is what names it, and a server cannot pass off
/// another as this one.
fn decode(hex: &str, expected: Txid) -> Result<Transaction, CallError> {
    let tx: Transaction =
        deserialize_hex(hex).map_err(|_| CallError::Failed("unexpected response".to_owned()))?;
    if tx.compute_txid() != expected {
        return Err(CallError::Failed("unexpected response".to_owned()));
    }
    Ok(tx)
}

/// The transactions of a round, as the wallet keeps them.
async fn read(
    connection: &mut Connection,
    round: &[Picked],
    ours: &ScriptBuf,
    network: Network,
) -> Result<Vec<AddressTx>, String> {
    // Outputs paying the address, from the transactions read so far:
    // what a spend from it takes as input, no fetch needed.
    let mut paid_to_us: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut read = Vec::with_capacity(round.len());
    for chunk in round.chunks(TXS_AT_ONCE) {
        let txids: Vec<Txid> = chunk.iter().map(|(txid, _)| *txid).collect();
        let txs = fetch_txs(connection, &txids).await?;
        for tx in &txs {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey == *ours {
                    paid_to_us.insert(OutPoint::new(txid, vout as u32), output.clone());
                }
            }
        }
        let in_chunk: HashMap<Txid, &Transaction> = txids.iter().copied().zip(&txs).collect();
        let mut prevouts: HashMap<OutPoint, TxOut> = HashMap::new();
        let mut wanted: HashMap<Txid, Vec<u32>> = HashMap::new();
        for tx in txs.iter().filter(|tx| !tx.is_coinbase()) {
            for input in &tx.input {
                let spent = input.previous_output;
                let known = paid_to_us.get(&spent).cloned().or_else(|| {
                    in_chunk
                        .get(&spent.txid)
                        .and_then(|parent| parent.output.get(spent.vout as usize).cloned())
                });
                match known {
                    Some(output) => {
                        prevouts.insert(spent, output);
                    }
                    None => wanted.entry(spent.txid).or_default().push(spent.vout),
                }
            }
        }
        fetch_outputs(connection, wanted, &mut prevouts).await?;
        for (tx, (_, height)) in txs.iter().zip(chunk) {
            read.push(to_address_tx(tx, *height, &prevouts, ours, network));
        }
    }
    Ok(read)
}

/// Transactions by txid, in the order asked. One the server does not
/// have fails the round: the history it sent named it.
async fn fetch_txs(
    connection: &mut Connection,
    txids: &[Txid],
) -> Result<Vec<Transaction>, String> {
    let mut found: Vec<Option<Transaction>> = vec![None; txids.len()];
    connection
        .batch::<String>(
            "blockchain.transaction.get",
            txids.iter().map(|txid| json!([txid.to_string()])).collect(),
            |index, answer| {
                let tx = decode(&answer?, txids[index])?;
                found[index] = Some(tx);
                Ok(())
            },
        )
        .await?;
    found
        .into_iter()
        .zip(txids)
        .map(|(tx, txid)| tx.ok_or_else(|| format!("the server did not send transaction {txid}")))
        .collect()
}

/// The outputs `wanted` names, read off the transactions that created
/// them, each dropped once its outputs are kept. One the server does
/// not have is left unknown: the fee of its spender is then unknown too.
async fn fetch_outputs(
    connection: &mut Connection,
    wanted: HashMap<Txid, Vec<u32>>,
    prevouts: &mut HashMap<OutPoint, TxOut>,
) -> Result<(), String> {
    let wanted: Vec<(Txid, Vec<u32>)> = wanted.into_iter().collect();
    connection
        .batch::<String>(
            "blockchain.transaction.get",
            wanted
                .iter()
                .map(|(txid, _)| json!([txid.to_string()]))
                .collect(),
            |index, answer| {
                let (txid, vouts) = &wanted[index];
                let hex = match answer {
                    Ok(hex) => hex,
                    Err(CallError::Refused(_)) => return Ok(()),
                    Err(other) => return Err(other),
                };
                let tx = decode(&hex, *txid)?;
                for vout in vouts {
                    if let Some(output) = tx.output.get(*vout as usize) {
                        prevouts.insert(OutPoint::new(*txid, *vout), output.clone());
                    }
                }
                Ok(())
            },
        )
        .await?;
    Ok(())
}

/// The time of the blocks at these heights, from their headers. Past
/// [`MAX_HEADERS`] distinct heights the rest stay without a time.
async fn block_times(
    connection: &mut Connection,
    heights: impl IntoIterator<Item = u32>,
) -> Result<HashMap<u32, u64>, String> {
    let mut seen = HashSet::new();
    let heights: Vec<u32> = heights
        .into_iter()
        .filter(|height| seen.insert(*height))
        .take(MAX_HEADERS)
        .collect();
    let mut times = HashMap::new();
    connection
        .batch::<String>(
            "blockchain.block.header",
            heights.iter().map(|height| json!([height])).collect(),
            |index, answer| {
                // A block the server cannot describe leaves its
                // transactions without a time, nothing more.
                if let Ok(hex) = answer
                    && let Ok(header) = deserialize_hex::<Header>(&hex)
                {
                    times.insert(heights[index], u64::from(header.time));
                }
                Ok(())
            },
        )
        .await?;
    Ok(times)
}

/// One transaction as seen from the watched address: the shape the
/// Esplora path gives it.
fn to_address_tx(
    tx: &Transaction,
    height: Option<u32>,
    prevouts: &HashMap<OutPoint, TxOut>,
    ours: &ScriptBuf,
    network: Network,
) -> AddressTx {
    let coinbase = tx.is_coinbase();
    let received: u64 = tx
        .output
        .iter()
        .filter(|output| output.script_pubkey == *ours)
        .map(|output| output.value.to_sat())
        .fold(0, u64::saturating_add);
    let mut spent = 0u64;
    let mut paid_in = Some(0u64);
    let inputs = tx
        .input
        .iter()
        .map(|input| {
            // A coinbase input spends nothing: its outpoint is all
            // zeroes and must never reach a screen.
            if coinbase {
                return TxIo::default();
            }
            let spends = input.previous_output;
            match prevouts.get(&spends) {
                Some(prevout) => {
                    let value = prevout.value.to_sat();
                    let is_mine = prevout.script_pubkey == *ours;
                    if is_mine {
                        spent = spent.saturating_add(value);
                    }
                    paid_in = paid_in.and_then(|sum| sum.checked_add(value));
                    TxIo {
                        address: script_address(&prevout.script_pubkey, network),
                        value_sats: Some(value),
                        is_mine,
                        prev_txid: Some(spends.txid.to_string()),
                        prev_vout: Some(spends.vout),
                        ..TxIo::default()
                    }
                }
                None => {
                    paid_in = None;
                    TxIo {
                        prev_txid: Some(spends.txid.to_string()),
                        prev_vout: Some(spends.vout),
                        ..TxIo::default()
                    }
                }
            }
        })
        .collect();
    let outputs = tx
        .output
        .iter()
        .map(|output| TxIo {
            address: script_address(&output.script_pubkey, network),
            value_sats: Some(output.value.to_sat()),
            is_mine: output.script_pubkey == *ours,
            change: false,
            op_return: tx_extras::op_return_of(&output.script_pubkey),
            ..TxIo::default()
        })
        .collect();
    let paid_out = tx
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
    let fee = match (coinbase, paid_in, paid_out) {
        (false, Some(paid_in), Some(paid_out)) => paid_in.checked_sub(paid_out),
        _ => None,
    };
    let extras = tx_extras::analyze(tx, |outpoint| prevouts.get(outpoint).cloned());
    AddressTx {
        txid: tx.compute_txid().to_string(),
        net_sats: (received as i64).saturating_sub(spent as i64),
        fee_sats: fee,
        height,
        timestamp: None,
        vsize: tx.vsize() as u64,
        inputs,
        outputs,
        extras: Some(extras),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeElectrum, nowhere, script, transaction};

    /// The BIP-173 test vector address, and its script.
    const ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const OURS: &str = "0014751e76e8199196d454941c45d1b3a323f1433bd6";

    fn target(server: &FakeElectrum) -> Target {
        Target::new(format!("tcp://{}", server.address), None)
    }

    /// Someone funds a transaction, pays the address from it, and the
    /// address pays onwards, keeping change.
    fn story() -> (Transaction, Transaction, Transaction) {
        let parent = transaction(&[nowhere(7, 0)], &[(&script(9), 80_000)]);
        let payment = transaction(
            &[OutPoint::new(parent.compute_txid(), 0)],
            &[(OURS, 50_000), (&script(9), 29_000)],
        );
        let spend = transaction(
            &[OutPoint::new(payment.compute_txid(), 0)],
            &[(&script(8), 30_000), (OURS, 19_500)],
        );
        (parent, payment, spend)
    }

    #[tokio::test]
    async fn an_address_reads_over_electrum_as_over_esplora() {
        let server = FakeElectrum::start().await;
        let (parent, payment, spend) = story();
        for tx in [&parent, &payment, &spend] {
            server.add_tx(tx);
        }
        server.set_history(
            OURS,
            &[(payment.compute_txid(), 90), (spend.compute_txid(), 0)],
        );
        server.set_unspent(OURS, &[(spend.compute_txid(), 1, 0, 19_500)]);

        let state = fetch_state(&target(&server), ADDRESS, Network::Signet, None)
            .await
            .unwrap();
        assert_eq!(state.tip_height, 100);
        assert_eq!(state.txs.len(), 2);
        // Newest first: the one still in the mempool.
        let (pending, received) = (&state.txs[0], &state.txs[1]);
        assert_eq!(pending.txid, spend.compute_txid().to_string());
        assert_eq!(pending.height, None);
        assert_eq!(pending.net_sats, 19_500 - 50_000);
        assert_eq!(pending.fee_sats, Some(500));
        assert!(pending.inputs[0].is_mine);
        assert_eq!(
            pending.inputs[0].prev_txid,
            Some(payment.compute_txid().to_string())
        );
        assert_eq!(received.txid, payment.compute_txid().to_string());
        assert_eq!(received.net_sats, 50_000);
        assert_eq!(received.fee_sats, Some(1_000));
        assert_eq!(received.height, Some(90));
        assert_eq!(received.timestamp, Some(1_700_000_090));
        assert_eq!(received.vsize, payment.vsize() as u64);
        assert_eq!(received.inputs[0].value_sats, Some(80_000));
        assert!(!received.inputs[0].is_mine);
        assert_eq!(received.outputs[0].address.as_deref(), Some(ADDRESS));
        assert!(received.outputs[0].is_mine);
        assert!(received.extras.is_some());
        assert_eq!(
            state.utxos,
            vec![AddressUtxo {
                txid: spend.compute_txid().to_string(),
                vout: 1,
                value_sats: 19_500,
                height: None,
                timestamp: None,
            }]
        );
        assert_eq!((state.funded_sats, state.spent_sats), (69_500, 50_000));
        assert!(!state.truncated);
        assert_eq!(state.history_cursor, None);
        assert_eq!(crate::wallet::views::address_balance(&state).total, 19_500);
    }

    /// A long history comes in rounds, newest first, each continuing
    /// from the cursor the one before left.
    #[tokio::test]
    async fn a_long_history_comes_in_rounds() {
        let server = FakeElectrum::start().await;
        let payments: Vec<Transaction> = (0..5u8)
            .map(|n| transaction(&[nowhere(n, 0)], &[(OURS, 1_000 + u64::from(n))]))
            .collect();
        for tx in &payments {
            server.add_tx(tx);
        }
        // Two in block 10, in that order within it, then one a block.
        let heights = [10, 10, 11, 12, 13];
        let history: Vec<(Txid, i64)> = payments
            .iter()
            .zip(heights)
            .map(|(tx, height)| (tx.compute_txid(), height))
            .collect();
        server.set_history(OURS, &history);
        let txid = |n: usize| payments[n].compute_txid().to_string();
        let target = target(&server);

        let first = state_in_rounds_of(&target, ADDRESS, Network::Signet, None, 2)
            .await
            .unwrap();
        let listed: Vec<String> = first.txs.iter().map(|tx| tx.txid.clone()).collect();
        assert_eq!(listed, [txid(4), txid(3)]);
        assert!(first.truncated);
        assert_eq!(first.history_cursor, Some(txid(3)));
        // A payment whose funding transaction the server does not have
        // has no known fee, and nothing worse.
        assert_eq!(first.txs[0].fee_sats, None);
        assert_eq!(first.txs[0].net_sats, 1_004);

        let second = history_in_rounds_of(&target, ADDRESS, Network::Signet, &txid(3), None, 2)
            .await
            .unwrap();
        let listed: Vec<String> = second.txs.iter().map(|tx| tx.txid.clone()).collect();
        assert_eq!(listed, [txid(2), txid(1)]);
        assert_eq!(second.cursor, Some(txid(1)));
        let last = history_in_rounds_of(&target, ADDRESS, Network::Signet, &txid(1), None, 2)
            .await
            .unwrap();
        let listed: Vec<String> = last.txs.iter().map(|tx| tx.txid.clone()).collect();
        assert_eq!(listed, [txid(0)]);
        assert_eq!(last.cursor, None);

        // A cursor the history no longer holds: sync first.
        let moved = history_in_rounds_of(
            &target,
            ADDRESS,
            Network::Signet,
            &nowhere(9, 0).txid.to_string(),
            None,
            2,
        )
        .await
        .unwrap_err();
        assert!(moved.contains("changed since the last sync"), "{moved}");
    }

    /// A server that will not send a history this long says so, and the
    /// message names what can read it. One that sends more than a line
    /// may hold is cut off with the same kind of message.
    #[tokio::test]
    async fn a_history_too_long_for_the_server_says_what_reads_it() {
        let server = FakeElectrum::start().await;
        server.state.lock().unwrap().refuse.insert(
            "blockchain.scripthash.get_history",
            "history too large".to_owned(),
        );
        let refused = fetch_state(&target(&server), ADDRESS, Network::Signet, None)
            .await
            .unwrap_err();
        assert!(
            refused.contains("too long for it (history too large)"),
            "{refused}"
        );
        assert!(refused.contains("Esplora"), "{refused}");

        let server = FakeElectrum::start().await;
        server.state.lock().unwrap().flood =
            Some(("blockchain.scripthash.get_history", MAX_LINE + 4096));
        let flooded = fetch_state(&target(&server), ADDRESS, Network::Signet, None)
            .await
            .unwrap_err();
        assert!(
            flooded.contains("longer than an Electrum answer"),
            "{flooded}"
        );
    }

    /// A transaction is what its hash says: bytes of another one sent in
    /// its place are refused, whatever they hold.
    #[tokio::test]
    async fn a_transaction_passed_off_as_another_is_refused() {
        let server = FakeElectrum::start().await;
        let (_, payment, spend) = story();
        server.set_history(OURS, &[(payment.compute_txid(), 90)]);
        server.state.lock().unwrap().txs.insert(
            payment.compute_txid(),
            bdk_wallet::bitcoin::consensus::encode::serialize_hex(&spend),
        );
        let error = fetch_state(&target(&server), ADDRESS, Network::Signet, None)
            .await
            .unwrap_err();
        assert_eq!(error, "unexpected response");
    }

    /// An onion server without a route to it: nothing is opened.
    #[tokio::test]
    async fn an_onion_server_without_tor_is_never_reached() {
        let onion = Target::new(
            "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001",
            None,
        );
        let error = fetch_state(&onion, ADDRESS, Network::Signet, None)
            .await
            .unwrap_err();
        assert!(error.starts_with("tor: "), "{error}");
    }

    /// The wallet manager syncs a watched address over Electrum, where
    /// it used to ask for an Esplora backend.
    #[tokio::test]
    async fn the_manager_syncs_a_watched_address_over_electrum() {
        let server = FakeElectrum::start().await;
        let (parent, payment, _) = story();
        server.add_tx(&parent);
        server.add_tx(&payment);
        server.set_history(OURS, &[(payment.compute_txid(), 90)]);
        server.set_unspent(OURS, &[(payment.compute_txid(), 0, 90, 50_000)]);
        let dir = tempfile::tempdir().unwrap();
        let manager =
            crate::WalletManager::open(dir.path(), crate::store::VaultKey::Raw([7; 32])).unwrap();
        manager
            .set_backend(Network::Signet, server.backend())
            .await
            .unwrap();
        let parsed = crate::input::parse_input(ADDRESS).unwrap();
        let wallet = manager
            .add_wallet("Watched", &parsed, Network::Signet)
            .await
            .unwrap();
        let report = manager.sync_wallet(&wallet.id).await.unwrap();
        assert_eq!(report.new_txs.len(), 1);
        assert_eq!(report.balance.confirmed, 50_000);
        let snapshot = manager.wallet_snapshot(&wallet.id).await.unwrap();
        assert_eq!(snapshot.txs[0].fee_sats, Some(1_000));
        assert_eq!(manager.load_more_history(&wallet.id).await.unwrap(), 0);
    }

    const SIGNET_ELECTRUM: &str = "ssl://signet-electrumx.wakiyamap.dev:50002";
    /// Where a recent block is read. It serves no address routes.
    const SIGNET_ESPLORA: &str = "https://mempool.emzy.de/signet/api";
    /// Where the address is read. It limits requests per address: this
    /// test asks it for a handful.
    const SIGNET_ADDRESSES: &str = "https://blockstream.info/signet/api";

    /// Live. An address a recent signet transaction spent from, with a
    /// short history, read over Electrum and over Esplora: the same
    /// transactions, with the same amounts, fees, sizes, heights, times
    /// and deep facts, and the same coins. A few requests to each
    /// Esplora server, and the Electrum calls of one round.
    #[tokio::test]
    #[ignore = "talks to public signet servers"]
    async fn live_an_address_reads_the_same_over_electrum_and_esplora() {
        let esplora = crate::chain::esplora::client(SIGNET_ESPLORA, None).unwrap();
        let addresses = crate::chain::esplora::client(SIGNET_ADDRESSES, None).unwrap();
        let tip = esplora.get_height().await.unwrap();
        let block = esplora.get_block_hash(tip - 3).await.unwrap();
        let txids = esplora.get_block_txids(&block).await.unwrap();
        let mut address = None;
        // The address an input of a recent transaction spent from: one
        // that was paid, then spent, so both sides are read.
        for txid in txids.iter().skip(1).take(12) {
            let Ok(Some(tx)) = esplora.get_tx(txid).await else {
                continue;
            };
            let spent = tx.input[0].previous_output;
            let Ok(Some(parent)) = esplora.get_tx(&spent.txid).await else {
                continue;
            };
            let Some(candidate) = parent.output.get(spent.vout as usize).and_then(|output| {
                bdk_wallet::bitcoin::Address::from_script(
                    &output.script_pubkey,
                    bdk_wallet::bitcoin::Network::Signet,
                )
                .ok()
            }) else {
                continue;
            };
            let Ok(stats) = addresses.get_address_stats(&candidate).await else {
                continue;
            };
            if (1..=40).contains(&(stats.chain_stats.tx_count + stats.mempool_stats.tx_count)) {
                address = Some(candidate.to_string());
                break;
            }
        }
        let address = address.expect("a recent signet address with a short history");
        println!("reading {address}");
        let by_esplora =
            crate::chain::esplora::fetch_address_state(&addresses, &address, Network::Signet)
                .await
                .unwrap();

        // The server signs its own certificate: accepted by its
        // fingerprint, the way the settings screen does it.
        let pin = match super::super::inspect(&Target::new(SIGNET_ELECTRUM, None))
            .await
            .expect("the signet Electrum server answers")
        {
            super::super::Inspection::Tls(crate::chain::tls::Verdict::Unknown {
                fingerprint,
                ..
            }) => Some(fingerprint),
            _ => None,
        };
        let by_electrum = fetch_state(
            &Target::new(SIGNET_ELECTRUM, pin),
            &address,
            Network::Signet,
            None,
        )
        .await
        .unwrap();

        // One line per transaction and per coin, in a fixed order.
        let key = |state: &AddressWatchState| {
            let mut lines: Vec<String> = state
                .txs
                .iter()
                .map(|tx| {
                    format!(
                        "tx {} net {} fee {:?} at {:?} time {:?} vsize {}",
                        tx.txid, tx.net_sats, tx.fee_sats, tx.height, tx.timestamp, tx.vsize
                    )
                })
                .chain(state.utxos.iter().map(|coin| {
                    format!(
                        "coin {}:{} {} at {:?} time {:?}",
                        coin.txid, coin.vout, coin.value_sats, coin.height, coin.timestamp
                    )
                }))
                .collect();
            lines.sort();
            lines
        };
        assert_eq!(key(&by_electrum), key(&by_esplora));
        assert!(by_electrum.tip_height.abs_diff(by_esplora.tip_height) <= 1);
        let extras = |state: &AddressWatchState| {
            let mut all: Vec<(String, Option<crate::wallet::tx_extras::TxExtras>)> = state
                .txs
                .iter()
                .map(|tx| (tx.txid.clone(), tx.extras.clone()))
                .collect();
            all.sort_by(|a, b| a.0.cmp(&b.0));
            all
        };
        assert_eq!(extras(&by_electrum), extras(&by_esplora));
        println!(
            "{} transactions, {} coins, the same both ways",
            by_electrum.txs.len(),
            by_electrum.utxos.len()
        );
    }
}
