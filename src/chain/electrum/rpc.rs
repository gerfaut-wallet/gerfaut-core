//! A small asynchronous Electrum client, for what the blocking client of
//! BDK does not do: the history of one address, its coins and its
//! transactions. It is a future like any other. Dropped, it closes its
//! socket, and nothing of it waits on a thread.
//!
//! The socket is opened the way the live watcher opens its own
//! ([`crate::chain::net`]): TCP, the Tor proxy in front of it for a
//! hidden service and a refusal without one, TLS checked by the
//! verifier every Electrum connection goes through, an accepted
//! fingerprint included. Every answer is one line of at most
//! [`super::MAX_LINE`] bytes, a connection reads [`super::MAX_READ`] at
//! most, every answer together, requests go out a window at a time, and
//! each answer has the socket timeout of the server to arrive in.

use std::collections::HashMap;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

use super::{
    CLIENT_NAME, MAX_LINE, MAX_READ, PROTOCOL, TIMEOUT, TOR_TIMEOUT, Target, parse, too_long, words,
};
use crate::chain::Fault;
use crate::chain::net::{self, BoxStream, LineReader, LineTooLong};

/// Requests awaiting their answer at any time: as many as the live
/// watch keeps, and for the same reason. ElectrumX, from 1.18 on, holds
/// small answers back until a kilobyte of them waits or a second has
/// passed, and some forty-byte answers fill that kilobyte; fewer would
/// wait the second at every round.
const WINDOW: usize = 32;
/// Lines that answer nothing asked, in a row, before the server is
/// taken for one that does not speak the protocol.
const MAX_STRAY: usize = 1_000;

/// Why a call came back without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallError {
    /// The server answered with an error: its words, kept short, and
    /// whether it turned the request down for want of memory
    /// ([`super::out_of_budget`]), which is an outage of the server
    /// whatever was asked.
    Refused { words: String, busy: bool },
    /// The server turned the request down for want of memory, in these
    /// words: it is asked again once, a moment later, before a caller
    /// hears of it as a refusal.
    Busy(String),
    /// The answer was longer than a line may be.
    TooLong,
    /// The connection failed, or the answer was not the protocol.
    Failed(Fault),
}

impl CallError {
    /// A refusal in the server's words.
    pub(crate) fn refused(words: impl Into<String>) -> CallError {
        CallError::Refused {
            words: words.into(),
            busy: false,
        }
    }

    /// What a caller hears of a refusal for want of memory.
    fn busy(words: String) -> CallError {
        CallError::Refused { words, busy: true }
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Refused { words, .. } | CallError::Busy(words) => {
                write!(f, "the server refused the request: {words}")
            }
            CallError::TooLong => f.write_str(&too_long(MAX_LINE)),
            CallError::Failed(fault) => write!(f, "{fault}"),
        }
    }
}

/// A refusal for want of memory is an outage, and a failed connection
/// is what it was found to be; any other refusal, whatever its words,
/// is not.
impl From<CallError> for Fault {
    fn from(error: CallError) -> Fault {
        match &error {
            CallError::Refused { busy: true, .. } | CallError::Busy(_) => {
                Fault::outage(error.to_string())
            }
            CallError::Refused { busy: false, .. } | CallError::TooLong => {
                Fault::other(error.to_string())
            }
            CallError::Failed(fault) => fault.clone(),
        }
    }
}

/// One request as it goes on the wire, its parameters borrowed: a batch
/// keeps them for the requests it asks again, and copies none.
#[derive(Serialize)]
struct Outgoing<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: &'a Value,
}

/// One answer as it comes off the wire: the result is kept as its text
/// until the caller says what it should be.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(default)]
    id: Option<u64>,
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
    #[serde(default)]
    error: Option<Value>,
}

pub(crate) struct Connection {
    reader: LineReader<ReadHalf<BoxStream>>,
    writer: WriteHalf<BoxStream>,
    next_id: u64,
    /// How long each answer may take to arrive.
    timeout: Duration,
    /// Bytes read since the connection opened, and how many it may.
    read: usize,
    read_max: usize,
    /// The waits left to this connection for a server out of memory:
    /// see [`super::PAUSES`].
    pauses: u32,
}

impl Connection {
    /// Connects to `target` and agrees on the protocol. `proxy` is the
    /// Tor proxy the caller resolved; only an onion host goes through
    /// it, and an onion host without one is refused before any socket.
    pub(crate) async fn open(target: &Target, proxy: Option<&str>) -> Result<Self, Fault> {
        let (tls, host, port) = parse(&target.url)?;
        let onion = super::is_onion(target, &host);
        let timeout = if onion { TOR_TIMEOUT } else { TIMEOUT };
        let proxy = proxy.filter(|_| onion);
        let stream = net::open(&host, port, target.security(tls), proxy, timeout).await?;
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = Connection {
            reader: LineReader::new(reader, MAX_LINE),
            writer,
            next_id: 0,
            timeout,
            read: 0,
            read_max: MAX_READ,
            pauses: super::PAUSES,
        };
        connection
            .call::<Value>("server.version", json!([CLIENT_NAME, [PROTOCOL, PROTOCOL]]))
            .await?;
        Ok(connection)
    }

    /// One call, and its result read as `T`.
    pub(crate) async fn call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, CallError> {
        let mut answer = None;
        self.batch(method, vec![params], |_, result| {
            answer = Some(result);
            Ok(())
        })
        .await?;
        answer.unwrap_or_else(|| Err(CallError::Failed(Fault::other("no answer"))))
    }

    /// The same method for each of `params`, a window at a time. Each
    /// result is handed to `each` with the index of its parameters as
    /// soon as it arrives, in whatever order the server answers, so a
    /// caller keeps what it needs of it and nothing more. An error from
    /// `each` ends the batch. The requests the server turned down for
    /// want of memory are asked again once, after
    /// [`super::busy_pause`], and their answers then handed over, a
    /// second refusal as a refusal; once the connection has taken its
    /// waits ([`super::PAUSES`]), the first refusal is.
    pub(crate) async fn batch<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Vec<Value>,
        mut each: impl FnMut(usize, Result<T, CallError>) -> Result<(), CallError>,
    ) -> Result<(), CallError> {
        let mut busy = Vec::new();
        let patient = self.pauses > 0;
        self.round(
            method,
            params.iter().enumerate(),
            |index, result| match result {
                Err(CallError::Busy(_)) if patient => {
                    busy.push(index);
                    Ok(())
                }
                Err(CallError::Busy(words)) => each(index, Err(CallError::busy(words))),
                result => each(index, result),
            },
        )
        .await?;
        if busy.is_empty() {
            return Ok(());
        }
        self.pauses -= 1;
        tokio::time::sleep(super::busy_pause()).await;
        busy.sort_unstable();
        let again = busy.into_iter().map(|index| (index, &params[index]));
        self.round(method, again, |index, result| match result {
            Err(CallError::Busy(words)) => each(index, Err(CallError::busy(words))),
            result => each(index, result),
        })
        .await
    }

    /// The requests of `queue`, each the index of its parameters and
    /// those parameters, a window at a time: see [`Self::batch`].
    async fn round<T: DeserializeOwned>(
        &mut self,
        method: &str,
        mut queue: impl Iterator<Item = (usize, &Value)>,
        mut each: impl FnMut(usize, Result<T, CallError>) -> Result<(), CallError>,
    ) -> Result<(), CallError> {
        let mut waiting: HashMap<u64, usize> = HashMap::new();
        loop {
            while waiting.len() < WINDOW {
                let Some((index, params)) = queue.next() else {
                    break;
                };
                let id = self.send(method, params).await?;
                waiting.insert(id, index);
            }
            if waiting.is_empty() {
                return Ok(());
            }
            let (id, result) = self.receive::<T>(&waiting).await?;
            if let Some(index) = waiting.remove(&id) {
                each(index, result)?;
            }
        }
    }

    async fn send(&mut self, method: &str, params: &Value) -> Result<u64, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Outgoing {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let mut line = serde_json::to_string(&request)
            .map_err(|_| CallError::Failed(Fault::other("the request could not be written")))?;
        line.push('\n');
        let write = async {
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.flush().await
        };
        match tokio::time::timeout(self.timeout, write).await {
            Ok(Ok(())) => Ok(id),
            Ok(Err(error)) => Err(CallError::Failed(Fault::outage(format!(
                "the connection was closed: {error}"
            )))),
            // A server that takes no more of what it is sent is as
            // down as one that sends nothing back.
            Err(_) => Err(CallError::Failed(Fault::outage(
                "the server stopped reading",
            ))),
        }
    }

    /// The next answer to one of the requests `waiting` for one. Lines
    /// that answer nothing asked, notifications among them, are read
    /// and dropped.
    async fn receive<T: DeserializeOwned>(
        &mut self,
        waiting: &HashMap<u64, usize>,
    ) -> Result<(u64, Result<T, CallError>), CallError> {
        for _ in 0..MAX_STRAY {
            let line = match tokio::time::timeout(self.timeout, self.reader.next_line()).await {
                Err(_) => {
                    return Err(CallError::Failed(Fault::outage(format!(
                        "timed out after {} s",
                        self.timeout.as_secs()
                    ))));
                }
                Ok(Err(error)) if LineTooLong::is(&error) => {
                    return Err(CallError::TooLong);
                }
                Ok(Err(error)) => {
                    return Err(CallError::Failed(Fault::outage(format!(
                        "the connection was closed: {error}"
                    ))));
                }
                Ok(Ok(None)) => {
                    return Err(CallError::Failed(Fault::outage(
                        "the connection was closed",
                    )));
                }
                Ok(Ok(Some(line))) => line,
            };
            self.read = self.read.saturating_add(line.len());
            if self.read > self.read_max {
                return Err(CallError::Failed(Fault::other(format!(
                    "the server sent more than {} MiB on one connection",
                    self.read_max >> 20
                ))));
            }
            let Ok(envelope) = serde_json::from_slice::<Envelope<'_>>(&line) else {
                continue;
            };
            let Some(id) = envelope.id.filter(|id| waiting.contains_key(id)) else {
                continue;
            };
            if let Some(error) = envelope.error.filter(|error| !error.is_null()) {
                if super::out_of_budget(&error) {
                    return Ok((id, Err(CallError::Busy(words(&error)))));
                }
                return Ok((id, Err(CallError::refused(words(&error)))));
            }
            let text = envelope.result.map_or("null", RawValue::get);
            let result = serde_json::from_str::<T>(text)
                .map_err(|_| CallError::Failed(Fault::other("unexpected response")));
            return Ok((id, result));
        }
        Err(CallError::Failed(Fault::other(
            "the server sends answers to nothing it was asked",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakeElectrum;

    /// A connection reads so much in all, every answer together, and no
    /// more: a server that keeps sending fails the call instead of
    /// keeping the client reading.
    #[tokio::test]
    async fn a_connection_reads_so_much_and_no_more() {
        let server = FakeElectrum::start().await;
        let target = Target::new(format!("tcp://{}", server.address), None);
        let mut connection = Connection::open(&target, None).await.unwrap();
        connection.read_max = connection.read + 1_000;
        let mut answered = 0;
        let headers = (0..50).map(|height| json!([height])).collect();
        let refused = connection
            .batch::<String>("blockchain.block.header", headers, |_, answer| {
                answer?;
                answered += 1;
                Ok(())
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refused.starts_with("the server sent more than"),
            "{refused}"
        );
        assert!(answered < 10, "{answered}");
    }

    /// The requests of a batch go out a window at a time, wide enough to
    /// fill the kilobyte ElectrumX holds small answers back for: the
    /// server's wait comes at the end of the batch, not at every round.
    #[tokio::test]
    async fn a_batch_fills_what_a_padding_server_holds_back() {
        let server = FakeElectrum::start().await;
        server.state.lock().unwrap().hold = Some((1024, std::time::Duration::from_millis(50)));
        let target = Target::new(format!("tcp://{}", server.address), None);
        let mut connection = Connection::open(&target, None).await.unwrap();
        let hashes = (0..100).map(|n| json!([format!("{n:064x}")])).collect();
        let mut answered = 0;
        connection
            .batch::<Value>("blockchain.scripthash.get_history", hashes, |_, answer| {
                answer?;
                answered += 1;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(answered, 100);
        let waits = server.state.lock().unwrap().timed_flushes;
        assert!(waits <= 2, "{waits} waits");
    }

    /// Requests the server turns down for want of memory, the electrs of
    /// Blockstream under load, are asked again once, five seconds later
    /// and no more than a fifth beyond, all of them after one wait: two
    /// transactions of three here. A second refusal is the answer, in
    /// the server's words: the history on another connection.
    #[tokio::test]
    async fn requests_turned_down_for_memory_are_asked_again_once() {
        use crate::testkit::{nowhere, script, scripthash, transaction};
        let server = FakeElectrum::start().await;
        let txs: Vec<_> = (1..=3)
            .map(|n| transaction(&[nowhere(n, 0)], &[(&script(n), 1_000)]))
            .collect();
        for tx in &txs {
            server.add_tx(tx);
        }
        {
            let mut state = server.state.lock().unwrap();
            state.busy.insert("blockchain.transaction.get", 2);
            state.busy.insert("blockchain.scripthash.get_history", 2);
        }
        let target = Target::new(format!("tcp://{}", server.address), None);
        let mut fetching = Connection::open(&target, None).await.unwrap();
        let mut reading = Connection::open(&target, None).await.unwrap();
        let params: Vec<Value> = txs
            .iter()
            .map(|tx| json!([tx.compute_txid().to_string()]))
            .collect();
        let started = std::time::Instant::now();
        let mut read = vec![false; txs.len()];
        let (fetched, history) = tokio::join!(
            fetching.batch::<String>("blockchain.transaction.get", params, |index, hex| {
                read[index] =
                    hex? == bdk_wallet::bitcoin::consensus::encode::serialize_hex(&txs[index]);
                Ok(())
            }),
            reading.call::<Value>(
                "blockchain.scripthash.get_history",
                json!([scripthash(&script(1))]),
            ),
        );
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(8),
            "{waited:?}"
        );
        fetched.unwrap();
        assert_eq!(read, [true, true, true]);
        assert_eq!(
            history.unwrap_err(),
            CallError::Refused {
                words: "response budget exhausted, retry later".to_owned(),
                busy: true,
            }
        );
        let asked = server.state.lock().unwrap().asked.clone();
        let count = |method: &str| asked.iter().filter(|asked| *asked == method).count();
        assert_eq!(count("blockchain.transaction.get"), 5);
        assert_eq!(count("blockchain.scripthash.get_history"), 2);
    }

    /// A connection that has taken its waits hands a refusal for want of
    /// memory over at once, as a refusal.
    #[tokio::test]
    async fn a_connection_out_of_waits_takes_the_refusal_at_once() {
        let server = FakeElectrum::start().await;
        server
            .state
            .lock()
            .unwrap()
            .busy
            .insert("blockchain.transaction.get", 1);
        let target = Target::new(format!("tcp://{}", server.address), None);
        let mut connection = Connection::open(&target, None).await.unwrap();
        connection.pauses = 0;
        let started = std::time::Instant::now();
        let refused = connection
            .call::<String>("blockchain.transaction.get", json!(["00".repeat(32)]))
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(Fault::from(refused.clone()).is_outage());
        assert_eq!(
            refused,
            CallError::Refused {
                words: "response budget exhausted, retry later".to_owned(),
                busy: true,
            }
        );
    }
}
