//! A small asynchronous Electrum client, for what the blocking client of
//! BDK does not do: the history of one address, its coins and its
//! transactions. It is a future like any other. Dropped, it closes its
//! socket, and nothing of it waits on a thread.
//!
//! The socket is opened the way the live watcher opens its own
//! ([`crate::watch::net`]): TCP, the Tor proxy in front of it for a
//! hidden service and a refusal without one, TLS checked by the
//! verifier every Electrum connection goes through, an accepted
//! fingerprint included. Every answer is one line of at most
//! [`super::MAX_LINE`] bytes, requests go out a window at a time, and
//! each answer has the socket timeout of the server to arrive in.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

use super::{CLIENT_NAME, MAX_LINE, PROTOCOL, TIMEOUT, TOR_TIMEOUT, Target, parse, too_long};
use crate::watch::net::{self, BoxStream, LineReader, LineTooLong, Security};

/// Requests awaiting their answer at any time.
const WINDOW: usize = 16;
/// Lines that answer nothing asked, in a row, before the server is
/// taken for one that does not speak the protocol.
const MAX_STRAY: usize = 1_000;

/// Why a call came back without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallError {
    /// The server answered with an error: its words, kept short.
    Refused(String),
    /// The answer was longer than a line may be.
    TooLong,
    /// The connection failed, or the answer was not the protocol.
    Failed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Refused(words) => write!(f, "the server refused the request: {words}"),
            CallError::TooLong => f.write_str(&too_long(MAX_LINE)),
            CallError::Failed(detail) => f.write_str(detail),
        }
    }
}

impl From<CallError> for String {
    fn from(error: CallError) -> String {
        error.to_string()
    }
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
}

impl Connection {
    /// Connects to `target` and agrees on the protocol. `proxy` is the
    /// Tor proxy the caller resolved; only an onion host goes through
    /// it, and an onion host without one is refused before any socket.
    pub(crate) async fn open(target: &Target, proxy: Option<&str>) -> Result<Self, String> {
        let (tls, host, port) = parse(&target.url)?;
        let onion = crate::chain::is_onion(&target.url);
        let timeout = if onion { TOR_TIMEOUT } else { TIMEOUT };
        let security = if tls {
            Security::Electrum {
                pin: target.pin.as_deref(),
            }
        } else {
            Security::Plain
        };
        let proxy = proxy.filter(|_| onion);
        let stream = net::open(&host, port, security, proxy, timeout).await?;
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = Connection {
            reader: LineReader::new(reader, MAX_LINE),
            writer,
            next_id: 0,
            timeout,
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
        answer.unwrap_or_else(|| Err(CallError::Failed("no answer".to_owned())))
    }

    /// The same method for each of `params`, a window at a time. Each
    /// result is handed to `each` with the index of its parameters as
    /// soon as it arrives, in whatever order the server answers, so a
    /// caller keeps what it needs of it and nothing more. An error from
    /// `each` ends the batch.
    pub(crate) async fn batch<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Vec<Value>,
        mut each: impl FnMut(usize, Result<T, CallError>) -> Result<(), CallError>,
    ) -> Result<(), CallError> {
        let mut waiting: HashMap<u64, usize> = HashMap::new();
        let mut queue = params.into_iter().enumerate();
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

    async fn send(&mut self, method: &str, params: Value) -> Result<u64, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        line.push('\n');
        let write = async {
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.flush().await
        };
        match tokio::time::timeout(self.timeout, write).await {
            Ok(Ok(())) => Ok(id),
            Ok(Err(error)) => Err(CallError::Failed(format!(
                "the connection was closed: {error}"
            ))),
            Err(_) => Err(CallError::Failed("the server stopped reading".to_owned())),
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
                    return Err(CallError::Failed(format!(
                        "timed out after {} s",
                        self.timeout.as_secs()
                    )));
                }
                Ok(Err(error)) if LineTooLong::is(&error) => {
                    return Err(CallError::TooLong);
                }
                Ok(Err(error)) => {
                    return Err(CallError::Failed(format!(
                        "the connection was closed: {error}"
                    )));
                }
                Ok(Ok(None)) => {
                    return Err(CallError::Failed("the connection was closed".to_owned()));
                }
                Ok(Ok(Some(line))) => line,
            };
            let Ok(envelope) = serde_json::from_slice::<Envelope<'_>>(&line) else {
                continue;
            };
            let Some(id) = envelope.id.filter(|id| waiting.contains_key(id)) else {
                continue;
            };
            if let Some(error) = envelope.error.filter(|error| !error.is_null()) {
                return Ok((id, Err(CallError::Refused(words(&error)))));
            }
            let text = envelope.result.map_or("null", RawValue::get);
            let result = serde_json::from_str::<T>(text)
                .map_err(|_| CallError::Failed("unexpected response".to_owned()));
            return Ok((id, result));
        }
        Err(CallError::Failed(
            "the server sends answers to nothing it was asked".to_owned(),
        ))
    }
}

/// The message of a JSON-RPC error, kept short: it comes from the
/// server and ends up on a screen.
fn words(error: &Value) -> String {
    let text = error
        .get("message")
        .and_then(Value::as_str)
        .map_or_else(|| error.to_string(), str::to_owned);
    text.chars().take(200).collect()
}
