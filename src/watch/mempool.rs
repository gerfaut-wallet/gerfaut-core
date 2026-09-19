//! The WebSocket of a mempool instance, `/api/v1/ws`: every block, and
//! the transactions of as many scripts as the server tracks on one
//! connection.
//!
//! That number is `MAX_TRACKED_ADDRESSES` on the server: one by
//! default, ten on the public instances. The server names it when it
//! refuses a longer list, and the list is cut to it: the head of every
//! wallet is pushed, and the scripts past it are polled over the REST
//! API of the same server, three a minute.
//!
//! Any Esplora address is tried. A server that is not a mempool
//! instance answers the upgrade with an HTTP status, which is how the
//! watcher learns to poll it instead.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{WebSocketStream, client_async_with_config};
use url::Url;

use super::net::{self, BoxStream, Security};
use super::poll::{self, Poller};
use super::{ChangeReason, Exit, Hub, Wake, WatchState, WatchTransport};
use crate::chain::Endpoint;

/// The largest message read. A notification carries whole
/// transactions, so it can be large; past this the connection is
/// dropped and reopened, which reports every wallet once.
const MAX_MESSAGE: usize = 4 << 20;
/// Scripts asked for before the server has named its limit.
const FIRST_ASK: usize = 100;

type Socket = WebSocketStream<BoxStream>;

/// The WebSocket address of an Esplora base address, the host and port
/// to connect to, and what to lay over the socket.
fn address(base: &str) -> Result<(Url, String, u16, bool), String> {
    let mut url = Url::parse(base).map_err(|_| "the address cannot be read".to_owned())?;
    let secure = match url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(format!("{other}:// has no WebSocket")),
    };
    let host = crate::chain::host_of_parsed(&url).ok_or("the address has no host")?;
    let port = url
        .port_or_known_default()
        .ok_or("the address has no port")?;
    let path = format!("{}/v1/ws", url.path().trim_end_matches('/'));
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    url.set_scheme(if secure { "wss" } else { "ws" })
        .map_err(|()| "the address cannot be read".to_owned())?;
    Ok((url, host, port, secure))
}

pub(super) async fn run(hub: &mut Hub, endpoint: &Endpoint, base: &str) -> Exit {
    let (mut url, host, port, secure) = match address(base) {
        Ok(parts) => parts,
        Err(detail) => return Exit::NoPush(detail),
    };
    let label = endpoint.label();
    hub.set_status(|status| {
        if status.state != WatchState::Reconnecting {
            status.state = WatchState::Connecting;
        }
        status.transport = Some(WatchTransport::MempoolWebsocket);
        status.server = Some(label.clone());
    });
    let proxy = match hub.proxy_for(endpoint).await {
        Ok(proxy) => proxy,
        Err(Exit::Lost(detail)) => return Exit::Unreachable(detail),
        Err(exit) => return exit,
    };
    // Credentials in the address travel as a header, the way the HTTP
    // client of a sync sends them, and not in the request line.
    let authorization = (!url.username().is_empty()).then(|| {
        let pair = format!("{}:{}", url.username(), url.password().unwrap_or_default());
        format!("Basic {}", data_encoding::BASE64.encode(pair.as_bytes()))
    });
    let _ = url.set_username("");
    let _ = url.set_password(None);

    let budget = hub.connect_budget(endpoint);
    let opening = {
        let proxy = proxy.clone();
        async move {
            let security = if secure {
                Security::Public
            } else {
                Security::Plain
            };
            let stream = net::open(&host, port, security, proxy.as_deref(), budget)
                .await
                .map_err(Exit::Unreachable)?;
            let mut request = url
                .as_str()
                .into_client_request()
                .map_err(|e| Exit::NoPush(e.to_string()))?;
            if let Some(authorization) = authorization
                && let Ok(value) = HeaderValue::from_str(&authorization)
            {
                request.headers_mut().insert(AUTHORIZATION, value);
            }
            let config = WebSocketConfig::default()
                .max_message_size(Some(MAX_MESSAGE))
                .max_frame_size(Some(MAX_MESSAGE));
            let upgrade = client_async_with_config(request, stream, Some(config));
            match tokio::time::timeout(budget, upgrade).await {
                Ok(Ok((socket, _))) => Ok(socket),
                // The server answered, and not with a WebSocket: it is
                // there, and has no push to offer.
                Ok(Err(WsError::Http(response))) => Err(Exit::NoPush(format!(
                    "HTTP {}: no WebSocket here",
                    response.status().as_u16()
                ))),
                Ok(Err(error)) => Err(Exit::Unreachable(describe(&error))),
                Err(_) => Err(Exit::Unreachable(format!(
                    "timed out after {} s",
                    budget.as_secs()
                ))),
            }
        }
    };
    let mut socket: Socket = match hub.during(opening).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(exit)) | Err(exit) => return exit,
    };

    hub.alive();
    hub.set_status(|status| {
        status.state = WatchState::Connected;
        status.transport = Some(WatchTransport::MempoolWebsocket);
        status.server = Some(label.clone());
        status.detail = None;
        status.pushed_scripts = 0;
    });
    // This transport keeps no record of what it missed: after a loss,
    // every wallet is worth one sync.
    if hub.had_session {
        hub.mark_all(ChangeReason::Reconnected);
    }
    hub.had_session = true;

    let mut tracked: Vec<String> = Vec::new();
    let want = json!({ "action": "want", "data": ["blocks"] });
    if let Err(detail) = say(&mut socket, &want).await {
        return Exit::Lost(detail);
    }
    if let Err(detail) = track(hub, &mut socket, &mut tracked).await {
        return Exit::Lost(detail);
    }
    let mut poller = match Poller::new(base, proxy.as_deref()) {
        Ok(poller) => poller,
        Err(detail) => return Exit::Lost(detail),
    };

    let mut keepalive = tokio::time::interval_at(
        Instant::now() + hub.timings.keepalive,
        hub.timings.keepalive,
    );
    let mut round = tokio::time::interval_at(Instant::now() + hub.timings.poll, hub.timings.poll);
    let mut pong_by: Option<Instant> = None;
    loop {
        let outcome: Result<(), String> = tokio::select! {
            message = socket.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    hub.alive();
                    pong_by = None;
                    match read(hub, text.as_str()) {
                        Some(limit) => {
                            hub.track_limit = Some(limit);
                            track(hub, &mut socket, &mut tracked).await
                        }
                        None => Ok(()),
                    }
                }
                Some(Ok(Message::Close(_))) | None => Err("the connection was closed".to_owned()),
                Some(Ok(_)) => {
                    hub.alive();
                    pong_by = None;
                    Ok(())
                }
                Some(Err(error)) => Err(describe(&error)),
            },
            wake = hub.wake() => match wake {
                Wake::Stop => {
                    let _ = socket.close(None).await;
                    return Exit::Stop;
                }
                Wake::Reconfigured => {
                    let _ = socket.close(None).await;
                    return Exit::Reconfigured;
                }
                Wake::Wallets if hub.watched.entries.is_empty() => {
                    let _ = socket.close(None).await;
                    return Exit::Reprobe;
                }
                Wake::Wallets => track(hub, &mut socket, &mut tracked).await,
                Wake::Tick { idle } => {
                    // A deadline set before the device slept says
                    // nothing about the server.
                    if idle > hub.timings.keepalive * 2 {
                        pong_by = None;
                    }
                    pong_by.get_or_insert(Instant::now() + hub.pong_budget(endpoint));
                    say(&mut socket, &json!({ "action": "ping" })).await
                }
                Wake::Flushed => Ok(()),
            },
            _ = keepalive.tick() => {
                pong_by.get_or_insert(Instant::now() + hub.pong_budget(endpoint));
                say(&mut socket, &json!({ "action": "ping" })).await
            }
            _ = round.tick() => {
                // The scripts the server does not push, and only those.
                let plan = poller.plan(&hub.watched, tracked.len(), 0);
                match hub.during(plan.check()).await {
                    Ok(Ok(found)) => poll::apply(hub, found),
                    // The REST side failing does not end a push
                    // connection that works.
                    Ok(Err(_)) => {}
                    Err(exit) => return exit,
                }
                Ok(())
            }
            () = super::sleep_until(pong_by), if pong_by.is_some() => {
                Err("the server stopped answering".to_owned())
            }
        };
        if let Err(detail) = outcome {
            return Exit::Lost(detail);
        }
    }
}

/// Asks the server to track the head of the list, as long as its limit
/// allows, when that differs from what it tracks already.
async fn track(
    hub: &mut Hub,
    socket: &mut Socket,
    tracked: &mut Vec<String>,
) -> Result<(), String> {
    let limit = hub.track_limit.unwrap_or(FIRST_ASK);
    let wanted: Vec<String> = hub
        .watched
        .entries
        .iter()
        .take(limit)
        .map(|entry| entry.hex.clone())
        .collect();
    if wanted == *tracked {
        return Ok(());
    }
    say(socket, &json!({ "track-scriptpubkeys": wanted })).await?;
    *tracked = wanted;
    let pushed = tracked.len() as u32;
    hub.set_status(|status| status.pushed_scripts = pushed);
    Ok(())
}

/// What is read of a message: the scripts it names, never the
/// transactions under them, and the height of a block, never the block.
/// The rest is skipped as it is parsed, so a large message costs its
/// own size and nothing more.
#[derive(serde::Deserialize)]
struct Frame {
    #[serde(default, rename = "multi-scriptpubkey-transactions")]
    scripts: Option<std::collections::HashMap<String, serde::de::IgnoredAny>>,
    #[serde(default)]
    block: Option<Height>,
    /// The answer to `want`: the recent blocks, the tip among them.
    #[serde(default)]
    blocks: Option<Vec<Height>>,
    #[serde(default, rename = "track-scriptpubkeys-error")]
    refusal: Option<String>,
}

#[derive(serde::Deserialize)]
struct Height {
    #[serde(default)]
    height: Option<u32>,
}

/// Reads one message. Returns the tracking limit when the server just
/// named one by refusing the list.
fn read(hub: &mut Hub, text: &str) -> Option<usize> {
    let frame: Frame = serde_json::from_str(text).ok()?;
    for script in frame.scripts.iter().flat_map(|scripts| scripts.keys()) {
        hub.mark_entry(&script.to_ascii_lowercase(), ChangeReason::Activity);
    }
    let tip = frame
        .block
        .iter()
        .chain(frame.blocks.iter().flatten())
        .filter_map(|block| block.height)
        .max();
    if let Some(height) = tip {
        hub.new_tip(height, true);
    }
    // "... supports tracking a maximum of 10 scriptpubkeys"
    let named = frame
        .refusal?
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|digits| digits.parse::<usize>().ok())
        .next_back();
    let current = hub.track_limit.unwrap_or(FIRST_ASK);
    Some(match named {
        Some(limit) if limit < current => limit,
        _ => 0,
    })
}

async fn say(socket: &mut Socket, message: &Value) -> Result<(), String> {
    let send = socket.send(Message::text(message.to_string()));
    match tokio::time::timeout(std::time::Duration::from_secs(20), send).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(describe(&error)),
        Err(_) => Err("the server stopped reading".to_owned()),
    }
}

fn describe(error: &WsError) -> String {
    match error {
        WsError::ConnectionClosed | WsError::AlreadyClosed => {
            "the connection was closed".to_owned()
        }
        WsError::Io(error) => format!("the connection was closed: {error}"),
        WsError::Capacity(_) => "the server sent more than a message may hold".to_owned(),
        _ => "unexpected response".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_websocket_address_follows_the_esplora_one() {
        let (url, host, port, secure) = address("https://mempool.space/signet/api").unwrap();
        assert_eq!(url.as_str(), "wss://mempool.space/signet/api/v1/ws");
        assert_eq!((host.as_str(), port, secure), ("mempool.space", 443, true));
        let (url, host, port, secure) = address("http://Umbrel.Local:3006/api/").unwrap();
        assert_eq!(url.as_str(), "ws://umbrel.local:3006/api/v1/ws");
        assert_eq!((host.as_str(), port, secure), ("umbrel.local", 3006, false));
        assert!(address("ssl://node.example:50002").is_err());
    }
}
