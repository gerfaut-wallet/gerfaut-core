//! The HTTP client for the premium server, one method per route.
//!
//! JSON in, JSON out, one bearer key. The models here are the bodies
//! the server's `docs/API.md` promises, decoded once for both apps.
//! Errors are sorted by what the screen has to do about them: an
//! unknown key sends the user back to the key field, a key with no paid
//! time left to the renewal page, a refusal is shown in the server's own
//! words, and a server that cannot be reached is the "watch is offline"
//! banner rather than a dialog.
//!
//! Signed answers are verified before they are returned, a heartbeat
//! and a certificate alike, with the key this crate embeds and never the
//! one the answer carries: a captive portal or a stale cache cannot tell
//! an app it is watched or paid for. The HTTP client is the crate's own,
//! so a `.onion` base URL goes through the Tor route the manager
//! resolved.

use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::licence::{self, Claims, Heartbeat, KEY_ALPHABET, LICENCE_PUBLIC_KEY_HEX};
use crate::chain;
use crate::error::{CoreError, CoreResult, PremiumError};

/// The production server.
pub const DEFAULT_BASE_URL: &str = "https://api.gerfaut-wallet.com";
/// The ntfy instance the server publishes to; what the app offers the
/// user to subscribe to.
pub const NTFY_BASE_URL: &str = "https://ntfy.gerfaut-wallet.com";
/// The Telegram bot that links channels.
pub const TELEGRAM_BOT: &str = "GerfautAlertsBot";
/// Symbols in a generated ntfy topic: 120 bits from the key alphabet.
/// The topic is the only thing between the public and the account's
/// notifications, so it is not something to type.
const NTFY_TOPIC_SYMBOLS: usize = 24;

// --- models ---------------------------------------------------------------

/// `GET /v1/health`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub ok: bool,
    /// The network the server watches, as it names it.
    pub network: String,
    pub node: NodeHealth,
    pub engine: EngineHealth,
    /// Unix seconds on the server.
    pub now: i64,
}

/// The server's node, as `getblockchaininfo` describes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeHealth {
    pub headers: i64,
    pub blocks: i64,
    pub initial_block_download: bool,
    pub verification_progress: f64,
}

/// The watching engine: where it stands, and nothing about what it
/// watches. The counters it used to publish were a side channel on a
/// route anyone can poll, and no screen ever read them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineHealth {
    pub tip_height: Option<i64>,
    /// When the tip was last seen. Kept as the server sent it: the
    /// server writes a date type whose JSON form is not a unix time.
    #[serde(default)]
    pub tip_seen_at: Option<serde_json::Value>,
}

/// `GET /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Paid time left right now.
    pub active: bool,
    /// Unix seconds; `None` for a key never paid for.
    pub paid_until: Option<i64>,
    pub wallets: i64,
    pub channels: i64,
    pub network: String,
}

/// `GET /v1/licence`, with the certificate already verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Licence {
    /// `base64url(claims).base64url(signature)`, to store as is.
    pub certificate: String,
    /// The key the server says it signs with. Informative: the
    /// certificate was checked against the embedded key.
    pub public_key: String,
    pub paid_until: i64,
    pub claims: Claims,
}

/// `GET /v1/heartbeat`, verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatReport {
    pub heartbeat: Heartbeat,
    /// The exact JSON text the signature covers.
    pub payload: String,
    /// Hex Ed25519 signature over `payload`.
    pub signature: String,
    /// The key the server says it signs with; see [`Licence::public_key`].
    pub public_key: String,
}

/// One wallet the server watches for this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletWatch {
    /// The app's own wallet id.
    pub id: String,
    pub name: String,
    pub script_kind: String,
    /// Unix seconds.
    pub watched_since: i64,
    /// Unix seconds when the first scan of the UTXO set finished; `None`
    /// while it runs.
    pub baseline_at: Option<i64>,
    pub baseline_height: Option<i64>,
    pub coins: u64,
    pub value_sats: u64,
}

/// Where an account wants to be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Ntfy,
    Telegram,
    Email,
    Webhook,
}

/// One channel, as the server describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub kind: ChannelKind,
    /// Masked except for webhooks: proof it is the right one, not a
    /// copy of it.
    pub target: String,
    /// False for a Telegram channel whose code was not sent to the bot
    /// yet.
    pub linked: bool,
    /// The code to send the bot, while a Telegram channel is unlinked.
    #[serde(default)]
    pub link_code: Option<String>,
    #[serde(default)]
    pub link_url: Option<String>,
    /// The name of what the channel is linked to, when the server has
    /// one: the Telegram chat that sent the code. So the owner sees who
    /// receives their alerts, not only that someone does. Absent for
    /// the other kinds, and from a server that predates it.
    #[serde(default)]
    pub linked_name: Option<String>,
    pub enabled: bool,
    /// Unix seconds.
    pub created_at: i64,
}

/// What happened to a watched wallet. A kind this build does not know
/// reads as [`EventKind::Other`], so a newer server never breaks the
/// list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A transaction spending from the wallet entered the mempool.
    SpendDetected,
    /// That spend is in a block.
    SpendConfirmed,
    /// A daily scan found coins gone without the spend being seen live.
    CoinsGone,
    ReceiveDetected,
    ReceiveConfirmed,
    /// A branch opens, or will within 30, 7 or 1 day.
    TimelockDue,
    /// The first scan is done.
    WalletRegistered,
    #[serde(other)]
    Other,
}

/// One entry of the account's event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Increasing; the cursor for the next poll.
    pub id: i64,
    pub kind: EventKind,
    /// The app's own wallet id.
    pub wallet: String,
    pub wallet_name: String,
    /// Unix seconds.
    pub at: i64,
    /// The kind's own fields, as the API documents them.
    pub data: serde_json::Value,
}

// --- request and response bodies -----------------------------------------

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Deserialize)]
struct HeartbeatBody<'a> {
    /// The exact text, not a re-serialization: the signature is over
    /// bytes.
    #[serde(borrow)]
    heartbeat: &'a RawValue,
    signature: String,
    public_key: String,
}

#[derive(Deserialize)]
struct LicenceBody {
    certificate: String,
    public_key: String,
    paid_until: i64,
}

#[derive(Deserialize)]
struct WalletsBody {
    wallets: Vec<WalletWatch>,
}

#[derive(Deserialize)]
struct ChannelsBody {
    channels: Vec<Channel>,
}

#[derive(Deserialize)]
struct EventsBody {
    events: Vec<Event>,
}

#[derive(Serialize)]
struct WalletBody<'a> {
    name: &'a str,
    input: &'a str,
}

#[derive(Serialize)]
struct ChannelBody<'a> {
    kind: ChannelKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a str>,
}

#[derive(Serialize)]
struct ConfirmBody<'a> {
    code: &'a str,
}

#[derive(Deserialize)]
struct DeletedBody {
    deleted: bool,
}

// --- client ---------------------------------------------------------------

/// A client for one server and one account key.
#[derive(Clone)]
pub struct PremiumClient {
    base_url: String,
    key: Option<String>,
    /// Hex of the key signed answers are checked against.
    public_key_hex: String,
    http: reqwest::Client,
}

impl fmt::Debug for PremiumClient {
    /// The key stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PremiumClient")
            .field("base_url", &self.base_url)
            .field("key", &self.key.as_ref().map(|_| "set"))
            .finish_non_exhaustive()
    }
}

impl PremiumClient {
    /// A client for `base_url`, through `proxy` when given. `proxy` is
    /// the Tor route the manager resolved, `host:port` or
    /// `user:password@host:port`; an onion base URL without one is
    /// refused here, before anything could look the name up.
    pub fn new(base_url: &str, key: Option<String>, proxy: Option<&str>) -> CoreResult<Self> {
        if chain::is_onion(base_url) && proxy.is_none() {
            let host = chain::host_of(base_url).unwrap_or_else(|| base_url.to_owned());
            return Err(CoreError::Tor(format!(
                "no Tor proxy to reach {host} through"
            )));
        }
        Ok(Self::with_http(
            base_url,
            key,
            crate::price::client_through(proxy)?,
        ))
    }

    /// A client over an HTTP client built elsewhere.
    pub fn with_http(base_url: &str, key: Option<String>, http: reqwest::Client) -> Self {
        PremiumClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            key: key.map(|key| licence::normalize_key(&key)),
            public_key_hex: LICENCE_PUBLIC_KEY_HEX.to_owned(),
            http,
        }
    }

    /// Checks signed answers against another key: for a server that is
    /// not the production one.
    pub fn with_public_key(mut self, public_key_hex: &str) -> Self {
        self.public_key_hex = public_key_hex.to_owned();
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The account key, normalized.
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    pub fn set_key(&mut self, key: Option<String>) {
        self.key = key.map(|key| licence::normalize_key(&key));
    }

    // --- public routes ------------------------------------------------

    pub async fn health(&self) -> CoreResult<Health> {
        let body = self.raw(self.http.get(self.url("/v1/health"))).await?;
        decode(&body)
    }

    /// The server's signed heartbeat, verified against the embedded key
    /// and against `now_unix`, this device's clock.
    pub async fn heartbeat(&self, now_unix: i64) -> CoreResult<HeartbeatReport> {
        let body = self.raw(self.http.get(self.url("/v1/heartbeat"))).await?;
        let parsed: HeartbeatBody<'_> = decode(&body)?;
        let payload = parsed.heartbeat.get().to_owned();
        let heartbeat =
            licence::verify_heartbeat(&payload, &parsed.signature, &self.public_key_hex, now_unix)?;
        Ok(HeartbeatReport {
            heartbeat,
            payload,
            signature: parsed.signature,
            public_key: parsed.public_key,
        })
    }

    // --- account ------------------------------------------------------

    pub async fn account(&self) -> CoreResult<Account> {
        let body = self
            .raw(self.authorized(self.http.get(self.url("/v1/account")))?)
            .await?;
        decode(&body)
    }

    /// The certificate, verified against the embedded key before it is
    /// returned. Refused with [`PremiumError::NoPaidTime`] for a key
    /// never paid for.
    pub async fn licence(&self) -> CoreResult<Licence> {
        let body = self
            .raw(self.authorized(self.http.get(self.url("/v1/licence")))?)
            .await?;
        let parsed: LicenceBody = decode(&body)?;
        let claims = licence::verify_certificate(&parsed.certificate, &self.public_key_hex)?;
        Ok(Licence {
            certificate: parsed.certificate,
            public_key: parsed.public_key,
            paid_until: parsed.paid_until,
            claims,
        })
    }

    /// Deletes the account: the key, the wallets it watches, its
    /// channels and its events, all at once. The server takes any key
    /// it knows, paid time left or not: leaving is not something to
    /// pay for. Confirmed by the server's own word, or not at all.
    pub async fn delete_account(&self) -> CoreResult<()> {
        let request = self.http.delete(self.url("/v1/account"));
        let body = self.raw(self.authorized(request)?).await?;
        let confirmed: DeletedBody = decode(&body)?;
        if !confirmed.deleted {
            return Err(PremiumError::UnexpectedResponse(
                "the server did not confirm the deletion".to_owned(),
            )
            .into());
        }
        Ok(())
    }

    // --- wallets ------------------------------------------------------

    pub async fn wallets(&self) -> CoreResult<Vec<WalletWatch>> {
        let body = self
            .raw(self.authorized(self.http.get(self.url("/v1/wallets")))?)
            .await?;
        decode::<WalletsBody>(&body).map(|b| b.wallets)
    }

    /// Registers, or replaces, a wallet under the app's own `id`.
    /// `input` is the descriptor text as the app imported it; a single
    /// address is refused by the server for now.
    pub async fn put_wallet(&self, id: &str, name: &str, input: &str) -> CoreResult<()> {
        let request = self
            .http
            .put(self.url(&format!("/v1/wallets/{id}")))
            .json(&WalletBody { name, input });
        self.raw(self.authorized(request)?).await.map(drop)
    }

    pub async fn delete_wallet(&self, id: &str) -> CoreResult<()> {
        let request = self.http.delete(self.url(&format!("/v1/wallets/{id}")));
        self.raw(self.authorized(request)?).await.map(drop)
    }

    // --- channels -----------------------------------------------------

    pub async fn channels(&self) -> CoreResult<Vec<Channel>> {
        let body = self
            .raw(self.authorized(self.http.get(self.url("/v1/channels")))?)
            .await?;
        decode::<ChannelsBody>(&body).map(|b| b.channels)
    }

    /// Adds a channel. `target` is the ntfy topic, the e-mail address or
    /// the webhook URL, and nothing for Telegram, whose answer carries
    /// the code to send the bot. `secret` is the webhook's HMAC key.
    pub async fn create_channel(
        &self,
        kind: ChannelKind,
        target: Option<&str>,
        secret: Option<&str>,
    ) -> CoreResult<Channel> {
        let request = self.http.post(self.url("/v1/channels")).json(&ChannelBody {
            kind,
            target,
            secret,
        });
        let body = self.raw(self.authorized(request)?).await?;
        decode(&body)
    }

    /// Confirms a channel with the code the server sent to it: an
    /// e-mail address is written to only once its owner typed the code
    /// back. A wrong or expired code is [`PremiumError::Rejected`] in
    /// the server's words, and the server stops answering after five
    /// tries. The channel comes back as `GET /v1/channels` lists it.
    pub async fn confirm_channel(&self, id: &str, code: &str) -> CoreResult<Channel> {
        let request = self
            .http
            .post(self.url(&format!("/v1/channels/{id}/confirm")))
            .json(&ConfirmBody { code });
        let body = self.raw(self.authorized(request)?).await?;
        decode(&body)
    }

    pub async fn delete_channel(&self, id: &str) -> CoreResult<()> {
        let request = self.http.delete(self.url(&format!("/v1/channels/{id}")));
        self.raw(self.authorized(request)?).await.map(drop)
    }

    /// Sends a test message right away. The provider's refusal, if any,
    /// comes back as [`PremiumError::Rejected`] in the server's words.
    pub async fn test_channel(&self, id: &str) -> CoreResult<()> {
        let request = self.http.post(self.url(&format!("/v1/channels/{id}/test")));
        self.raw(self.authorized(request)?).await.map(drop)
    }

    // --- events -------------------------------------------------------

    /// Events with an id greater than `after`, oldest first, at most
    /// `limit` of them (the server caps it at 500).
    pub async fn events(&self, after: i64, limit: u32) -> CoreResult<Vec<Event>> {
        let request = self.http.get(self.url(&events_path(after, limit)));
        let body = self.raw(self.authorized(request)?).await?;
        decode::<EventsBody>(&body).map(|b| b.events)
    }

    // --- plumbing -----------------------------------------------------

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// The request with the account key, or [`PremiumError::NoKey`].
    fn authorized(&self, request: reqwest::RequestBuilder) -> CoreResult<reqwest::RequestBuilder> {
        let key = self.key.as_deref().ok_or(PremiumError::NoKey)?;
        Ok(request.bearer_auth(key))
    }

    /// Sends the request and returns the body of a successful answer;
    /// anything else becomes the error the status stands for.
    async fn raw(&self, request: reqwest::RequestBuilder) -> CoreResult<Vec<u8>> {
        let response = request
            .send()
            .await
            .map_err(|e| PremiumError::Unreachable(describe(&e)))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| PremiumError::Unreachable(describe(&e)))?;
        if (200..300).contains(&status) {
            return Ok(body.to_vec());
        }
        Err(refusal(status, &body).into())
    }
}

fn events_path(after: i64, limit: u32) -> String {
    format!("/v1/events?after={after}&limit={limit}")
}

/// A body decoded as the route promises, or the answer named as
/// unexpected: a captive portal's page, a proxy's error, a newer
/// server's shape.
fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> CoreResult<T> {
    serde_json::from_slice(body).map_err(|e| PremiumError::UnexpectedResponse(e.to_string()).into())
}

/// What a failing status means, with the server's own sentence when the
/// body carries one.
fn refusal(status: u16, body: &[u8]) -> PremiumError {
    let words = serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .map(|b| b.error);
    match status {
        401 => PremiumError::UnknownKey,
        403 => PremiumError::NoPaidTime,
        400..=499 => PremiumError::Rejected(words.unwrap_or_else(|| format!("HTTP {status}"))),
        _ => PremiumError::Unreachable(match words {
            Some(words) => format!("HTTP {status}: {words}"),
            None => format!("HTTP {status}"),
        }),
    }
}

/// What went wrong on the way to the server, as a sentence.
fn describe(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "timed out".to_owned();
    }
    chain::esplora::describe_failure(error)
}

// --- helpers for the channel screens --------------------------------------

/// A fresh ntfy topic: long enough that nobody guesses it, made of the
/// key alphabet so it reads the same everywhere it is shown.
pub fn new_ntfy_topic() -> String {
    let mut bytes = [0u8; NTFY_TOPIC_SYMBOLS];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| KEY_ALPHABET[usize::from(*b & 31)] as char)
        .collect()
}

/// What the user subscribes to in the ntfy app.
pub fn ntfy_subscribe_url(base: &str, topic: &str) -> String {
    format!("{}/{topic}", base.trim_end_matches('/'))
}

/// A link that opens the bot with the link code filled in, so tapping
/// Start sends `/start <code>` without typing it.
pub fn telegram_link_url(bot: &str, code: &str) -> String {
    format!("https://t.me/{}?start={code}", bot.trim_start_matches('@'))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::*;
    use crate::premium::licence::testing::Issuer;

    const NOW: i64 = 1_790_000_000;

    /// A server that answers every request the same way and hands each
    /// request, head and body, to the test.
    struct Stub {
        base_url: String,
        seen: mpsc::UnboundedReceiver<String>,
    }

    impl Stub {
        async fn request(&mut self) -> String {
            self.seen.recv().await.expect("a request")
        }
    }

    async fn stub(status: u16, body: &str) -> Stub {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, seen) = mpsc::unbounded_channel();
        let body = body.to_owned();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                // The head, then as many bytes as Content-Length says.
                let expected = loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        break None;
                    };
                    if n == 0 {
                        break None;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some(head_end) = text.find("\r\n\r\n") {
                        let length = text[..head_end]
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        break Some(head_end + 4 + length);
                    }
                };
                if let Some(expected) = expected {
                    while bytes.len() < expected {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                }
                let _ = sender.send(String::from_utf8_lossy(&bytes).into_owned());
                let response = format!(
                    "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Stub {
            base_url: format!("http://{address}"),
            seen,
        }
    }

    fn client(stub: &Stub, key: Option<&str>) -> PremiumClient {
        PremiumClient::new(&stub.base_url, key.map(str::to_owned), None).unwrap()
    }

    fn premium_error(error: CoreError) -> PremiumError {
        match error {
            CoreError::Premium(error) => error,
            other => panic!("not a premium error: {other}"),
        }
    }

    fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (found, value) = line.split_once(':')?;
            found.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn body_of(request: &str) -> &str {
        request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    #[test]
    fn urls_are_built_from_the_base_however_it_ends() {
        let http = reqwest::Client::new();
        let plain = PremiumClient::with_http("https://api.example.org", None, http.clone());
        assert_eq!(plain.url("/v1/health"), "https://api.example.org/v1/health");
        let slashed = PremiumClient::with_http("https://api.example.org/", None, http);
        assert_eq!(slashed.base_url(), "https://api.example.org");
        assert_eq!(
            slashed.url("/v1/health"),
            "https://api.example.org/v1/health"
        );
        assert_eq!(events_path(0, 100), "/v1/events?after=0&limit=100");
        assert_eq!(events_path(4242, 5), "/v1/events?after=4242&limit=5");
    }

    #[test]
    fn the_key_is_kept_normalized_and_out_of_debug_output() {
        let mut client = PremiumClient::with_http(
            DEFAULT_BASE_URL,
            Some("ABCD-EFGH IJKM-NPQR".to_owned()),
            reqwest::Client::new(),
        );
        assert_eq!(client.key(), Some("abcdefghijkmnpqr"));
        let shown = format!("{client:?}");
        assert!(!shown.contains("abcdefghijkmnpqr"), "{shown}");
        assert!(shown.contains(DEFAULT_BASE_URL));
        client.set_key(None);
        assert_eq!(client.key(), None);
    }

    #[test]
    fn an_onion_base_needs_a_proxy() {
        let onion = "http://gerfautexample000000000000000000000000000000000000000.onion";
        let refused = PremiumClient::new(onion, None, None).unwrap_err();
        assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
        assert!(PremiumClient::new(onion, None, Some("127.0.0.1:9050")).is_ok());
        assert!(PremiumClient::new(DEFAULT_BASE_URL, None, None).is_ok());
    }

    #[tokio::test]
    async fn the_bearer_key_is_sent_normalized() {
        let mut stub = stub(
            200,
            r#"{"active":true,"paid_until":1800000000,"wallets":2,"channels":1,"network":"bitcoin"}"#,
        )
        .await;
        let account = client(&stub, Some("ABCD-EFGH-IJKM-NPQR"))
            .account()
            .await
            .unwrap();
        assert_eq!(
            account,
            Account {
                active: true,
                paid_until: Some(1_800_000_000),
                wallets: 2,
                channels: 1,
                network: "bitcoin".to_owned(),
            }
        );
        let request = stub.request().await;
        assert!(request.starts_with("GET /v1/account HTTP/1.1"), "{request}");
        assert_eq!(
            header(&request, "authorization"),
            Some("Bearer abcdefghijkmnpqr")
        );
    }

    #[tokio::test]
    async fn an_account_route_without_a_key_never_reaches_the_network() {
        // A port nothing listens on: reaching it would be an error of
        // another kind.
        let client = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(client.account().await.unwrap_err()),
            PremiumError::NoKey
        );
        assert_eq!(
            premium_error(client.wallets().await.unwrap_err()),
            PremiumError::NoKey
        );
        assert_eq!(
            premium_error(client.put_wallet("w", "n", "wpkh(...)").await.unwrap_err()),
            PremiumError::NoKey
        );
    }

    #[tokio::test]
    async fn the_health_body_decodes_as_the_server_writes_it() {
        // `tip_seen_at` is the server's date type in its JSON form, a
        // tuple of components; it must not break the decode.
        let mut public = stub(
            200,
            r#"{"ok":true,"network":"bitcoin","node":{"headers":910000,"blocks":910000,"initial_block_download":false,"verification_progress":0.9999},"engine":{"tip_height":910000,"tip_seen_at":[2026,248,12,0,0,0,0,0,0]},"now":1790000000}"#,
        )
        .await;
        let health = client(&public, None).health().await.unwrap();
        assert!(health.ok);
        assert_eq!(health.network, "bitcoin");
        assert_eq!(health.node.blocks, 910_000);
        assert!(!health.node.initial_block_download);
        assert_eq!(health.engine.tip_height, Some(910_000));
        assert!(health.engine.tip_seen_at.is_some());
        assert_eq!(health.now, NOW);
        // No key is sent on a public route, even when one is set.
        let request = public.request().await;
        assert!(request.starts_with("GET /v1/health HTTP/1.1"), "{request}");
        assert_eq!(header(&request, "authorization"), None);
        let _ = client(&public, Some("abcdefghijkmnpqr")).health().await;
        assert_eq!(header(&public.request().await, "authorization"), None);

        // A server from before the counters were dropped still decodes:
        // what it adds is ignored, what it lacks reads as unknown.
        let older = stub(
            200,
            r#"{"ok":true,"network":"bitcoin","node":{"headers":1,"blocks":1,"initial_block_download":false,"verification_progress":1.0},"engine":{"wallets":3,"scripts":1200,"coins":41,"tip_height":null},"now":1790000000}"#,
        )
        .await;
        let health = client(&older, None).health().await.unwrap();
        assert_eq!(health.engine.tip_height, None);
        assert_eq!(health.engine.tip_seen_at, None);
    }

    #[tokio::test]
    async fn wallets_and_channels_decode() {
        let stub_wallets = stub(
            200,
            r#"{"wallets":[{"id":"w1","name":"Cold","script_kind":"p2wsh","watched_since":1789000000,"baseline_at":1789000100,"baseline_height":909000,"coins":3,"value_sats":150000000},{"id":"w2","name":"New","script_kind":"p2tr","watched_since":1790000000,"baseline_at":null,"baseline_height":null,"coins":0,"value_sats":0}]}"#,
        )
        .await;
        let wallets = client(&stub_wallets, Some("abcdefghijkmnpqr"))
            .wallets()
            .await
            .unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].id, "w1");
        assert_eq!(wallets[0].baseline_height, Some(909_000));
        assert_eq!(wallets[0].value_sats, 150_000_000);
        assert_eq!(wallets[1].baseline_at, None);

        let stub_channels = stub(
            200,
            r#"{"channels":[{"id":"0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f","kind":"ntfy","target":"abc…xyz","linked":true,"link_code":null,"link_url":null,"linked_name":null,"enabled":true,"created_at":1789000000},{"id":"1c5c2f2d-8e2f-4c7b-8e1f-2b3c4d5e6f70","kind":"telegram","target":"","linked":false,"link_code":"0123456789ab","link_url":"https://t.me/GerfautAlertsBot","enabled":true,"created_at":1789000001},{"id":"2d6d3030-9f30-4d8c-9f20-3c4d5e6f7081","kind":"webhook","target":"https://hooks.example.org/gerfaut","linked":true,"link_code":null,"link_url":null,"enabled":false,"created_at":1789000002},{"id":"3e7e4141-a041-4e9d-a031-4d5e6f708192","kind":"telegram","target":"…4242","linked":true,"link_code":null,"link_url":null,"linked_name":"Alice","enabled":true,"created_at":1789000003}]}"#,
        )
        .await;
        let channels = client(&stub_channels, Some("abcdefghijkmnpqr"))
            .channels()
            .await
            .unwrap();
        assert_eq!(channels.len(), 4);
        assert_eq!(channels[0].kind, ChannelKind::Ntfy);
        assert!(channels[0].linked);
        assert_eq!(channels[0].linked_name, None);
        assert_eq!(channels[1].kind, ChannelKind::Telegram);
        assert!(!channels[1].linked);
        assert_eq!(channels[1].link_code.as_deref(), Some("0123456789ab"));
        // A server that does not send the name reads as no name.
        assert_eq!(channels[1].linked_name, None);
        assert_eq!(channels[2].kind, ChannelKind::Webhook);
        assert_eq!(channels[2].target, "https://hooks.example.org/gerfaut");
        assert!(!channels[2].enabled);
        assert_eq!(channels[3].linked_name.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn events_decode_and_keep_kinds_this_build_does_not_know() {
        let mut stub = stub(
            200,
            r#"{"events":[{"id":41,"kind":"spend_detected","wallet":"w1","wallet_name":"Cold","at":1790000000,"data":{"txid":"aa","value_sats":5000,"inputs":1,"outputs":2,"height":null}},{"id":42,"kind":"timelock_due","wallet":"w1","wallet_name":"Cold","at":1790000100,"data":{"branch_id":"b","label":"Recovery","summary":"key B after 1 year","milestone":"7d","remaining_seconds":600000,"spendable_now":false}},{"id":43,"kind":"something_new","wallet":"w2","wallet_name":"New","at":1790000200,"data":{}}]}"#,
        )
        .await;
        let events = client(&stub, Some("abcdefghijkmnpqr"))
            .events(40, 50)
            .await
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, EventKind::SpendDetected);
        assert_eq!(events[0].data["value_sats"], 5000);
        assert!(events[0].data["height"].is_null());
        assert_eq!(events[1].kind, EventKind::TimelockDue);
        assert_eq!(events[1].data["milestone"], "7d");
        assert_eq!(events[2].kind, EventKind::Other);
        let request = stub.request().await;
        assert!(
            request.starts_with("GET /v1/events?after=40&limit=50 HTTP/1.1"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn statuses_map_to_what_the_screen_does_about_them() {
        let unknown = stub(401, r#"{"error":"unknown key"}"#).await;
        assert_eq!(
            premium_error(
                client(&unknown, Some("abcdefghijkmnpqr"))
                    .account()
                    .await
                    .unwrap_err()
            ),
            PremiumError::UnknownKey
        );
        let unpaid = stub(403, r#"{"error":"this key has no paid time left"}"#).await;
        assert_eq!(
            premium_error(
                client(&unpaid, Some("abcdefghijkmnpqr"))
                    .put_wallet("w1", "Cold", "wpkh(...)")
                    .await
                    .unwrap_err()
            ),
            PremiumError::NoPaidTime
        );
        let refused = stub(
            400,
            r#"{"error":"a single address cannot be watched yet; send a descriptor"}"#,
        )
        .await;
        assert_eq!(
            premium_error(
                client(&refused, Some("abcdefghijkmnpqr"))
                    .put_wallet("w1", "Cold", "bc1q...")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected(
                "a single address cannot be watched yet; send a descriptor".to_owned()
            )
        );
        // A refusal without the promised body still names its status.
        let bare = stub(404, "not found").await;
        assert_eq!(
            premium_error(
                client(&bare, Some("abcdefghijkmnpqr"))
                    .delete_channel("nope")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected("HTTP 404".to_owned())
        );
        // The server is there and not well: for the banner, offline.
        let down = stub(503, r#"{"error":"node unreachable"}"#).await;
        assert_eq!(
            premium_error(client(&down, None).health().await.unwrap_err()),
            PremiumError::Unreachable("HTTP 503: node unreachable".to_owned())
        );
        let broken = stub(500, "").await;
        assert_eq!(
            premium_error(client(&broken, None).health().await.unwrap_err()),
            PremiumError::Unreachable("HTTP 500".to_owned())
        );
        // A page where JSON was promised: a captive portal, a proxy.
        let portal = stub(200, "<html><body>Sign in to the network</body></html>").await;
        assert!(matches!(
            premium_error(client(&portal, None).health().await.unwrap_err()),
            PremiumError::UnexpectedResponse(_)
        ));
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = PremiumClient::new(&format!("http://{address}"), None, None).unwrap();
        assert_eq!(
            premium_error(client.health().await.unwrap_err()),
            PremiumError::Unreachable("could not connect".to_owned())
        );
    }

    #[tokio::test]
    async fn put_wallet_sends_the_name_and_the_descriptor() {
        let mut put = stub(
            200,
            r#"{"id":"w1","name":"Cold","script_kind":"p2wsh","watching":true}"#,
        )
        .await;
        client(&put, Some("abcdefghijkmnpqr"))
            .put_wallet("w1", "Cold", "wsh(sortedmulti(2,A,B,C))")
            .await
            .unwrap();
        let request = put.request().await;
        assert!(
            request.starts_with("PUT /v1/wallets/w1 HTTP/1.1"),
            "{request}"
        );
        assert_eq!(header(&request, "content-type"), Some("application/json"));
        let body: serde_json::Value = serde_json::from_str(body_of(&request)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "name": "Cold", "input": "wsh(sortedmulti(2,A,B,C))" })
        );

        let mut gone = stub(200, r#"{"id":"w1","watching":false}"#).await;
        client(&gone, Some("abcdefghijkmnpqr"))
            .delete_wallet("w1")
            .await
            .unwrap();
        assert!(
            gone.request()
                .await
                .starts_with("DELETE /v1/wallets/w1 HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn create_channel_sends_only_what_was_given() {
        let mut telegram = stub(
            200,
            r#"{"id":"1c5c2f2d-8e2f-4c7b-8e1f-2b3c4d5e6f70","kind":"telegram","target":"","linked":false,"link_code":"0123456789ab","link_url":"https://t.me/GerfautAlertsBot","enabled":true,"created_at":1789000001}"#,
        )
        .await;
        let channel = client(&telegram, Some("abcdefghijkmnpqr"))
            .create_channel(ChannelKind::Telegram, None, None)
            .await
            .unwrap();
        assert_eq!(channel.link_code.as_deref(), Some("0123456789ab"));
        let request = telegram.request().await;
        assert!(
            request.starts_with("POST /v1/channels HTTP/1.1"),
            "{request}"
        );
        assert_eq!(body_of(&request), r#"{"kind":"telegram"}"#);

        let mut webhook = stub(
            200,
            r#"{"id":"2d6d3030-9f30-4d8c-9f20-3c4d5e6f7081","kind":"webhook","target":"https://hooks.example.org/g","linked":true,"link_code":null,"link_url":null,"enabled":true,"created_at":1789000002}"#,
        )
        .await;
        client(&webhook, Some("abcdefghijkmnpqr"))
            .create_channel(
                ChannelKind::Webhook,
                Some("https://hooks.example.org/g"),
                Some("s3cret"),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_str(body_of(&webhook.request().await)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "kind": "webhook",
                "target": "https://hooks.example.org/g",
                "secret": "s3cret"
            })
        );

        let mut tested = stub(200, r#"{"id":"x","sent":true}"#).await;
        client(&tested, Some("abcdefghijkmnpqr"))
            .test_channel("x")
            .await
            .unwrap();
        assert!(
            tested
                .request()
                .await
                .starts_with("POST /v1/channels/x/test HTTP/1.1")
        );
    }

    /// The code goes in the body, the channel comes back as the list
    /// shows it, and a code the server refuses is refused in its words.
    #[tokio::test]
    async fn confirm_channel_sends_the_code_and_reads_the_channel_back() {
        let mut confirmed = stub(
            200,
            r#"{"id":"4f8f5252-b152-4fae-b142-5e6f70819203","kind":"email","target":"a…@example.org","linked":true,"link_code":null,"link_url":null,"linked_name":null,"enabled":true,"created_at":1789000004}"#,
        )
        .await;
        let channel = client(&confirmed, Some("abcdefghijkmnpqr"))
            .confirm_channel("4f8f5252-b152-4fae-b142-5e6f70819203", "482913")
            .await
            .unwrap();
        assert_eq!(channel.kind, ChannelKind::Email);
        assert!(channel.linked);
        let request = confirmed.request().await;
        assert!(
            request.starts_with(
                "POST /v1/channels/4f8f5252-b152-4fae-b142-5e6f70819203/confirm HTTP/1.1"
            ),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some("Bearer abcdefghijkmnpqr")
        );
        assert_eq!(body_of(&request), r#"{"code":"482913"}"#);

        let wrong = stub(400, r#"{"error":"wrong or expired code"}"#).await;
        assert_eq!(
            premium_error(
                client(&wrong, Some("abcdefghijkmnpqr"))
                    .confirm_channel("x", "000000")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected("wrong or expired code".to_owned())
        );
        let exhausted = stub(429, r#"{"error":"too many tries"}"#).await;
        assert_eq!(
            premium_error(
                client(&exhausted, Some("abcdefghijkmnpqr"))
                    .confirm_channel("x", "000000")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected("too many tries".to_owned())
        );
        // No key, no request.
        let nobody = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(nobody.confirm_channel("x", "1").await.unwrap_err()),
            PremiumError::NoKey
        );
    }

    /// Deleting the account is one request with the key, taken on the
    /// server's word alone: an answer that does not say `deleted` is
    /// not a deletion.
    #[tokio::test]
    async fn delete_account_is_confirmed_by_the_server_or_not_at_all() {
        let mut deleted = stub(200, r#"{"deleted":true}"#).await;
        client(&deleted, Some("abcdefghijkmnpqr"))
            .delete_account()
            .await
            .unwrap();
        let request = deleted.request().await;
        assert!(
            request.starts_with("DELETE /v1/account HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some("Bearer abcdefghijkmnpqr")
        );

        let unconfirmed = stub(200, r#"{"deleted":false}"#).await;
        assert!(matches!(
            premium_error(
                client(&unconfirmed, Some("abcdefghijkmnpqr"))
                    .delete_account()
                    .await
                    .unwrap_err()
            ),
            PremiumError::UnexpectedResponse(_)
        ));
        let unknown = stub(401, r#"{"error":"unknown key"}"#).await;
        assert_eq!(
            premium_error(
                client(&unknown, Some("abcdefghijkmnpqr"))
                    .delete_account()
                    .await
                    .unwrap_err()
            ),
            PremiumError::UnknownKey
        );
        let nobody = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(nobody.delete_account().await.unwrap_err()),
            PremiumError::NoKey
        );
    }

    /// The heartbeat is checked against the key this build embeds, on
    /// the exact text the server signed; the key the body carries is
    /// only reported.
    #[tokio::test]
    async fn a_heartbeat_is_verified_against_the_embedded_key() {
        let issuer = Issuer::from_seed(7);
        let (payload, signature) = issuer.heartbeat(NOW, Some(910_000));
        let body = format!(
            r#"{{"heartbeat": {payload}, "public_key": "{}", "signature": "{signature}"}}"#,
            Issuer::from_seed(9).public_key_hex()
        );
        let stub = stub(200, &body).await;
        let report = client(&stub, None)
            .with_public_key(&issuer.public_key_hex())
            .heartbeat(NOW + 10)
            .await
            .unwrap();
        assert_eq!(report.heartbeat.now, NOW);
        assert_eq!(report.heartbeat.tip_height, Some(910_000));
        assert_eq!(report.payload, payload);
        assert_eq!(report.signature, signature);
        assert_eq!(report.public_key, Issuer::from_seed(9).public_key_hex());

        // The production key is the default, and this is not its server.
        assert!(matches!(
            premium_error(client(&stub, None).heartbeat(NOW).await.unwrap_err()),
            PremiumError::InvalidHeartbeat(_)
        ));
        // Genuine, and too old to mean anything.
        assert_eq!(
            premium_error(
                client(&stub, None)
                    .with_public_key(&issuer.public_key_hex())
                    .heartbeat(NOW + 3_600)
                    .await
                    .unwrap_err()
            ),
            PremiumError::StaleHeartbeat { skew: 3_600 }
        );
    }

    #[tokio::test]
    async fn a_licence_comes_back_with_verified_claims() {
        let issuer = Issuer::from_seed(7);
        let claims = Claims {
            v: 1,
            sub: "cd".repeat(32),
            exp: NOW + 30 * 86_400,
            iat: NOW,
        };
        let certificate = issuer.issue(&claims);
        let body = format!(
            r#"{{"certificate":"{certificate}","public_key":"{}","paid_until":{}}}"#,
            issuer.public_key_hex(),
            claims.exp
        );
        let stub = stub(200, &body).await;
        let licence = client(&stub, Some("abcdefghijkmnpqr"))
            .with_public_key(&issuer.public_key_hex())
            .licence()
            .await
            .unwrap();
        assert_eq!(licence.certificate, certificate);
        assert_eq!(licence.paid_until, claims.exp);
        assert_eq!(licence.claims, claims);

        // Signed by someone else: refused, whatever the body claims.
        assert!(matches!(
            premium_error(
                client(&stub, Some("abcdefghijkmnpqr"))
                    .licence()
                    .await
                    .unwrap_err()
            ),
            PremiumError::InvalidCertificate(_)
        ));
    }

    #[test]
    fn ntfy_topics_are_long_random_and_readable() {
        let topic = new_ntfy_topic();
        assert_eq!(topic.len(), NTFY_TOPIC_SYMBOLS);
        assert!(topic.bytes().all(|b| KEY_ALPHABET.contains(&b)));
        assert_ne!(topic, new_ntfy_topic());
        assert_eq!(
            ntfy_subscribe_url(NTFY_BASE_URL, &topic),
            format!("https://ntfy.gerfaut-wallet.com/{topic}")
        );
        assert_eq!(
            ntfy_subscribe_url("https://ntfy.example.org/", "t"),
            "https://ntfy.example.org/t"
        );
    }

    #[test]
    fn the_telegram_link_carries_the_code() {
        assert_eq!(
            telegram_link_url(TELEGRAM_BOT, "0123456789ab"),
            "https://t.me/GerfautAlertsBot?start=0123456789ab"
        );
        assert_eq!(
            telegram_link_url("@GerfautAlertsBot", "c"),
            "https://t.me/GerfautAlertsBot?start=c"
        );
    }

    #[test]
    fn channel_kinds_and_event_kinds_use_the_api_spelling() {
        assert_eq!(
            serde_json::to_string(&ChannelKind::Ntfy).unwrap(),
            r#""ntfy""#
        );
        assert_eq!(
            serde_json::from_str::<EventKind>(r#""receive_confirmed""#).unwrap(),
            EventKind::ReceiveConfirmed
        );
        assert_eq!(
            serde_json::from_str::<EventKind>(r#""wallet_registered""#).unwrap(),
            EventKind::WalletRegistered
        );
        assert_eq!(
            serde_json::from_str::<EventKind>(r#""coins_gone""#).unwrap(),
            EventKind::CoinsGone
        );
    }
}
