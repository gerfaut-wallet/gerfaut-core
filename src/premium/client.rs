//! The HTTP client for the premium server, one method per route.
//!
//! JSON in, JSON out, one bearer credential. The account key goes with
//! one request only, the connection of this device; every other route
//! carries the token the server handed the device then. The models here
//! are the bodies the server's `docs/API.md` promises, decoded once for
//! both apps. Errors are sorted by what the screen has to do about them:
//! an unknown key sends the user back to the key field, a key with no
//! paid time left to the renewal page, a device still waiting to its
//! "waiting for approval" card, a disowned one to "connect again", a
//! refusal is shown in the server's own words, and a server that cannot
//! be reached is the "watch is offline" banner rather than a dialog.
//!
//! Signed answers are verified before they are returned, a heartbeat
//! and a certificate alike, with the key this build trusts and never the
//! one the answer carries: a captive portal or a stale cache cannot tell
//! an app it is watched or paid for. The HTTP client is the crate's own,
//! so a `.onion` base URL goes through the Tor route the manager
//! resolved.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use url::Url;

use super::device::{self, ConnectedDevice, Device, DevicePlatform};
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

/// The premium server this build talks to, and the hex of the key its
/// signed answers are checked against: [`DEFAULT_BASE_URL`] and
/// [`LICENCE_PUBLIC_KEY_HEX`]. A debug build takes
/// `GERFAUT_PREMIUM_URL` and `GERFAUT_PREMIUM_PUBLIC_KEY` from the
/// environment first, to run against a server of its own; a release
/// build has no code that reads them. The apps call this where they
/// used to name the production server, and every client checks
/// signatures against the key it returns.
pub fn endpoint() -> (String, String) {
    let (url, public_key) = endpoint_overrides();
    endpoint_from(url, public_key)
}

/// What the environment names in place of the production server.
#[cfg(debug_assertions)]
fn endpoint_overrides() -> (Option<String>, Option<String>) {
    (
        std::env::var("GERFAUT_PREMIUM_URL").ok(),
        std::env::var("GERFAUT_PREMIUM_PUBLIC_KEY").ok(),
    )
}

/// Nothing: a release build talks to the production server.
#[cfg(not(debug_assertions))]
fn endpoint_overrides() -> (Option<String>, Option<String>) {
    (None, None)
}

/// The production endpoint, with what an override names in its place;
/// a blank one names nothing.
fn endpoint_from(url: Option<String>, public_key: Option<String>) -> (String, String) {
    let pick = |value: Option<String>, default: &str| {
        value
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default.to_owned())
    };
    (
        pick(url, DEFAULT_BASE_URL),
        pick(public_key, LICENCE_PUBLIC_KEY_HEX),
    )
}

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

/// The server's node, as `getblockchaininfo` describes it. A node that
/// missed the server's deadline while still feeding the engine is a slow
/// node, not an outage: it comes back as `answering: false` and nothing
/// else, since the numbers would be older than the answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeHealth {
    /// Whether the node answered the server in time. A server that
    /// predates the flag only ever published the numbers, so its silence
    /// here means it did.
    #[serde(default = "answered")]
    pub answering: bool,
    #[serde(default)]
    pub headers: Option<i64>,
    #[serde(default)]
    pub blocks: Option<i64>,
    #[serde(default)]
    pub initial_block_download: Option<bool>,
    #[serde(default)]
    pub verification_progress: Option<f64>,
}

/// What a body without the flag means; see [`NodeHealth::answering`].
fn answered() -> bool {
    true
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
    /// True while that scan is still to come: the coins already on the
    /// addresses are not counted below yet. A server that predates the
    /// flag does not send it, and [`PremiumClient::wallets`] reads it
    /// from `baseline_at` then.
    #[serde(default)]
    pub baseline_pending: bool,
    pub baseline_height: Option<i64>,
    pub coins: u64,
    pub value_sats: u64,
    /// False once the server has refused the wallet: it keeps the row,
    /// to say why in `refusal`, and watches nothing under it. A server
    /// that predates the flag refuses no wallet and does not send it.
    #[serde(default = "watching_by_default")]
    pub watching: bool,
    /// Why the server does not watch this wallet, when it does not.
    #[serde(default)]
    pub refusal: Option<WalletRefusal>,
}

fn watching_by_default() -> bool {
    true
}

/// Why the server stopped watching a wallet, or never started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRefusal {
    /// For the app. `too_many_coins` is the only one today; an app that
    /// meets another shows the message all the same.
    pub code: String,
    /// For the person who owns the wallet, in English, to show as it is.
    pub message: String,
}

/// What a [`EventKind::WalletRefused`] event carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRefused {
    pub code: String,
    /// The ceiling the wallet went past, when the code is about one.
    #[serde(default)]
    pub limit: Option<u64>,
    pub message: String,
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
    /// Unix seconds since the channel has been live: `created_at` for
    /// the kinds that need no confirmation, an ntfy topic and a
    /// webhook, and the confirmation for the others, the code typed
    /// back for an address, the chat that answered the bot. `None`
    /// while one waits, and from a server that sends no date.
    #[serde(default)]
    pub linked_at: Option<i64>,
    /// False for a channel the server stopped delivering to. Only a
    /// webhook is ever turned off, and only for pointing at a private or
    /// local address; it still reads as linked, so a screen that says
    /// nothing about this flag shows a channel that receives nothing.
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
    /// The server no longer watches the wallet, and says why: read it
    /// with [`Event::wallet_refused`].
    WalletRefused,
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

impl Event {
    /// The refusal a [`EventKind::WalletRefused`] event carries; `None`
    /// for any other kind, or for data this build cannot read.
    pub fn wallet_refused(&self) -> Option<WalletRefused> {
        (self.kind == EventKind::WalletRefused)
            .then(|| serde_json::from_value(self.data.clone()).ok())
            .flatten()
    }
}

// --- request and response bodies -----------------------------------------

/// The server's error body: its sentence, and for the refusals the
/// apps act on, a code and the fields that go with it.
struct ErrorBody {
    error: String,
    code: Option<String>,
    pending_until: Option<i64>,
}

impl ErrorBody {
    /// The body, when it is the server's envelope: a JSON object with a
    /// sentence under `error`. A code or a field of another type than
    /// the one promised reads as absent, and the sentence still counts.
    fn read(body: &[u8]) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        Some(ErrorBody {
            error: value.get("error")?.as_str()?.to_owned(),
            code: value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            pending_until: value
                .get("pending_until")
                .and_then(serde_json::Value::as_i64),
        })
    }
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

#[derive(Serialize)]
struct ConnectBody<'a> {
    platform: DevicePlatform,
    token: &'a str,
}

#[derive(Serialize)]
struct NewKeyBody<'a> {
    key: &'a str,
}

#[derive(Deserialize)]
struct DeviceBody {
    device: Device,
}

#[derive(Deserialize)]
struct DevicesBody {
    devices: Vec<Device>,
}

#[derive(Deserialize)]
struct KeyBody {
    key: String,
}

// --- client ---------------------------------------------------------------

/// Told the token a request carried when the server answered that it
/// no longer knows it: how the manager drops a disowned token whoever
/// made the call.
pub(crate) type DisownedHook =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// What a request carries to say whose it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    /// Nothing: a public route.
    Public,
    /// The account key: the connection of a device, and nothing else.
    Key,
    /// This device's token: every other account route.
    Device,
}

/// A client for one server, one account key and one device token.
#[derive(Clone)]
pub struct PremiumClient {
    base_url: String,
    key: Option<String>,
    /// The token the server handed this device when it connected.
    token: Option<String>,
    /// Hex of the key signed answers are checked against.
    public_key_hex: String,
    http: reqwest::Client,
    disowned: Option<DisownedHook>,
}

impl fmt::Debug for PremiumClient {
    /// The key and the token stay out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PremiumClient")
            .field("base_url", &self.base_url)
            .field("key", &self.key.as_ref().map(|_| "set"))
            .field("token", &self.token.as_ref().map(|_| "set"))
            .finish_non_exhaustive()
    }
}

impl PremiumClient {
    /// A client for `base_url`, through `proxy` when given. `proxy` is
    /// the Tor route the manager resolved, `host:port` or
    /// `user:password@host:port`; an onion base URL without one is
    /// refused here, before anything could look the name up.
    ///
    /// The client holds no device token: the manager's
    /// [`crate::WalletManager::premium_client`] builds one that does, and
    /// every account route but [`Self::connect_device`] needs it.
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

    /// A client over an HTTP client built elsewhere. Signed answers are
    /// checked against the key [`endpoint`] names.
    pub fn with_http(base_url: &str, key: Option<String>, http: reqwest::Client) -> Self {
        PremiumClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            key: key.map(|key| licence::normalize_key(&key)),
            token: None,
            public_key_hex: endpoint().1,
            http,
            disowned: None,
        }
    }

    /// Checks signed answers against another key: for a server that is
    /// not the production one.
    pub fn with_public_key(mut self, public_key_hex: &str) -> Self {
        self.public_key_hex = public_key_hex.to_owned();
        self
    }

    /// Carries this device's token on every account route.
    pub(crate) fn with_device_token(mut self, token: Option<String>) -> Self {
        self.token = token;
        self
    }

    /// Tells `hook` the token a request carried when the server
    /// disowns it.
    pub(crate) fn on_disowned(mut self, hook: DisownedHook) -> Self {
        self.disowned = Some(hook);
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

    /// Whether the client carries a device token.
    pub fn has_device_token(&self) -> bool {
        self.token.is_some()
    }

    pub(crate) fn device_token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    // --- public routes ------------------------------------------------

    pub async fn health(&self) -> CoreResult<Health> {
        let body = self
            .send(self.http.get(self.url("/v1/health")), Auth::Public)
            .await?;
        decode(&body)
    }

    /// The server's signed heartbeat, verified against the trusted key
    /// and against `now_unix`, this device's clock.
    pub async fn heartbeat(&self, now_unix: i64) -> CoreResult<HeartbeatReport> {
        let body = self
            .send(self.http.get(self.url("/v1/heartbeat")), Auth::Public)
            .await?;
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

    // --- devices ------------------------------------------------------

    /// Connects this device with the account key: the one request the
    /// key goes with. `token` is the device's own, drawn here and kept
    /// in the vault before the request leaves; the same request sent
    /// again is answered with the device it already made, so a lost
    /// answer costs nothing. [`crate::WalletManager::premium_connect`]
    /// does all that; call it rather than this. The first device an
    /// account ever has gets full access at once. Any later one waits,
    /// and every other device is told it came. A key the server does
    /// not know is [`PremiumError::UnknownKey`], one whose devices fill
    /// every slot [`PremiumError::TooManyDevices`]. A token of another
    /// shape than the server's is not taken, whichever side drew it.
    pub async fn connect_device(
        &self,
        platform: DevicePlatform,
        token: &str,
    ) -> CoreResult<ConnectedDevice> {
        if platform == DevicePlatform::Other {
            return Err(CoreError::InvalidInput {
                kind: "device platform",
                detail: "the server takes android, ios, windows, macos and linux".to_owned(),
            });
        }
        if !device::is_device_token(token) {
            return Err(CoreError::InvalidInput {
                kind: "device token",
                detail: "not of the shape the server hands out".to_owned(),
            });
        }
        let request = self
            .http
            .post(self.url("/v1/devices"))
            .json(&ConnectBody { platform, token });
        let body = self.send(request, Auth::Key).await?;
        let connected: ConnectedDevice = decode(&body)?;
        if !device::is_device_token(connected.token()) {
            return Err(PremiumError::UnexpectedResponse(
                "the server handed out a token of another shape".to_owned(),
            )
            .into());
        }
        Ok(connected)
    }

    /// This device, as the server sees it. Any device may ask, a waiting
    /// one too.
    pub async fn device_me(&self) -> CoreResult<Device> {
        let body = self
            .send(self.http.get(self.url("/v1/devices/me")), Auth::Device)
            .await?;
        decode::<DeviceBody>(&body).map(|b| b.device)
    }

    /// Every device of the account, oldest first. Full access only.
    pub async fn devices(&self) -> CoreResult<Vec<Device>> {
        let body = self
            .send(self.http.get(self.url("/v1/devices")), Auth::Device)
            .await?;
        decode::<DevicesBody>(&body).map(|b| b.devices)
    }

    /// Gives a waiting device full access now. One that already has it
    /// is [`PremiumError::Rejected`] in the server's words.
    pub async fn approve_device(&self, id: &str) -> CoreResult<Device> {
        let request = self.http.post(self.device_resource(id, &["approve"])?);
        let body = self.send(request, Auth::Device).await?;
        decode::<DeviceBody>(&body).map(|b| b.device)
    }

    /// Disconnects a device: refuses a waiting one, or takes full access
    /// away from another. Confirmed by the server's own word, or not at
    /// all.
    pub async fn remove_device(&self, id: &str) -> CoreResult<()> {
        let request = self.http.delete(self.device_resource(id, &[])?);
        let body = self.send(request, Auth::Device).await?;
        confirmed_deleted(&body)
    }

    /// Disconnects this device. Confirmed by the server's own word, or
    /// not at all.
    pub async fn log_out_device(&self) -> CoreResult<()> {
        let request = self.http.delete(self.url("/v1/devices/me"));
        let body = self.send(request, Auth::Device).await?;
        confirmed_deleted(&body)
    }

    /// Replaces the account key with `key`, drawn here and kept in the
    /// vault before the request leaves; the same request sent again is
    /// answered with the key the account already has. The old key stops
    /// working everywhere at once, every other device is disconnected,
    /// and this one stays connected.
    /// [`crate::WalletManager::premium_change_key`] does all that; call
    /// it rather than this. Returns the account's key as the server
    /// says it is now, normalized; an answer that does not hold one of
    /// the right shape is [`PremiumError::UnexpectedResponse`].
    pub async fn change_key(&self, key: &str) -> CoreResult<String> {
        if !licence::is_well_formed_key(key) {
            return Err(CoreError::InvalidInput {
                kind: "premium key",
                detail: "a key is sixteen symbols, shown as xxxx-xxxx-xxxx-xxxx".to_owned(),
            });
        }
        let request = self
            .http
            .post(self.url("/v1/account/key"))
            .json(&NewKeyBody {
                key: &licence::normalize_key(key),
            });
        let body = self.send(request, Auth::Device).await?;
        let key = decode::<KeyBody>(&body)?.key;
        if !licence::is_well_formed_key(&key) {
            return Err(PremiumError::UnexpectedResponse(
                "the server answered with a key of another shape".to_owned(),
            )
            .into());
        }
        Ok(licence::normalize_key(&key))
    }

    // --- account ------------------------------------------------------

    pub async fn account(&self) -> CoreResult<Account> {
        let body = self
            .send(self.http.get(self.url("/v1/account")), Auth::Device)
            .await?;
        decode(&body)
    }

    /// The certificate, verified against the trusted key before it is
    /// returned. A waiting device may ask. Refused with
    /// [`PremiumError::NoPaidTime`] for a key never paid for.
    pub async fn licence(&self) -> CoreResult<Licence> {
        let body = self
            .send(self.http.get(self.url("/v1/licence")), Auth::Device)
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
        let body = self.send(request, Auth::Device).await?;
        confirmed_deleted(&body)
    }

    // --- wallets ------------------------------------------------------

    pub async fn wallets(&self) -> CoreResult<Vec<WalletWatch>> {
        let body = self
            .send(self.http.get(self.url("/v1/wallets")), Auth::Device)
            .await?;
        let mut wallets = decode::<WalletsBody>(&body)?.wallets;
        // A server that predates the flag leaves it false, which would
        // read as a scan already done. The date it does send answers the
        // same question, so it settles the ones that say nothing.
        // A refused wallet has no date either, and no scan to come.
        for wallet in &mut wallets {
            wallet.baseline_pending =
                wallet.baseline_pending || (wallet.watching && wallet.baseline_at.is_none());
        }
        Ok(wallets)
    }

    /// Registers, or replaces, a wallet under the app's own `id`.
    /// `input` is what the app imported: the descriptor text, or for a
    /// wallet that is a single address, that address, bare or as
    /// `addr(<address>)`. The server answers `200` before it has counted
    /// the wallet's coins; one past its ceiling is refused by the scan,
    /// which [`PremiumClient::wallets`] then reports as `watching: false`
    /// with the reason, and sending it again as it was is
    /// [`PremiumError::Rejected`] in the same words.
    ///
    /// The answer is dropped: it repeats the request, plus the
    /// `baseline_pending` flag that [`PremiumClient::wallets`] reports
    /// for this wallet like any other. A screen that wants to say the
    /// first scan is running reads the list it refreshes anyway.
    pub async fn put_wallet(&self, id: &str, name: &str, input: &str) -> CoreResult<()> {
        let request = self
            .http
            .put(self.resource(&["v1", "wallets", id])?)
            .json(&WalletBody { name, input });
        self.send(request, Auth::Device).await.map(drop)
    }

    pub async fn delete_wallet(&self, id: &str) -> CoreResult<()> {
        let request = self.http.delete(self.resource(&["v1", "wallets", id])?);
        self.send(request, Auth::Device).await.map(drop)
    }

    // --- channels -----------------------------------------------------

    pub async fn channels(&self) -> CoreResult<Vec<Channel>> {
        let body = self
            .send(self.http.get(self.url("/v1/channels")), Auth::Device)
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
        let body = self.send(request, Auth::Device).await?;
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
            .post(self.resource(&["v1", "channels", id, "confirm"])?)
            .json(&ConfirmBody { code });
        let body = self.send(request, Auth::Device).await?;
        decode(&body)
    }

    pub async fn delete_channel(&self, id: &str) -> CoreResult<()> {
        let request = self.http.delete(self.resource(&["v1", "channels", id])?);
        self.send(request, Auth::Device).await.map(drop)
    }

    /// Sends a test message right away. The provider's refusal, if any,
    /// comes back as [`PremiumError::Rejected`] in the server's words.
    pub async fn test_channel(&self, id: &str) -> CoreResult<()> {
        let request = self
            .http
            .post(self.resource(&["v1", "channels", id, "test"])?);
        self.send(request, Auth::Device).await.map(drop)
    }

    // --- events -------------------------------------------------------

    /// Events with an id greater than `after`, oldest first, at most
    /// `limit` of them (the server caps it at 500).
    pub async fn events(&self, after: i64, limit: u32) -> CoreResult<Vec<Event>> {
        let request = self.http.get(self.url(&events_path(after, limit)));
        let body = self.send(request, Auth::Device).await?;
        decode::<EventsBody>(&body).map(|b| b.events)
    }

    // --- plumbing -----------------------------------------------------

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// The URL of a resource under the base, each segment encoded on
    /// its way into the path. An id the server handed out is one
    /// segment whatever it holds: a slash, a question mark, a hash or
    /// a space in it names a stranger resource, and encoded it names
    /// none. Three spellings the path syntax swallows instead of
    /// encoding, `.`, `..` and nothing at all, would name the
    /// collection itself, the removal of one channel sent as a request
    /// on all of them: refused before a URL is built. The ids the apps
    /// draw pass through untouched.
    fn resource(&self, segments: &[&str]) -> CoreResult<String> {
        if segments.iter().any(|s| matches!(*s, "" | "." | "..")) {
            return Err(PremiumError::Rejected(
                "the server named an id this app cannot use".to_owned(),
            )
            .into());
        }
        let unusable = |detail: String| {
            PremiumError::Unreachable(format!(
                "{} is not a server address: {detail}",
                self.base_url
            ))
        };
        let mut url = Url::parse(&self.base_url).map_err(|e| unusable(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| unusable("it cannot carry a path".to_owned()))?
            .pop_if_empty()
            .extend(segments);
        Ok(url.into())
    }

    /// The URL of one device of the account, and of a route under it.
    /// `me` is refused as an id: it names this device's own route, and
    /// the refusal of a device listed under that name would disconnect
    /// the one that asked.
    fn device_resource(&self, id: &str, tail: &[&str]) -> CoreResult<String> {
        if id == "me" {
            return Err(PremiumError::Rejected(
                "the server named an id this app cannot use".to_owned(),
            )
            .into());
        }
        let mut segments = vec!["v1", "devices", id];
        segments.extend_from_slice(tail);
        self.resource(&segments)
    }

    /// Sends the request with what `auth` names, and returns the body of
    /// a successful answer; anything else becomes the error the status
    /// stands for. A route that needs a credential the client does not
    /// hold never reaches the network: [`PremiumError::NoKey`] or
    /// [`PremiumError::NoDevice`]. When the server disowns the token a
    /// request carried, the hook hears of it before the error returns.
    async fn send(&self, request: reqwest::RequestBuilder, auth: Auth) -> CoreResult<Vec<u8>> {
        let request = match auth {
            Auth::Public => request,
            Auth::Key => request.bearer_auth(self.key.as_deref().ok_or(PremiumError::NoKey)?),
            Auth::Device => {
                request.bearer_auth(self.token.as_deref().ok_or(PremiumError::NoDevice)?)
            }
        };
        let answer = self.raw(request, auth).await;
        if let Err(CoreError::Premium(PremiumError::DeviceDisconnected)) = &answer
            && auth == Auth::Device
            && let (Some(hook), Some(token)) = (&self.disowned, &self.token)
        {
            hook(token.clone()).await;
        }
        answer
    }

    async fn raw(&self, request: reqwest::RequestBuilder, auth: Auth) -> CoreResult<Vec<u8>> {
        let response = request
            .send()
            .await
            .map_err(|e| PremiumError::Unreachable(describe(&e)))?;
        let status = response.status().as_u16();
        let retry_after = retry_after(response.headers());
        let body = response
            .bytes()
            .await
            .map_err(|e| PremiumError::Unreachable(describe(&e)))?;
        if (200..300).contains(&status) {
            return Ok(body.to_vec());
        }
        Err(refusal(status, retry_after, &body, auth).into())
    }
}

/// `{"id", "deleted": true}`, or the removal is not taken as done.
fn confirmed_deleted(body: &[u8]) -> CoreResult<()> {
    if !decode::<DeletedBody>(body)?.deleted {
        return Err(PremiumError::UnexpectedResponse(
            "the server did not confirm the deletion".to_owned(),
        )
        .into());
    }
    Ok(())
}

/// The longest wait a `Retry-After` is believed for, in seconds. The
/// server's windows are a minute or an hour; a header asking for more
/// comes from something else on the path.
const RETRY_AFTER_MAX: u64 = 3_600;

/// The whole seconds a `Retry-After` header asks for, one at least and
/// [`RETRY_AFTER_MAX`] at most. The date form, which the server never
/// sends, reads as no header.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let seconds: u64 = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(seconds.clamp(1, RETRY_AFTER_MAX))
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
/// body carries one. A status that settles something is an answer only
/// in the server's own words: a bare 404 is what a captive portal or a
/// proxy without a route answers, a bare 401 or 403 what one that wants
/// a login first answers, and neither says anything about what the
/// server holds, a key it would no longer know least of all.
///
/// Among the server's words, the code of a device refusal comes first,
/// then its sentence: see [`device_refusal`]. A 401 in the server's
/// words is an unknown key only where a key was sent; where a token was,
/// it is a refusal like another unless it is the one that disowns the
/// token, since reading more into it would have the app drop what the
/// server may still honour.
///
/// The server sends `Retry-After` with every 429 that a wait resolves,
/// and only with those: that is a rate limit. Its one other 429, five
/// wrong codes on a channel, comes without the header and is a refusal
/// in its own words, since waiting changes nothing there. A bare 429
/// is somebody on the path asking for the same patience.
fn refusal(status: u16, retry_after: Option<u64>, body: &[u8], auth: Auth) -> PremiumError {
    let envelope = ErrorBody::read(body);
    if (400..=499).contains(&status)
        && let Some(named) = envelope.as_ref().and_then(device_refusal)
    {
        return named;
    }
    let words = envelope.map(|b| b.error);
    match status {
        429 if retry_after.is_some() || words.is_none() => {
            PremiumError::RateLimited { retry_after }
        }
        401 if words.is_some() && auth != Auth::Device => PremiumError::UnknownKey,
        403 if words.is_some() => PremiumError::NoPaidTime,
        404 | 410 if words.is_some() => PremiumError::NotFound,
        400..=499 => PremiumError::Rejected(words.unwrap_or_else(|| format!("HTTP {status}"))),
        _ => PremiumError::Unreachable(match words {
            Some(words) => format!("HTTP {status}: {words}"),
            None => format!("HTTP {status}"),
        }),
    }
}

/// The device refusals the apps act on, by code, with the sentence the
/// server words each in.
const DEVICE_REFUSALS: [(&str, &str); 4] = [
    (
        "device_pending",
        "this device is waiting for approval: approve it on another of your devices, or wait \
         until it gets full access",
    ),
    (
        "device_disconnected",
        "this device was disconnected from the Premium account",
    ),
    (
        "device_required",
        "connect this device with the Premium key first",
    ),
    (
        "too_many_devices",
        "this key already has 10 devices; disconnect one from a device with full access",
    ),
];

/// The device refusal an error body names: by its code when it carries
/// one this build knows, by its exact sentence otherwise, and none for
/// anything else. A wait whose end the body does not give is a refusal
/// in the server's words, not a date made up here.
fn device_refusal(envelope: &ErrorBody) -> Option<PremiumError> {
    let known = |code: &str| DEVICE_REFUSALS.iter().any(|(known, _)| *known == code);
    let code = match envelope.code.as_deref().filter(|code| known(code)) {
        Some(code) => code,
        None => {
            DEVICE_REFUSALS
                .iter()
                .find(|(_, sentence)| *sentence == envelope.error)?
                .0
        }
    };
    Some(match code {
        "device_pending" => match envelope.pending_until {
            Some(until) => PremiumError::DevicePending { until },
            None => PremiumError::Rejected(envelope.error.clone()),
        },
        "device_disconnected" => PremiumError::DeviceDisconnected,
        "device_required" => PremiumError::DeviceRequired,
        _ => PremiumError::TooManyDevices(envelope.error.clone()),
    })
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
    use crate::premium::licence::fixtures;

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
        stub_with(status, "", body).await
    }

    /// The same, with header lines of its own, each ended by `\r\n`.
    async fn stub_with(status: u16, headers: &'static str, body: &str) -> Stub {
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
                    "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\n{headers}\
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

    /// The token of the device the tests speak for.
    const TOKEN: &str = "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA";
    const KEY: &str = "abcdefghijkmnpqr";
    /// The key a key change asks for.
    const NEW_KEY: &str = "wxyz23456789abcd";

    fn client(stub: &Stub, key: Option<&str>) -> PremiumClient {
        PremiumClient::new(&stub.base_url, key.map(str::to_owned), None).unwrap()
    }

    /// A connected device: the key, and the token it earned.
    fn device(stub: &Stub) -> PremiumClient {
        client(stub, Some(KEY)).with_device_token(Some(TOKEN.to_owned()))
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

    /// An id the server handed out goes into the path as one segment,
    /// whatever it holds: the request names the resource it was meant
    /// for and nothing beside it.
    #[tokio::test]
    async fn a_server_supplied_id_is_one_path_segment_whatever_it_holds() {
        let mut stub = stub(200, "{}").await;
        let client = device(&stub);

        client.delete_wallet("a/b?c#d e").await.unwrap();
        let request = stub.request().await;
        assert!(
            request.starts_with("DELETE /v1/wallets/a%2Fb%3Fc%23d%20e HTTP/1.1"),
            "{request}"
        );

        client
            .put_wallet("../account", "name", "wpkh(x)")
            .await
            .unwrap();
        let request = stub.request().await;
        assert!(
            request.starts_with("PUT /v1/wallets/..%2Faccount HTTP/1.1"),
            "{request}"
        );

        // Already encoded is not a way out: the id is the text as given.
        let _ = client.confirm_channel("x%2Fy", "123456").await;
        let request = stub.request().await;
        assert!(
            request.starts_with("POST /v1/channels/x%252Fy/confirm HTTP/1.1"),
            "{request}"
        );

        // The ids the apps draw pass through untouched.
        client
            .delete_wallet("0f3b7c2e-1a2b-4c3d-8e9f-a0b1c2d3e4f5")
            .await
            .unwrap();
        let request = stub.request().await;
        assert!(
            request.starts_with("DELETE /v1/wallets/0f3b7c2e-1a2b-4c3d-8e9f-a0b1c2d3e4f5 HTTP/1.1"),
            "{request}"
        );
    }

    /// An id the path syntax would swallow names the collection, not a
    /// resource in it: `..` would turn the removal of one channel into
    /// a request on all of them. Refused before any URL is built, so
    /// nothing is sent.
    #[tokio::test]
    async fn an_id_the_path_would_swallow_is_refused_unsent() {
        // A port nothing listens on: reaching it would be an error of
        // another kind.
        let client = PremiumClient::new(
            "http://127.0.0.1:9",
            Some("abcdefghijkmnpqr".to_owned()),
            None,
        )
        .unwrap();
        let refusal =
            PremiumError::Rejected("the server named an id this app cannot use".to_owned());
        for id in ["..", ".", ""] {
            assert_eq!(
                premium_error(client.delete_channel(id).await.unwrap_err()),
                refusal,
                "{id:?}"
            );
            assert_eq!(
                premium_error(client.delete_wallet(id).await.unwrap_err()),
                refusal,
                "{id:?}"
            );
            assert_eq!(
                premium_error(client.test_channel(id).await.unwrap_err()),
                refusal,
                "{id:?}"
            );
            assert_eq!(
                premium_error(client.resource(&["v1", "channels", id]).unwrap_err()),
                refusal,
                "{id:?}"
            );
        }
        // One that merely contains the spelling is an id like any other.
        assert_eq!(
            client.resource(&["v1", "channels", "..x", "test"]).unwrap(),
            "http://127.0.0.1:9/v1/channels/..x/test"
        );
    }

    #[test]
    fn resources_sit_under_the_base_path() {
        let http = reqwest::Client::new();
        let plain = PremiumClient::with_http("https://api.example.org", None, http.clone());
        assert_eq!(
            plain.resource(&["v1", "wallets", "w1"]).unwrap(),
            "https://api.example.org/v1/wallets/w1"
        );
        let prefixed =
            PremiumClient::with_http("https://api.example.org/premium/", None, http.clone());
        assert_eq!(
            prefixed
                .resource(&["v1", "channels", "c1", "test"])
                .unwrap(),
            "https://api.example.org/premium/v1/channels/c1/test"
        );
        let unusable = PremiumClient::with_http("not a server", None, http);
        assert!(matches!(
            premium_error(unusable.resource(&["v1"]).unwrap_err()),
            PremiumError::Unreachable(_)
        ));
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
        let client_with_token = client.clone().with_device_token(Some(TOKEN.to_owned()));
        let shown = format!("{client:?} {client_with_token:?} {client_with_token:#?}");
        assert!(!shown.contains("abcdefghijkmnpqr"), "{shown}");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(!shown.contains("q83v"), "{shown}");
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

    /// The key goes with the connection of the device, normalized, and
    /// with nothing else; every other account route carries the token.
    #[tokio::test]
    async fn the_key_goes_with_the_connection_and_the_token_with_the_rest() {
        let mut connecting = stub(
            201,
            &format!(
                r#"{{"device":{{"id":"0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f","platform":"android","connected_at":1790000000,"access":"pending","pending_until":1790864000,"approved_at":null,"this_device":true}},"token":"{TOKEN}"}}"#
            ),
        )
        .await;
        let connected = client(&connecting, Some("ABCD-EFGH-IJKM-NPQR"))
            .connect_device(DevicePlatform::Android, TOKEN)
            .await
            .unwrap();
        assert_eq!(connected.device.id, "0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f");
        assert!(connected.device.is_pending());
        assert_eq!(connected.device.pending_until, Some(1_790_864_000));
        assert_eq!(connected.token(), TOKEN);
        let request = connecting.request().await;
        assert!(
            request.starts_with("POST /v1/devices HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some("Bearer abcdefghijkmnpqr")
        );
        assert_eq!(
            body_of(&request),
            format!(r#"{{"platform":"android","token":"{TOKEN}"}}"#)
        );

        let mut stub = stub(
            200,
            r#"{"active":true,"paid_until":1800000000,"wallets":2,"channels":1,"network":"bitcoin"}"#,
        )
        .await;
        let account = device(&stub).account().await.unwrap();
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
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert!(!request.contains(KEY), "{request}");
    }

    /// A token of another shape than the server's is not taken: it would
    /// be stored, then sent in a header on every request.
    #[tokio::test]
    async fn a_token_of_another_shape_is_not_taken() {
        for token in [
            "abcdefghijkmnpqr",
            "gdt1_short",
            "gdt1_AAAAAAAAAAAAAAAAAAAAAAAAAAAA\\r\\nX: 1",
        ] {
            let connecting = stub(
                201,
                &format!(
                    r#"{{"device":{{"id":"d","platform":"linux","connected_at":1,"access":"full"}},"token":"{token}"}}"#
                ),
            )
            .await;
            assert!(
                matches!(
                    premium_error(
                        client(&connecting, Some(KEY))
                            .connect_device(DevicePlatform::Linux, TOKEN)
                            .await
                            .unwrap_err()
                    ),
                    PremiumError::UnexpectedResponse(_)
                ),
                "{token}"
            );
        }
    }

    #[tokio::test]
    async fn an_account_route_without_a_token_never_reaches_the_network() {
        // A port nothing listens on: reaching it would be an error of
        // another kind.
        let keyed = PremiumClient::new("http://127.0.0.1:9", Some(KEY.to_owned()), None).unwrap();
        assert!(!keyed.has_device_token());
        for refused in [
            keyed.account().await.unwrap_err(),
            keyed.licence().await.unwrap_err(),
            keyed.wallets().await.unwrap_err(),
            keyed.put_wallet("w", "n", "wpkh(...)").await.unwrap_err(),
            keyed.device_me().await.unwrap_err(),
            keyed.devices().await.unwrap_err(),
            keyed.approve_device("d").await.unwrap_err(),
            keyed.remove_device("d").await.unwrap_err(),
            keyed.log_out_device().await.unwrap_err(),
            keyed.change_key(NEW_KEY).await.unwrap_err(),
            keyed.delete_account().await.unwrap_err(),
        ] {
            assert_eq!(premium_error(refused), PremiumError::NoDevice);
        }
        // Without a key, not even a connection is asked for; a platform
        // the server does not take is refused before the key is looked
        // at.
        let nobody = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(
                nobody
                    .connect_device(DevicePlatform::Windows, TOKEN)
                    .await
                    .unwrap_err()
            ),
            PremiumError::NoKey
        );
        assert!(matches!(
            keyed
                .connect_device(DevicePlatform::Other, TOKEN)
                .await
                .unwrap_err(),
            CoreError::InvalidInput { .. }
        ));
    }

    #[tokio::test]
    async fn the_health_body_decodes_as_the_server_writes_it() {
        // `tip_seen_at` is the server's date type in its JSON form, a
        // tuple of components; it must not break the decode.
        let mut public = stub(
            200,
            r#"{"ok":true,"network":"bitcoin","node":{"answering":true,"headers":910000,"blocks":910000,"initial_block_download":false,"verification_progress":0.9999},"engine":{"tip_height":910000,"tip_seen_at":[2026,248,12,0,0,0,0,0,0]},"now":1790000000}"#,
        )
        .await;
        let health = client(&public, None).health().await.unwrap();
        assert!(health.ok);
        assert_eq!(health.network, "bitcoin");
        assert!(health.node.answering);
        assert_eq!(health.node.blocks, Some(910_000));
        assert_eq!(health.node.initial_block_download, Some(false));
        assert_eq!(health.engine.tip_height, Some(910_000));
        assert!(health.engine.tip_seen_at.is_some());
        assert_eq!(health.now, NOW);
        // No key is sent on a public route, even when one is set.
        let request = public.request().await;
        assert!(request.starts_with("GET /v1/health HTTP/1.1"), "{request}");
        assert_eq!(header(&request, "authorization"), None);
        let _ = device(&public).health().await;
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
        assert!(
            health.node.answering,
            "a server that only ever sent the numbers was answering"
        );
    }

    /// A node too slow to answer, still feeding the engine: the server
    /// says so and drops its numbers. That is a health body like any
    /// other, not a shape the app has to call unexpected.
    #[tokio::test]
    async fn a_health_body_from_a_node_that_is_not_answering_decodes() {
        let slow = stub(
            200,
            r#"{"ok":true,"network":"bitcoin","node":{"answering":false},"engine":{"tip_height":910000,"tip_seen_at":[2026,248,12,0,0,0,0,0,0],"heard_at":1789999900},"now":1790000000}"#,
        )
        .await;
        let health = client(&slow, None).health().await.unwrap();
        assert!(health.ok);
        assert!(!health.node.answering);
        assert_eq!(health.node.headers, None);
        assert_eq!(health.node.blocks, None);
        assert_eq!(health.node.initial_block_download, None);
        assert_eq!(health.node.verification_progress, None);
        assert_eq!(health.engine.tip_height, Some(910_000));
    }

    #[tokio::test]
    async fn wallets_and_channels_decode() {
        let stub_wallets = stub(
            200,
            r#"{"wallets":[{"id":"w1","name":"Cold","script_kind":"p2wsh","watched_since":1789000000,"baseline_at":1789000100,"baseline_pending":false,"baseline_height":909000,"coins":3,"value_sats":150000000},{"id":"w2","name":"New","script_kind":"p2tr","watched_since":1790000000,"baseline_at":null,"baseline_pending":true,"baseline_height":null,"coins":0,"value_sats":0}]}"#,
        )
        .await;
        let wallets = device(&stub_wallets).wallets().await.unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].id, "w1");
        assert_eq!(wallets[0].baseline_height, Some(909_000));
        assert_eq!(wallets[0].value_sats, 150_000_000);
        assert!(!wallets[0].baseline_pending, "that scan is done");
        assert_eq!(wallets[1].baseline_at, None);
        assert!(
            wallets[1].baseline_pending,
            "the flag the server sends reaches the app"
        );

        let stub_channels = stub(
            200,
            r#"{"channels":[{"id":"0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f","kind":"ntfy","target":"abc…xyz","linked":true,"link_code":null,"link_url":null,"linked_name":null,"linked_at":1789000000,"enabled":true,"created_at":1789000000},{"id":"1c5c2f2d-8e2f-4c7b-8e1f-2b3c4d5e6f70","kind":"telegram","target":"","linked":false,"link_code":"0123456789ab","link_url":"https://t.me/GerfautAlertsBot","enabled":true,"created_at":1789000001},{"id":"2d6d3030-9f30-4d8c-9f20-3c4d5e6f7081","kind":"webhook","target":"https://hooks.example.org/gerfaut","linked":true,"link_code":null,"link_url":null,"enabled":false,"created_at":1789000002},{"id":"3e7e4141-a041-4e9d-a031-4d5e6f708192","kind":"telegram","target":"…4242","linked":true,"link_code":null,"link_url":null,"linked_name":"Alice","linked_at":1789000500,"enabled":true,"created_at":1789000003}]}"#,
        )
        .await;
        let channels = device(&stub_channels).channels().await.unwrap();
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
        assert_eq!(
            channels[3].linked_at,
            Some(1_789_000_500),
            "the date the chat answered the bot"
        );
        assert_eq!(
            channels[0].linked_at,
            Some(1_789_000_000),
            "a topic needs no confirming: live since it was created"
        );
        // Waiting for the bot, and a server that sends no date at all,
        // both read as no date.
        assert_eq!(channels[1].linked_at, None);
        assert_eq!(channels[2].linked_at, None);
    }

    /// A server from before the flag says nothing about the scan. The
    /// date it does send must not read as a scan already done.
    #[tokio::test]
    async fn a_scan_still_to_run_is_read_from_the_date_when_the_flag_is_absent() {
        let older = stub(
            200,
            r#"{"wallets":[{"id":"w1","name":"Cold","script_kind":"p2wsh","watched_since":1789000000,"baseline_at":null,"baseline_height":null,"coins":0,"value_sats":0},{"id":"w2","name":"Warm","script_kind":"p2tr","watched_since":1789000000,"baseline_at":1789000100,"baseline_height":909000,"coins":1,"value_sats":5000}]}"#,
        )
        .await;
        let wallets = device(&older).wallets().await.unwrap();
        assert!(wallets[0].baseline_pending, "no date means it is running");
        assert!(!wallets[1].baseline_pending, "a date means it finished");
    }

    #[tokio::test]
    async fn events_decode_and_keep_kinds_this_build_does_not_know() {
        let mut stub = stub(
            200,
            r#"{"events":[{"id":41,"kind":"spend_detected","wallet":"w1","wallet_name":"Cold","at":1790000000,"data":{"txid":"aa","value_sats":5000,"inputs":1,"outputs":2,"height":null}},{"id":42,"kind":"timelock_due","wallet":"w1","wallet_name":"Cold","at":1790000100,"data":{"branch_id":"b","label":"Recovery","summary":"key B after 1 year","milestone":"7d","remaining_seconds":600000,"spendable_now":false}},{"id":43,"kind":"something_new","wallet":"w2","wallet_name":"New","at":1790000200,"data":{}}]}"#,
        )
        .await;
        let events = device(&stub).events(40, 50).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, EventKind::SpendDetected);
        assert_eq!(events[0].data["value_sats"], 5000);
        assert!(events[0].data["height"].is_null());
        assert_eq!(events[1].kind, EventKind::TimelockDue);
        assert_eq!(events[1].data["milestone"], "7d");
        assert_eq!(events[2].kind, EventKind::Other);
        assert_eq!(events[0].wallet_refused(), None);
        let request = stub.request().await;
        assert!(
            request.starts_with("GET /v1/events?after=40&limit=50 HTTP/1.1"),
            "{request}"
        );
    }

    /// A wallet the server refused stays in the list to say why, with
    /// no scan to wait for, and the event that announced it carries the
    /// same words. A server from before all that sends neither field,
    /// and every wallet of its list is watched.
    #[tokio::test]
    async fn a_refused_wallet_says_why_in_the_list_and_in_its_event() {
        let listed = stub(
            200,
            r#"{"wallets":[{"id":"w1","name":"Busy","script_kind":"p2wpkh","watched_since":1789000000,"baseline_at":null,"baseline_pending":false,"watching":false,"refusal":{"code":"too_many_coins","message":"This wallet holds more than 5,000 coins."},"baseline_height":null,"coins":0,"value_sats":0},{"id":"w2","name":"Address","script_kind":"p2tr","watched_since":1789000000,"baseline_at":1789000100,"baseline_pending":false,"watching":true,"refusal":null,"baseline_height":909000,"coins":1,"value_sats":5000},{"id":"w3","name":"Old server","script_kind":"p2wsh","watched_since":1789000000,"baseline_at":1789000100,"baseline_height":909000,"coins":1,"value_sats":5000}]}"#,
        )
        .await;
        let wallets = device(&listed).wallets().await.unwrap();
        assert!(!wallets[0].watching);
        assert!(!wallets[0].baseline_pending, "no scan is coming");
        assert_eq!(
            wallets[0].refusal,
            Some(WalletRefusal {
                code: "too_many_coins".to_owned(),
                message: "This wallet holds more than 5,000 coins.".to_owned(),
            })
        );
        assert!(wallets[1].watching && wallets[1].refusal.is_none());
        assert!(wallets[2].watching && wallets[2].refusal.is_none());

        let logged = stub(
            200,
            r#"{"events":[{"id":7,"kind":"wallet_refused","wallet":"w1","wallet_name":"Busy","at":1790000000,"data":{"code":"too_many_coins","limit":5000,"message":"This wallet holds more than 5,000 coins."}},{"id":8,"kind":"wallet_refused","wallet":"w1","wallet_name":"Busy","at":1790000001,"data":{"code":"something_new","message":"No longer watched."}}]}"#,
        )
        .await;
        let events = device(&logged).events(0, 50).await.unwrap();
        assert_eq!(events[0].kind, EventKind::WalletRefused);
        assert_eq!(
            events[0].wallet_refused(),
            Some(WalletRefused {
                code: "too_many_coins".to_owned(),
                limit: Some(5000),
                message: "This wallet holds more than 5,000 coins.".to_owned(),
            })
        );
        // A code this build does not know still has its sentence.
        assert_eq!(events[1].wallet_refused().unwrap().limit, None);
    }

    #[tokio::test]
    async fn statuses_map_to_what_the_screen_does_about_them() {
        // An unknown key is an answer about the key, on the one route
        // that sends it.
        let unknown = stub(401, r#"{"error":"unknown key"}"#).await;
        assert_eq!(
            premium_error(
                client(&unknown, Some(KEY))
                    .connect_device(DevicePlatform::Linux, TOKEN)
                    .await
                    .unwrap_err()
            ),
            PremiumError::UnknownKey
        );
        // Where a token went, the same words are not about a key, and
        // are a refusal like another: nothing the app holds is dropped
        // on their account.
        assert_eq!(
            premium_error(device(&unknown).account().await.unwrap_err()),
            PremiumError::Rejected("unknown key".to_owned())
        );
        let unpaid = stub(403, r#"{"error":"this key has no paid time left"}"#).await;
        assert_eq!(
            premium_error(
                device(&unpaid)
                    .put_wallet("w1", "Cold", "wpkh(...)")
                    .await
                    .unwrap_err()
            ),
            PremiumError::NoPaidTime
        );
        // A wallet the scan refused, sent again as it was (HTTP 409).
        let sentence = "This wallet holds more than 5,000 coins, which is more than Gerfaut \
                        Premium watches.";
        let refused = stub(409, &format!(r#"{{"error":"{sentence}"}}"#)).await;
        assert_eq!(
            premium_error(
                device(&refused)
                    .put_wallet("w1", "Cold", "addr(bc1q...)")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected(sentence.to_owned())
        );
        // A refusal without the promised body still names its status.
        let bare = stub(405, "method not allowed").await;
        assert_eq!(
            premium_error(device(&bare).delete_channel("nope").await.unwrap_err()),
            PremiumError::Rejected("HTTP 405".to_owned())
        );
        // Nothing under that id, whether the server says so or says it
        // is gone, in its own words: one answer, not a refusal to read
        // the words of.
        for status in [404, 410] {
            let missing = stub(status, r#"{"error":"no such channel"}"#).await;
            assert_eq!(
                premium_error(device(&missing).delete_channel("nope").await.unwrap_err()),
                PremiumError::NotFound,
                "HTTP {status}"
            );
        }
        // The same status without the server's envelope is the page of
        // a captive portal or a proxy without a route, not the server
        // saying there is nothing there: a refusal, which settles
        // nothing. A rate limit is a refusal like any other, and says
        // nothing about what the server holds.
        for status in [404, 410] {
            let portal = stub(status, "<html><body>Not Found</body></html>").await;
            assert_eq!(
                premium_error(device(&portal).delete_channel("nope").await.unwrap_err()),
                PremiumError::Rejected(format!("HTTP {status}")),
                "HTTP {status}"
            );
        }
        // So is a bare 401 or 403, the page of a portal that wants a
        // login first: taken for the server's word, the first would
        // make the app forget a key the server still knows.
        for status in [401, 403] {
            let portal = stub(status, "<html><body>Sign in to continue</body></html>").await;
            assert_eq!(
                premium_error(device(&portal).delete_account().await.unwrap_err()),
                PremiumError::Rejected(format!("HTTP {status}")),
                "HTTP {status}"
            );
        }
        // A rate limit is its own answer: it is about the client, not
        // about the request, and says how long to wait. The wait is held
        // to a sane range, and a header that is not a number of seconds
        // reads as none.
        for (header, retry_after) in [
            ("Retry-After: 42\r\n", 42),
            ("Retry-After: 0\r\n", 1),
            ("Retry-After: 999999999\r\n", 3_600),
        ] {
            let limited = stub_with(429, header, r#"{"error":"too many requests"}"#).await;
            assert_eq!(
                premium_error(device(&limited).delete_channel("nope").await.unwrap_err()),
                PremiumError::RateLimited {
                    retry_after: Some(retry_after)
                },
                "{header:?}"
            );
        }
        // Without the header and without the server's words, it is
        // somebody on the path: patience all the same, for a time nobody
        // named. The date form of the header is one the server never
        // sends, and reads as none.
        for header in ["", "Retry-After: Wed, 21 Oct 2026 07:28:00 GMT\r\n"] {
            let portal = stub_with(429, header, "<html>Too Many Requests</html>").await;
            assert_eq!(
                premium_error(device(&portal).delete_channel("nope").await.unwrap_err()),
                PremiumError::RateLimited { retry_after: None },
                "{header:?}"
            );
        }
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
        device(&put)
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
        device(&gone).delete_wallet("w1").await.unwrap();
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
        let channel = device(&telegram)
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
        device(&webhook)
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
        device(&tested).test_channel("x").await.unwrap();
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
        let channel = device(&confirmed)
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
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(body_of(&request), r#"{"code":"482913"}"#);

        let wrong = stub(400, r#"{"error":"wrong or expired code"}"#).await;
        assert_eq!(
            premium_error(
                device(&wrong)
                    .confirm_channel("x", "000000")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected("wrong or expired code".to_owned())
        );
        let exhausted = stub(429, r#"{"error":"too many tries"}"#).await;
        assert_eq!(
            premium_error(
                device(&exhausted)
                    .confirm_channel("x", "000000")
                    .await
                    .unwrap_err()
            ),
            PremiumError::Rejected("too many tries".to_owned())
        );
        // No token, no request.
        let nobody = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(nobody.confirm_channel("x", "1").await.unwrap_err()),
            PremiumError::NoDevice
        );
    }

    /// Deleting the account is one request with the token, taken on the
    /// server's word alone: an answer that does not say `deleted` is
    /// not a deletion.
    #[tokio::test]
    async fn delete_account_is_confirmed_by_the_server_or_not_at_all() {
        let mut deleted = stub(200, r#"{"deleted":true}"#).await;
        device(&deleted).delete_account().await.unwrap();
        let request = deleted.request().await;
        assert!(
            request.starts_with("DELETE /v1/account HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );

        let unconfirmed = stub(200, r#"{"deleted":false}"#).await;
        assert!(matches!(
            premium_error(device(&unconfirmed).delete_account().await.unwrap_err()),
            PremiumError::UnexpectedResponse(_)
        ));
        let disowned = stub(
            401,
            r#"{"error":"this device was disconnected from the Premium account","code":"device_disconnected"}"#,
        )
        .await;
        assert_eq!(
            premium_error(device(&disowned).delete_account().await.unwrap_err()),
            PremiumError::DeviceDisconnected
        );
        let nobody = PremiumClient::new("http://127.0.0.1:9", None, None).unwrap();
        assert_eq!(
            premium_error(nobody.delete_account().await.unwrap_err()),
            PremiumError::NoDevice
        );
    }

    /// The heartbeat is checked against the key this build embeds, on
    /// the exact text the server signed; the key the body carries is
    /// only reported.
    #[tokio::test]
    async fn a_heartbeat_is_verified_against_the_embedded_key() {
        let (payload, signature) = fixtures::HEARTBEAT_AT_910000;
        let body = format!(
            r#"{{"heartbeat": {payload}, "public_key": "{}", "signature": "{signature}"}}"#,
            fixtures::OTHER_PUBLIC_KEY_HEX
        );
        let stub = stub(200, &body).await;
        let report = client(&stub, None)
            .with_public_key(fixtures::SERVER_PUBLIC_KEY_HEX)
            .heartbeat(NOW + 10)
            .await
            .unwrap();
        assert_eq!(report.heartbeat.now, NOW);
        assert_eq!(report.heartbeat.tip_height, Some(910_000));
        assert_eq!(report.payload, payload);
        assert_eq!(report.signature, signature);
        assert_eq!(report.public_key, fixtures::OTHER_PUBLIC_KEY_HEX);

        // The production key is the default, and this is not its server.
        assert!(matches!(
            premium_error(client(&stub, None).heartbeat(NOW).await.unwrap_err()),
            PremiumError::InvalidHeartbeat(_)
        ));
        // Genuine, and too old to mean anything.
        assert_eq!(
            premium_error(
                client(&stub, None)
                    .with_public_key(fixtures::SERVER_PUBLIC_KEY_HEX)
                    .heartbeat(NOW + 3_600)
                    .await
                    .unwrap_err()
            ),
            PremiumError::StaleHeartbeat { skew: 3_600 }
        );
    }

    #[tokio::test]
    async fn a_licence_comes_back_with_verified_claims() {
        let claims = Claims {
            v: 1,
            sub: "cd".repeat(32),
            exp: NOW + 30 * 86_400,
            iat: NOW,
        };
        let certificate = fixtures::ACCOUNT_CERTIFICATE;
        let body = format!(
            r#"{{"certificate":"{certificate}","public_key":"{}","paid_until":{}}}"#,
            fixtures::SERVER_PUBLIC_KEY_HEX,
            claims.exp
        );
        let stub = stub(200, &body).await;
        let licence = device(&stub)
            .with_public_key(fixtures::SERVER_PUBLIC_KEY_HEX)
            .licence()
            .await
            .unwrap();
        assert_eq!(licence.certificate, certificate);
        assert_eq!(licence.paid_until, claims.exp);
        assert_eq!(licence.claims, claims);

        // Signed by someone else: refused, whatever the body claims.
        assert!(matches!(
            premium_error(device(&stub).licence().await.unwrap_err()),
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

    const PENDING: &str = "this device is waiting for approval: approve it on another of your \
                           devices, or wait until it gets full access";
    const DISCONNECTED: &str = "this device was disconnected from the Premium account";
    const REQUIRED: &str = "connect this device with the Premium key first";
    const TOO_MANY: &str =
        "this key already has 10 devices; disconnect one from a device with full access";

    fn refused(status: u16, body: &str) -> PremiumError {
        refusal(status, None, body.as_bytes(), Auth::Device)
    }

    /// Every device refusal the server words, read by its code.
    #[test]
    fn device_refusals_are_read_by_their_code() {
        assert_eq!(
            refused(
                403,
                &format!(
                    r#"{{"error":"{PENDING}","code":"device_pending","pending_until":1790864000}}"#
                )
            ),
            PremiumError::DevicePending {
                until: 1_790_864_000
            }
        );
        assert_eq!(
            refused(
                401,
                &format!(r#"{{"error":"{DISCONNECTED}","code":"device_disconnected"}}"#)
            ),
            PremiumError::DeviceDisconnected
        );
        assert_eq!(
            refusal(
                401,
                None,
                format!(r#"{{"error":"{REQUIRED}","code":"device_required"}}"#).as_bytes(),
                Auth::Key
            ),
            PremiumError::DeviceRequired
        );
        assert_eq!(
            refusal(
                409,
                None,
                format!(r#"{{"error":"{TOO_MANY}","code":"too_many_devices"}}"#).as_bytes(),
                Auth::Key
            ),
            PremiumError::TooManyDevices(TOO_MANY.to_owned())
        );
        // The code decides, whatever the sentence says: a server that
        // rewords one is still read.
        assert_eq!(
            refused(401, r#"{"error":"gone","code":"device_disconnected"}"#),
            PremiumError::DeviceDisconnected
        );
        assert_eq!(
            refused(
                403,
                r#"{"error":"wait","code":"device_pending","pending_until":7}"#
            ),
            PremiumError::DevicePending { until: 7 }
        );
        assert_eq!(
            refused(
                409,
                r#"{"error":"eleven is too many","code":"too_many_devices"}"#
            ),
            PremiumError::TooManyDevices("eleven is too many".to_owned())
        );
    }

    /// Without a code this build knows, the exact sentence names the
    /// refusal; and anything else keeps the rules a status had before.
    #[test]
    fn a_device_refusal_without_its_code_is_read_by_its_sentence() {
        assert_eq!(
            refused(401, &format!(r#"{{"error":"{DISCONNECTED}"}}"#)),
            PremiumError::DeviceDisconnected
        );
        assert_eq!(
            refused(
                401,
                &format!(r#"{{"error":"{DISCONNECTED}","code":"something_new"}}"#)
            ),
            PremiumError::DeviceDisconnected
        );
        assert_eq!(
            refused(401, &format!(r#"{{"error":"{REQUIRED}"}}"#)),
            PremiumError::DeviceRequired
        );
        assert_eq!(
            refused(409, &format!(r#"{{"error":"{TOO_MANY}"}}"#)),
            PremiumError::TooManyDevices(TOO_MANY.to_owned())
        );
        assert_eq!(
            refused(
                403,
                &format!(r#"{{"error":"{PENDING}","pending_until":9}}"#)
            ),
            PremiumError::DevicePending { until: 9 }
        );
        // A wait with no end given is shown in the server's words, not
        // read as a date nobody sent, nor as unpaid time.
        assert_eq!(
            refused(
                403,
                &format!(r#"{{"error":"{PENDING}","code":"device_pending"}}"#)
            ),
            PremiumError::Rejected(PENDING.to_owned())
        );
        assert_eq!(
            refused(
                403,
                &format!(
                    r#"{{"error":"{PENDING}","code":"device_pending","pending_until":"soon"}}"#
                )
            ),
            PremiumError::Rejected(PENDING.to_owned())
        );
        // A code this build does not know, with a sentence it does not
        // know either: the rules of the status, as before.
        assert_eq!(
            refused(
                403,
                r#"{"error":"this key has no paid time left","code":"no_paid_time"}"#
            ),
            PremiumError::NoPaidTime
        );
        // A code of another type is no code, and the words still count.
        assert_eq!(
            refused(401, &format!(r#"{{"error":"{DISCONNECTED}","code":42}}"#)),
            PremiumError::DeviceDisconnected
        );
        assert_eq!(
            refused(404, r#"{"error":"no such device","code":42}"#),
            PremiumError::NotFound
        );
    }

    /// A code proves nothing without the server's envelope, and nothing
    /// on a status that is not a refusal of the request.
    #[test]
    fn a_device_code_outside_the_server_envelope_proves_nothing() {
        // No sentence: not the server's envelope.
        assert_eq!(
            refused(401, r#"{"code":"device_disconnected"}"#),
            PremiumError::Rejected("HTTP 401".to_owned())
        );
        assert_eq!(
            refused(401, "device_disconnected"),
            PremiumError::Rejected("HTTP 401".to_owned())
        );
        // A bare 401 or 403 still settles nothing.
        assert_eq!(
            refused(401, "<html>Sign in</html>"),
            PremiumError::Rejected("HTTP 401".to_owned())
        );
        assert_eq!(
            refused(403, ""),
            PremiumError::Rejected("HTTP 403".to_owned())
        );
        // A server failing is a server failing, whatever it names.
        assert_eq!(
            refused(
                503,
                &format!(r#"{{"error":"{DISCONNECTED}","code":"device_disconnected"}}"#)
            ),
            PremiumError::Unreachable(format!("HTTP 503: {DISCONNECTED}"))
        );
    }

    /// Each device route goes where the contract says, with the token,
    /// and an id the server handed out is one encoded segment.
    #[tokio::test]
    async fn device_routes_go_where_the_contract_says() {
        let device_json = r#"{"id":"d/1","platform":"ios","connected_at":1790000000,"access":"full","pending_until":null,"approved_at":1790000100,"this_device":false}"#;
        let mut one = stub(200, &format!(r#"{{"device":{device_json}}}"#)).await;
        let me = device(&one).device_me().await.unwrap();
        assert_eq!(me.platform, DevicePlatform::Ios);
        let request = one.request().await;
        assert!(
            request.starts_with("GET /v1/devices/me HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );

        let approved = device(&one).approve_device("d/1").await.unwrap();
        assert_eq!(approved.approved_at, Some(1_790_000_100));
        let request = one.request().await;
        assert!(
            request.starts_with("POST /v1/devices/d%2F1/approve HTTP/1.1"),
            "{request}"
        );

        let mut list = stub(
            200,
            &format!(
                r#"{{"devices":[{device_json},{{"id":"d2","platform":"android","connected_at":1790000200,"access":"pending","pending_until":1790864200,"approved_at":null,"this_device":true}}]}}"#
            ),
        )
        .await;
        let devices = device(&list).devices().await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices[1].is_pending() && devices[1].this_device);
        let request = list.request().await;
        assert!(request.starts_with("GET /v1/devices HTTP/1.1"), "{request}");

        let mut deleted = stub(200, r#"{"id":"d2","deleted":true}"#).await;
        device(&deleted).remove_device("d2").await.unwrap();
        let request = deleted.request().await;
        assert!(
            request.starts_with("DELETE /v1/devices/d2 HTTP/1.1"),
            "{request}"
        );
        device(&deleted).log_out_device().await.unwrap();
        let request = deleted.request().await;
        assert!(
            request.starts_with("DELETE /v1/devices/me HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );

        // Not confirmed, not done.
        let unconfirmed = stub(200, r#"{"id":"d2","deleted":false}"#).await;
        for outcome in [
            device(&unconfirmed).remove_device("d2").await,
            device(&unconfirmed).log_out_device().await,
        ] {
            assert!(matches!(
                premium_error(outcome.unwrap_err()),
                PremiumError::UnexpectedResponse(_)
            ));
        }
        // Refusals in the server's words.
        let missing = stub(404, r#"{"error":"no such device"}"#).await;
        assert_eq!(
            premium_error(device(&missing).remove_device("d9").await.unwrap_err()),
            PremiumError::NotFound
        );
        let already = stub(400, r#"{"error":"this device already has full access"}"#).await;
        assert_eq!(
            premium_error(device(&already).approve_device("d1").await.unwrap_err()),
            PremiumError::Rejected("this device already has full access".to_owned())
        );
        let waiting = stub(
            403,
            &format!(
                r#"{{"error":"{PENDING}","code":"device_pending","pending_until":1790864000}}"#
            ),
        )
        .await;
        assert_eq!(
            premium_error(device(&waiting).devices().await.unwrap_err()),
            PremiumError::DevicePending {
                until: 1_790_864_000
            }
        );
    }

    /// `me` names this device's own route: listed as the id of another
    /// device, refusing that device would disconnect this one. It is
    /// refused unsent, like the ids the path would swallow.
    #[tokio::test]
    async fn an_id_that_names_this_device_route_is_refused_unsent() {
        let client = PremiumClient::new("http://127.0.0.1:9", Some(KEY.to_owned()), None)
            .unwrap()
            .with_device_token(Some(TOKEN.to_owned()));
        let refusal =
            PremiumError::Rejected("the server named an id this app cannot use".to_owned());
        for id in ["me", "..", ".", ""] {
            assert_eq!(
                premium_error(client.remove_device(id).await.unwrap_err()),
                refusal,
                "{id:?}"
            );
            assert_eq!(
                premium_error(client.approve_device(id).await.unwrap_err()),
                refusal,
                "{id:?}"
            );
        }
    }

    #[tokio::test]
    async fn change_key_returns_the_new_key_normalized_or_nothing() {
        let mut changed = stub(200, r#"{"key":"WXYZ-2345-6789-ABCD"}"#).await;
        assert_eq!(
            device(&changed).change_key(NEW_KEY).await.unwrap(),
            "wxyz23456789abcd"
        );
        let request = changed.request().await;
        assert!(
            request.starts_with("POST /v1/account/key HTTP/1.1"),
            "{request}"
        );
        assert_eq!(
            header(&request, "authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(body_of(&request), format!(r#"{{"key":"{NEW_KEY}"}}"#));
        // A key or a token of the wrong shape never leaves.
        let nowhere = PremiumClient::new("http://127.0.0.1:9", Some(KEY.to_owned()), None)
            .unwrap()
            .with_device_token(Some(TOKEN.to_owned()));
        assert!(matches!(
            nowhere.change_key("not a key").await.unwrap_err(),
            CoreError::InvalidInput { .. }
        ));
        assert!(matches!(
            nowhere
                .connect_device(DevicePlatform::Linux, "gdt1_short")
                .await
                .unwrap_err(),
            CoreError::InvalidInput { .. }
        ));
        for body in [r#"{"key":"not a key"}"#, r#"{"key":""}"#, r#"{}"#] {
            let odd = stub(200, body).await;
            assert!(
                matches!(
                    premium_error(device(&odd).change_key(NEW_KEY).await.unwrap_err()),
                    PremiumError::UnexpectedResponse(_)
                ),
                "{body}"
            );
        }
    }

    /// The hook hears of the token a request carried when, and only
    /// when, the server disowned it.
    #[tokio::test]
    async fn a_disowned_token_is_reported_to_the_hook() {
        let heard = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let hook: DisownedHook = {
            let heard = heard.clone();
            Arc::new(move |token| {
                heard.lock().unwrap().push(token);
                Box::pin(async {})
            })
        };
        let disowned = stub(
            401,
            &format!(r#"{{"error":"{DISCONNECTED}","code":"device_disconnected"}}"#),
        )
        .await;
        let refused = device(&disowned)
            .on_disowned(hook.clone())
            .wallets()
            .await
            .unwrap_err();
        assert_eq!(premium_error(refused), PremiumError::DeviceDisconnected);
        assert_eq!(*heard.lock().unwrap(), vec![TOKEN.to_owned()]);

        // Any other refusal, and a route that carried no token, are not
        // the token disowned.
        let unpaid = stub(403, r#"{"error":"this key has no paid time left"}"#).await;
        let _ = device(&unpaid).on_disowned(hook.clone()).wallets().await;
        let _ = device(&disowned)
            .on_disowned(hook.clone())
            .connect_device(DevicePlatform::Linux, TOKEN)
            .await;
        let _ = device(&disowned).on_disowned(hook).health().await;
        assert_eq!(heard.lock().unwrap().len(), 1);
    }

    #[test]
    fn an_endpoint_override_replaces_what_it_names_and_nothing_else() {
        let production = (
            DEFAULT_BASE_URL.to_owned(),
            LICENCE_PUBLIC_KEY_HEX.to_owned(),
        );
        assert_eq!(endpoint_from(None, None), production);
        assert_eq!(
            endpoint_from(Some("  ".to_owned()), Some(String::new())),
            production
        );
        assert_eq!(
            endpoint_from(
                Some(" http://127.0.0.1:8080 ".to_owned()),
                Some(fixtures::SERVER_PUBLIC_KEY_HEX.to_owned())
            ),
            (
                "http://127.0.0.1:8080".to_owned(),
                fixtures::SERVER_PUBLIC_KEY_HEX.to_owned()
            )
        );
        assert_eq!(
            endpoint_from(Some("http://127.0.0.1:8080".to_owned()), None).1,
            LICENCE_PUBLIC_KEY_HEX
        );
    }

    /// What [`endpoint`] returns, in a process whose environment names
    /// a local server. Run by the test below, in a process of its own,
    /// so no test changes the environment of the others.
    #[test]
    #[ignore = "run by the_environment_is_read_by_debug_builds_only"]
    fn endpoint_in_its_own_process() {
        let (url, public_key) = endpoint();
        let client = PremiumClient::with_http(&url, None, reqwest::Client::new());
        println!("endpoint {url} {public_key} {}", client.public_key_hex);
    }

    /// A debug build reads the override from the environment, and a
    /// release build does not, however the environment is set: this
    /// test runs in both (`cargo test` and `cargo test --release`), and
    /// asks a process of its own, started with the override set.
    #[test]
    fn the_environment_is_read_by_debug_builds_only() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "premium::client::tests::endpoint_in_its_own_process",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("GERFAUT_PREMIUM_URL", "http://127.0.0.1:8080")
            .env(
                "GERFAUT_PREMIUM_PUBLIC_KEY",
                fixtures::SERVER_PUBLIC_KEY_HEX,
            )
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let said = String::from_utf8_lossy(&output.stdout);
        let expected = if cfg!(debug_assertions) {
            format!(
                "endpoint http://127.0.0.1:8080 {0} {0}",
                fixtures::SERVER_PUBLIC_KEY_HEX
            )
        } else {
            format!(
                "endpoint {DEFAULT_BASE_URL} {0} {0}",
                LICENCE_PUBLIC_KEY_HEX
            )
        };
        assert!(said.contains(&expected), "{said}");
    }
}
