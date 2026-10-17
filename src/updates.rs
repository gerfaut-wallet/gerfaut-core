//! Release update check against GitHub, and the rule both apps follow.
//!
//! Read-only: one request for the latest release of the app's own
//! repository, which sends the version in no way and nothing about the
//! wallets. The apps run it from a button, and on their own at most
//! once a day unless the user turned that off. Failures (offline,
//! private repository, rate limit) degrade to "could not check", never
//! to an error state.
//!
//! The request goes out through the wallet manager and nowhere else,
//! because it has to take the route the syncs take. Someone who reaches
//! their backend through Tor does not expect the app to show GitHub
//! their address once a day: with an onion backend configured the check
//! goes through the same Tor proxy, and when Tor cannot be had it does
//! not go at all.
//!
//! What to make of the answer is decided here too, once for both apps:
//! when a check is due ([`UpdateRecord::due`]), which release is worth
//! announcing and what the user closed ([`UpdateRecord::status`]). The
//! vault keeps the [`UpdateRecord`], and the apps show what the
//! [`UpdateStatus`] says. The page an app opens is its own constant,
//! never an address the answer names: the answer is read for its tag
//! alone.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// What the apps say about releases, all of it decided here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    /// The app checks on its own, at most once a day.
    pub automatic: bool,
    /// The release to announce in the desktop's strip or Android's
    /// card: newer than the running version, never a pre-release, and
    /// not closed. `None` when there is nothing to say.
    pub announce: Option<String>,
    /// The newer release known, closed or not: what Settings › About
    /// offers to get.
    pub available: Option<String>,
    /// The last check that was to go out did not, because Tor is needed
    /// and could not be had: for the check a session makes, because no
    /// Tor was running, since that one never starts it. The next check
    /// that goes out clears it.
    pub tor_unavailable: bool,
}

/// What the vault keeps of the update check, in a record of its own.
/// A vault written before it existed reads as the check left on, a
/// first session not yet seen, and nothing known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRecord {
    /// The app checks on its own. On unless the user turned it off.
    #[serde(default = "on")]
    pub(crate) automatic: bool,
    /// When a session first opened on this vault, unix seconds, by a
    /// clock that could be right ([`UpdateRecord::session_at`]). No
    /// check goes out on its own within a day of it: a new install is up
    /// to date, and the user gets to see the setting before the app
    /// speaks to GitHub.
    #[serde(default)]
    pub(crate) first_session_at: Option<u64>,
    /// When the last check the app made on its own went out, answered
    /// or not, unix seconds. A day Tor was needed and could not be had
    /// leaves it as it was, and the button leaves it alone.
    #[serde(default)]
    pub(crate) checked_at: Option<u64>,
    /// The release the last answer named, in the one form a version is
    /// kept and shown in. `None` when the answer named no release, a
    /// pre-release among them: a release taken back stops being offered.
    #[serde(default)]
    pub(crate) latest: Option<String>,
    /// The release the notice was last closed on: neither it nor any
    /// release before it is announced again.
    #[serde(default)]
    pub(crate) dismissed: Option<String>,
    /// See [`UpdateStatus::tor_unavailable`].
    #[serde(default)]
    pub(crate) tor_unavailable: bool,
}

fn on() -> bool {
    true
}

impl Default for UpdateRecord {
    fn default() -> Self {
        UpdateRecord {
            automatic: true,
            first_session_at: None,
            checked_at: None,
            latest: None,
            dismissed: None,
            tor_unavailable: false,
        }
    }
}

/// Seconds between two checks the app makes on its own, and between the
/// first session and the first of them.
pub(crate) const CHECK_EVERY: u64 = 24 * 60 * 60;

/// 16 October 2026, midnight UTC, in unix seconds. No build of this
/// code was made before that day, so a clock that is right cannot read
/// an earlier time while it runs: such a time is a clock that is not
/// set yet, or was reset by a flat battery. Taken as the first session,
/// it would end the day that asks nothing once the clock is set right,
/// and the check would go out minutes after the install. Never raised
/// past the day of the build that carries it.
pub(crate) const NO_RIGHT_CLOCK_BEFORE: u64 = 1_792_108_800;

impl UpdateRecord {
    /// Whether the app should check on its own at `now`, unix seconds:
    /// the setting is on, a day has gone by since the first session, and
    /// another since the last check. A last check from the future is a
    /// clock that was moved back, and holds nothing back. A first
    /// session from the future is a clock that was ahead at the first
    /// launch, then set right: it holds the check back until the next
    /// session brings it to now ([`Self::session_at`]), so the first day
    /// still asks nothing.
    pub(crate) fn due(&self, now: u64) -> bool {
        let recent = |at: Option<u64>| at.is_some_and(|at| at <= now && now - at < CHECK_EVERY);
        let first_day = self
            .first_session_at
            .is_none_or(|at| at > now || now - at < CHECK_EVERY);
        self.automatic && !first_day && !recent(self.checked_at)
    }

    /// A session opened at `now`: the first one starts the day that
    /// asks nothing, and a first session from the future comes back to
    /// now. A time before [`NO_RIGHT_CLOCK_BEFORE`] is a clock not yet
    /// set right, and starts nothing: the first session is the next one
    /// that reads a time it could be.
    pub(crate) fn session_at(&mut self, now: u64) {
        if now < NO_RIGHT_CLOCK_BEFORE {
            return;
        }
        if self.first_session_at.is_none_or(|at| at > now) {
            self.first_session_at = Some(now);
        }
    }

    /// What to say to someone running `running`. A running version that
    /// does not read as one hears of nothing.
    pub(crate) fn status(&self, running: &str) -> UpdateStatus {
        let available = Version::parse(running).and_then(|running| {
            self.latest
                .as_deref()
                .and_then(Version::parse)
                .filter(|latest| latest.is_release() && *latest > running)
        });
        let closed = self.dismissed.as_deref().and_then(Version::parse);
        let announce = available
            .as_ref()
            .filter(|latest| closed.as_ref().is_none_or(|closed| *latest > closed));
        UpdateStatus {
            automatic: self.automatic,
            announce: announce.map(Version::to_string),
            available: available.as_ref().map(Version::to_string),
            tor_unavailable: self.tor_unavailable,
        }
    }

    /// Takes the tag a check answered: the release it names, or nothing
    /// when it names none.
    pub(crate) fn answered(&mut self, tag: &str) {
        self.latest = Version::parse(tag)
            .filter(Version::is_release)
            .map(|version| version.to_string());
    }

    /// Closes the notice on `version`, and so on every release up to it.
    /// A version closed before that is later stays the one kept.
    pub(crate) fn dismiss(&mut self, version: &Version) {
        let closed = self.dismissed.as_deref().and_then(Version::parse);
        if closed.is_none_or(|closed| *version > closed) {
            self.dismissed = Some(version.to_string());
        }
    }
}

/// A version as Semantic Versioning 2.0.0 reads it, strictly, after one
/// leading `v`, and ordered the way it says. Build metadata is read and
/// dropped: it orders nothing. The text may come from the network, so
/// what does not read as a version is none at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    numbers: [u64; 3],
    /// The identifiers after the hyphen; empty for a release.
    pre: Vec<Identifier>,
}

/// One identifier of a pre-release. A number sorts before a word, and
/// two words sort in ASCII order: the order of the variants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Identifier {
    Numeric(u64),
    Alphanumeric(String),
}

impl Version {
    /// Reads `1.2.3`, `v1.2.3`, `1.2.3-rc.1` and `1.2.3+build`; `None`
    /// for anything else, a number with a leading zero, a space or a
    /// fourth number among them.
    pub(crate) fn parse(text: &str) -> Option<Version> {
        if text.len() > TAG_MAX {
            return None;
        }
        let text = text.strip_prefix('v').unwrap_or(text);
        let (text, build) = match text.split_once('+') {
            Some((text, build)) => (text, Some(build)),
            None => (text, None),
        };
        if let Some(build) = build
            && !build.split('.').all(|part| word(part).is_some())
        {
            return None;
        }
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let mut numbers = [0u64; 3];
        for slot in &mut numbers {
            *slot = number(parts.next()?)?;
        }
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre.split('.').map(identifier).collect::<Option<Vec<_>>>()?,
        };
        Some(Version { numbers, pre })
    }

    /// A release, not a pre-release. A pre-release is never announced,
    /// to anyone.
    pub(crate) fn is_release(&self) -> bool {
        self.pre.is_empty()
    }
}

/// Digits, with no leading zero, that fit.
fn number(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Letters, digits and hyphens, at least one.
fn word(text: &str) -> Option<&str> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then_some(text)
}

fn identifier(text: &str) -> Option<Identifier> {
    let text = word(text)?;
    if text.bytes().all(|b| b.is_ascii_digit()) {
        number(text).map(Identifier::Numeric)
    } else {
        Some(Identifier::Alphanumeric(text.to_owned()))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.numbers.cmp(&other.numbers).then_with(|| {
            // A release comes after every pre-release of its numbers;
            // between two pre-releases, the identifiers decide, one by
            // one, and more of them win when all before are equal.
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The one form a version is kept and shown in: no `v`, no build
/// metadata, rebuilt from what was read and never the text that came in.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch] = self.numbers;
        write!(f, "{major}.{minor}.{patch}")?;
        for (i, identifier) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match identifier {
                Identifier::Numeric(number) => write!(f, "{number}")?,
                Identifier::Alphanumeric(word) => f.write_str(word)?,
            }
        }
        Ok(())
    }
}

/// Where the releases are read from.
pub(crate) const GITHUB_API: &str = "https://api.github.com";

/// The version of GitHub's REST API the check is written against, which
/// GitHub's documentation asks each request to name: the latest, whose
/// changes leave the release and its tag as they were.
pub(crate) const GITHUB_API_VERSION: &str = "2026-03-10";

/// Asks for the latest release of `owner/repo` and gives back its tag.
/// `proxy` is the Tor SOCKS proxy the manager resolved when the check
/// has to go through Tor; the name of the host then goes to the proxy,
/// never to a resolver.
///
/// A version GitHub no longer supports is answered `410 Gone`: an
/// install left without updates for years, the one the check is for,
/// then asks once more without naming one, as GitHub reads it by
/// default. Once, and both requests within the one budget of the check.
pub(crate) async fn latest_tag(api: &str, repo: &str, proxy: Option<&str>) -> CoreResult<String> {
    latest_tag_within(api, repo, proxy, budget(proxy)).await
}

/// [`latest_tag`], all of it within `budget`.
pub(crate) async fn latest_tag_within(
    api: &str,
    repo: &str,
    proxy: Option<&str>,
    budget: std::time::Duration,
) -> CoreResult<String> {
    tokio::time::timeout(budget, ask_latest(api, repo, proxy))
        .await
        .map_err(|_| check_error("timed out".to_owned()))?
}

async fn ask_latest(api: &str, repo: &str, proxy: Option<&str>) -> CoreResult<String> {
    let client = client(proxy)?;
    let ask = |version: Option<&'static str>| {
        let mut request = client
            .get(format!("{api}/repos/{repo}/releases/latest"))
            .header("Accept", "application/vnd.github+json");
        if let Some(version) = version {
            request = request.header("X-GitHub-Api-Version", version);
        }
        request.send()
    };
    let mut response = ask(Some(GITHUB_API_VERSION)).await.map_err(failed)?;
    if response.status() == reqwest::StatusCode::GONE {
        response = ask(None).await.map_err(failed)?;
    }
    if !response.status().is_success() {
        return Err(check_error(format!("http {}", response.status())));
    }
    let body = body_of(response).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| check_error(e.to_string()))?;
    read_tag(&value)
}

fn failed(e: reqwest::Error) -> CoreError {
    check_error(crate::chain::esplora::describe_failure(&e))
}

/// The body of an answer, read a chunk at a time and refused past
/// [`MAX_ANSWER`].
async fn body_of(mut response: reqwest::Response) -> CoreResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err(check_error("the answer is far too large".to_owned()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// How long a check may take, its every request together: a Tor
/// circuit is slower to build than a connection is to open.
fn budget(proxy: Option<&str>) -> std::time::Duration {
    std::time::Duration::from_secs(if proxy.is_some() { 60 } else { 15 })
}

/// The client the check goes out with: through the Tor proxy when there
/// is one, and through no other proxy at all.
fn client(proxy: Option<&str>) -> CoreResult<reqwest::Client> {
    let mut builder = crate::chain::http_client()
        .timeout(budget(proxy))
        .user_agent("gerfaut")
        .redirect(crate::chain::redirects());
    if let Some(proxy) = proxy {
        let proxy = reqwest::Proxy::all(format!("socks5h://{proxy}"))
            .map_err(|e| CoreError::Tor(format!("invalid Tor proxy address: {e}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| CoreError::Internal(format!("http client: {e}")))
}

/// Largest answer read from the releases API: one release, its notes
/// and its assets fit many times over.
const MAX_ANSWER: usize = 1 << 20;

/// Longest version taken: `v1.2.3` and any suffix a release could carry
/// fit well within it.
const TAG_MAX: usize = 32;

/// The tag the answer names, held to what a tag looks like. Whether it
/// reads as a version is the record's question.
fn read_tag(value: &serde_json::Value) -> CoreResult<String> {
    value["tag_name"]
        .as_str()
        .filter(|tag| {
            !tag.is_empty() && tag.len() <= TAG_MAX && tag.chars().all(|c| c.is_ascii_graphic())
        })
        .map(str::to_owned)
        .ok_or_else(|| check_error("no version tag in response".to_owned()))
}

fn check_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "github".to_owned(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = CHECK_EVERY;
    const NOW: u64 = 1_800_000_000;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} reads as a version"))
    }

    /// A vault opened before today that knows of `latest`.
    fn knowing(latest: &str) -> UpdateRecord {
        UpdateRecord {
            first_session_at: Some(NOW - 10 * DAY),
            latest: Some(latest.to_owned()),
            ..UpdateRecord::default()
        }
    }

    #[test]
    fn a_tag_is_read_as_it_was_written_or_not_at_all() {
        let read = |tag: &str| read_tag(&serde_json::json!({ "tag_name": tag }));
        assert_eq!(read("v0.2.0").unwrap(), "v0.2.0");
        // The address the answer names is never read: the apps open
        // their own page.
        assert_eq!(
            read_tag(&serde_json::json!({
                "tag_name": "v0.2.0",
                "html_url": "https://evil.example/download",
            }))
            .unwrap(),
            "v0.2.0"
        );
        assert!(read(&"9".repeat(33)).is_err());
        assert!(read("").is_err());
        assert!(read("v1.0.0 <b>").is_err());
        assert!(read_tag(&serde_json::json!({ "tag_name": 2 })).is_err());
        assert!(read_tag(&serde_json::json!({})).is_err());
    }

    /// The check goes out straight, or through the Tor proxy, and never
    /// through a proxy the environment names.
    #[test]
    fn a_check_takes_no_proxy_but_tor() {
        assert!(!crate::chain::takes_a_proxy(&client(None).unwrap()));
        assert!(crate::chain::takes_a_proxy(
            &client(Some("127.0.0.1:9050")).unwrap()
        ));
    }

    #[test]
    fn a_leading_v_and_build_metadata_change_nothing() {
        assert_eq!(version("v1.2.3"), version("1.2.3"));
        assert_eq!(version("1.2.3+build.5"), version("1.2.3"));
        assert_eq!(version("v1.2.3-rc.1+sha.abc").to_string(), "1.2.3-rc.1");
        assert_eq!(version("0.10.0").to_string(), "0.10.0");
    }

    #[test]
    fn numbers_compare_as_numbers() {
        assert!(version("0.1.10") > version("0.1.9"));
        assert!(version("1.0.0") > version("0.99.99"));
        assert!(version("v0.2.0") > version("0.1.0"));
        assert_eq!(version("0.1.0").cmp(&version("v0.1.0")), Ordering::Equal);
    }

    /// The example of the specification, §11, in its order.
    #[test]
    fn pre_releases_follow_the_order_of_the_specification() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(version(pair[0]) < version(pair[1]), "{pair:?}");
        }
        assert!(version("0.2.0") > version("0.2.0-rc.1"));
        assert!(version("0.2.0-rc.1") > version("0.1.0"));
        assert!(version("1.0.0-0.3.7") < version("1.0.0-x.7.z.92"));
        assert!(version("1.0.0-x-y-z.--") > version("1.0.0-x"));
    }

    #[test]
    fn anything_else_is_not_a_version() {
        for text in [
            "",
            "nightly",
            "v",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3-rc..1",
            "1.2.3+",
            "1.2.3+a+b",
            "1.2.3-rc_1",
            " 1.2.3",
            "1.2.3 ",
            "V1.2.3",
            "vv1.2.3",
            "-1.2.3",
            "1.2.3<b>",
            "<img src=x onerror=alert(1)>",
            "0.2.0<script>alert(1)</script>",
            "99999999999999999999.0.0",
            "1.2.3-99999999999999999999",
        ] {
            assert_eq!(Version::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_check_waits_a_day_after_the_first_session() {
        let fresh = UpdateRecord::default();
        assert!(!fresh.due(NOW), "no first session seen yet");
        let first = UpdateRecord {
            first_session_at: Some(NOW),
            ..UpdateRecord::default()
        };
        assert!(!first.due(NOW));
        assert!(!first.due(NOW + DAY - 1));
        assert!(first.due(NOW + DAY));
    }

    /// A clock a year ahead at the first launch, then set right: the
    /// first day still asks nothing, counted from the session that saw
    /// the right time.
    #[test]
    fn a_first_session_from_the_future_comes_back_to_now() {
        let mut record = UpdateRecord::default();
        record.session_at(NOW + 365 * DAY);
        assert!(
            !record.due(NOW),
            "a first session ahead holds the check back"
        );
        record.session_at(NOW);
        assert_eq!(record.first_session_at, Some(NOW));
        assert!(!record.due(NOW + DAY - 1));
        assert!(record.due(NOW + DAY));
        record.session_at(NOW + 2 * DAY);
        assert_eq!(
            record.first_session_at,
            Some(NOW),
            "a later session moves nothing"
        );
    }

    /// A clock behind at the first launch, never set or reset by a flat
    /// battery, then set right: the time it read starts nothing, and the
    /// first day is counted from the session that saw the right time.
    #[test]
    fn a_first_session_before_any_right_clock_starts_nothing() {
        let mut record = UpdateRecord::default();
        record.session_at(0);
        record.session_at(NO_RIGHT_CLOCK_BEFORE - 1);
        assert_eq!(record.first_session_at, None);
        assert!(!record.due(NOW), "no first session seen yet");
        record.session_at(NOW);
        assert_eq!(record.first_session_at, Some(NOW));
        assert!(!record.due(NOW + DAY - 1));
        assert!(record.due(NOW + DAY));

        let mut fresh = UpdateRecord::default();
        fresh.session_at(NO_RIGHT_CLOCK_BEFORE);
        assert_eq!(fresh.first_session_at, Some(NO_RIGHT_CLOCK_BEFORE));
    }

    #[test]
    fn a_check_goes_at_most_once_a_day() {
        let record = UpdateRecord {
            first_session_at: Some(NOW - 10 * DAY),
            checked_at: Some(NOW),
            ..UpdateRecord::default()
        };
        assert!(!record.due(NOW + 3600));
        assert!(!record.due(NOW + DAY - 1));
        assert!(record.due(NOW + DAY));
        // A clock that went back: the stamp holds nothing back.
        assert!(record.due(NOW - 60));
        let never = UpdateRecord {
            checked_at: None,
            ..record
        };
        assert!(never.due(NOW));
    }

    #[test]
    fn nothing_is_due_once_turned_off() {
        let off = UpdateRecord {
            automatic: false,
            first_session_at: Some(NOW - 10 * DAY),
            ..UpdateRecord::default()
        };
        assert!(!off.due(NOW));
    }

    #[test]
    fn only_a_newer_release_is_announced() {
        let status = knowing("0.2.0").status("0.1.0");
        assert_eq!(status.announce.as_deref(), Some("0.2.0"));
        assert_eq!(status.available.as_deref(), Some("0.2.0"));
        assert!(status.automatic);
        assert!(!status.tor_unavailable);

        for running in ["0.2.0", "0.3.0", "1.0.0"] {
            let status = knowing("0.2.0").status(running);
            assert_eq!(status.announce, None, "{running}");
            assert_eq!(status.available, None, "{running}");
        }
    }

    /// A pre-release is never announced, not even to someone running
    /// one; the release it prepares is announced to them.
    #[test]
    fn a_pre_release_is_never_announced() {
        for running in ["0.1.0", "0.2.0-rc.1", "0.3.0-beta"] {
            assert_eq!(
                knowing("0.3.0-rc.1").status(running).announce,
                None,
                "{running}"
            );
        }
        assert_eq!(
            knowing("0.2.0").status("0.2.0-rc.1").announce.as_deref(),
            Some("0.2.0")
        );
        let mut record = knowing("0.2.0");
        record.answered("v0.3.0-rc.1");
        assert_eq!(record.latest, None, "a pre-release named takes back");
    }

    #[test]
    fn an_answer_is_kept_in_its_one_form() {
        let mut record = UpdateRecord::default();
        record.answered("v0.2.0+build.7");
        assert_eq!(record.latest.as_deref(), Some("0.2.0"));
        record.answered("nightly");
        assert_eq!(record.latest, None, "no version, nothing known");
        record.answered("v0.1.0");
        assert_eq!(record.latest.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn a_closed_release_stays_closed_and_a_newer_one_shows() {
        let mut record = knowing("0.2.0");
        record.dismiss(&version("0.2.0"));
        let status = record.status("0.1.0");
        assert_eq!(status.announce, None);
        assert_eq!(
            status.available.as_deref(),
            Some("0.2.0"),
            "About still offers it"
        );

        record.answered("v0.3.0");
        assert_eq!(record.status("0.1.0").announce.as_deref(), Some("0.3.0"));

        // An older one closed later does not reopen what was closed.
        record.dismiss(&version("0.3.0"));
        record.dismiss(&version("0.2.0"));
        assert_eq!(record.dismissed.as_deref(), Some("0.3.0"));
        assert_eq!(record.status("0.1.0").announce, None);
    }

    /// What the vault holds is read as a version or not at all: a value
    /// written by hand, or by a build that kept another form, says
    /// nothing.
    #[test]
    fn a_stored_value_that_is_no_version_says_nothing() {
        assert_eq!(knowing("<b>9.9.9</b>").status("0.1.0").announce, None);
        assert_eq!(knowing("0.2.0").status("garbage").announce, None);
        let record = UpdateRecord {
            dismissed: Some("garbage".to_owned()),
            ..knowing("0.2.0")
        };
        assert_eq!(record.status("0.1.0").announce.as_deref(), Some("0.2.0"));
    }

    #[test]
    fn a_vault_written_before_reads_as_on_and_knowing_nothing() {
        let record: UpdateRecord = serde_json::from_str("{}").unwrap();
        assert_eq!(record, UpdateRecord::default());
        assert!(record.automatic);
        assert_eq!(
            record.status("0.1.0"),
            UpdateStatus {
                automatic: true,
                announce: None,
                available: None,
                tor_unavailable: false,
            }
        );
    }
}
