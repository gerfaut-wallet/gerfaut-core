//! The update check against a releases API that lives in the test, on
//! a vault on disk, with a clock the test moves by hand.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::chain::BackendConfig;
use crate::chain::tor::{TorMode, TorSettings, socks};
use crate::manager::tests::support::{closed_port, manager as open};
use crate::network::Network;

const REPO: &str = "gerfaut-wallet/gerfaut-desktop";
const DAY: u64 = crate::updates::CHECK_EVERY;
const NOW: u64 = 1_800_000_000;
const ONION: &str = "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001";

/// Something that answers like the releases API: the tag a test sets,
/// or a failure when it sets none, and counts who came.
struct Releases {
    api: String,
    visits: Arc<Mutex<u32>>,
    tag: Arc<Mutex<Option<String>>>,
}

impl Releases {
    async fn start(tag: &str) -> Releases {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let visits = Arc::new(Mutex::new(0u32));
        let tag = Arc::new(Mutex::new(Some(tag.to_owned())));
        let (counted, answered) = (visits.clone(), tag.clone());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                *counted.lock().unwrap() += 1;
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let tag = answered.lock().unwrap().clone();
                let answer = match tag {
                    // The page it names is never the one an app opens.
                    Some(tag) => {
                        let body = format!(
                            r#"{{"tag_name":"{tag}","html_url":"https://evil.example/download"}}"#
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                    None => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                        .to_owned(),
                };
                let _ = stream.write_all(answer.as_bytes()).await;
            }
        });
        Releases {
            api: format!("http://{address}"),
            visits,
            tag,
        }
    }

    /// What the next answers say; `None` makes them fail.
    fn answer(&self, tag: Option<&str>) {
        *self.tag.lock().unwrap() = tag.map(str::to_owned);
    }

    fn visits(&self) -> u32 {
        *self.visits.lock().unwrap()
    }

    async fn session(&self, manager: &WalletManager, running: &str, now: u64) -> UpdateStatus {
        manager
            .update_session_at(&self.api, REPO, running, now)
            .await
    }

    async fn button(&self, manager: &WalletManager, running: &str) -> CoreResult<UpdateStatus> {
        manager.check_update_at(&self.api, REPO, running).await
    }
}

/// A manager whose first session was a day ago, with nothing checked
/// since: the next session asks.
async fn opened_yesterday(dir: &std::path::Path, releases: &Releases) -> WalletManager {
    let manager = open(dir).await;
    releases.session(&manager, "0.1.0", NOW - DAY).await;
    assert_eq!(releases.visits(), 0, "the first session asks nothing");
    manager
}

/// An onion backend on mainnet, and a system Tor at `proxy`.
async fn through_tor(manager: &WalletManager, proxy: String) {
    manager
        .set_backend(
            Network::Mainnet,
            BackendConfig::CustomElectrum {
                url: ONION.to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(proxy),
        })
        .await
        .unwrap();
    assert!(manager.uses_tor().await);
}

#[tokio::test]
async fn the_first_day_asks_nothing_and_the_next_one_does() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = open(dir.path()).await;

    let status = releases.session(&manager, "0.1.0", NOW).await;
    assert_eq!(status.announce, None);
    assert!(status.automatic);
    releases.session(&manager, "0.1.0", NOW + DAY - 1).await;
    assert_eq!(releases.visits(), 0);

    let status = releases.session(&manager, "0.1.0", NOW + DAY).await;
    assert_eq!(releases.visits(), 1);
    assert_eq!(status.announce.as_deref(), Some("0.2.0"));
    assert_eq!(status.available.as_deref(), Some("0.2.0"));
    assert_eq!(manager.update_status("0.1.0").await, status);
}

/// A clock a year ahead at the first launch, then set right: the first
/// day asks nothing all the same, counted from the right time.
#[tokio::test]
async fn a_clock_ahead_at_the_first_launch_still_waits_a_day() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = open(dir.path()).await;

    releases.session(&manager, "0.1.0", NOW + 365 * DAY).await;
    releases.session(&manager, "0.1.0", NOW).await;
    releases.session(&manager, "0.1.0", NOW + DAY - 1).await;
    assert_eq!(releases.visits(), 0);

    releases.session(&manager, "0.1.0", NOW + DAY).await;
    assert_eq!(releases.visits(), 1);
}

/// A check counts whatever its answer, and what it found is the
/// vault's: a restart neither asks again within the day nor forgets.
/// None of it is in the preferences the apps write.
#[tokio::test]
async fn a_check_goes_at_most_once_a_day_and_outlives_the_app() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    releases.answer(None);
    assert_eq!(
        releases.session(&manager, "0.1.0", NOW).await.announce,
        None
    );
    assert_eq!(releases.visits(), 1, "a failed check is a check");

    releases.answer(Some("v0.2.0"));
    releases.session(&manager, "0.1.0", NOW + 3600).await;
    assert_eq!(releases.visits(), 1);
    let status = releases.session(&manager, "0.1.0", NOW + DAY).await;
    assert_eq!(releases.visits(), 2);
    assert_eq!(status.announce.as_deref(), Some("0.2.0"));
    assert!(manager.settings().await.app_prefs.is_empty());
    drop(manager);

    let manager = open(dir.path()).await;
    assert_eq!(manager.update_status("0.1.0").await, status);
    releases.session(&manager, "0.1.0", NOW + DAY + 3600).await;
    assert_eq!(releases.visits(), 2);
    releases.session(&manager, "0.1.0", NOW + 2 * DAY).await;
    assert_eq!(releases.visits(), 3);
}

/// Two sessions that find the check due at the same moment send one.
#[tokio::test]
async fn two_sessions_at_once_ask_once() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    let (first, second) = tokio::join!(
        releases.session(&manager, "0.1.0", NOW),
        releases.session(&manager, "0.1.0", NOW),
    );
    assert_eq!(releases.visits(), 1);
    let found = Some("0.2.0".to_owned());
    assert!(first.announce == found || second.announce == found);
}

#[tokio::test]
async fn a_closed_release_stays_closed_and_a_newer_one_shows() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    let status = releases.session(&manager, "0.1.0", NOW).await;
    manager
        .dismiss_update(status.announce.as_deref().unwrap())
        .await
        .unwrap();
    let status = manager.update_status("0.1.0").await;
    assert_eq!(status.announce, None);
    assert_eq!(
        status.available.as_deref(),
        Some("0.2.0"),
        "About still offers it"
    );
    drop(manager);

    let manager = open(dir.path()).await;
    assert_eq!(manager.update_status("0.1.0").await.announce, None);
    releases.answer(Some("v0.3.0"));
    let status = releases.session(&manager, "0.1.0", NOW + DAY).await;
    assert_eq!(status.announce.as_deref(), Some("0.3.0"));

    assert!(matches!(
        manager.dismiss_update("0.3.0 <b>").await,
        Err(CoreError::InvalidInput { .. })
    ));
    assert_eq!(
        manager.update_status("0.1.0").await.announce.as_deref(),
        Some("0.3.0")
    );
}

/// A pre-release is announced to nobody, and the release it prepares
/// is announced to whoever runs it.
#[tokio::test]
async fn a_pre_release_is_never_announced_and_its_release_is() {
    let releases = Releases::start("v0.2.0-rc.1").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    let status = releases.session(&manager, "0.1.0", NOW).await;
    assert_eq!(releases.visits(), 1);
    assert_eq!(status.announce, None);
    assert_eq!(status.available, None);
    assert_eq!(manager.update_status("0.2.0-rc.0").await.announce, None);

    releases.answer(Some("v0.2.0"));
    let status = releases.session(&manager, "0.2.0-rc.1", NOW + DAY).await;
    assert_eq!(status.announce.as_deref(), Some("0.2.0"));
    assert_eq!(manager.update_status("0.2.0").await.announce, None);
}

#[tokio::test]
async fn turned_off_it_asks_nothing_and_the_button_still_does() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    manager.set_update_automatic(false).await.unwrap();
    for day in 0..3 {
        let status = releases.session(&manager, "0.1.0", NOW + day * DAY).await;
        assert!(!status.automatic);
    }
    assert_eq!(releases.visits(), 0);

    let status = releases.button(&manager, "0.1.0").await.unwrap();
    assert_eq!(releases.visits(), 1);
    assert_eq!(status.available.as_deref(), Some("0.2.0"));
    assert_eq!(status.announce, None, "seen on About, not announced again");

    manager.set_update_automatic(true).await.unwrap();
    assert!(manager.update_status("0.1.0").await.automatic);
    releases.session(&manager, "0.1.0", NOW + 3 * DAY).await;
    assert_eq!(releases.visits(), 2, "the button kept no schedule");
}

/// The button answers what it finds, on screen, so the notice says
/// nothing of it; it neither spends nor moves the daily check.
#[tokio::test]
async fn the_button_closes_what_it_finds_and_leaves_the_schedule_alone() {
    let releases = Releases::start("v0.1.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    releases.session(&manager, "0.1.0", NOW).await;
    assert_eq!(releases.visits(), 1);

    releases.answer(Some("v0.2.0"));
    let status = releases.button(&manager, "0.1.0").await.unwrap();
    assert_eq!(releases.visits(), 2);
    assert_eq!(status.announce, None);
    assert_eq!(status.available.as_deref(), Some("0.2.0"));
    releases.session(&manager, "0.1.0", NOW + 3600).await;
    assert_eq!(releases.visits(), 2);
    releases.session(&manager, "0.1.0", NOW + DAY).await;
    assert_eq!(releases.visits(), 3);

    releases.answer(None);
    assert!(matches!(
        releases.button(&manager, "0.1.0").await,
        Err(CoreError::Sync { .. })
    ));
    let status = manager.update_status("0.1.0").await;
    assert_eq!(
        status.available.as_deref(),
        Some("0.2.0"),
        "a failure forgets nothing"
    );
}

#[tokio::test]
async fn without_tor_the_check_goes_straight() {
    let releases = Releases::start("v9.0.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = open(dir.path()).await;
    assert!(!manager.uses_tor().await);
    let status = releases.button(&manager, "0.1.0").await.unwrap();
    assert_eq!(status.available.as_deref(), Some("9.0.0"));
    assert_eq!(releases.visits(), 1);
}

/// Tor is needed and is not there: nothing goes out, the session says
/// why, and the day is not spent. Once the route is back, the next
/// session asks, the same day.
#[tokio::test]
async fn a_day_without_the_tor_it_needs_is_not_spent() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    through_tor(&manager, closed_port().await).await;

    let status = releases.session(&manager, "0.1.0", NOW).await;
    assert!(status.tor_unavailable);
    assert_eq!(status.announce, None);
    let refused = releases.button(&manager, "0.1.0").await.unwrap_err();
    assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
    assert_eq!(releases.visits(), 0, "nothing left in the clear");
    assert!(manager.update_status("0.1.0").await.tor_unavailable);

    manager
        .set_backend(Network::Mainnet, BackendConfig::default())
        .await
        .unwrap();
    assert!(!manager.uses_tor().await);
    let status = releases.session(&manager, "0.1.0", NOW + 60).await;
    assert_eq!(releases.visits(), 1);
    assert!(!status.tor_unavailable);
    assert_eq!(status.announce.as_deref(), Some("0.2.0"));
}

/// The check a session makes waits for a Tor that already runs: with
/// the built-in client not started, nothing goes out, the day is not
/// spent, and the client is still not started afterwards. Starting it
/// is for a sync or the live watch. Built with `embedded-tor`, the one
/// build where a session could start it.
#[cfg(feature = "embedded-tor")]
#[tokio::test]
async fn a_session_never_starts_the_built_in_tor() {
    let releases = Releases::start("v0.2.0").await;
    let dir = tempfile::tempdir().unwrap();
    let manager = opened_yesterday(dir.path(), &releases).await;
    through_tor(&manager, closed_port().await).await;
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::Embedded,
            socks_proxy: None,
        })
        .await
        .unwrap();

    let session = releases.session(&manager, "0.1.0", NOW);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), session)
        .await
        .expect("no bootstrap is waited for");
    assert!(status.tor_unavailable);
    assert_eq!(releases.visits(), 0);
    let tor = manager.tor_status().await;
    assert!(!tor.running && tor.error.is_none(), "{tor:?}");
}

/// An onion backend on any network, even one that is not shown now,
/// sends the check through the Tor proxy, by name.
#[tokio::test]
async fn with_an_onion_backend_the_check_goes_through_tor() {
    let releases = Releases::start("v0.1.0").await;
    let upstream = releases.api.trim_start_matches("http://").to_owned();
    let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy = listener.local_addr().unwrap().to_string();
    // A system Tor: no credentials, the greeting a probe expects.
    let seen = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = seen.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client
                    .write_all(&[socks::VERSION, socks::NO_AUTH])
                    .await
                    .ok()?;
                let mut head = [0u8; 5];
                // A probe hangs up here; a request goes on.
                client.read_exact(&mut head).await.ok()?;
                let mut name = vec![0u8; usize::from(head[4]) + 2];
                client.read_exact(&mut name).await.ok()?;
                let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
                name.truncate(name.len() - 2);
                seen.lock()
                    .unwrap()
                    .push((String::from_utf8_lossy(&name).into_owned(), port));
                let mut server = TcpStream::connect(&upstream).await.ok()?;
                client
                    .write_all(&[socks::VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut server)
                    .await
                    .ok()?;
                Some(())
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let manager = open(dir.path()).await;
    through_tor(&manager, proxy).await;
    manager.set_active_network(Network::Signet).await.unwrap();
    assert!(manager.uses_tor().await);

    let status = manager
        .check_update_at("http://releases.test", REPO, "0.1.0")
        .await
        .unwrap();
    assert_eq!(status.available, None);
    assert!(!status.tor_unavailable);
    assert_eq!(
        *asked.lock().unwrap(),
        vec![("releases.test".to_owned(), 80)],
        "the name went to the proxy, and nowhere else"
    );
    assert_eq!(releases.visits(), 1);
}
