//! The watcher against the servers of [`crate::testkit`]: an Electrum
//! server, and a mempool instance with its WebSocket and the REST
//! routes polling reads.

use std::net::Ipv4Addr;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::*;
use crate::chain::tor::{TorMode, TorSettings};
use crate::testkit::{
    ADDRESS, ADDRESS_SCRIPT, FakeElectrum, FakeMempool, esplora_payment, script, scripthash,
};

const WAIT: Duration = Duration::from_secs(10);

fn timings() -> Timings {
    Timings {
        quiet: Duration::from_millis(40),
        burst: Duration::from_millis(200),
        gap: Duration::from_millis(150),
        keepalive: Duration::from_millis(150),
        pong: Duration::from_millis(400),
        backoff_first: Duration::from_millis(20),
        backoff_cap: Duration::from_millis(100),
        stable: Duration::from_secs(1),
        connect: Duration::from_secs(5),
        tor_connect: Duration::from_secs(5),
        poll: Duration::from_millis(100),
        reprobe: Duration::from_secs(3600),
        retries: [Duration::from_millis(20), Duration::from_millis(50)],
        hold: Duration::from_millis(100),
        hold_cap: Duration::from_millis(400),
        due: Duration::from_secs(3600),
        refused: Duration::from_millis(600),
    }
}

fn config(backend: BackendConfig) -> WatchConfig {
    WatchConfig {
        network: Network::Signet,
        backend,
        electrum_certs: TrustedCerts::new(),
        tor: TorSettings::default(),
        data_dir: std::env::temp_dir(),
        keepalive_secs: None,
    }
}

fn wallet(id: &str, scripts: &[u8], lookahead: &[u8], has_pending: bool) -> WatchedWallet {
    WatchedWallet {
        wallet_id: id.to_owned(),
        scripts: scripts
            .iter()
            .map(|n| WatchedScript {
                script: script(*n),
                lookahead: lookahead.contains(n),
                status: None,
                counts: None,
            })
            .collect(),
        has_pending,
        pinned: false,
        holds_coins: false,
        unlisted: 0,
    }
}

/// The next event that is not a status, within the wait.
async fn next_event(events: &mut WatchEvents) -> WatchEvent {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(WatchEvent::Status(_))) => {}
            Ok(Some(event)) => return event,
            Ok(None) => panic!("the watcher stopped"),
            Err(_) => panic!("no event within {WAIT:?}"),
        }
    }
}

/// Nothing but statuses for a while.
async fn no_event(events: &mut WatchEvents, during: Duration) {
    let quiet = async {
        loop {
            match events.next().await {
                Some(WatchEvent::Status(_)) => {}
                other => return other,
            }
        }
    };
    if let Ok(event) = tokio::time::timeout(during, quiet).await {
        panic!("expected silence, got {event:?}");
    }
}

async fn until(watch: &LiveWatch, what: &str, holds: impl Fn(&WatchStatus) -> bool) -> WatchStatus {
    let started = std::time::Instant::now();
    loop {
        let status = watch.status();
        if holds(&status) {
            return status;
        }
        assert!(started.elapsed() < WAIT, "never {what}: {status:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A wallet reported whole.
fn changed(id: &str, reason: ChangeReason, rescan: bool) -> WatchEvent {
    moved(id, reason, rescan, &[])
}

/// A wallet reported with the scripts that moved.
fn moved(id: &str, reason: ChangeReason, rescan: bool, scripts: &[u8]) -> WatchEvent {
    let mut scripts: Vec<String> = scripts.iter().map(|n| script(*n)).collect();
    scripts.sort();
    WatchEvent::WalletChanged {
        wallet_id: id.to_owned(),
        reason,
        rescan,
        scripts,
    }
}

/// The next reports, one per wallet named, in whatever order they come.
async fn reported(events: &mut WatchEvents, ids: &[&str], reason: ChangeReason) {
    let mut seen = Vec::new();
    for _ in ids {
        seen.push(next_event(events).await);
    }
    seen.sort_by_key(|event| format!("{event:?}"));
    let mut expected: Vec<WatchEvent> = ids.iter().map(|id| changed(id, reason, false)).collect();
    expected.sort_by_key(|event| format!("{event:?}"));
    assert_eq!(seen, expected);
}

#[tokio::test]
async fn electrum_pushes_a_change_once_per_burst() {
    let server = FakeElectrum::start().await;
    // Something landed on "b" while nothing listened.
    server.set_status(&script(4), "dd");
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![
            wallet("a", &[1, 2, 3], &[3], false),
            wallet("b", &[4], &[], false),
        ],
        Some(timings()),
    );
    let status = until(&watch, "subscribed", |s| s.pushed_scripts == 4).await;
    assert_eq!(status.state, WatchState::Connected);
    assert_eq!(status.transport, Some(WatchTransport::Electrum));
    assert_eq!(status.server.as_deref(), Some("127.0.0.1"));
    assert_eq!(status.watched_scripts, 4);
    // The head of every wallet first, then the next rank.
    assert_eq!(
        server.subscriptions(),
        vec![vec![
            scripthash(&script(1)),
            scripthash(&script(4)),
            scripthash(&script(2)),
            scripthash(&script(3)),
        ]]
    );
    // A script whose status differs from what its wallet holds is
    // reported, named, once every script has its first status: what
    // happened before anything listened, and nothing else.
    assert_eq!(
        next_event(&mut events).await,
        moved("b", ChangeReason::Started, false, &[4])
    );
    no_event(&mut events, Duration::from_millis(300)).await;

    // A transaction touching two scripts of one wallet: two notices,
    // one report, naming both.
    server.set_status(&script(1), "aa");
    server.set_status(&script(2), "bb");
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, false, &[1, 2])
    );
    no_event(&mut events, Duration::from_millis(300)).await;

    // The same status again is no change, however often it is sent.
    for _ in 0..50 {
        server.set_status(&script(1), "aa");
    }
    no_event(&mut events, Duration::from_millis(300)).await;

    // Past the revealed addresses.
    server.set_status(&script(3), "cc");
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, true, &[3])
    );

    // The wallet synced and now holds what the server lists: the same
    // status again is nothing new.
    watch.set_wallets(vec![
        WatchedWallet {
            scripts: vec![WatchedScript {
                script: script(1),
                lookahead: false,
                status: Some("ab".to_owned()),
                counts: None,
            }],
            ..wallet("a", &[], &[], false)
        },
        wallet("b", &[4], &[], false),
    ]);
    until(&watch, "the list shrinks", |s| s.watched_scripts == 2).await;
    server.set_status(&script(1), "ab");
    no_event(&mut events, Duration::from_millis(300)).await;

    // A block.
    server.push(
        json!({
            "jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
            "params": [{ "height": 101, "hex": "00" }],
        })
        .to_string(),
    );
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 101 }
    );

    // Garbage, an unknown script and an answer nobody asked for are
    // read and dropped.
    server.push("not json".to_owned());
    server.push(json!({ "id": 999_999, "result": "zz" }).to_string());
    server.push(
        json!({ "method": "blockchain.scripthash.subscribe", "params": ["ff", "zz"] }).to_string(),
    );
    no_event(&mut events, Duration::from_millis(300)).await;
    assert_eq!(watch.status().state, WatchState::Connected);

    watch.stop();
    assert!(
        tokio::time::timeout(WAIT, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "a stopped watcher closes its events"
    );
    assert_eq!(watch.status(), WatchStatus::default());
}

#[tokio::test]
async fn electrum_reconnects_and_reports_what_moved_meanwhile() {
    let server = FakeElectrum::start().await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false), wallet("b", &[2], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 2).await;
    // Nothing differs from what the wallets hold: nothing to report.
    no_event(&mut events, Duration::from_millis(300)).await;

    // The connection drops, and a payment to "b" lands while it is down.
    server.hang_up();
    server
        .state
        .lock()
        .unwrap()
        .statuses
        .insert(scripthash(&script(2)), Some("dd".to_owned()));
    // Every script is asked for again, and only the one that moved is
    // reported.
    assert_eq!(
        next_event(&mut events).await,
        moved("b", ChangeReason::Reconnected, false, &[2])
    );
    no_event(&mut events, Duration::from_millis(300)).await;
    let subscriptions = server.subscriptions();
    assert_eq!(subscriptions.len(), 2, "one reconnection");
    assert_eq!(subscriptions[1].len(), 2, "both scripts asked for again");
    assert_eq!(watch.status().state, WatchState::Connected);

    // A script revealed by a sync is subscribed on the open connection,
    // and nothing else is sent again.
    watch.set_wallets(vec![
        wallet("a", &[1, 5], &[], false),
        wallet("b", &[2], &[], false),
    ]);
    until(&watch, "the new script is subscribed", |s| {
        s.pushed_scripts == 3
    })
    .await;
    let subscriptions = server.subscriptions();
    assert_eq!(subscriptions.len(), 2);
    assert_eq!(subscriptions[1].last(), Some(&scripthash(&script(5))));
    assert_eq!(subscriptions[1].len(), 3);
    server.set_status(&script(5), "ee");
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, false, &[5])
    );

    // A removed wallet is heard no more.
    watch.set_wallets(vec![wallet("a", &[1, 5], &[], false)]);
    until(&watch, "the list shrinks", |s| s.watched_scripts == 2).await;
    server.set_status(&script(2), "ff");
    no_event(&mut events, Duration::from_millis(300)).await;
    assert_eq!(server.subscriptions().len(), 2, "no reconnection for that");
}

/// How many requests of a method the server has had, over every
/// connection.
fn asked(server: &FakeElectrum, method: &str) -> usize {
    let state = server.state.lock().unwrap();
    state.asked.iter().filter(|asked| *asked == method).count()
}

/// Drops the connection and waits for the next one to have asked for
/// what it asks for, and for whatever it reports to be reported.
async fn reconnected(server: &FakeElectrum, events: &mut WatchEvents) {
    let sessions = asked(server, "blockchain.headers.subscribe");
    server.hang_up();
    within("connected again", WAIT, || {
        asked(server, "blockchain.headers.subscribe") > sessions
    })
    .await;
    no_event(events, Duration::from_millis(300)).await;
}

/// A script the server refused has no status to compare with: it is
/// reported once, for a sync to say what it holds, and is not asked of
/// that server again. A reconnection neither asks for it nor reports
/// it: it is left to the regular syncs, and the status counts it out.
/// A new configuration asks for it again.
#[tokio::test]
async fn a_script_the_server_refused_is_left_to_the_syncs() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().refuse.insert(
        "blockchain.scripthash.subscribe",
        "history too long".to_owned(),
    );
    let wallets = vec![wallet("a", &[1], &[], false), wallet("b", &[2], &[], false)];
    let (watch, mut events) =
        LiveWatch::start_with(config(server.backend()), wallets.clone(), Some(timings()));
    // Refused, and answered all the same: the watch is ready.
    let mut seen = vec![next_event(&mut events).await, next_event(&mut events).await];
    seen.sort_by_key(|event| format!("{event:?}"));
    assert_eq!(
        seen,
        vec![
            moved("a", ChangeReason::Started, false, &[1]),
            moved("b", ChangeReason::Started, false, &[2]),
        ]
    );
    let status = watch.status();
    assert_eq!(status.pushed_scripts, 0);
    assert_eq!((status.left_out_wallets, status.left_out_scripts), (2, 2));
    assert!(
        status
            .wallets
            .iter()
            .all(|wallet| wallet.coverage == Coverage::SyncOnly)
    );

    // The server would take them now, and one of them moved: the next
    // connection asks for neither, and reports nothing.
    server.state.lock().unwrap().refuse.clear();
    server
        .state
        .lock()
        .unwrap()
        .statuses
        .insert(scripthash(&script(2)), Some("bb".to_owned()));
    reconnected(&server, &mut events).await;
    assert_eq!(asked(&server, "blockchain.scripthash.subscribe"), 2);
    assert_eq!(watch.status().left_out_scripts, 2);

    watch.reconfigure(config(server.backend()), wallets);
    assert_eq!(
        next_event(&mut events).await,
        moved("b", ChangeReason::Started, false, &[2])
    );
    let status = until(&watch, "subscribed", |s| s.pushed_scripts == 2).await;
    assert_eq!(status.left_out_scripts, 0);
    no_event(&mut events, Duration::from_millis(300)).await;
}

/// A server that takes so many subscriptions on one connection and no
/// more, whether its refusal says so or it only refuses one after the
/// other: what it took is watched, and every script past it is reported
/// once, for a sync of its own. The next connection asks for the head
/// of the list up to what it took, and reports nothing for the rest;
/// the status says how much of the wallet is heard.
#[tokio::test]
async fn electrum_keeps_to_what_a_server_takes() {
    let all: Vec<u8> = (1..=10).collect();
    for words in ["subscription limit reached (3 max per client)", "nope"] {
        let server = FakeElectrum::start().await;
        server.state.lock().unwrap().subscription_limit = Some((3, words));
        let (watch, mut events) = LiveWatch::start_with(
            config(server.backend()),
            vec![wallet("a", &all, &[], false)],
            Some(timings()),
        );
        let mut reported = BTreeSet::new();
        while reported.len() < 7 {
            match next_event(&mut events).await {
                WatchEvent::WalletChanged {
                    wallet_id,
                    reason,
                    scripts,
                    ..
                } => {
                    assert_eq!((wallet_id.as_str(), reason), ("a", ChangeReason::Started));
                    reported.extend(scripts);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let past: BTreeSet<String> = (4..=10).map(script).collect();
        assert_eq!(reported, past, "{words}");
        let status = watch.status();
        assert_eq!(status.pushed_scripts, 3);
        assert_eq!(
            status.wallets,
            [WalletCoverage {
                wallet_id: "a".to_owned(),
                coverage: Coverage::Partial,
                watched_scripts: 3,
                left_out_scripts: 7,
            }]
        );

        let before = asked(&server, "blockchain.scripthash.subscribe");
        reconnected(&server, &mut events).await;
        within("asked for the head", WAIT, || {
            server
                .subscriptions()
                .get(1)
                .is_some_and(|asked| asked.len() == 3)
        })
        .await;
        let head: Vec<String> = (1..=3).map(|n| scripthash(&script(n))).collect();
        assert_eq!(server.subscriptions()[1], head, "{words}");
        assert_eq!(
            asked(&server, "blockchain.scripthash.subscribe"),
            before + 3
        );
        assert_eq!(watch.status().pushed_scripts, 3);
    }
}

/// A server that cuts the watch for what it costs, ElectrumX past its
/// budget, is left alone a long while, and asked for half as many
/// scripts when the watch comes back to it.
#[tokio::test]
async fn a_server_that_cuts_the_watch_for_its_cost_is_asked_less() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().cost_cut = Some(6);
    let refused = Duration::from_secs(1);
    let started = std::time::Instant::now();
    let all: Vec<u8> = (1..=10).collect();
    let (watch, _events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &all, &[], false)],
        Some(Timings {
            refused,
            ..timings()
        }),
    );
    let status = until(&watch, "cut", |s| s.state == WatchState::Reconnecting).await;
    assert_eq!(status.detail.as_deref(), Some("excessive resource usage"));
    within("connected again", WAIT, || {
        server.subscriptions().len() == 2
    })
    .await;
    // Left alone four fifths of the wait at least, not the backoff of a
    // lost connection.
    assert!(started.elapsed() >= refused.mul_f64(0.8));
    within("asked for half", WAIT, || {
        server.subscriptions()[1].len() == 3
    })
    .await;
    let head: Vec<String> = (1..=3).map(|n| scripthash(&script(n))).collect();
    assert_eq!(server.subscriptions()[1], head);
    let status = until(&watch, "connected", |s| s.state == WatchState::Connected).await;
    assert_eq!(
        status.wallets[0],
        WalletCoverage {
            wallet_id: "a".to_owned(),
            coverage: Coverage::Partial,
            watched_scripts: 3,
            left_out_scripts: 7,
        }
    );
}

/// Over Electrum a confirmation comes as the new status of the scripts
/// of the transaction. A wallet waiting for one, whose list the watch
/// does not hear whole, past the caps or what the server takes, may
/// wait on a script nothing pushes: a block syncs it. One heard whole
/// waits for the push.
#[tokio::test]
async fn a_block_syncs_a_waiting_wallet_the_watch_does_not_hear_whole() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().subscription_limit =
        Some((2, "subscription limit reached (2 max per client)"));
    // The list is 1, 5, 2, 3, 4: the server takes 1 and 5.
    let (_watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![
            wallet("a", &[1, 2, 3, 4], &[], true),
            wallet("b", &[5], &[], true),
        ],
        Some(timings()),
    );
    let mut refused = BTreeSet::new();
    while refused.len() < 3 {
        match next_event(&mut events).await {
            WatchEvent::WalletChanged {
                wallet_id, scripts, ..
            } if wallet_id == "a" => refused.extend(scripts),
            other => panic!("unexpected {other:?}"),
        }
    }
    server.push(
        json!({
            "jsonrpc": "2.0", "method": "blockchain.headers.subscribe",
            "params": [{ "height": 101, "hex": "00" }],
        })
        .to_string(),
    );
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 101 }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );
    no_event(&mut events, Duration::from_millis(300)).await;
}

/// A server that says it takes no more subscriptions is at its limit,
/// and the scripts still waiting their turn are not asked for. Nothing
/// watches them from then on, and nothing says what they did while
/// nothing listened: each is reported, as a refused one is, for a sync
/// to catch up on it. Once: the next connection asks for none.
#[tokio::test]
async fn electrum_reports_the_scripts_it_gave_up_on() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().refuse.insert(
        "blockchain.scripthash.subscribe",
        "too many subscriptions".to_owned(),
    );
    let all: Vec<u8> = (1..=40).collect();
    let (_watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &all, &[], false)],
        Some(timings()),
    );
    let mut reported = BTreeSet::new();
    while reported.len() < all.len() {
        match next_event(&mut events).await {
            WatchEvent::WalletChanged {
                wallet_id,
                reason,
                scripts,
                ..
            } => {
                assert_eq!((wallet_id.as_str(), reason), ("a", ChangeReason::Started));
                assert!(!scripts.is_empty(), "named, not the whole wallet");
                reported.extend(scripts);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let expected: BTreeSet<String> = all.iter().map(|n| script(*n)).collect();
    assert_eq!(reported, expected);
    let before = asked(&server, "blockchain.scripthash.subscribe");
    assert!(before < all.len(), "the queue was given up");
    reconnected(&server, &mut events).await;
    assert_eq!(asked(&server, "blockchain.scripthash.subscribe"), before);
}

#[tokio::test]
async fn electrum_unsubscribes_where_the_server_can() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().version = "1.4.2";
    let (watch, _events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false), wallet("b", &[2], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 2).await;
    watch.set_wallets(vec![wallet("a", &[1], &[], false)]);
    let started = std::time::Instant::now();
    while server.state.lock().unwrap().unsubscribed.is_empty() {
        assert!(started.elapsed() < WAIT, "never unsubscribed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.state.lock().unwrap().unsubscribed,
        vec![scripthash(&script(2))]
    );
}

/// A socket that stays open and says nothing is found by the ping, and
/// by the tick of a host whose timers were asleep.
#[tokio::test]
async fn electrum_gives_up_on_a_server_that_stops_answering() {
    let server = FakeElectrum::start().await;
    let (watch, _events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(Timings {
            keepalive: Duration::from_secs(3600),
            ..timings()
        }),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 1).await;
    server.state.lock().unwrap().silent = true;
    // No timer will ping for an hour; the host's tick does.
    watch.tick();
    let status = until(&watch, "reconnecting", |s| {
        s.state == WatchState::Reconnecting
    })
    .await;
    assert_eq!(
        status.detail.as_deref(),
        Some("the server stopped answering")
    );
    // And once the server answers again, the watcher is back.
    server.state.lock().unwrap().silent = false;
    watch.tick();
    until(&watch, "connected again", |s| {
        s.state == WatchState::Connected && s.pushed_scripts == 1
    })
    .await;
}

/// A server of another network is refused before it hears of a script,
/// over Electrum as over Esplora, and left alone a while: it would
/// report changes that never happened on the wallet's network. Once it
/// serves the wallet's network, the watch takes it.
#[tokio::test]
async fn a_server_of_another_network_is_refused_and_left_alone() {
    let electrum = FakeElectrum::start().await;
    electrum.state.lock().unwrap().genesis = Some(bdk_wallet::bitcoin::Network::Testnet4);
    let wallets = vec![wallet("a", &[1], &[], false)];
    let (watch, _events) = LiveWatch::start_with(
        config(electrum.backend()),
        wallets.clone(),
        Some(Timings {
            refused: Duration::from_secs(3600),
            ..timings()
        }),
    );
    let status = until(&watch, "refused", |s| s.state == WatchState::Reconnecting).await;
    assert_eq!(
        status.detail.as_deref(),
        Some(crate::chain::ANOTHER_NETWORK)
    );
    assert!(!electrum.was_asked("blockchain.scripthash.subscribe"));
    // Left alone, whatever the host asks meanwhile.
    watch.tick();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(electrum.subscriptions().len(), 1);
    // A new configuration tries it again at once.
    electrum.state.lock().unwrap().genesis = None;
    watch.reconfigure(config(electrum.backend()), wallets);
    until(&watch, "connected", |s| {
        s.state == WatchState::Connected && s.pushed_scripts == 1
    })
    .await;

    let mempool = FakeMempool::start(false, 0).await;
    mempool.state.lock().unwrap().genesis = Some(bdk_wallet::bitcoin::Network::Testnet4);
    let (watch, _events) = LiveWatch::start_with(
        config(mempool.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(timings()),
    );
    let status = until(&watch, "refused", |s| s.state == WatchState::Reconnecting).await;
    assert_eq!(
        status.detail.as_deref(),
        Some(crate::chain::ANOTHER_NETWORK)
    );
    assert!(mempool.state.lock().unwrap().looked_up.is_empty());
    mempool.state.lock().unwrap().genesis = None;
    until(&watch, "polling", |s| s.state == WatchState::Polling).await;
}

/// An onion backend with no Tor to go through: the watcher says why and
/// keeps trying, and no connection is ever opened around Tor.
#[tokio::test]
async fn an_onion_backend_without_tor_never_connects_in_the_clear() {
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let onion = "gerfautexample000000000000000000000000000000000000000.onion";
    for backend in [
        BackendConfig::CustomElectrum {
            url: format!("tcp://{onion}:50001"),
            own_node: false,
        },
        BackendConfig::CustomEsplora {
            url: format!("http://{onion}/api"),
            own_node: false,
        },
    ] {
        let mut config = config(backend);
        config.tor = TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed.clone()),
        };
        let (watch, mut events) =
            LiveWatch::start_with(config, vec![wallet("a", &[1], &[], false)], Some(timings()));
        let status = until(&watch, "reconnecting", |s| {
            s.state == WatchState::Reconnecting
        })
        .await;
        let detail = status.detail.unwrap();
        assert!(detail.starts_with("tor: "), "{detail}");
        assert_eq!(status.pushed_scripts, 0);
        no_event(&mut events, Duration::from_millis(300)).await;
    }
}

#[tokio::test]
async fn a_mempool_websocket_pushes_what_it_tracks_and_polls_the_rest() {
    let server = FakeMempool::start(true, 2).await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![
            wallet("a", &[1, 2, 3], &[], true),
            wallet("b", &[4], &[], false),
        ],
        Some(timings()),
    );
    // The server names its limit by refusing the list, and the head of
    // every wallet is what it is given then.
    let status = until(&watch, "tracking", |s| s.pushed_scripts == 2).await;
    assert_eq!(status.state, WatchState::Connected);
    assert_eq!(status.transport, Some(WatchTransport::MempoolWebsocket));
    assert_eq!(status.watched_scripts, 4);
    // The status counts the list once it is sent, the server answering
    // only a refusal: what the server read is what it records, a moment
    // later on a loaded machine.
    within("tracked", WAIT, || {
        !server.state.lock().unwrap().tracked.is_empty()
    })
    .await;
    assert_eq!(
        server.state.lock().unwrap().tracked,
        vec![vec![script(1), script(4)]]
    );
    reported(&mut events, &["a", "b"], ChangeReason::Started).await;

    // A pushed transaction.
    server.push(json!({ "multi-scriptpubkey-transactions": {
        script(4): { "mempool": [{ "txid": "00" }], "confirmed": [], "removed": [] }
    } }));
    assert_eq!(
        next_event(&mut events).await,
        moved("b", ChangeReason::Activity, false, &[4])
    );

    // A block: the wallet waiting for a confirmation is worth a sync,
    // the other is not.
    server.push(json!({ "block": { "height": 501, "id": "00" } }));
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 501 }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );

    // The scripts the server does not push are polled, and only those.
    let started = std::time::Instant::now();
    while !server
        .state
        .lock()
        .unwrap()
        .looked_up
        .contains(&FakeMempool::rest_key(&script(3)))
    {
        assert!(started.elapsed() < WAIT, "never polled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server
        .state
        .lock()
        .unwrap()
        .counts
        .insert(FakeMempool::rest_key(&script(3)), 1);
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, false, &[3])
    );
    let looked_up = server.state.lock().unwrap().looked_up.clone();
    assert!(!looked_up.contains(&FakeMempool::rest_key(&script(1))));
    assert!(!looked_up.contains(&FakeMempool::rest_key(&script(4))));

    // The connection drops: this transport cannot say what it missed,
    // so every wallet is reported once, and the list is tracked again.
    for socket in &server.state.lock().unwrap().sockets {
        let _ = socket.send(None);
    }
    let mut reported = vec![next_event(&mut events).await, next_event(&mut events).await];
    reported.sort_by_key(|event| format!("{event:?}"));
    assert_eq!(
        reported,
        vec![
            changed("a", ChangeReason::Reconnected, false),
            changed("b", ChangeReason::Reconnected, false),
        ]
    );
    until(&watch, "tracking again", |s| {
        s.state == WatchState::Connected && s.pushed_scripts == 2
    })
    .await;
}

#[tokio::test]
async fn an_esplora_without_a_websocket_is_polled() {
    let server = FakeMempool::start(false, 0).await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1, 2], &[2], true)],
        Some(timings()),
    );
    let status = until(&watch, "polling", |s| s.state == WatchState::Polling).await;
    assert_eq!(status.transport, Some(WatchTransport::EsploraPolling));
    assert_eq!(status.pushed_scripts, 0);
    reported(&mut events, &["a"], ChangeReason::Started).await;
    no_event(&mut events, Duration::from_millis(300)).await;

    server
        .state
        .lock()
        .unwrap()
        .counts
        .insert(FakeMempool::rest_key(&script(2)), 1);
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, true, &[2])
    );

    server.state.lock().unwrap().tip = 501;
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 501 }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );
}

/// Polling reads a few scripts a round, the rest in turn: a script may
/// be read for the first time well after the watch started, and what
/// arrived there meanwhile, after the catch-up sync read it, must not
/// be taken for where it stands. Its first reading is compared with
/// what the wallet holds for it.
#[tokio::test]
async fn a_first_poll_is_compared_with_what_the_wallet_holds() {
    let server = FakeMempool::start(false, 0).await;
    let mut listed = wallet("a", &[1, 2, 3, 4, 5, 6], &[], false);
    let one_payment = poll::Fingerprint {
        mempool: crate::chain::esplora::Tally {
            txs: 1,
            funded: 1,
            funded_sats: 1_000,
            ..Default::default()
        },
        ..Default::default()
    };
    for (index, script) in listed.scripts.iter_mut().enumerate() {
        script.counts = Some(if index == 4 {
            one_payment
        } else {
            poll::Fingerprint::default()
        });
    }
    {
        let mut state = server.state.lock().unwrap();
        // Held by the wallet already: nothing to say.
        state.counts.insert(FakeMempool::rest_key(&script(5)), 1);
        // Arrived after the catch-up, before the first reading.
        state.counts.insert(FakeMempool::rest_key(&script(6)), 1);
    }
    let (_watch, mut events) =
        LiveWatch::start_with(config(server.backend()), vec![listed], Some(timings()));
    reported(&mut events, &["a"], ChangeReason::Started).await;
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Activity, false, &[6])
    );
    no_event(&mut events, Duration::from_millis(500)).await;
}

/// One impossible height, from a lying server or a slip, does not hide
/// the blocks that follow it: the honest height after it becomes the
/// baseline again, and the next block is a block.
#[tokio::test]
async fn one_impossible_height_does_not_hide_later_blocks() {
    let server = FakeMempool::start(false, 0).await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1, 2], &[2], true)],
        Some(timings()),
    );
    until(&watch, "polling", |s| s.state == WatchState::Polling).await;
    reported(&mut events, &["a"], ChangeReason::Started).await;

    server.state.lock().unwrap().tip = 4_000_000_000;
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock {
            height: 4_000_000_000
        }
    );
    assert_eq!(
        next_event(&mut events).await,
        changed("a", ChangeReason::NewBlock, false)
    );

    server.state.lock().unwrap().tip = 501;
    no_event(&mut events, Duration::from_millis(300)).await;
    server.state.lock().unwrap().tip = 502;
    assert_eq!(
        next_event(&mut events).await,
        WatchEvent::NewBlock { height: 502 }
    );
}

/// Another backend: the old connection is closed, the new one opened,
/// and nothing of the old baseline is compared with the new server.
#[tokio::test]
async fn a_new_configuration_moves_the_watch() {
    let first = FakeElectrum::start().await;
    let second = FakeElectrum::start().await;
    second
        .state
        .lock()
        .unwrap()
        .statuses
        .insert(scripthash(&script(1)), Some("other".to_owned()));
    let (watch, mut events) = LiveWatch::start_with(
        config(first.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(timings()),
    );
    until(&watch, "subscribed", |s| s.pushed_scripts == 1).await;
    no_event(&mut events, Duration::from_millis(300)).await;
    watch.reconfigure(
        config(second.backend()),
        vec![wallet("a", &[1], &[], false)],
    );
    let started = std::time::Instant::now();
    while second.subscriptions().is_empty() {
        assert!(started.elapsed() < WAIT, "never moved");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until(&watch, "subscribed again", |s| s.pushed_scripts == 1).await;
    // Another server, which lists something the wallet does not hold.
    assert_eq!(
        next_event(&mut events).await,
        moved("a", ChangeReason::Started, false, &[1])
    );
    no_event(&mut events, Duration::from_millis(300)).await;

    // Nothing left to watch: the connection is given up.
    watch.set_wallets(Vec::new());
    until(&watch, "off", |s| s.state == WatchState::Off).await;
}

// --- the parts on their own ---------------------------------------------------

#[test]
fn the_automatic_backend_prefers_a_server_that_pushes() {
    let candidates_of = |network| {
        let mut config = config(BackendConfig::default());
        config.network = network;
        candidates(&config)
            .unwrap()
            .iter()
            .map(Endpoint::label)
            .collect::<Vec<_>>()
    };
    // An Electrum server of an operator the rotation already goes
    // through, then the rotation: no host the mode did not name.
    assert_eq!(
        candidates_of(Network::Mainnet),
        vec![
            "blockstream.info",
            "mempool.space",
            "blockstream.info",
            "mempool.emzy.de"
        ]
    );
    assert_eq!(candidates_of(Network::Signet)[0], "mempool.space");
    assert_eq!(candidates_of(Network::Signet).len(), 4);
    assert!(matches!(
        candidates(&config(BackendConfig::default())).unwrap()[0],
        Endpoint::Electrum(_)
    ));

    // A chosen server is the only one, whatever it speaks.
    let chosen = config(BackendConfig::Public {
        server: Some("blockstream.info".to_owned()),
    });
    assert_eq!(
        candidates(&chosen).unwrap(),
        vec![Endpoint::Esplora(
            "https://blockstream.info/signet/api".to_owned()
        )]
    );
}

/// Wallets each below what a watch takes of one, together past what it
/// takes of all: the tail of each is cut, and each is reported whole at
/// the start, since nothing will say what those scripts did. A wallet
/// the cut spared is not.
#[test]
fn wallets_the_whole_list_cut_short_are_caught_up_whole() {
    let mut wallets: Vec<WatchedWallet> = (0..15u32)
        .map(|w| WatchedWallet {
            wallet_id: format!("w{w}"),
            scripts: (0..150u32)
                .map(|n| WatchedScript {
                    script: format!("0014{:040x}", w * 1_000 + n),
                    lookahead: false,
                    status: None,
                    counts: None,
                })
                .collect(),
            has_pending: false,
            pinned: false,
            holds_coins: false,
            unlisted: 0,
        })
        .collect();
    wallets.insert(0, wallet("small", &[1, 2, 3], &[], false));
    let watched = Watched::new(wallets, WatchLimits::DEFAULT);
    assert_eq!(watched.entries.len(), MAX_SCRIPTS);
    let expected: Vec<String> = (0..15).map(|w| format!("w{w}")).collect();
    assert_eq!(watched.capped(None), expected);
}

#[test]
fn a_list_is_cut_to_what_can_be_watched() {
    let long: Vec<u8> = (0..=255).collect();
    let mut wallets = vec![wallet("a", &long, &[], false)];
    wallets[0].scripts.push(WatchedScript {
        script: "not hex".to_owned(),
        lookahead: false,
        status: None,
        counts: None,
    });
    wallets.push(wallet("b", &[1, 1, 250], &[1], false));
    let watched = Watched::new(wallets, WatchLimits::DEFAULT);
    assert_eq!(watched.entries.len(), MAX_SCRIPTS_PER_WALLET + 1);
    // Cut, so a start reports it whole.
    assert_eq!(watched.capped(None), vec!["a".to_owned()]);
    // Shared by two wallets, and revealed in one of them: not lookahead.
    let shared = watched.by_hex(&script(1)).unwrap();
    assert_eq!(shared.owners.len(), 2);
    assert!(!shared.lookahead);
    assert_eq!(
        watched
            .by_scripthash(&scripthash(&script(250)))
            .unwrap()
            .hex,
        script(250)
    );
}

/// A wallet of `count` distinct scripts, numbered from `first`.
fn numbered(id: &str, first: u32, count: u32) -> WatchedWallet {
    WatchedWallet {
        wallet_id: id.to_owned(),
        scripts: (first..first + count)
            .map(|n| WatchedScript {
                script: format!("0014{n:040x}"),
                lookahead: false,
                status: None,
                counts: None,
            })
            .collect(),
        has_pending: false,
        pinned: false,
        holds_coins: false,
        unlisted: 0,
    }
}

/// The same, pinned or holding coins as said.
fn flagged(id: &str, first: u32, count: u32, pinned: bool, holds_coins: bool) -> WatchedWallet {
    WatchedWallet {
        pinned,
        holds_coins,
        ..numbered(id, first, count)
    }
}

/// The wallet of each script of the list, in its order: the first that
/// lists it.
fn first_owners(watched: &Watched) -> Vec<usize> {
    watched
        .entries
        .iter()
        .map(|entry| entry.owners[0])
        .collect()
}

/// The wallets the user pinned come first, rank by rank among
/// themselves and up to what a watch takes of one wallet, whatever the
/// others hold. Pinned past the cap on the whole list, they leave the
/// others nothing.
#[test]
fn pinned_wallets_are_watched_first() {
    let wallets = || {
        vec![
            flagged("funded", 0, 10, false, true),
            flagged("pinned", 100, 10, true, false),
            flagged("also pinned", 200, 10, true, false),
        ]
    };
    let roomy = WatchLimits {
        per_wallet: 20,
        total: 25,
    };
    let watched = Watched::new(wallets(), roomy);
    let owners = first_owners(&watched);
    assert_eq!(owners[..4], [1, 2, 1, 2]);
    assert!(owners[..20].iter().all(|&owner| owner != 0));
    assert_eq!(owners[20..], [0; 5]);
    assert_eq!(watched.capped(None), vec!["funded".to_owned()]);

    let tight = WatchLimits {
        per_wallet: 20,
        total: 15,
    };
    let watched = Watched::new(wallets(), tight);
    let owners = first_owners(&watched);
    assert_eq!(owners.len(), 15);
    assert!(!owners.contains(&0));
    assert_eq!(watched.capped(None).len(), 3);
}

/// Among the wallets nobody pinned, at each rank one that holds coins
/// goes first, and the order of the list holds otherwise: when the cap
/// cuts a rank short, an empty wallet loses its script before a funded
/// one does.
#[test]
fn wallets_holding_coins_go_first_at_each_rank() {
    let wallets = vec![
        flagged("empty", 0, 10, false, false),
        flagged("funded", 100, 10, false, true),
        flagged("also empty", 200, 10, false, false),
    ];
    let limits = WatchLimits {
        per_wallet: 20,
        total: 25,
    };
    let watched = Watched::new(wallets, limits);
    let owners = first_owners(&watched);
    assert_eq!(owners[..6], [1, 0, 2, 1, 0, 2]);
    let kept = |owner| owners.iter().filter(|&&listed| listed == owner).count();
    assert_eq!((kept(0), kept(1), kept(2)), (8, 9, 8));
}

/// A script two wallets list is one subscription heard for both, the
/// pinned one and the other, even once the list is full.
#[test]
fn a_shared_script_is_heard_for_every_wallet_that_lists_it() {
    let shared = numbered("", 3, 1).scripts.remove(0);
    let own = numbered("", 600, 1).scripts.remove(0);
    let other = WatchedWallet {
        scripts: vec![shared.clone(), own.clone()],
        ..flagged("other", 0, 0, false, true)
    };
    let limits = WatchLimits {
        per_wallet: 20,
        total: 10,
    };
    let watched = Watched::new(vec![other, flagged("pinned", 0, 10, true, false)], limits);
    assert_eq!(watched.entries.len(), 10);
    assert_eq!(watched.by_hex(&shared.script).unwrap().owners, [1, 0]);
    assert!(watched.by_hex(&own.script).is_none());
    assert_eq!(watched.capped(None), vec!["other".to_owned()]);
}

/// What the watch hears of each wallet: all of it, its head, or
/// nothing, with what it leaves out counted, the scripts a list stopped
/// short of included.
#[test]
fn each_wallet_is_live_in_part_or_left_to_the_syncs() {
    fn coverage(wallets: &[WalletCoverage]) -> Vec<(&str, Coverage, u32, u32)> {
        wallets
            .iter()
            .map(|wallet| {
                (
                    wallet.wallet_id.as_str(),
                    wallet.coverage,
                    wallet.watched_scripts,
                    wallet.left_out_scripts,
                )
            })
            .collect::<Vec<_>>()
    }
    let cut_short = WatchedWallet {
        unlisted: 7,
        ..numbered("cut short", 100, 10)
    };
    let limits = WatchLimits {
        per_wallet: 20,
        total: 30,
    };
    let watched = Watched::new(
        vec![
            numbered("small", 0, 5),
            numbered("large", 200, 30),
            cut_short,
        ],
        limits,
    );
    assert_eq!(
        coverage(&watched.coverage(None)),
        [
            ("small", Coverage::Live, 5, 0),
            ("large", Coverage::Partial, 15, 15),
            ("cut short", Coverage::Partial, 10, 7),
        ]
    );
    assert_eq!(
        watched.capped(None),
        vec!["large".to_owned(), "cut short".to_owned()]
    );

    // Pinned wallets that take it all leave nothing to the others.
    let limits = WatchLimits {
        per_wallet: 20,
        total: 2,
    };
    let watched = Watched::new(
        vec![
            numbered("other", 10, 1),
            flagged("pinned", 0, 2, true, false),
        ],
        limits,
    );
    assert_eq!(
        coverage(&watched.coverage(None)),
        [
            ("other", Coverage::SyncOnly, 0, 1),
            ("pinned", Coverage::Live, 2, 0),
        ]
    );
}

/// What a server refused is counted out of each wallet: the scripts it
/// turned down one by one, and those past the most it takes, the head
/// of the list being what it is asked for.
#[test]
fn what_a_server_refused_is_counted_out() {
    let watched = Watched::new(
        vec![
            wallet("a", &[1, 2, 3], &[], false),
            wallet("b", &[4, 5], &[], false),
        ],
        WatchLimits::DEFAULT,
    );
    // The list is 1, 4, 2, 5, 3; 4 was refused, and two are taken.
    let refusals = Refusals {
        limit: Some(2),
        scripts: HashSet::from([scripthash(&script(4))]),
    };
    let heard: Vec<&str> = watched
        .heard(Some(&refusals))
        .map(|entry| entry.hex.as_str())
        .collect();
    assert_eq!(heard, [script(1), script(2)]);
    let coverage: Vec<(Coverage, u32, u32)> = watched
        .coverage(Some(&refusals))
        .iter()
        .map(|wallet| {
            (
                wallet.coverage,
                wallet.watched_scripts,
                wallet.left_out_scripts,
            )
        })
        .collect();
    assert_eq!(
        coverage,
        [(Coverage::Partial, 2, 1), (Coverage::SyncOnly, 0, 2)]
    );
    assert_eq!(
        watched.capped(Some(&refusals)),
        ["a".to_owned(), "b".to_owned()]
    );
    assert!(watched.capped(None).is_empty());
    assert_eq!(watched.heard(None).count(), 5);
}

/// The status a screen reads says how much of each wallet the watch
/// hears and what it leaves to the syncs, and says it again when the
/// backend becomes the user's own node, which takes the whole list.
#[tokio::test]
async fn the_status_says_how_much_of_each_wallet_is_live() {
    let server = FakeElectrum::start().await;
    let wallets = || vec![numbered("large", 0, 250), numbered("small", 1_000, 3)];
    let (watch, _events) =
        LiveWatch::start_with(config(server.backend()), wallets(), Some(timings()));
    let status = until(&watch, "subscribed", |s| s.pushed_scripts == 203).await;
    assert_eq!((status.left_out_wallets, status.left_out_scripts), (1, 50));
    assert_eq!(
        status.wallets,
        vec![
            WalletCoverage {
                wallet_id: "large".to_owned(),
                coverage: Coverage::Partial,
                watched_scripts: 200,
                left_out_scripts: 50,
            },
            WalletCoverage {
                wallet_id: "small".to_owned(),
                coverage: Coverage::Live,
                watched_scripts: 3,
                left_out_scripts: 0,
            },
        ]
    );

    let BackendConfig::CustomElectrum { url, .. } = server.backend() else {
        unreachable!("the fake server is an Electrum one");
    };
    let own = BackendConfig::CustomElectrum {
        url,
        own_node: true,
    };
    watch.reconfigure(config(own), wallets());
    let status = until(&watch, "subscribed whole", |s| s.pushed_scripts == 253).await;
    assert_eq!((status.left_out_wallets, status.left_out_scripts), (0, 0));
    assert!(
        status
            .wallets
            .iter()
            .all(|wallet| wallet.coverage == Coverage::Live)
    );
}

/// A long list is told in steps as the server answers, the last count
/// always: not one status per script.
#[tokio::test]
async fn subscriptions_are_told_in_steps() {
    let server = FakeElectrum::start().await;
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![numbered("large", 0, 150), numbered("small", 1_000, 50)],
        Some(timings()),
    );
    let mut told = Vec::new();
    while told.last() != Some(&200) {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(WatchEvent::Status(status))) if status.pushed_scripts > 0 => {
                told.push(status.pushed_scripts);
            }
            Ok(Some(_)) => {}
            other => panic!("never subscribed whole: {other:?}, told {told:?}"),
        }
    }
    told.dedup();
    assert_eq!(told, [100, 200]);
    assert_eq!(watch.status().pushed_scripts, 200);
}

/// A status, or a wallet list, written before coverage and pinning
/// existed still reads, with nothing left out and nothing pinned.
#[test]
fn a_status_and_a_list_from_before_coverage_still_read() {
    let status: WatchStatus = serde_json::from_str(
        r#"{"state":"connected","transport":"electrum","server":"node.example.org","detail":null,"watched_scripts":3,"pushed_scripts":3}"#,
    )
    .unwrap();
    assert_eq!((status.left_out_scripts, status.left_out_wallets), (0, 0));
    assert!(status.wallets.is_empty());
    let wallet: WatchedWallet =
        serde_json::from_str(r#"{"wallet_id":"w","scripts":[],"has_pending":false}"#).unwrap();
    assert!(!wallet.pinned && !wallet.holds_coins);
    assert_eq!(wallet.unlisted, 0);
    let json = serde_json::to_string(&WalletCoverage {
        wallet_id: "w".to_owned(),
        coverage: Coverage::SyncOnly,
        watched_scripts: 0,
        left_out_scripts: 4,
    })
    .unwrap();
    assert_eq!(
        json,
        r#"{"wallet_id":"w","coverage":"sync_only","watched_scripts":0,"left_out_scripts":4}"#
    );
}

/// On the user's own node a watch takes ten times as many scripts in
/// all, and a wallet may take all of them; anywhere else, what it took
/// before. The two wallets that share the whole of it share it evenly.
#[test]
fn the_users_own_node_lifts_what_a_watch_takes() {
    let own = |own_node| BackendConfig::CustomElectrum {
        url: "ssl://node.example.org:50002".to_owned(),
        own_node,
    };
    assert_eq!(
        WatchLimits::of(&BackendConfig::default()),
        WatchLimits::DEFAULT
    );
    assert_eq!(WatchLimits::of(&own(false)), WatchLimits::DEFAULT);
    assert_eq!(WatchLimits::of(&own(true)), WatchLimits::OWN_NODE);
    assert_eq!(WatchLimits::OWN_NODE.total, 20_000);

    let large = || vec![numbered("large", 0, 5_000)];
    let anywhere = Watched::new(large(), WatchLimits::DEFAULT);
    assert_eq!(anywhere.entries.len(), MAX_SCRIPTS_PER_WALLET);
    assert_eq!(anywhere.capped(None), vec!["large".to_owned()]);
    let at_home = Watched::new(large(), WatchLimits::OWN_NODE);
    assert_eq!(at_home.entries.len(), 5_000);
    assert!(at_home.capped(None).is_empty());

    let two = vec![numbered("a", 0, 15_000), numbered("b", 100_000, 15_000)];
    let shared = Watched::new(two, WatchLimits::OWN_NODE);
    assert_eq!(shared.entries.len(), OWN_NODE_MAX_SCRIPTS);
    let owned_by = |owner: usize| {
        shared
            .entries
            .iter()
            .filter(|entry| entry.owners == [owner])
            .count()
    };
    assert_eq!((owned_by(0), owned_by(1)), (10_000, 10_000));
    assert_eq!(shared.capped(None), vec!["a".to_owned(), "b".to_owned()]);
}

/// A block marked in the burst of a reconnection that cannot say what
/// it missed: the wallet goes out whole, for a reconnection, not for a
/// block, which only asks for what waits for one.
#[test]
fn a_block_in_a_catch_up_burst_leaves_it_a_catch_up() {
    let timings = timings();
    let start = Instant::now();
    for whole in [ChangeReason::Started, ChangeReason::Reconnected] {
        let mut debounce = Debouncer::default();
        debounce.mark("a", whole, false, None, start);
        debounce.mark("a", ChangeReason::NewBlock, false, None, start);
        let due = debounce.take_due(start + timings.burst, &timings);
        assert_eq!(due[0].1.reason, whole);
        assert_eq!(due[0].1.scripts, None);
    }
}

#[tokio::test]
async fn a_burst_is_one_report_and_a_flood_is_held_to_the_gap() {
    let timings = timings();
    let mut debounce = Debouncer::default();
    let start = Instant::now();
    debounce.mark("a", ChangeReason::NewBlock, false, Some("x"), start);
    debounce.mark(
        "a",
        ChangeReason::Activity,
        true,
        Some("y"),
        start + Duration::from_millis(10),
    );
    assert_eq!(
        debounce.pending["a"].scripts,
        Some(["x".to_owned(), "y".to_owned()].into())
    );
    debounce.mark(
        "a",
        ChangeReason::Reconnected,
        false,
        None,
        start + Duration::from_millis(20),
    );
    assert!(
        debounce
            .take_due(start + Duration::from_millis(30), &timings)
            .is_empty()
    );
    let due = debounce.take_due(start + Duration::from_millis(61), &timings);
    assert_eq!(due.len(), 1);
    // The reconnection, which asks for the whole wallet, is what the
    // report says: a change heard with it must not turn it into the
    // sync of a change.
    assert_eq!(due[0].1.reason, ChangeReason::Reconnected);
    assert!(due[0].1.rescan);
    // A mark of the whole wallet swallows the scripts named before.
    assert_eq!(due[0].1.scripts, None);

    // Marked without a pause, a wallet still goes out by the end of the
    // burst window.
    for step in 0..20 {
        debounce.mark(
            "b",
            ChangeReason::Activity,
            false,
            None,
            start + Duration::from_millis(step * 20),
        );
    }
    assert_eq!(
        debounce.next_deadline(&timings),
        Some(start + timings.burst)
    );

    // Reported a moment ago: the next report waits for the gap.
    debounce.reported.insert("c".to_owned(), start);
    debounce.mark(
        "c",
        ChangeReason::Activity,
        false,
        None,
        start + Duration::from_millis(1),
    );
    assert_eq!(
        debounce.due_at("c", &debounce.pending["c"], &timings),
        start + timings.gap
    );
}

#[test]
fn a_backoff_doubles_up_to_its_cap() {
    let timings = timings();
    let mut backoff = Backoff {
        next: Duration::ZERO,
    };
    let mut ceiling = timings.backoff_first;
    for _ in 0..8 {
        let delay = backoff.delay(&timings);
        assert!(
            delay >= ceiling / 2 && delay <= ceiling,
            "{delay:?} {ceiling:?}"
        );
        ceiling = (ceiling * 2).min(timings.backoff_cap);
    }
    assert_eq!(ceiling, timings.backoff_cap);
    backoff.reset();
    assert!(backoff.delay(&timings) <= timings.backoff_first);
}

/// A keepalive ping comes at the latest when it is due, and at random
/// before: never on the dot, never past what a server waits for.
#[test]
fn a_keepalive_comes_at_random_within_its_wait() {
    let timings = Timings {
        keepalive: Duration::from_secs(240),
        ..timings()
    };
    let waits: Vec<Duration> = (0..200).map(|_| timings.keepalive_wait()).collect();
    assert!(
        waits
            .iter()
            .all(|wait| { *wait >= Duration::from_secs(168) && *wait <= Duration::from_secs(240) })
    );
    let first = waits[0];
    assert!(waits.iter().any(|wait| *wait != first), "drawn, not fixed");
}

/// A server that limits the rate of requests is polled half as often
/// each time it does, ten minutes apart at most, never sooner than the
/// wait it named, and as usual half an hour after it last did.
#[test]
fn a_server_that_limits_the_rate_is_polled_less_often() {
    let every = Duration::from_secs(60);
    let around = |wait: Duration, pace: Duration| {
        assert!(
            wait >= pace.mul_f64(0.85) && wait <= pace.mul_f64(1.15),
            "{wait:?} {pace:?}"
        );
    };
    let now = Instant::now();
    let mut pace = poll::Pace::default();
    around(pace.wait(every, now), every);
    pace.limited(Duration::from_secs(5), now);
    around(pace.wait(every, now), every * 2);
    pace.limited(Duration::from_secs(5), now);
    around(pace.wait(every, now), every * 4);
    for _ in 0..20 {
        pace.limited(Duration::from_secs(5), now);
    }
    around(pace.wait(every, now), Duration::from_secs(600));
    // A wait the server named longer than that is waited out.
    pace.limited(Duration::from_secs(3_600), now);
    assert!(pace.wait(every, now) >= Duration::from_secs(3_600));
    // Half an hour after the last limit, the usual pace, the wait the
    // server named still kept to.
    let later = now + Duration::from_secs(30 * 60);
    assert!(pace.wait(every, later) >= Duration::from_secs(30 * 60));
    let past = now + Duration::from_secs(3_600);
    around(pace.wait(every, past), every);
}

// --- the manager ---------------------------------------------------------------

fn payment(confirmed: bool) -> Value {
    esplora_payment(0x11, 0x22, 50_000, confirmed)
}

async fn next_live(events: &mut crate::live::LiveEvents) -> crate::live::LiveEvent {
    loop {
        match tokio::time::timeout(WAIT, events.next()).await {
            Ok(Some(crate::live::LiveEvent::Status(_))) => {}
            Ok(Some(event)) => return event,
            Ok(None) => panic!("the live watch stopped"),
            Err(_) => panic!("no live event within {WAIT:?}"),
        }
    }
}

/// The whole path, against a fake Esplora: the watch sees the script
/// move, the manager syncs the wallet, and the payment is announced
/// when it enters the mempool and again when it confirms, once each,
/// whoever else syncs or asks, and across a restart.
#[tokio::test]
async fn the_manager_announces_a_payment_twice_and_no_more() {
    use crate::live::{LiveEvent, LiveTx};
    use crate::store::TxStage;

    let server = FakeMempool::start(false, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let key = crate::store::VaultKey::Raw([7; 32]);
    let manager = crate::WalletManager::open(dir.path(), key).unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_backend(Network::Signet, server.backend())
        .await
        .unwrap();
    let parsed = crate::input::parse_input(ADDRESS).unwrap();
    let wallet = manager
        .add_wallet("Watched", &parsed, Network::Signet)
        .await
        .unwrap();
    assert_eq!(
        manager.watch_list(Network::Signet).await,
        vec![WatchedWallet {
            wallet_id: wallet.id.clone(),
            scripts: vec![WatchedScript {
                script: ADDRESS_SCRIPT.to_owned(),
                lookahead: false,
                // Never synced: a status no server gives, so that the
                // watch syncs it once it starts.
                status: Some(String::new()),
                counts: None,
            }],
            has_pending: false,
            pinned: false,
            holds_coins: false,
            unlisted: 0,
        }]
    );
    manager.sync_wallet(&wallet.id).await.unwrap();

    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    let rest_key = FakeMempool::rest_key(ADDRESS_SCRIPT);
    let started = std::time::Instant::now();
    while !server.state.lock().unwrap().looked_up.contains(&rest_key) {
        assert!(started.elapsed() < WAIT, "never polled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The lookup is part of a round; the state follows the round.
    while manager.live_status().await.state != WatchState::Polling {
        assert!(started.elapsed() < WAIT, "never polling");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The watch catches up once it polls: a sync that finds nothing.
    match next_live(&mut events).await {
        LiveEvent::WalletSynced { report } => assert!(report.new_txs.is_empty()),
        other => panic!("expected the catch-up, got {other:?}"),
    }

    // The payment enters the mempool.
    {
        let mut state = server.state.lock().unwrap();
        state.address_txs = vec![payment(false)];
        state.counts.insert(rest_key.clone(), 1);
    }
    let announced = |stage| {
        LiveEvent::Transaction(LiveTx {
            wallet_id: wallet.id.clone(),
            txid: "11".repeat(32),
            net_sats: 50_000,
            stage,
            replaces: None,
        })
    };
    assert_eq!(next_live(&mut events).await, announced(TxStage::Mempool));
    match next_live(&mut events).await {
        LiveEvent::WalletSynced { report } => assert_eq!(report.new_txs.len(), 1),
        other => panic!("expected the sync, got {other:?}"),
    }

    // A block takes it: the wallet waits for one, so the new tip is
    // worth a sync, and that sync finds the confirmation.
    {
        let mut state = server.state.lock().unwrap();
        state.address_txs = vec![payment(true)];
        state.tip = 501;
    }
    loop {
        match next_live(&mut events).await {
            LiveEvent::NewBlock { height } => assert_eq!(height, 501),
            LiveEvent::WalletSynced { .. } => {}
            event => {
                assert_eq!(event, announced(TxStage::Confirmed));
                break;
            }
        }
    }

    // Anyone else reading the same news is told it was said already,
    // in this process and after a restart.
    let said = crate::wallet::snapshot::SyncReport {
        wallet_id: wallet.id.clone(),
        new_tx_count: 1,
        new_txs: vec![crate::wallet::snapshot::NewTx {
            txid: "11".repeat(32),
            net_sats: 50_000,
            confirmed: false,
        }],
        confirmed_txs: vec![crate::wallet::snapshot::NewTx {
            txid: "11".repeat(32),
            net_sats: 50_000,
            confirmed: true,
        }],
        ..manager.sync_wallet(&wallet.id).await.unwrap()
    };
    assert!(manager.claim_announcements(&said).await.unwrap().is_empty());
    manager.live_stop().await;
    assert!(
        tokio::time::timeout(WAIT, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "a stopped watch closes its events"
    );
    assert_eq!(manager.live_status().await, WatchStatus::default());
    drop(manager);
    let reopened =
        crate::WalletManager::open(dir.path(), crate::store::VaultKey::Raw([7; 32])).unwrap();
    assert!(
        reopened
            .claim_announcements(&said)
            .await
            .unwrap()
            .is_empty()
    );
    // Something never said is handed out, once, to whoever claims it
    // after the sync that found it, whether or not that is the caller
    // that ran the sync.
    let mut second = payment(false);
    second["txid"] = json!("44".repeat(32));
    second["vin"][0]["txid"] = json!("55".repeat(32));
    server.state.lock().unwrap().address_txs = vec![second, payment(true)];
    let found = reopened.sync_wallet(&wallet.id).await.unwrap();
    assert_eq!(found.new_txs.len(), 1);
    let nothing_listed = crate::wallet::snapshot::SyncReport {
        new_tx_count: 0,
        new_txs: Vec::new(),
        confirmed_txs: Vec::new(),
        ..found
    };
    let claimed = reopened.claim_announcements(&nothing_listed).await.unwrap();
    assert_eq!(
        claimed,
        vec![LiveTx {
            wallet_id: wallet.id.clone(),
            txid: "44".repeat(32),
            net_sats: 50_000,
            stage: TxStage::Mempool,
            replaces: None,
        }]
    );
    assert!(
        reopened
            .claim_announcements(&nothing_listed)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A descriptor wallet is watched from the address it shows next, past
/// the ones it has revealed, on both keychains.
#[tokio::test]
async fn a_descriptor_wallet_is_watched_past_what_it_revealed() {
    const EXTERNAL: &str = "wpkh(tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)";
    let dir = tempfile::tempdir().unwrap();
    let key = crate::store::VaultKey::Raw([7; 32]);
    let manager = crate::WalletManager::open(dir.path(), key).unwrap();
    let parsed = crate::input::parse_input(EXTERNAL).unwrap();
    let wallet = manager
        .add_wallet("Cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let next = manager.receive_addresses(&wallet.id, 0).await.unwrap()[0]
        .address
        .clone();
    let next_script = next
        .parse::<bdk_wallet::bitcoin::Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey()
        .to_hex_string();
    let list = manager.watch_list(Network::Signet).await;
    assert_eq!(list.len(), 1);
    assert!(!list[0].has_pending);
    let scripts = &list[0].scripts;
    assert_eq!(
        scripts[0].script, next_script,
        "the address shown comes first"
    );
    assert!(!scripts[0].lookahead);
    let gap = manager.settings().await.gap_limit as usize;
    let ahead = scripts.iter().filter(|script| script.lookahead).count();
    assert!(
        ahead >= gap,
        "{ahead} scripts past the revealed ones, gap {gap}"
    );
    let unique: std::collections::HashSet<&String> =
        scripts.iter().map(|script| &script.script).collect();
    assert_eq!(unique.len(), scripts.len());
    // Another network has nothing to watch.
    assert!(manager.watch_list(Network::Mainnet).await.is_empty());
}

// --- stopping -------------------------------------------------------------------

/// How long a stop may take, whatever the server does.
const PROMPT: Duration = Duration::from_secs(2);
/// How long its effects may take to show through other tasks, on a
/// machine busy with the rest of the suite.
const SETTLE: Duration = Duration::from_secs(5);

async fn within(what: &str, limit: Duration, holds: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !holds() {
        assert!(started.elapsed() < limit, "never {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A server that stops in the middle of an answer holds nothing up:
/// the watch stops at once, its events end, its connection is closed.
#[tokio::test]
async fn a_watch_stops_at_once_while_the_server_stalls() {
    let server = FakeElectrum::start().await;
    server.state.lock().unwrap().stall = Some("blockchain.scripthash.subscribe");
    let (watch, mut events) = LiveWatch::start_with(
        config(server.backend()),
        vec![wallet("a", &[1], &[], false)],
        Some(Timings {
            keepalive: Duration::from_secs(3600),
            ..timings()
        }),
    );
    within("asked to subscribe", WAIT, || {
        server.was_asked("blockchain.scripthash.subscribe")
    })
    .await;
    let started = std::time::Instant::now();
    watch.stop();
    assert_eq!(watch.status(), WatchStatus::default());
    assert!(
        tokio::time::timeout(SETTLE, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "the events of a stopped watch end"
    );
    within("closed the connection", SETTLE, || server.closed() == 1).await;
    assert!(started.elapsed() < SETTLE);
}

/// The live watch stops at once while one of its syncs waits on a
/// server stalled mid-answer: the sync is abandoned with its
/// connection, the events end, and the wallet can be synced again.
#[tokio::test]
async fn live_stop_abandons_a_sync_the_server_stalls() {
    let server = FakeElectrum::start().await;
    let dir = tempfile::tempdir().unwrap();
    let manager =
        crate::WalletManager::open(dir.path(), crate::store::VaultKey::Raw([7; 32])).unwrap();
    manager.set_active_network(Network::Signet).await.unwrap();
    manager
        .set_backend(Network::Signet, server.backend())
        .await
        .unwrap();
    let parsed = crate::input::parse_input(ADDRESS).unwrap();
    let wallet = manager
        .add_wallet("Watched", &parsed, Network::Signet)
        .await
        .unwrap();
    // The sync the watch runs to catch up is the one that stalls.
    server.state.lock().unwrap().stall = Some("blockchain.scripthash.get_history");
    let mut events = manager.live_start_with(Some(timings())).await.unwrap();
    within("asked for the history", WAIT, || {
        server.was_asked("blockchain.scripthash.get_history")
    })
    .await;

    let started = std::time::Instant::now();
    manager.live_stop().await;
    assert!(started.elapsed() < PROMPT, "{:?}", started.elapsed());
    assert_eq!(manager.live_status().await, WatchStatus::default());
    assert!(
        tokio::time::timeout(SETTLE, async { while events.next().await.is_some() {} })
            .await
            .is_ok(),
        "the events of a stopped watch end"
    );
    // The watch's connection and the sync's.
    within("closed both connections", SETTLE, || server.closed() == 2).await;
    server.state.lock().unwrap().stall = None;
    manager.sync_wallet(&wallet.id).await.unwrap();
}

// --- live -----------------------------------------------------------------------

const SIGNET_ELECTRUM: &str = "ssl://signet-electrumx.wakiyamap.dev:50002";
const SIGNET_ESPLORA: &str = "https://mempool.emzy.de/signet/api";

/// Scripts that are about to move: the outputs of transactions sitting
/// in the signet mempool, which the next block confirms. A script with
/// a long history is left out, as servers refuse to hash or count it.
async fn scripts_waiting_for_a_block() -> Vec<String> {
    let client = crate::chain::esplora::client(SIGNET_ESPLORA, None).unwrap();
    let mut scripts = Vec::new();
    let recent: Vec<serde_json::Value> = client.get_json("/mempool/recent").await.unwrap();
    for recent in recent {
        let Some(txid) = recent["txid"].as_str().and_then(|txid| txid.parse().ok()) else {
            continue;
        };
        let Ok(Some(tx)) = client.tx(&txid).await else {
            continue;
        };
        for output in tx.output {
            let Ok(stats) = client.scripthash_stats(&output.script_pubkey).await else {
                continue;
            };
            let hex = output.script_pubkey.to_hex_string();
            if stats.chain_stats.tx_count < 500 && !scripts.contains(&hex) {
                scripts.push(hex);
            }
        }
        if scripts.len() >= 8 {
            break;
        }
    }
    scripts.truncate(8);
    scripts
}

/// Live. The three transports watch the same scripts on signet, each
/// against a public server, until the next block confirms what was
/// pending on them. Every event is printed with the time it arrived:
/// run with `--nocapture` to compare the transports. Takes as long as
/// signet takes to find a block, ten minutes on average.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "talks to public signet servers until the next block"]
async fn live_the_three_transports_see_signet_move() {
    let scripts = scripts_waiting_for_a_block().await;
    assert!(
        !scripts.is_empty(),
        "the signet mempool is empty, try later"
    );
    println!("watching {scripts:?}");
    let wallets = vec![WatchedWallet {
        wallet_id: "pending".to_owned(),
        scripts: scripts
            .into_iter()
            .map(|script| WatchedScript {
                script,
                lookahead: false,
                status: None,
                counts: None,
            })
            .collect(),
        has_pending: true,
        pinned: false,
        holds_coins: false,
        unlisted: 0,
    }];
    // The Electrum server may sign its own certificate: accepted here
    // the way the settings screen does it, by its fingerprint.
    let mut electrum = config(BackendConfig::CustomElectrum {
        url: SIGNET_ELECTRUM.to_owned(),
        own_node: false,
    });
    let inspected = crate::chain::electrum::inspect(&crate::chain::electrum::Target::new(
        SIGNET_ELECTRUM,
        None,
    ))
    .await
    .expect("the signet Electrum server answers");
    if let crate::chain::electrum::Inspection::Tls(crate::chain::tls::Verdict::Unknown {
        fingerprint,
        ..
    }) = inspected
    {
        electrum.electrum_certs.insert(
            crate::chain::electrum::certificate_key(SIGNET_ELECTRUM),
            fingerprint,
        );
    }
    let websocket = config(BackendConfig::Public {
        server: Some("mempool.emzy.de".to_owned()),
    });
    let polling = config(BackendConfig::Public {
        server: Some("blockstream.info".to_owned()),
    });

    let started = std::time::Instant::now();
    let (seen, mut all_seen) = mpsc::unbounded_channel();
    let mut watches = Vec::new();
    for (name, config, transport, state) in [
        (
            "electrum",
            electrum,
            WatchTransport::Electrum,
            WatchState::Connected,
        ),
        (
            "websocket",
            websocket,
            WatchTransport::MempoolWebsocket,
            WatchState::Connected,
        ),
        (
            "polling",
            polling,
            WatchTransport::EsploraPolling,
            WatchState::Polling,
        ),
    ] {
        let (watch, mut events) = LiveWatch::start(config, wallets.clone());
        watches.push(watch);
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                let at = started.elapsed().as_secs_f32();
                println!("{at:>8.2} s  {name:<9}  {event:?}");
                match event {
                    WatchEvent::Status(status) if status.state == state => {
                        assert_eq!(status.transport, Some(transport), "{name}");
                    }
                    WatchEvent::WalletChanged { .. } => {
                        let _ = seen.send(name);
                    }
                    _ => {}
                }
            }
        });
    }
    // Polling is printed and not waited for: blockstream.info caps an
    // address at 700 requests an hour, which a machine running these
    // tests may already have spent.
    let mut reported = std::collections::BTreeSet::new();
    while !(reported.contains("electrum") && reported.contains("websocket")) {
        let name = tokio::time::timeout(Duration::from_secs(45 * 60), all_seen.recv())
            .await
            .unwrap_or_else(|_| panic!("only {reported:?} saw the scripts move"))
            .unwrap();
        reported.insert(name);
    }
    // A little longer, for the stragglers of the same block.
    tokio::time::sleep(Duration::from_secs(90)).await;
}
