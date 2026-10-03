//! The premium account, against a server on loopback.

use super::*;
use crate::chain::BackendConfig;
use crate::chain::tor::{TorMode, TorSettings};
use crate::input::parse_input;
use crate::manager::tests::support::{
    MULTIPATH, TOKEN, closed_port, connected, key, manager, store_premium, stored_premium,
};
use crate::network::Network;

/// An app reads the premium state, the wallet goes meanwhile, and
/// the copy comes back to dismiss a banner: its yes for the wallet
/// is stale, and the removal queued for the server stays.
#[tokio::test]
async fn a_stale_copy_cannot_take_back_a_removal() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    store_premium(
        &manager,
        PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        },
    )
    .await;
    let mut premium = manager.premium_state().await;
    premium.consent(&meta.id, 100);
    manager.set_premium_state(premium).await.unwrap();

    let mut stale = manager.premium_state().await;
    assert!(stale.is_consented(&meta.id));
    manager.remove_wallet(&meta.id).await.unwrap();
    stale.acknowledged_offline_until = Some(5);
    manager.set_premium_state(stale).await.unwrap();
    let premium = manager.premium_state().await;
    assert!(!premium.is_consented(&meta.id));
    assert_eq!(premium.pending_unwatch, vec![meta.id]);
    assert_eq!(premium.acknowledged_offline_until, Some(5));
}

/// A premium server that gives these answers in order, one
/// connection each, and hands the request line of each to the
/// test. After the last answer it is gone: the next connection is
/// refused.
async fn answering(answers: Vec<String>) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, seen) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        for answer in answers {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0u8; 4096];
            let n = stream.read(&mut bytes).await.unwrap();
            let first_line = String::from_utf8_lossy(&bytes[..n])
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            sender.send(first_line).unwrap();
            stream.write_all(answer.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{address}"), seen)
}

/// An HTTP answer with a JSON body, connection closed after it.
fn answer(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn the_flush_tells_the_server_and_keeps_what_it_could_not() {
    // Two answers, then the server is gone: 200 for the first
    // wallet, 404 for the second (already unknown, which is what we
    // wanted), and a refused connection for the third.
    let (base_url, mut seen) = answering(vec![
        answer("200 OK", "{}"),
        answer("404 Not Found", r#"{"error":"no such wallet"}"#),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    for id in ["w1", "w2", "w3"] {
        premium.queue_unwatch(id);
    }
    store_premium(&manager, connected(premium)).await;

    let outcome = manager.premium_flush_unwatch(&base_url).await;
    assert!(
        matches!(
            outcome,
            Err(CoreError::Premium(PremiumError::Unreachable(_)))
        ),
        "the third wallet met no server: {outcome:?}"
    );
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
    assert_eq!(
        manager.premium_state().await.pending_unwatch,
        vec!["w3".to_owned()],
        "told and already-gone leave the queue, the unreached one stays"
    );

    // Nothing waiting: no connection is even attempted.
    store_premium(
        &manager,
        connected(PremiumState {
            key: Some("abcdefghijkmnpqr".to_owned()),
            ..PremiumState::default()
        }),
    )
    .await;
    assert_eq!(manager.premium_flush_unwatch(&base_url).await.unwrap(), 0);
}

/// A refusal that is not "nothing under that id" says nothing
/// about what the server holds, and is about that one id: the
/// wallet it refused stays queued, the ones behind it are still
/// told, and the refusal comes back once the round is over. One id
/// the server never accepts used to hold every wallet behind it
/// for good.
#[tokio::test]
async fn the_flush_goes_on_past_a_refused_wallet_and_keeps_it() {
    let (base_url, mut seen) = answering(vec![
        answer("422 Unprocessable Entity", r#"{"error":"not a wallet id"}"#),
        answer("200 OK", "{}"),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    for id in ["w1", "w2"] {
        premium.queue_unwatch(id);
    }
    store_premium(&manager, connected(premium)).await;

    let outcome = manager.premium_flush_unwatch(&base_url).await;
    assert!(
        matches!(
            &outcome,
            Err(CoreError::Premium(PremiumError::Rejected(words))) if words == "not a wallet id"
        ),
        "{outcome:?}"
    );
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
    assert_eq!(
        manager.premium_state().await.pending_unwatch,
        vec!["w1".to_owned()],
        "the refused wallet waits for the next round, the one behind it was told"
    );

    // The next round starts again from the refused one, and meets
    // no server.
    let left = manager.premium_flush_unwatch(&base_url).await;
    assert!(
        matches!(left, Err(CoreError::Premium(PremiumError::Unreachable(_)))),
        "{left:?}"
    );
    assert_eq!(
        manager.premium_state().await.pending_unwatch,
        vec!["w1".to_owned()]
    );
}

/// The first error of the round is the one returned, and a server
/// that cannot be reached still ends the round where it stands:
/// the wallets after it are not tried, and wait with the refused
/// one.
#[tokio::test]
async fn the_flush_returns_its_first_error_and_stops_at_a_lost_server() {
    let (base_url, mut seen) = answering(vec![
        answer("200 OK", "{}"),
        answer("400 Bad Request", r#"{"error":"not a wallet id"}"#),
        answer("200 OK", "{}"),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    for id in ["w1", "w2", "w3", "w4"] {
        premium.queue_unwatch(id);
    }
    store_premium(&manager, connected(premium)).await;

    let outcome = manager.premium_flush_unwatch(&base_url).await;
    assert!(
        matches!(
            &outcome,
            Err(CoreError::Premium(PremiumError::Rejected(words))) if words == "not a wallet id"
        ),
        "{outcome:?}"
    );
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w3 HTTP/1.1");
    assert_eq!(
        manager.premium_state().await.pending_unwatch,
        vec!["w2".to_owned(), "w4".to_owned()],
        "the refused wallet and the one the lost server never heard of wait"
    );
}

/// A rate limit is about this client, not about the wallet it was
/// answered for: the round stops there, the requests behind it are
/// not sent to be turned away in their turn, and the queue waits
/// with the time the server asked for.
#[tokio::test]
async fn the_flush_stops_at_a_rate_limit_and_keeps_the_queue() {
    let body = r#"{"error":"too many requests"}"#;
    let (base_url, mut seen) = answering(vec![
        answer("200 OK", "{}"),
        format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        ),
        answer("200 OK", "{}"),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    for id in ["w1", "w2", "w3"] {
        premium.queue_unwatch(id);
    }
    store_premium(&manager, connected(premium)).await;

    let outcome = manager.premium_flush_unwatch(&base_url).await;
    assert!(
        matches!(
            &outcome,
            Err(CoreError::Premium(PremiumError::RateLimited {
                retry_after: Some(17)
            }))
        ),
        "{outcome:?}"
    );
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w1 HTTP/1.1");
    assert_eq!(seen.recv().await.unwrap(), "DELETE /v1/wallets/w2 HTTP/1.1");
    assert_eq!(
        manager.premium_state().await.pending_unwatch,
        vec!["w2".to_owned(), "w3".to_owned()],
        "the limited wallet and the one never sent wait"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), seen.recv())
            .await
            .is_err(),
        "nothing is sent behind a rate limit"
    );
}

/// Switching a wallet off withdraws the yes once the server has
/// nothing under its id: told, or already unknown. Removing the
/// wallet after that queues nothing, since the server has nothing
/// to hear. A refusal for lack of paid time, words about a key the
/// request never carried, a rate limit, or a server that cannot be
/// reached, leaves the yes in place, and a removal still queues its
/// message.
#[tokio::test]
async fn switching_a_wallet_off_withdraws_the_yes_once_the_server_has_heard() {
    let (base_url, mut seen) = answering(vec![
        answer("200 OK", "{}"),
        answer("404 Not Found", r#"{"error":"no such wallet"}"#),
        answer("401 Unauthorized", r#"{"error":"unknown key"}"#),
        answer("403 Forbidden", r#"{"error":"no paid time"}"#),
        answer("429 Too Many Requests", r#"{"error":"too many requests"}"#),
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    let parsed = parse_input(MULTIPATH).unwrap();
    let meta = manager
        .add_wallet("Signet cold", &parsed, Network::Signet)
        .await
        .unwrap();
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    for id in [meta.id.as_str(), "w2", "w3", "w4", "w5", "w6"] {
        premium.consent(id, 100);
    }
    store_premium(&manager, connected(premium)).await;

    // Told: the yes goes, and the removal that follows has nothing
    // to queue.
    manager
        .premium_unwatch_wallet(&base_url, &meta.id)
        .await
        .unwrap();
    assert_eq!(
        seen.recv().await.unwrap(),
        format!("DELETE /v1/wallets/{} HTTP/1.1", meta.id)
    );
    assert!(!manager.premium_state().await.is_consented(&meta.id));
    manager.remove_wallet(&meta.id).await.unwrap();
    let premium = manager.premium_state().await;
    assert!(premium.pending_unwatch.is_empty(), "{premium:?}");
    assert!(!premium.is_consented(&meta.id));

    // Already unknown to the server: as unwatched as told.
    manager
        .premium_unwatch_wallet(&base_url, "w2")
        .await
        .unwrap();
    assert!(!manager.premium_state().await.is_consented("w2"));
    // "unknown key" where a token went is not about a key, and
    // proves nothing about the wallet: the yes stands.
    let unknown = manager
        .premium_unwatch_wallet(&base_url, "w3")
        .await
        .unwrap_err();
    assert!(
        matches!(&unknown, CoreError::Premium(PremiumError::Rejected(words)) if words == "unknown key"),
        "{unknown}"
    );
    assert!(manager.premium_state().await.is_consented("w3"));

    // Refused for lack of paid time: still watched, the yes stands.
    let refused = manager
        .premium_unwatch_wallet(&base_url, "w4")
        .await
        .unwrap_err();
    assert!(
        matches!(refused, CoreError::Premium(PremiumError::NoPaidTime)),
        "{refused}"
    );
    assert!(manager.premium_state().await.is_consented("w4"));

    // Rate limited: the server still watches the wallet, and the
    // yes stands until it is told and heard.
    let limited = manager
        .premium_unwatch_wallet(&base_url, "w6")
        .await
        .unwrap_err();
    assert!(
        matches!(&limited, CoreError::Premium(PremiumError::Rejected(words)) if words == "too many requests"),
        "{limited}"
    );
    assert!(manager.premium_state().await.is_consented("w6"));

    // The server is gone: nothing changes here either.
    let unreached = manager
        .premium_unwatch_wallet(&base_url, "w5")
        .await
        .unwrap_err();
    assert!(
        matches!(unreached, CoreError::Premium(PremiumError::Unreachable(_))),
        "{unreached}"
    );
    let premium = manager.premium_state().await;
    assert!(premium.is_consented("w4") && premium.is_consented("w5"));
    assert!(premium.is_consented("w3") && premium.is_consented("w6"));
    assert_eq!(premium.watched.len(), 4);

    // The yes withdrawn, the question is asked again: a new yes
    // starts a fresh date.
    let mut premium = manager.premium_state().await;
    premium.consent("w2", 200);
    assert_eq!(premium.consented_at("w2"), Some(200));
}

#[tokio::test]
async fn the_premium_state_lives_in_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    assert_eq!(manager.premium_state().await, PremiumState::default());
    let mut premium = PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        ..PremiumState::default()
    };
    premium.consent("w1", 100);
    store_premium(&manager, premium.clone()).await;

    drop(manager);
    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(manager.premium_state().await, premium);
    // The client built from it carries the stored key, and a
    // clearnet server needs no Tor.
    let client = manager
        .premium_client("https://api.example.org/")
        .await
        .unwrap();
    assert_eq!(client.key(), Some("abcdefghijkmnpqr"));
    assert_eq!(client.base_url(), "https://api.example.org");
}

/// The premium client goes through Tor as soon as a backend of any
/// network is an onion, not only the one on screen: switching to a
/// network whose backend is in the clear must not show this
/// device's address to the premium server. Without Tor to be had,
/// no client is built at all.
#[tokio::test]
async fn the_premium_client_takes_tor_when_any_backend_is_an_onion() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_backend(
            Network::Signet,
            BackendConfig::CustomEsplora {
                url: "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/api"
                    .to_owned(),
                own_node: false,
            },
        )
        .await
        .unwrap();
    manager
        .set_tor_settings(TorSettings {
            mode: TorMode::System,
            socks_proxy: Some(closed_port().await),
        })
        .await
        .unwrap();
    manager.set_active_network(Network::Mainnet).await.unwrap();

    let refused = manager
        .premium_client_with_key("https://api.gerfaut-wallet.com", None)
        .await;
    assert!(matches!(refused, Err(CoreError::Tor(_))));
}

/// A premium server on loopback that answers every request the
/// same way and hands each request head to the test.
async fn premium_answering(
    status: u16,
    body: &'static str,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let _ = sender.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let response = format!(
                "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{address}"), receiver)
}

/// The account the vault keeps: a key, the device it connected, a
/// certificate, a consent, a banner dismissed.
fn premium_account() -> PremiumState {
    let mut premium = connected(PremiumState {
        key: Some("abcdefghijkmnpqr".to_owned()),
        certificate: Some("not.checked.here".to_owned()),
        acknowledged_offline_until: Some(1_800_000_000),
        pending_unwatch: Vec::new(),
        ..PremiumState::default()
    });
    premium.consent("w1", 1_790_000_000);
    premium
}

/// Deleting the account is one request with the stored token, and
/// the vault forgets the account only once the server said it did.
#[tokio::test]
async fn premium_delete_account_forgets_the_account_once_the_server_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;

    // Not connected: nothing to delete, and nothing is asked.
    let (base_url, mut seen) = premium_answering(200, r#"{"deleted":true}"#).await;
    let error = manager.premium_delete_account(&base_url).await.unwrap_err();
    assert!(
        matches!(error, CoreError::Premium(PremiumError::NoDevice)),
        "{error}"
    );
    assert!(seen.try_recv().is_err());

    store_premium(&manager, premium_account()).await;
    manager.premium_delete_account(&base_url).await.unwrap();
    let request = seen.recv().await.unwrap();
    assert!(
        request.starts_with("DELETE /v1/account HTTP/1.1"),
        "{request}"
    );
    assert!(request.contains(&format!("Bearer {TOKEN}")), "{request}");
    assert!(!request.contains("abcdefghijkmnpqr"), "{request}");
    assert_eq!(stored_premium(&manager).await, PremiumState::default());
    // Forgotten on disk as well.
    drop(manager);
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(stored_premium(&reopened).await, PremiumState::default());

    // The server did not confirm: the account stays.
    let refusing = tempfile::tempdir().unwrap();
    let kept = WalletManager::open(refusing.path(), key()).unwrap();
    store_premium(&kept, premium_account()).await;
    let (base_url, _) = premium_answering(503, r#"{"error":"node unreachable"}"#).await;
    assert!(kept.premium_delete_account(&base_url).await.is_err());
    assert_eq!(stored_premium(&kept).await, premium_account());
}

/// A disowned token is not a deleted account: the account may be
/// there still, and only this device lost it. The token goes, the
/// key and the rest stay. Any other refusal keeps everything.
#[tokio::test]
async fn premium_delete_account_keeps_the_account_the_server_did_not_delete() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    store_premium(&manager, premium_account()).await;
    let (base_url, mut seen) = premium_answering(
        401,
        r#"{"error":"this device was disconnected from the Premium account","code":"device_disconnected"}"#,
    )
    .await;
    let error = manager.premium_delete_account(&base_url).await.unwrap_err();
    assert!(
        matches!(error, CoreError::Premium(PremiumError::DeviceDisconnected)),
        "{error}"
    );
    let request = seen.recv().await.unwrap();
    assert!(
        request.starts_with("DELETE /v1/account HTTP/1.1"),
        "{request}"
    );
    let disowned = PremiumState {
        device: None,
        disconnected: true,
        ..premium_account()
    };
    assert_eq!(stored_premium(&manager).await, disowned);
    // On disk as well.
    drop(manager);
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(stored_premium(&reopened).await, disowned);

    // Words about a key the request never carried: kept whole.
    let refusing = tempfile::tempdir().unwrap();
    let kept = WalletManager::open(refusing.path(), key()).unwrap();
    store_premium(&kept, premium_account()).await;
    let (base_url, _) = premium_answering(401, r#"{"error":"unknown key"}"#).await;
    assert!(kept.premium_delete_account(&base_url).await.is_err());
    assert_eq!(stored_premium(&kept).await, premium_account());

    // Any other answer, a server without the route among them:
    // not gone, and kept.
    let (base_url, _) = premium_answering(404, r#"{"error":"no such route"}"#).await;
    let error = kept.premium_delete_account(&base_url).await.unwrap_err();
    assert!(
        matches!(error, CoreError::Premium(PremiumError::NotFound)),
        "{error}"
    );
    assert_eq!(stored_premium(&kept).await, premium_account());

    // A 401 without the server's envelope is a portal asking for a
    // login, not the server disowning the key: kept as well.
    let (base_url, _) = premium_answering(401, "<html>Sign in to continue</html>").await;
    let error = kept.premium_delete_account(&base_url).await.unwrap_err();
    assert!(
        matches!(&error, CoreError::Premium(PremiumError::UnexpectedResponse(words)) if words == "HTTP 401"),
        "{error}"
    );
    assert_eq!(stored_premium(&kept).await, premium_account());
}

#[tokio::test]
async fn premium_confirm_channel_goes_through_the_stored_token() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    store_premium(&manager, premium_account()).await;
    let (base_url, mut seen) = premium_answering(
        200,
        r#"{"id":"4f8f5252-b152-4fae-b142-5e6f70819203","kind":"email","target":"a…@example.org","linked":true,"link_code":null,"link_url":null,"linked_name":null,"enabled":true,"created_at":1789000004}"#,
    )
    .await;
    let channel = manager
        .premium_confirm_channel(&base_url, "4f8f5252-b152-4fae-b142-5e6f70819203", "482913")
        .await
        .unwrap();
    assert!(channel.linked);
    let request = seen.recv().await.unwrap();
    assert!(
        request
            .starts_with("POST /v1/channels/4f8f5252-b152-4fae-b142-5e6f70819203/confirm HTTP/1.1"),
        "{request}"
    );
    assert!(request.contains(&format!("Bearer {TOKEN}")), "{request}");
    assert!(!request.contains("abcdefghijkmnpqr"), "{request}");
    assert!(request.ends_with(r#"{"code":"482913"}"#), "{request}");
}
