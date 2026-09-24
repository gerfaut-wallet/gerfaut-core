//! Premium devices, against a scripted server on loopback.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::error::{CoreError, PremiumError};
use crate::manager::WalletManager;
use crate::manager::tests::{TOKEN, connected, store_premium, stored_premium};
use crate::premium::licence::fixtures;
use crate::premium::{DeviceAccess, DevicePlatform, PremiumState};
use crate::store::VaultKey;

const KEY: &str = "abcdefghijkmnpqr";
const OTHER_KEY: &str = "wxyz23456789abcd";
/// The token of the connection a test makes.
const NEW_TOKEN: &str = "gdt1_Zm9yIGEgbmV3IGNvbm5lY3Rpb24gb2YgdGhpcyBkZXZpY2U";
const THIS_DEVICE: &str = "0f3b7c2e-1a2b-4c3d-8e9f-a0b1c2d3e4f5";
const NEW_DEVICE: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const DISOWNED: &str = r#"{"error":"this device was disconnected from the Premium account","code":"device_disconnected"}"#;

/// A manager whose premium clients trust the test server's key.
fn premium_manager(dir: &std::path::Path) -> WalletManager {
    let manager = WalletManager::open(dir, VaultKey::Raw([9u8; 32])).unwrap();
    *manager.premium_public_key.lock().unwrap() = Some(fixtures::SERVER_PUBLIC_KEY_HEX.to_owned());
    manager
}

/// A premium server that gives these answers in order, one connection
/// each, and hands each request, head and body, to the test. After the
/// last answer it is gone: the next connection is refused.
async fn scripted(answers: Vec<String>) -> (String, UnboundedReceiver<String>) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, seen) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        for answer in answers {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&bytes);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let _ = sender.send(String::from_utf8_lossy(&bytes).into_owned());
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{address}"), seen)
}

fn answer(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn device_json(id: &str, access: &str, this_device: bool) -> String {
    let (pending_until, approved_at) = match access {
        "pending" => ("1790864000", "null"),
        _ => ("null", "1790000000"),
    };
    format!(
        r#"{{"id":"{id}","platform":"linux","connected_at":1790000000,"access":"{access}","pending_until":{pending_until},"approved_at":{approved_at},"this_device":{this_device}}}"#
    )
}

fn connected_answer(access: &str) -> String {
    answer(
        "201 Created",
        &format!(
            r#"{{"device":{},"token":"{NEW_TOKEN}"}}"#,
            device_json(NEW_DEVICE, access, true)
        ),
    )
}

fn licence_answer(certificate: &str) -> String {
    answer(
        "200 OK",
        &format!(
            r#"{{"certificate":"{certificate}","public_key":"{}","paid_until":1792592000}}"#,
            fixtures::SERVER_PUBLIC_KEY_HEX
        ),
    )
}

fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (found, value) = line.split_once(':')?;
        found.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn bearer(request: &str) -> Option<&str> {
    header(request, "authorization")?.strip_prefix("Bearer ")
}

fn body_of(request: &str) -> &str {
    request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

/// A vault from before devices: a key, its certificate, a consent.
fn old_vault() -> PremiumState {
    let mut premium = PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        ..PremiumState::default()
    };
    premium.consent("w1", 100);
    premium
}

fn premium_error(error: CoreError) -> PremiumError {
    match error {
        CoreError::Premium(error) => error,
        other => panic!("not a premium error: {other}"),
    }
}

/// The account's first device: the key goes once, with the platform,
/// and the key and the token it earned are stored together, then the
/// certificate, asked for with the token.
#[tokio::test]
async fn the_first_device_connects_and_keeps_key_and_token_together() {
    let (base_url, mut seen) = scripted(vec![
        connected_answer("full"),
        licence_answer(fixtures::VALID_CERTIFICATE),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());

    let device = manager
        .premium_connect(&base_url, "ABCD-EFGH ijkm-npqr", DevicePlatform::Linux)
        .await
        .unwrap();
    assert_eq!(device.id, NEW_DEVICE);
    assert_eq!(device.access, DeviceAccess::Full);
    assert!(device.this_device);

    let connect = seen.recv().await.unwrap();
    assert!(
        connect.starts_with("POST /v1/devices HTTP/1.1"),
        "{connect}"
    );
    assert_eq!(bearer(&connect), Some(KEY));
    assert_eq!(body_of(&connect), r#"{"platform":"linux"}"#);
    let licence = seen.recv().await.unwrap();
    assert!(licence.starts_with("GET /v1/licence HTTP/1.1"), "{licence}");
    assert_eq!(bearer(&licence), Some(NEW_TOKEN));

    let stored = stored_premium(&manager).await;
    assert_eq!(stored.key.as_deref(), Some(KEY));
    let credential = stored.device.as_ref().unwrap();
    assert_eq!(credential.id, NEW_DEVICE);
    assert_eq!(credential.token(), NEW_TOKEN);
    assert_eq!(credential.connected_at, 1_790_000_000);
    assert_eq!(
        stored.certificate.as_deref(),
        Some(fixtures::VALID_CERTIFICATE)
    );
    assert!(!stored.disconnected);
    // Kept on disk, all of it.
    drop(manager);
    let reopened = premium_manager(dir.path());
    assert_eq!(stored_premium(&reopened).await, stored);
}

/// A later device connects and waits: the certificate still comes, a
/// waiting device may have it, and the routes it may not use answer
/// with the date its wait ends, the token kept.
#[tokio::test]
async fn a_later_device_connects_and_waits() {
    let pending = r#"{"error":"this device is waiting for approval: approve it on another of your devices, or wait until it gets full access","code":"device_pending","pending_until":1790864000}"#;
    let (base_url, mut seen) = scripted(vec![
        connected_answer("pending"),
        licence_answer(fixtures::VALID_CERTIFICATE),
        answer("403 Forbidden", pending),
        answer(
            "200 OK",
            &format!(
                r#"{{"device":{}}}"#,
                device_json(NEW_DEVICE, "pending", true)
            ),
        ),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());

    let device = manager
        .premium_connect(&base_url, KEY, DevicePlatform::Android)
        .await
        .unwrap();
    assert!(device.is_pending());
    assert_eq!(device.pending_until, Some(1_790_864_000));
    assert!(
        seen.recv()
            .await
            .unwrap()
            .contains(r#"{"platform":"android"}"#)
    );
    seen.recv().await.unwrap();
    assert_eq!(
        stored_premium(&manager).await.certificate.as_deref(),
        Some(fixtures::VALID_CERTIFICATE)
    );

    let refused = manager.premium_devices(&base_url).await.unwrap_err();
    assert_eq!(
        premium_error(refused),
        PremiumError::DevicePending {
            until: 1_790_864_000
        }
    );
    assert!(
        seen.recv()
            .await
            .unwrap()
            .starts_with("GET /v1/devices HTTP/1.1")
    );
    assert!(
        stored_premium(&manager).await.has_device(),
        "a wait is not a refusal"
    );

    let me = manager.premium_device(&base_url).await.unwrap();
    assert!(me.is_pending() && me.this_device);
    assert!(
        seen.recv()
            .await
            .unwrap()
            .starts_with("GET /v1/devices/me HTTP/1.1")
    );
}

/// Nothing is stored unless the server connected the device: a key of
/// the wrong shape never leaves, and a refusal or a silence leaves the
/// vault as it was.
#[tokio::test]
async fn a_connection_the_server_did_not_make_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let (base_url, mut seen) = scripted(vec![
        answer("401 Unauthorized", r#"{"error":"unknown key"}"#),
        answer(
            "409 Conflict",
            r#"{"error":"this key already has 10 devices; disconnect one from a device with full access","code":"too_many_devices"}"#,
        ),
    ])
    .await;

    let malformed = manager
        .premium_connect(&base_url, "abcd-efgh", DevicePlatform::Linux)
        .await
        .unwrap_err();
    assert!(
        matches!(malformed, CoreError::InvalidInput { .. }),
        "{malformed}"
    );

    let unknown = manager
        .premium_connect(&base_url, KEY, DevicePlatform::Linux)
        .await
        .unwrap_err();
    assert_eq!(premium_error(unknown), PremiumError::UnknownKey);
    assert!(seen.recv().await.unwrap().starts_with("POST /v1/devices"));

    let full = manager
        .premium_connect(&base_url, KEY, DevicePlatform::Linux)
        .await
        .unwrap_err();
    assert!(matches!(
        premium_error(full),
        PremiumError::TooManyDevices(words) if words.starts_with("this key already has 10 devices")
    ));

    // The server is gone.
    let unreached = manager
        .premium_connect(&base_url, KEY, DevicePlatform::Linux)
        .await
        .unwrap_err();
    assert!(matches!(
        premium_error(unreached),
        PremiumError::Unreachable(_)
    ));
    assert_eq!(stored_premium(&manager).await, PremiumState::default());
}

/// A vault from before devices holds a key and no token: it connects
/// once, keeping what it had, and after that there is nothing to do.
#[tokio::test]
async fn an_old_vault_connects_once() {
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());

    // No key: nothing to connect, nothing asked.
    assert_eq!(
        manager
            .premium_ensure_device("http://127.0.0.1:9", DevicePlatform::Macos)
            .await
            .unwrap(),
        None
    );

    store_premium(&manager, old_vault()).await;
    let (base_url, mut seen) = scripted(vec![
        connected_answer("full"),
        licence_answer(fixtures::ACCOUNT_CERTIFICATE),
    ])
    .await;
    let device = manager
        .premium_ensure_device(&base_url, DevicePlatform::Macos)
        .await
        .unwrap()
        .expect("connected");
    assert_eq!(device.id, NEW_DEVICE);
    let connect = seen.recv().await.unwrap();
    assert_eq!(bearer(&connect), Some(KEY));
    assert_eq!(body_of(&connect), r#"{"platform":"macos"}"#);
    seen.recv().await.unwrap();

    let stored = stored_premium(&manager).await;
    assert_eq!(stored.device.as_ref().unwrap().token(), NEW_TOKEN);
    assert_eq!(
        stored.certificate.as_deref(),
        Some(fixtures::ACCOUNT_CERTIFICATE)
    );
    assert!(stored.is_consented("w1"), "what the old vault held stays");

    // Connected: nothing more to do, and the server, gone now, is not
    // asked.
    assert_eq!(
        manager
            .premium_ensure_device(&base_url, DevicePlatform::Macos)
            .await
            .unwrap(),
        None
    );
}

/// A device the server disowned is not connected again behind the
/// user's back, and neither is one whose stored key the server no
/// longer knows: asked once, that answer is kept.
#[tokio::test]
async fn a_disowned_device_waits_for_the_user_to_connect_again() {
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    store_premium(
        &manager,
        PremiumState {
            disconnected: true,
            ..old_vault()
        },
    )
    .await;
    // A port nothing listens on: asking would be an error.
    assert_eq!(
        manager
            .premium_ensure_device("http://127.0.0.1:9", DevicePlatform::Linux)
            .await
            .unwrap(),
        None
    );

    // The mark is the core's: an app handing the state back cannot lift it.
    manager.set_premium_state(old_vault()).await.unwrap();
    assert!(stored_premium(&manager).await.disconnected);
    store_premium(&manager, old_vault()).await;
    let (base_url, mut seen) = scripted(vec![answer(
        "401 Unauthorized",
        r#"{"error":"unknown key"}"#,
    )])
    .await;
    let unknown = manager
        .premium_ensure_device(&base_url, DevicePlatform::Linux)
        .await
        .unwrap_err();
    assert_eq!(premium_error(unknown), PremiumError::UnknownKey);
    seen.recv().await.unwrap();
    let stored = stored_premium(&manager).await;
    assert!(stored.disconnected && !stored.has_device());
    assert_eq!(stored.key.as_deref(), Some(KEY), "the key stays");
    assert_eq!(
        manager
            .premium_ensure_device(&base_url, DevicePlatform::Linux)
            .await
            .unwrap(),
        None
    );

    // Connecting again is the user's call, and it clears the mark.
    let (base_url, _) = scripted(vec![
        connected_answer("pending"),
        licence_answer(fixtures::VALID_CERTIFICATE),
    ])
    .await;
    manager
        .premium_connect(&base_url, KEY, DevicePlatform::Linux)
        .await
        .unwrap();
    let stored = stored_premium(&manager).await;
    assert!(!stored.disconnected && stored.has_device());
}

/// After the connection, every call carries the token, and none the
/// key: the manager's own functions and a client an app took from it
/// alike.
#[tokio::test]
async fn the_token_goes_on_every_later_call_and_the_key_on_none() {
    let list = format!(
        r#"{{"devices":[{},{}]}}"#,
        device_json(NEW_DEVICE, "full", true),
        device_json("d2", "pending", false)
    );
    let (base_url, mut seen) = scripted(vec![
        connected_answer("full"),
        licence_answer(fixtures::VALID_CERTIFICATE),
        answer("200 OK", &list),
        answer(
            "200 OK",
            &format!(r#"{{"device":{}}}"#, device_json("d2", "full", false)),
        ),
        answer(
            "200 OK",
            r#"{"active":true,"paid_until":1792592000,"wallets":0,"channels":0,"network":"bitcoin"}"#,
        ),
        licence_answer(fixtures::ACCOUNT_CERTIFICATE),
        answer("200 OK", "{}"),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    manager
        .premium_connect(&base_url, KEY, DevicePlatform::Windows)
        .await
        .unwrap();

    let devices = manager.premium_devices(&base_url).await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices[1].is_pending());
    let approved = manager
        .premium_approve_device(&base_url, "d2")
        .await
        .unwrap();
    assert_eq!(approved.access, DeviceAccess::Full);
    let client = manager.premium_client(&base_url).await.unwrap();
    assert!(client.has_device_token());
    client.account().await.unwrap();
    let licence = manager.premium_refresh_licence(&base_url).await.unwrap();
    assert_eq!(licence.certificate, fixtures::ACCOUNT_CERTIFICATE);
    manager
        .premium_unwatch_wallet(&base_url, "w1")
        .await
        .unwrap();

    let first = seen.recv().await.unwrap();
    assert_eq!(bearer(&first), Some(KEY), "{first}");
    let mut routes = Vec::new();
    for _ in 0..6 {
        let request = seen.recv().await.unwrap();
        assert_eq!(bearer(&request), Some(NEW_TOKEN), "{request}");
        assert!(!request.contains(KEY), "{request}");
        routes.push(request.lines().next().unwrap().to_owned());
    }
    assert_eq!(
        routes,
        [
            "GET /v1/licence HTTP/1.1",
            "GET /v1/devices HTTP/1.1",
            "POST /v1/devices/d2/approve HTTP/1.1",
            "GET /v1/account HTTP/1.1",
            "GET /v1/licence HTTP/1.1",
            "DELETE /v1/wallets/w1 HTTP/1.1",
        ]
    );
    assert_eq!(
        stored_premium(&manager).await.certificate.as_deref(),
        Some(fixtures::ACCOUNT_CERTIFICATE)
    );
}

/// Whatever call hears that the token is disowned, the manager's or a
/// client an app took from it, the token goes and the key stays; and
/// a disowned token is not taken for a newer one stored since.
#[tokio::test]
async fn a_disowned_token_is_dropped_whoever_asked() {
    let (base_url, _) = scripted(vec![
        answer("401 Unauthorized", DISOWNED),
        answer("401 Unauthorized", DISOWNED),
        answer("401 Unauthorized", DISOWNED),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        key_saved: true,
        ..PremiumState::default()
    });
    let disowned = PremiumState {
        device: None,
        disconnected: true,
        ..account.clone()
    };

    store_premium(&manager, account.clone()).await;
    let refused = manager.premium_devices(&base_url).await.unwrap_err();
    assert_eq!(premium_error(refused), PremiumError::DeviceDisconnected);
    assert_eq!(stored_premium(&manager).await, disowned);
    // What follows needs no network to know it is not connected.
    assert_eq!(
        premium_error(manager.premium_device(&base_url).await.unwrap_err()),
        PremiumError::NoDevice
    );

    store_premium(&manager, account.clone()).await;
    let client = manager.premium_client(&base_url).await.unwrap();
    let refused = client.wallets().await.unwrap_err();
    assert_eq!(premium_error(refused), PremiumError::DeviceDisconnected);
    assert_eq!(stored_premium(&manager).await, disowned);

    // A client built before a new connection, told afterwards that its
    // token is disowned: the new one stays.
    store_premium(&manager, account.clone()).await;
    let stale = manager.premium_client(&base_url).await.unwrap();
    let mut newer = account.clone();
    newer.device = Some(crate::premium::DeviceCredential::new(
        NEW_DEVICE.to_owned(),
        NEW_TOKEN.to_owned(),
        1_790_000_500,
    ));
    store_premium(&manager, newer.clone()).await;
    assert!(stale.channels().await.is_err());
    assert_eq!(stored_premium(&manager).await, newer);
}

/// Changing the key stores the new one at once, not saved yet, and the
/// certificate that goes with it; this device keeps its token.
#[tokio::test]
async fn changing_the_key_stores_it_and_its_certificate() {
    let (base_url, mut seen) = scripted(vec![
        answer("200 OK", r#"{"key":"WXYZ-2345-6789-ABCD"}"#),
        licence_answer(fixtures::ACCOUNT_CERTIFICATE),
        answer("200 OK", r#"{"key":"abcd-efgh-ijkm-npqr"}"#),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        key_saved: true,
        announced_devices: vec!["d2".to_owned()],
        ..PremiumState::default()
    });
    store_premium(&manager, account.clone()).await;

    let shown = manager.premium_change_key(&base_url).await.unwrap();
    assert_eq!(shown, "wxyz-2345-6789-abcd");
    let change = seen.recv().await.unwrap();
    assert!(
        change.starts_with("POST /v1/account/key HTTP/1.1"),
        "{change}"
    );
    assert_eq!(bearer(&change), Some(TOKEN));
    assert_eq!(bearer(&seen.recv().await.unwrap()), Some(TOKEN));
    let stored = stored_premium(&manager).await;
    assert_eq!(
        stored,
        PremiumState {
            key: Some(OTHER_KEY.to_owned()),
            certificate: Some(fixtures::ACCOUNT_CERTIFICATE.to_owned()),
            key_saved: false,
            announced_devices: Vec::new(),
            ..account.clone()
        }
    );

    // The certificate cannot be had this time: the key is stored and
    // shown all the same, and the last certificate stays.
    let shown = manager.premium_change_key(&base_url).await.unwrap();
    assert_eq!(shown, "abcd-efgh-ijkm-npqr");
    let stored = stored_premium(&manager).await;
    assert_eq!(stored.key.as_deref(), Some(KEY));
    assert_eq!(
        stored.certificate.as_deref(),
        Some(fixtures::ACCOUNT_CERTIFICATE)
    );
    assert_eq!(stored.device.as_ref().unwrap().token(), TOKEN);
}

/// Logging out tells the server when it can, and clears the account
/// whether it could or not; the consents stay.
#[tokio::test]
async fn logging_out_clears_the_account_even_when_the_server_is_away() {
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let mut account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        key_saved: true,
        checklist_hidden: true,
        announced_devices: vec!["d2".to_owned()],
        ..PremiumState::default()
    });
    account.consent("w1", 100);
    let mut left = PremiumState::default();
    left.consent("w1", 100);

    let (base_url, mut seen) = scripted(vec![answer(
        "200 OK",
        &format!(r#"{{"id":"{THIS_DEVICE}","deleted":true}}"#),
    )])
    .await;
    store_premium(&manager, account.clone()).await;
    manager.premium_log_out(&base_url).await.unwrap();
    let request = seen.recv().await.unwrap();
    assert!(
        request.starts_with("DELETE /v1/devices/me HTTP/1.1"),
        "{request}"
    );
    assert_eq!(bearer(&request), Some(TOKEN));
    assert_eq!(stored_premium(&manager).await, left);

    // The server is gone now: the account is cleared all the same.
    store_premium(&manager, account.clone()).await;
    manager.premium_log_out(&base_url).await.unwrap();
    assert_eq!(stored_premium(&manager).await, left);
    // And a server that refuses changes nothing to that either.
    let (base_url, _) = scripted(vec![answer("401 Unauthorized", DISOWNED)]).await;
    store_premium(&manager, account).await;
    manager.premium_log_out(&base_url).await.unwrap();
    assert_eq!(stored_premium(&manager).await, left);
    drop(manager);
    let reopened = premium_manager(dir.path());
    assert_eq!(stored_premium(&reopened).await, left);
}

/// Removing another device leaves this one connected; removing this
/// one drops its token once the server confirmed, and the key stays.
#[tokio::test]
async fn removing_this_device_drops_its_token() {
    let deleted = |id: &str| answer("200 OK", &format!(r#"{{"id":"{id}","deleted":true}}"#));
    let (base_url, mut seen) = scripted(vec![
        deleted("d2"),
        answer("404 Not Found", r#"{"error":"no such device"}"#),
        deleted(THIS_DEVICE),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        announced_devices: vec!["d2".to_owned()],
        ..PremiumState::default()
    });
    store_premium(&manager, account.clone()).await;

    manager
        .premium_remove_device(&base_url, "d2")
        .await
        .unwrap();
    assert!(
        seen.recv()
            .await
            .unwrap()
            .starts_with("DELETE /v1/devices/d2 HTTP/1.1")
    );
    let stored = stored_premium(&manager).await;
    assert_eq!(stored.device, account.device);
    assert!(stored.announced_devices.is_empty());

    // Not confirmed: nothing changes.
    assert_eq!(
        premium_error(
            manager
                .premium_remove_device(&base_url, THIS_DEVICE)
                .await
                .unwrap_err()
        ),
        PremiumError::NotFound
    );
    assert!(stored_premium(&manager).await.has_device());

    manager
        .premium_remove_device(&base_url, THIS_DEVICE)
        .await
        .unwrap();
    seen.recv().await.unwrap();
    assert_eq!(
        seen.recv().await.unwrap().lines().next(),
        Some(format!("DELETE /v1/devices/{THIS_DEVICE} HTTP/1.1").as_str())
    );
    let stored = stored_premium(&manager).await;
    assert!(!stored.has_device() && stored.disconnected);
    assert_eq!(stored.key.as_deref(), Some(KEY));
}

/// A key entered again on the device it connected connects nothing
/// new: a new device would wait where this one may not. A token the
/// server disowned meanwhile is replaced by a new connection.
#[tokio::test]
async fn the_same_key_again_connects_nothing_new() {
    let (base_url, mut seen) = scripted(vec![
        answer(
            "200 OK",
            &format!(r#"{{"device":{}}}"#, device_json(THIS_DEVICE, "full", true)),
        ),
        licence_answer(fixtures::VALID_CERTIFICATE),
        answer("401 Unauthorized", DISOWNED),
        connected_answer("pending"),
        licence_answer(fixtures::VALID_CERTIFICATE),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    store_premium(
        &manager,
        connected(PremiumState {
            key: Some(KEY.to_owned()),
            ..PremiumState::default()
        }),
    )
    .await;

    let device = manager
        .premium_connect(&base_url, "ABCD-EFGH-IJKM-NPQR", DevicePlatform::Linux)
        .await
        .unwrap();
    assert_eq!(device.id, THIS_DEVICE);
    assert!(seen.recv().await.unwrap().starts_with("GET /v1/devices/me"));
    seen.recv().await.unwrap();
    assert_eq!(
        stored_premium(&manager).await.device.unwrap().token(),
        TOKEN
    );

    let device = manager
        .premium_connect(&base_url, KEY, DevicePlatform::Linux)
        .await
        .unwrap();
    assert_eq!(device.id, NEW_DEVICE);
    assert!(seen.recv().await.unwrap().starts_with("GET /v1/devices/me"));
    let connect = seen.recv().await.unwrap();
    assert!(
        connect.starts_with("POST /v1/devices HTTP/1.1"),
        "{connect}"
    );
    let stored = stored_premium(&manager).await;
    assert_eq!(stored.device.unwrap().token(), NEW_TOKEN);
    assert!(!stored.disconnected);
}

/// Another key moves the device to that account: the server hears
/// that the old connection is over, and nothing this device knew of
/// the old account stays.
#[tokio::test]
async fn another_key_moves_the_device_to_its_account() {
    let (base_url, mut seen) = scripted(vec![
        connected_answer("pending"),
        answer(
            "200 OK",
            &format!(r#"{{"id":"{THIS_DEVICE}","deleted":true}}"#),
        ),
        licence_answer(fixtures::ACCOUNT_CERTIFICATE),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let mut account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        key_saved: true,
        checklist_hidden: true,
        announced_devices: vec!["d2".to_owned()],
        ..PremiumState::default()
    });
    account.consent("w1", 100);
    store_premium(&manager, account).await;

    manager
        .premium_connect(&base_url, OTHER_KEY, DevicePlatform::Linux)
        .await
        .unwrap();
    assert_eq!(bearer(&seen.recv().await.unwrap()), Some(OTHER_KEY));
    let farewell = seen.recv().await.unwrap();
    assert!(
        farewell.starts_with("DELETE /v1/devices/me HTTP/1.1"),
        "{farewell}"
    );
    assert_eq!(bearer(&farewell), Some(TOKEN));
    assert_eq!(bearer(&seen.recv().await.unwrap()), Some(NEW_TOKEN));

    let stored = stored_premium(&manager).await;
    assert_eq!(stored.key.as_deref(), Some(OTHER_KEY));
    assert_eq!(stored.device.as_ref().unwrap().token(), NEW_TOKEN);
    assert_eq!(
        stored.certificate.as_deref(),
        Some(fixtures::ACCOUNT_CERTIFICATE)
    );
    assert!(!stored.key_saved && !stored.checklist_hidden);
    assert!(stored.announced_devices.is_empty());
    assert!(stored.is_consented("w1"));
}

/// Two calls at once on an old vault connect one device, not two: the
/// second finds the first one's token.
#[tokio::test]
async fn two_calls_at_once_connect_one_device() {
    let (base_url, mut seen) = scripted(vec![
        connected_answer("full"),
        licence_answer(fixtures::VALID_CERTIFICATE),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    store_premium(&manager, old_vault()).await;

    let (first, second) = tokio::join!(
        manager.premium_ensure_device(&base_url, DevicePlatform::Linux),
        manager.premium_ensure_device(&base_url, DevicePlatform::Linux),
    );
    let connected: Vec<_> = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(connected.len(), 1);
    assert!(seen.recv().await.unwrap().starts_with("POST /v1/devices"));
    assert!(seen.recv().await.unwrap().starts_with("GET /v1/licence"));
    assert!(seen.try_recv().is_err());
}

/// Each waiting device is handed out once to be announced, the record
/// survives a restart, and a device that stopped waiting leaves it.
#[tokio::test]
async fn waiting_devices_are_announced_once() {
    let ids = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    assert_eq!(
        manager
            .premium_mark_announced(&ids(&["d2", "d3"]))
            .await
            .unwrap(),
        ids(&["d2", "d3"])
    );
    assert!(
        manager
            .premium_mark_announced(&ids(&["d2", "d3"]))
            .await
            .unwrap()
            .is_empty()
    );
    drop(manager);
    let manager = premium_manager(dir.path());
    assert_eq!(
        manager
            .premium_mark_announced(&ids(&["d3", "d4"]))
            .await
            .unwrap(),
        ids(&["d4"])
    );
    assert_eq!(
        manager.premium_state().await.announced_devices,
        ids(&["d3", "d4"])
    );

    manager.premium_set_key_saved(true).await.unwrap();
    manager.premium_hide_checklist().await.unwrap();
    let state = manager.premium_state().await;
    assert!(state.key_saved && state.checklist_hidden);
    manager.premium_set_key_saved(false).await.unwrap();
    assert!(!manager.premium_state().await.key_saved);
}

/// The token never reaches an app: not in the state it reads, not in
/// the settings, not in a debug print. What it hands back cannot drop,
/// replace or move the account's credentials either.
#[tokio::test]
async fn the_token_never_reaches_an_app() {
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        ..PremiumState::default()
    });
    store_premium(&manager, account.clone()).await;

    let state = manager.premium_state().await;
    let settings = manager.settings().await;
    for shown in [
        format!("{state:?}"),
        format!("{settings:?}"),
        format!("{:?}", stored_premium(&manager).await),
        format!("{:#?}", stored_premium(&manager).await),
        serde_json::to_string(&state).unwrap(),
        serde_json::to_string(&settings).unwrap(),
    ] {
        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(!shown.contains("q83v"), "{shown}");
    }
    assert!(state.has_device(), "the app still knows it is connected");
    assert_eq!(state.device.as_ref().unwrap().id, THIS_DEVICE);

    // Handed back with the token blanked, the banner dismissed, and
    // everything the app has no say in changed: only the banner moves.
    let mut handed_back = state.clone();
    handed_back.acknowledged_offline_until = Some(5);
    handed_back.disconnected = true;
    handed_back.certificate = Some(fixtures::EXPIRED_CERTIFICATE.to_owned());
    handed_back.key = Some(OTHER_KEY.to_owned());
    manager.set_premium_state(handed_back).await.unwrap();
    assert_eq!(
        stored_premium(&manager).await,
        PremiumState {
            acknowledged_offline_until: Some(5),
            ..account.clone()
        }
    );
    let mut forgotten = manager.premium_state().await;
    forgotten.key = None;
    forgotten.device = None;
    manager.set_premium_state(forgotten).await.unwrap();
    assert_eq!(stored_premium(&manager).await.key.as_deref(), Some(KEY));
    assert_eq!(stored_premium(&manager).await.device, account.device);
}

/// A copy of the state read before the key changed, or before a log
/// out, and handed back after it, brings back neither the old key nor
/// the old token, and drops neither the new key nor the certificate
/// that came with it.
#[tokio::test]
async fn a_stale_copy_cannot_bring_back_a_key_or_a_token() {
    let (base_url, _) = scripted(vec![
        answer("200 OK", r#"{"key":"WXYZ-2345-6789-ABCD"}"#),
        licence_answer(fixtures::ACCOUNT_CERTIFICATE),
        answer(
            "200 OK",
            &format!(r#"{{"id":"{THIS_DEVICE}","deleted":true}}"#),
        ),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let manager = premium_manager(dir.path());
    let mut account = connected(PremiumState {
        key: Some(KEY.to_owned()),
        certificate: Some(fixtures::VALID_CERTIFICATE.to_owned()),
        key_saved: true,
        announced_devices: vec!["d2".to_owned()],
        ..PremiumState::default()
    });
    account.consent("w1", 100);
    store_premium(&manager, account).await;

    // Read, then the key changes, then the copy comes back with the
    // banner dismissed. The old key was saved; the new one is not, and
    // the copy cannot say it is.
    let mut stale = manager.premium_state().await;
    manager.premium_change_key(&base_url).await.unwrap();
    let changed = stored_premium(&manager).await;
    stale.acknowledged_offline_until = Some(5);
    manager.set_premium_state(stale).await.unwrap();
    let stored = stored_premium(&manager).await;
    assert_eq!(stored.key.as_deref(), Some(OTHER_KEY));
    assert!(!stored.key_saved);
    assert!(stored.announced_devices.is_empty());
    assert_eq!(
        stored.certificate.as_deref(),
        Some(fixtures::ACCOUNT_CERTIFICATE)
    );
    assert_eq!(stored.device.as_ref().unwrap().token(), TOKEN);
    assert_eq!(
        stored,
        PremiumState {
            acknowledged_offline_until: Some(5),
            ..changed
        }
    );

    // Read, then this device logs out, then the copy comes back: the
    // account stays gone, and nothing connects it behind the user's
    // back.
    let stale = manager.premium_state().await;
    manager.premium_log_out(&base_url).await.unwrap();
    manager.set_premium_state(stale).await.unwrap();
    let stored = stored_premium(&manager).await;
    assert_eq!(stored.key, None);
    assert_eq!(stored.certificate, None);
    assert!(!stored.has_device() && !stored.disconnected);
    assert!(stored.is_consented("w1"));
    assert_eq!(
        manager
            .premium_ensure_device("http://127.0.0.1:9", DevicePlatform::Linux)
            .await
            .unwrap(),
        None
    );
}
