//! Release update check against GitHub.
//!
//! Read-only: one request for the latest release of the app's own
//! repository, which sends the version in no way and nothing about the
//! wallets. The apps run it from a button, and on their own at most
//! once a day unless the user turned that off. Failures (offline,
//! private repository, rate limit) degrade to "could not check", never
//! to an error state.
//!
//! The request goes out through [`crate::WalletManager::check_update`]
//! and nowhere else, because it has to take the route the syncs take.
//! Someone who reaches their backend through Tor does not expect the
//! app to show GitHub their address once a day: with an onion backend
//! configured the check goes through the same Tor proxy, and when Tor
//! cannot be had it does not go at all.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Outcome of a release check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCheck {
    /// Latest published tag, for example `v0.2.0`.
    pub latest: String,
    /// Web page of the latest release.
    pub url: String,
    /// True when the latest tag is newer than the running version.
    pub update_available: bool,
}

/// Compares two `x.y.z` versions, ignoring a leading `v`.
///
/// Unparseable versions compare as not newer: a malformed tag must not
/// nag users with a phantom update.
fn is_newer(latest: &str, current: &str) -> bool {
    fn parts(version: &str) -> Option<[u64; 3]> {
        let trimmed = version.trim().trim_start_matches('v');
        let mut out = [0u64; 3];
        let mut count = 0;
        for (i, part) in trimmed.split('.').enumerate() {
            if i >= 3 {
                return None;
            }
            out[i] = part.parse().ok()?;
            count = i + 1;
        }
        (count >= 2).then_some(out)
    }
    match (parts(latest), parts(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

/// Where the releases are read from.
pub(crate) const GITHUB_API: &str = "https://api.github.com";

/// Queries the latest release of `owner/repo` and compares it with the
/// running version. `proxy` is the Tor SOCKS proxy the manager resolved
/// when the check has to go through Tor; the name of the host then goes
/// to the proxy, never to a resolver.
pub(crate) async fn check_update(
    api: &str,
    repo: &str,
    current_version: &str,
    proxy: Option<&str>,
) -> CoreResult<UpdateCheck> {
    // A Tor circuit is slower to build than a connection is to open.
    let budget = if proxy.is_some() { 60 } else { 15 };
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(budget))
        .user_agent("gerfaut");
    if let Some(proxy) = proxy {
        let proxy = reqwest::Proxy::all(format!("socks5h://{proxy}"))
            .map_err(|e| CoreError::Tor(format!("invalid Tor proxy address: {e}")))?;
        builder = builder.proxy(proxy);
    }
    let client = builder
        .build()
        .map_err(|e| CoreError::Internal(format!("http client: {e}")))?;
    let response = client
        .get(format!("{api}/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| check_error(crate::chain::esplora::describe_failure(&e)))?;
    if !response.status().is_success() {
        return Err(check_error(format!("http {}", response.status())));
    }
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| check_error(e.to_string()))?;
    let latest = value["tag_name"]
        .as_str()
        .ok_or_else(|| check_error("no tag in response".to_owned()))?
        .to_owned();
    let url = value["html_url"]
        .as_str()
        .unwrap_or(&format!("https://github.com/{repo}/releases/latest"))
        .to_owned();
    Ok(UpdateCheck {
        update_available: is_newer(&latest, current_version),
        latest,
        url,
    })
}

fn check_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "github".to_owned(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::chain::BackendConfig;
    use crate::chain::tor::{TorMode, TorSettings, socks};
    use crate::network::Network;
    use crate::store::VaultKey;

    const ONION: &str = "tcp://gerfautexample000000000000000000000000000000000000000.onion:50001";

    /// Something that answers like the releases API, and counts who
    /// came.
    async fn releases(tag: &'static str) -> (String, Arc<Mutex<u32>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let visits = Arc::new(Mutex::new(0u32));
        let counted = visits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                *counted.lock().unwrap() += 1;
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let body = format!(r#"{{"tag_name":"{tag}","html_url":"https://example.org/r"}}"#);
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
            }
        });
        (format!("http://{address}"), visits)
    }

    #[tokio::test]
    async fn without_tor_the_check_goes_straight() {
        let (api, visits) = releases("v9.0.0").await;
        let dir = tempfile::tempdir().unwrap();
        let manager = crate::WalletManager::open(dir.path(), VaultKey::Raw([3; 32])).unwrap();
        assert!(!manager.uses_tor().await);
        let check = manager
            .check_update_at(&api, "gerfaut-wallet/gerfaut-desktop", "0.1.0")
            .await
            .unwrap();
        assert!(check.update_available);
        assert_eq!(check.latest, "v9.0.0");
        assert_eq!(*visits.lock().unwrap(), 1);
    }

    /// An onion backend on any network, even one that is not shown
    /// now, sends the check through the Tor proxy, by name.
    #[tokio::test]
    async fn with_an_onion_backend_the_check_goes_through_tor() {
        let (api, visits) = releases("v0.1.0").await;
        let upstream = api.trim_start_matches("http://").to_owned();
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
        let manager = crate::WalletManager::open(dir.path(), VaultKey::Raw([3; 32])).unwrap();
        manager
            .set_backend(
                Network::Mainnet,
                BackendConfig::CustomElectrum {
                    url: ONION.to_owned(),
                },
            )
            .await
            .unwrap();
        manager.set_active_network(Network::Signet).await.unwrap();
        manager
            .set_tor_settings(TorSettings {
                mode: TorMode::System,
                socks_proxy: Some(proxy),
            })
            .await
            .unwrap();
        assert!(manager.uses_tor().await);

        let check = manager
            .check_update_at(
                "http://releases.test",
                "gerfaut-wallet/gerfaut-desktop",
                "0.1.0",
            )
            .await
            .unwrap();
        assert!(!check.update_available);
        assert_eq!(
            *asked.lock().unwrap(),
            vec![("releases.test".to_owned(), 80)],
            "the name went to the proxy, and nowhere else"
        );
        assert_eq!(*visits.lock().unwrap(), 1);
    }

    /// Tor is needed and is not there: a Tor error, and no request.
    #[tokio::test]
    async fn without_the_tor_it_needs_the_check_does_not_go() {
        let (api, visits) = releases("v9.0.0").await;
        let closed = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            listener.local_addr().unwrap().to_string()
        };
        let dir = tempfile::tempdir().unwrap();
        let manager = crate::WalletManager::open(dir.path(), VaultKey::Raw([3; 32])).unwrap();
        manager
            .set_backend(
                Network::Mainnet,
                BackendConfig::CustomElectrum {
                    url: ONION.to_owned(),
                },
            )
            .await
            .unwrap();
        manager
            .set_tor_settings(TorSettings {
                mode: TorMode::System,
                socks_proxy: Some(closed),
            })
            .await
            .unwrap();
        let refused = manager
            .check_update_at(&api, "gerfaut-wallet/gerfaut-desktop", "0.1.0")
            .await
            .unwrap_err();
        assert!(matches!(refused, CoreError::Tor(_)), "{refused}");
        assert_eq!(*visits.lock().unwrap(), 0, "nothing left in the clear");
    }

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.2.0"));
        assert!(!is_newer("nightly", "0.1.0"), "malformed tags never nag");
        assert!(!is_newer("0.2.0", "garbage"));
    }
}
