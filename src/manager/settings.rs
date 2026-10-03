//! The settings: the backend of each network and the certificates
//! accepted for it, the gap limit, the app's preferences, and Tor. A
//! sync, a broadcast, the premium client and the update check ask here
//! whether they go through Tor, and by which proxy.

use std::path::PathBuf;

use crate::chain::tor::{self, TorRoute, TorSettings, TorStatus};
use crate::chain::{self, BackendConfig, CertificateReport, CertificateStatus, Endpoint};
use crate::error::{CoreError, CoreResult};
use crate::network::Network;
use crate::store::Settings;

use super::WalletManager;

impl WalletManager {
    // --- settings ------------------------------------------------------

    /// The settings as the apps may see them: the lock's hash stays in
    /// the vault, the apps only need to know a lock exists and its kind,
    /// and the premium device token stays too, as in
    /// [`Self::premium_state`].
    pub async fn settings(&self) -> Settings {
        let mut settings = self.state.lock().await.payload.settings.clone();
        if let Some(lock) = &mut settings.app_lock {
            lock.secret = None;
        }
        settings.premium.redact();
        settings
    }

    pub async fn set_active_network(&self, network: Network) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            self.state.lock().await.commit(|payload| {
                payload.settings.active_network = network;
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Remembers the backend of a network. A custom address is stored
    /// in the form a scan reads it into, the host in lower case and an
    /// IPv6 literal in brackets, and refused with the reason when the
    /// parser the sync reads with cannot read it: stored as typed, an
    /// address that parser gives up on has no host to be an onion, and
    /// the sync would hand it to the resolver in the clear. One already
    /// in that form is stored byte for byte, and the certificate
    /// accepted for it stays keyed to it.
    pub async fn set_backend(&self, network: Network, config: BackendConfig) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            let config = config.canonical()?;
            self.state.lock().await.commit(|payload| {
                payload.settings.backends.insert(network, config);
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    // --- Electrum certificates ------------------------------------------

    /// What this server's certificate amounts to right now, and the
    /// fingerprint to show when the user has to decide. Reads only: the
    /// settings screen asks, the user answers.
    pub async fn inspect_certificate(&self, url: &str) -> CoreResult<CertificateReport> {
        let host = chain::electrum::certificate_key(url);
        let pin = self
            .state
            .lock()
            .await
            .payload
            .settings
            .electrum_certs
            .get(&host)
            .cloned();
        let status = match chain::inspect_certificate(url.to_owned(), pin.clone()).await {
            Ok(chain::electrum::Inspection::NotTls) => CertificateStatus::NotTls,
            Ok(chain::electrum::Inspection::Tor) => CertificateStatus::Tor,
            Ok(chain::electrum::Inspection::Tls(verdict)) => match verdict {
                chain::tls::Verdict::Trusted => CertificateStatus::Trusted,
                chain::tls::Verdict::Pinned => CertificateStatus::Pinned {
                    fingerprint: pin.unwrap_or_default(),
                },
                chain::tls::Verdict::Unknown {
                    fingerprint,
                    reason,
                    subject,
                    expires,
                } => CertificateStatus::Unknown {
                    fingerprint,
                    reason,
                    subject,
                    expires,
                },
                chain::tls::Verdict::Changed { stored, presented } => {
                    CertificateStatus::Changed { stored, presented }
                }
            },
            Err(detail) => CertificateStatus::Unreachable { detail },
        };
        Ok(CertificateReport { host, status })
    }

    /// Remembers the certificate the user accepted for this server.
    /// From then on that host must present exactly this certificate:
    /// anything else is refused, never accepted again in silence.
    pub async fn trust_certificate(&self, url: &str, fingerprint: &str) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            if !chain::tls::is_fingerprint(fingerprint) {
                return Err(CoreError::InvalidInput {
                    kind: "certificate fingerprint",
                    detail: "expected 32 hexadecimal bytes separated by colons".to_owned(),
                });
            }
            let host = chain::electrum::certificate_key(url);
            self.state.lock().await.commit(|payload| {
                payload
                    .settings
                    .electrum_certs
                    .insert(host, fingerprint.to_ascii_uppercase());
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Drops an accepted certificate: the next connection to that host
    /// asks again.
    pub async fn forget_certificate(&self, host: &str) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            self.state.lock().await.commit(|payload| {
                payload.settings.electrum_certs.remove(host);
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Sets the gap limit shared by every wallet. Takes effect on the
    /// next sync; a raised limit widens the scan, a lowered one only
    /// narrows future scans (revealed addresses stay watched).
    pub async fn set_gap_limit(&self, gap_limit: u32) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            if !(1..=500).contains(&gap_limit) {
                return Err(CoreError::InvalidInput {
                    kind: "gap limit",
                    detail: "must be between 1 and 500".to_owned(),
                });
            }
            self.state.lock().await.commit(|payload| {
                payload.settings.gap_limit = gap_limit;
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Stores one small app preference (theme, hidden balances, ...) in
    /// the encrypted vault.
    pub async fn set_app_pref(&self, key: String, value: String) -> CoreResult<()> {
        self.state.lock().await.commit(|payload| {
            payload.settings.app_prefs.insert(key, value);
            Ok(())
        })
    }

    // --- tor -----------------------------------------------------------

    /// Where Tor stands: the mode, the proxy in effect, and how far the
    /// embedded client got. Reads only; nothing is probed or started.
    pub async fn tor_status(&self) -> TorStatus {
        let settings = self.state.lock().await.payload.settings.tor.clone();
        tor::status(&settings).await
    }

    /// Persists how `.onion` hosts are reached. A proxy address is
    /// `host:port`, checked here so a typo fails at the settings screen
    /// and not at the next sync; blank means the default.
    pub async fn set_tor_settings(&self, settings: TorSettings) -> CoreResult<()> {
        let result: CoreResult<()> = async {
            let socks_proxy = settings
                .socks_proxy
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(tor::parse_socks_address)
                .transpose()?;
            self.state.lock().await.commit(|payload| {
                payload.settings.tor = TorSettings {
                    mode: settings.mode,
                    socks_proxy,
                };
                Ok(())
            })
        }
        .await;
        self.live_refresh().await;
        result
    }

    /// Reaches Tor now, the way the settings say, so a settings screen
    /// can show the outcome before any wallet needs it. With the
    /// embedded client this is its bootstrap: up to about 90 seconds on
    /// a first run, a few on later ones. A mode that leads to a system
    /// proxy costs one probe.
    pub async fn tor_connect(&self) -> CoreResult<TorRoute> {
        let (settings, data_dir) = self.tor_setup().await;
        tor::resolve(&settings, &data_dir).await
    }

    /// The proxy to hand the chain layer for these endpoints: a Tor
    /// route when at least one host is an onion, nothing otherwise. A
    /// clearnet-only list never probes for Tor, let alone starts it.
    /// The lock is released before resolving: a first bootstrap takes
    /// a while, and reads must not wait on it.
    pub(super) async fn tor_proxy_for(&self, endpoints: &[Endpoint]) -> CoreResult<Option<String>> {
        if !chain::needs_tor(endpoints) {
            return Ok(None);
        }
        let (settings, data_dir) = self.tor_setup().await;
        let route = tor::resolve(&settings, &data_dir).await?;
        Ok(Some(route.proxy()))
    }

    /// What resolving a route needs from the state, copied out.
    pub(super) async fn tor_setup(&self) -> (TorSettings, PathBuf) {
        let state = self.state.lock().await;
        (state.payload.settings.tor.clone(), state.data_dir.clone())
    }

    /// Whether this user reaches a backend through Tor: the active
    /// network's, or the one configured for any other network. It
    /// decides the route of what is not a sync and must not give away
    /// more than one, the update check first: someone who set an onion
    /// backend anywhere is not someone whose address GitHub should see.
    /// For the apps, the reason a check is paused while Tor is down.
    pub async fn uses_tor(&self) -> bool {
        if self.backend_needs_tor().await {
            return true;
        }
        let state = self.state.lock().await;
        let settings = &state.payload.settings;
        settings.backends.iter().any(|(network, config)| {
            match chain::endpoints(config, *network, &settings.electrum_certs) {
                Ok(endpoints) => chain::needs_tor(&endpoints),
                // An address kept from before addresses were checked,
                // which no sync will connect to: if it so much as names
                // an onion, its owner meant Tor.
                Err(_) => match config {
                    BackendConfig::CustomEsplora { url, .. }
                    | BackendConfig::CustomElectrum { url, .. } => {
                        url.to_ascii_lowercase().contains(".onion")
                    }
                    BackendConfig::Public { .. } => false,
                },
            }
        })
    }

    /// Asks GitHub for the latest release of `owner/repo` and compares
    /// it with the running version: for the button, and for the check
    /// the apps run on their own once a day. It takes the route the
    /// syncs take. When [`Self::uses_tor`] says so it goes through the
    /// Tor proxy a sync would resolve, and when that proxy cannot be
    /// had it fails with [`CoreError::Tor`] before any request exists:
    /// never a request in the clear. Anything else that goes wrong is
    /// "could not check".
    pub async fn check_update(
        &self,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<crate::updates::UpdateCheck> {
        self.check_update_at(crate::updates::GITHUB_API, repo, current_version)
            .await
    }

    pub(crate) async fn check_update_at(
        &self,
        api: &str,
        repo: &str,
        current_version: &str,
    ) -> CoreResult<crate::updates::UpdateCheck> {
        let proxy = if self.uses_tor().await {
            let (settings, data_dir) = self.tor_setup().await;
            Some(tor::resolve(&settings, &data_dir).await?.proxy())
        } else {
            None
        };
        crate::updates::check_update(api, repo, current_version, proxy.as_deref()).await
    }

    /// Whether the backend of the active network is reached through
    /// Tor: the same question a sync asks, over the same endpoints.
    async fn backend_needs_tor(&self) -> bool {
        let (config, certs, network) = {
            let state = self.state.lock().await;
            let network = state.payload.settings.active_network;
            let (config, certs) = state.chain_setup(network);
            (config, certs, network)
        };
        chain::endpoints(&config, network, &certs)
            .is_ok_and(|endpoints| chain::needs_tor(&endpoints))
    }
}

#[cfg(test)]
mod tests;
