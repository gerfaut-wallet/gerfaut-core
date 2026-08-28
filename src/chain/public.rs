//! The public servers Gerfaut proposes, per network.
//!
//! Two families sit side by side. The Esplora instances are the ones
//! Gerfaut has always used and the only ones that can serve a
//! single-address wallet; they are what the automatic mode rotates
//! through. The Electrum servers are the list Sparrow Wallet ships for
//! the same networks, kept so a user who already trusts one of them can
//! point Gerfaut at it without typing a URL.
//!
//! Several of those Electrum servers sign their own certificate, which
//! nothing public vouches for. They are listed all the same, marked, and
//! the settings screen shows their fingerprint for an explicit
//! acceptance before the first connection — the trust-on-first-use of
//! `chain::tls`. What is never done is connecting to them with
//! verification turned off: that would be an unauthenticated connection
//! under a trusted-looking name.
//!
//! Every entry is a keyless, free, publicly documented endpoint. The
//! identifiers are stable: they are what the settings store, so a host
//! keeps its id even when its URL changes.

use serde::{Deserialize, Serialize};

use crate::network::Network;

/// Protocol a public server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerProtocol {
    Esplora,
    Electrum,
}

/// One public server offered in the settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicServer {
    /// Stable key stored in the settings.
    pub id: String,
    /// What the settings show: the host, nothing else.
    pub label: String,
    pub protocol: ServerProtocol,
    /// Endpoint Gerfaut talks to.
    pub url: String,
    /// Whether this server signs its own certificate, so the settings
    /// screen can say it before the user picks it rather than after.
    pub self_signed: bool,
}

pub(crate) struct Entry {
    id: &'static str,
    label: &'static str,
    protocol: ServerProtocol,
    url: &'static str,
    self_signed: bool,
}

use ServerProtocol::{Electrum, Esplora};

/// Mainnet: the three Esplora instances first, then the public Electrum
/// servers Sparrow Wallet ships.
const MAINNET: &[Entry] = &[
    Entry {
        id: "mempool.space",
        label: "mempool.space",
        protocol: Esplora,
        url: "https://mempool.space/api",
        self_signed: false,
    },
    Entry {
        id: "blockstream.info",
        label: "blockstream.info",
        protocol: Esplora,
        url: "https://blockstream.info/api",
        self_signed: false,
    },
    Entry {
        id: "mempool.emzy.de",
        label: "mempool.emzy.de",
        protocol: Esplora,
        url: "https://mempool.emzy.de/api",
        self_signed: false,
    },
    Entry {
        id: "electrum:blockstream.info",
        label: "blockstream.info:700",
        protocol: Electrum,
        url: "ssl://blockstream.info:700",
        self_signed: false,
    },
    Entry {
        id: "electrum:electrum.blockstream.info",
        label: "electrum.blockstream.info:50002",
        protocol: Electrum,
        url: "ssl://electrum.blockstream.info:50002",
        self_signed: false,
    },
    Entry {
        id: "electrum:electrum.diynodes.com",
        label: "electrum.diynodes.com:50022",
        protocol: Electrum,
        url: "ssl://electrum.diynodes.com:50022",
        self_signed: false,
    },
    Entry {
        id: "electrum:frigate.2140.dev",
        label: "frigate.2140.dev:50002",
        protocol: Electrum,
        url: "ssl://frigate.2140.dev:50002",
        self_signed: false,
    },
    // The rest of Sparrow's list. These sign their own certificate:
    // picking one asks for its fingerprint before anything connects.
    Entry {
        id: "electrum:bitcoin.lu.ke",
        label: "bitcoin.lu.ke:50002",
        protocol: Electrum,
        url: "ssl://bitcoin.lu.ke:50002",
        self_signed: true,
    },
    Entry {
        id: "electrum:electrum.emzy.de",
        label: "electrum.emzy.de:50002",
        protocol: Electrum,
        url: "ssl://electrum.emzy.de:50002",
        self_signed: true,
    },
    Entry {
        id: "electrum:electrum.bitaroo.net",
        label: "electrum.bitaroo.net:50002",
        protocol: Electrum,
        url: "ssl://electrum.bitaroo.net:50002",
        self_signed: true,
    },
    Entry {
        id: "electrum:fulcrum.sethforprivacy.com",
        label: "fulcrum.sethforprivacy.com:50002",
        protocol: Electrum,
        url: "ssl://fulcrum.sethforprivacy.com:50002",
        self_signed: true,
    },
];

const SIGNET: &[Entry] = &[
    Entry {
        id: "mempool.space",
        label: "mempool.space",
        protocol: Esplora,
        url: "https://mempool.space/signet/api",
        self_signed: false,
    },
    Entry {
        id: "blockstream.info",
        label: "blockstream.info",
        protocol: Esplora,
        url: "https://blockstream.info/signet/api",
        self_signed: false,
    },
    Entry {
        id: "mempool.emzy.de",
        label: "mempool.emzy.de",
        protocol: Esplora,
        url: "https://mempool.emzy.de/signet/api",
        self_signed: false,
    },
    Entry {
        id: "electrum:mempool.space",
        label: "mempool.space:60602",
        protocol: Electrum,
        url: "ssl://mempool.space:60602",
        self_signed: false,
    },
];

const TESTNET4: &[Entry] = &[
    Entry {
        id: "mempool.space",
        label: "mempool.space",
        protocol: Esplora,
        url: "https://mempool.space/testnet4/api",
        self_signed: false,
    },
    Entry {
        id: "mempool.emzy.de",
        label: "mempool.emzy.de",
        protocol: Esplora,
        url: "https://mempool.emzy.de/testnet4/api",
        self_signed: false,
    },
    Entry {
        id: "electrum:mempool.space",
        label: "mempool.space:40002",
        protocol: Electrum,
        url: "ssl://mempool.space:40002",
        self_signed: false,
    },
    Entry {
        id: "electrum:blackie.c3-soft.com",
        label: "blackie.c3-soft.com:57010",
        protocol: Electrum,
        url: "ssl://blackie.c3-soft.com:57010",
        self_signed: false,
    },
];

fn entries(network: Network) -> &'static [Entry] {
    match network {
        Network::Mainnet => MAINNET,
        Network::Signet => SIGNET,
        Network::Testnet4 => TESTNET4,
        // A local chain has no public server, by definition.
        Network::Regtest => &[],
    }
}

/// Public servers offered for a network, in the order the settings list
/// them. Empty on regtest.
pub fn public_servers(network: Network) -> Vec<PublicServer> {
    entries(network)
        .iter()
        .map(|entry| PublicServer {
            id: entry.id.to_owned(),
            label: entry.label.to_owned(),
            protocol: entry.protocol,
            url: entry.url.to_owned(),
            self_signed: entry.self_signed,
        })
        .collect()
}

/// Looks up one server by the identifier stored in the settings.
pub(crate) fn find(network: Network, id: &str) -> Option<&'static Entry> {
    entries(network).iter().find(|entry| entry.id == id)
}

impl Entry {
    pub(crate) fn url(&self) -> &'static str {
        self.url
    }

    pub(crate) fn label(&self) -> &'static str {
        self.label
    }

    pub(crate) fn protocol(&self) -> ServerProtocol {
        self.protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_lists_its_own_servers() {
        for network in Network::ALL {
            let servers = public_servers(network);
            if network == Network::Regtest {
                assert!(servers.is_empty());
                continue;
            }
            assert!(servers.len() >= 3, "{network} is too thin");
            // The automatic mode rotates over the Esplora entries, so at
            // least two independent operators must speak Esplora.
            let esplora = servers
                .iter()
                .filter(|s| s.protocol == ServerProtocol::Esplora)
                .count();
            assert!(esplora >= 2, "{network} needs a second Esplora");
            assert!(
                servers
                    .iter()
                    .any(|s| s.protocol == ServerProtocol::Electrum),
                "{network} lists no Electrum server"
            );
        }
    }

    #[test]
    fn identifiers_are_unique_and_resolvable() {
        for network in Network::ALL {
            let servers = public_servers(network);
            let ids: std::collections::BTreeSet<&str> =
                servers.iter().map(|s| s.id.as_str()).collect();
            assert_eq!(ids.len(), servers.len(), "{network} repeats an id");
            for server in &servers {
                let found = find(network, &server.id).expect("id resolves");
                assert_eq!(found.url(), server.url);
            }
            assert!(find(network, "nope.example.org").is_none());
        }
    }

    #[test]
    fn urls_match_their_protocol_and_network() {
        for network in Network::ALL {
            for server in public_servers(network) {
                match server.protocol {
                    ServerProtocol::Esplora => {
                        assert!(server.url.starts_with("https://"), "{}", server.url);
                        assert!(server.url.ends_with("/api"), "{}", server.url);
                        let path = match network {
                            Network::Mainnet => "",
                            other => other.as_str(),
                        };
                        assert!(server.url.contains(path), "{} on {network}", server.url);
                    }
                    ServerProtocol::Electrum => {
                        assert!(server.url.starts_with("ssl://"), "{}", server.url);
                        assert!(server.id.starts_with("electrum:"), "{}", server.id);
                    }
                }
            }
        }
    }

    /// The Esplora entries must stay in step with the fallback list the
    /// automatic mode rotates through: a server added to one and not the
    /// other would be either unreachable or unlistable.
    #[test]
    fn esplora_entries_are_the_automatic_rotation() {
        for network in Network::ALL {
            let listed: Vec<String> = public_servers(network)
                .into_iter()
                .filter(|s| s.protocol == ServerProtocol::Esplora)
                .map(|s| s.url)
                .collect();
            let rotation: Vec<String> = network
                .default_esplora_urls()
                .iter()
                .map(|url| (*url).to_owned())
                .collect();
            assert_eq!(listed, rotation, "{network}");
        }
    }

    /// Cross-checks the catalogue against the live network: every
    /// Esplora instance must serve a plausible tip height.
    #[tokio::test]
    #[ignore = "talks to the public servers"]
    async fn every_public_esplora_answers() {
        let mut reached = 0;
        for network in Network::ALL {
            for server in public_servers(network) {
                if server.protocol != ServerProtocol::Esplora {
                    continue;
                }
                let client = crate::chain::esplora::client(&server.url).unwrap();
                match client.get_height().await {
                    Ok(height) => {
                        reached += 1;
                        assert!(height > 100_000, "{} on {network}: {height}", server.label);
                    }
                    Err(error) => eprintln!("{} on {network} unreachable: {error}", server.label),
                }
            }
        }
        assert!(reached >= 1, "no public Esplora reachable at all");
    }

    /// Same for the Electrum list, through Gerfaut's own TLS: a server
    /// listed as vouched for must be vouched for, one listed as
    /// self-signed must present exactly that — a certificate nothing
    /// vouches for, which then serves once its fingerprint is accepted.
    #[test]
    #[ignore = "talks to the public servers"]
    fn every_public_electrum_answers() {
        use crate::chain::electrum::{Inspection, Target, inspect_blocking};
        use crate::chain::tls::Verdict;

        let mut reached = 0;
        for network in Network::ALL {
            for server in public_servers(network) {
                if server.protocol != ServerProtocol::Electrum {
                    continue;
                }
                let verdict = match inspect_blocking(&Target::new(&server.url, None)) {
                    Ok(Inspection::Tls(verdict)) => verdict,
                    // Kept loud rather than fatal: a public server can be
                    // down for a day without failing a build.
                    Ok(other) => panic!("{} is not a TLS server: {other:?}", server.label),
                    Err(error) => {
                        eprintln!("{} on {network} unreachable: {error}", server.label);
                        continue;
                    }
                };
                reached += 1;
                match (server.self_signed, verdict) {
                    (false, Verdict::Trusted) => {
                        eprintln!("{} on {network}: vouched for", server.label);
                    }
                    (true, Verdict::Unknown { fingerprint, .. }) => {
                        // Accepted once, it must carry a real sync.
                        let accepted = Target::new(&server.url, Some(fingerprint.clone()));
                        assert_eq!(
                            inspect_blocking(&accepted).unwrap(),
                            Inspection::Tls(Verdict::Pinned),
                            "{} refuses the fingerprint it just presented",
                            server.label
                        );
                        eprintln!("{} on {network}: self-signed, {fingerprint}", server.label);
                    }
                    (false, other) => panic!(
                        "{} is listed as vouched for but presents {other:?}",
                        server.label
                    ),
                    (true, other) => panic!(
                        "{} is listed as self-signed but presents {other:?}",
                        server.label
                    ),
                }
            }
        }
        assert!(reached >= 1, "no public Electrum reachable at all");
    }
}
