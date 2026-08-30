//! Reading a server address the way a node hands it out.
//!
//! A node distribution does not ask people to retype an onion address:
//! Umbrel, Start9, RaspiBlitz and the rest print a QR next to their
//! Electrum app, and every Electrum client since the beginning has read
//! the same one-line form — `host:port:s` for TLS, `host:port:t` for
//! plain TCP. Around it, the same screens hand out `ssl://`, `tcp://`
//! and plain `https://` endpoints depending on which app printed them.
//!
//! This module turns any of those into the two fields the settings
//! screen holds, and says which of the two backends it is. It decides
//! nothing on its own: what it returns fills the form, and the person
//! still presses Save.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Which backend the scanned address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannedBackendKind {
    /// An Electrum protocol server: electrs, Fulcrum, ElectrumX.
    Electrum,
    /// An Esplora-compatible HTTP API.
    Esplora,
}

/// A server address, read and normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedBackend {
    pub kind: ScannedBackendKind,
    /// The address in the form the backend configuration stores:
    /// `ssl://host:port`, `tcp://host:port`, or the HTTP endpoint.
    pub url: String,
    /// Host alone, brackets stripped from an IPv6 literal.
    pub host: String,
    /// Port, when the address carried one or a default applies.
    pub port: Option<u16>,
    /// Whether the connection is encrypted. Meaningless for Esplora
    /// over plain HTTP, where it simply mirrors the scheme.
    pub tls: bool,
    /// A Tor hidden service: the address is its own identity, and TLS
    /// on top of it buys nothing.
    pub onion: bool,
}

/// Ports an Electrum server conventionally serves in the clear. A
/// scanned address that names one of them without saying `s` or `t`
/// means plain TCP, whatever the client default is.
const PLAIN_PORTS: &[u16] = &[50001, 60001, 20001, 50003];
/// The mirror set: ports that conventionally carry TLS.
const TLS_PORTS: &[u16] = &[50002, 60002, 20002, 50004];

const ELECTRUM_TLS_PORT: u16 = 50002;
const ELECTRUM_TCP_PORT: u16 = 50001;

fn reject(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidInput {
        kind: "server",
        detail: detail.into(),
    }
}

/// Splits `host[:port]`, keeping an IPv6 literal's own colons out of it.
fn split_host_port(rest: &str) -> Result<(String, Option<u16>), CoreError> {
    let port_of = |port: &str| {
        port.parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| reject(format!("{port} is not a port number")))
    };
    let (host, port) = match rest.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| reject("the address opens a bracket it never closes"))?;
            match tail.strip_prefix(':') {
                Some(port) => (host.to_owned(), Some(port_of(port)?)),
                None => (host.to_owned(), None),
            }
        }
        None => match rest.rsplit_once(':') {
            // More than one colon and no brackets: a bare IPv6 literal,
            // which has no room left for a port.
            Some((head, _)) if head.contains(':') => (rest.to_owned(), None),
            Some((host, port)) => (host.to_owned(), Some(port_of(port)?)),
            None => (rest.to_owned(), None),
        },
    };
    if host.is_empty() {
        return Err(reject("the address has no host"));
    }
    if host.contains(char::is_whitespace) {
        return Err(reject("the address has a space in it"));
    }
    Ok((host, port))
}

fn electrum(host: String, port: Option<u16>, tls: bool) -> ScannedBackend {
    let onion = host.to_ascii_lowercase().ends_with(".onion");
    let port = port.unwrap_or(if tls {
        ELECTRUM_TLS_PORT
    } else {
        ELECTRUM_TCP_PORT
    });
    let scheme = if tls { "ssl" } else { "tcp" };
    // An IPv6 literal goes back into its brackets: without them the
    // address and its port cannot be told apart again.
    let shown = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    ScannedBackend {
        kind: ScannedBackendKind::Electrum,
        url: format!("{scheme}://{shown}:{port}"),
        host,
        port: Some(port),
        tls,
        onion,
    }
}

/// What the address is, read as tolerantly as it can be without
/// guessing. Returns an error naming what was seen instead, so the
/// screen can say why a scan was refused.
pub fn parse_backend(text: &str) -> CoreResult<ScannedBackend> {
    let text = text.trim();
    if text.is_empty() {
        return Err(reject("nothing to read"));
    }
    // Anything that is plainly wallet material, named rather than
    // rejected as gibberish: this is the scanner people already use to
    // add a wallet, and pointing the wrong QR at it is the likely slip.
    let lower = text.to_ascii_lowercase();
    for (prefix, what) in [
        ("ur:", "a UR QR code"),
        ("b$", "a BBQr code"),
        ("xpub", "an extended public key"),
        ("ypub", "an extended public key"),
        ("zpub", "an extended public key"),
        ("tpub", "an extended public key"),
        ("vpub", "an extended public key"),
        ("upub", "an extended public key"),
        ("wpkh(", "a descriptor"),
        ("wsh(", "a descriptor"),
        ("sh(", "a descriptor"),
        ("tr(", "a descriptor"),
        ("pkh(", "a descriptor"),
        ("bitcoin:", "a payment request"),
        ("bc1", "a Bitcoin address"),
        ("tb1", "a Bitcoin address"),
        ("bcrt1", "a Bitcoin address"),
    ] {
        if lower.starts_with(prefix) {
            return Err(reject(format!(
                "this is {what}, not the address of a server"
            )));
        }
    }

    if let Some((scheme, rest)) = text.split_once("://") {
        let rest = rest.trim_end_matches('/');
        return match scheme.to_ascii_lowercase().as_str() {
            "http" | "https" => {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
                let (host, port) = split_host_port(authority)?;
                let onion = host.to_ascii_lowercase().ends_with(".onion");
                let tls = scheme.eq_ignore_ascii_case("https");
                Ok(ScannedBackend {
                    kind: ScannedBackendKind::Esplora,
                    url: format!("{}://{}", scheme.to_ascii_lowercase(), rest),
                    host,
                    port,
                    tls,
                    onion,
                })
            }
            // `electrum://` is what a few node dashboards print; it says
            // the protocol, never whether the socket is encrypted.
            "ssl" | "tls" | "electrums" => {
                let (host, port) = split_host_port(strip_path(rest))?;
                Ok(electrum(host, port, true))
            }
            "tcp" | "electrum" => {
                let (host, port) = split_host_port(strip_path(rest))?;
                Ok(electrum(host, port, false))
            }
            other => Err(reject(format!(
                "{other}:// is not an address Gerfaut can connect to"
            ))),
        };
    }

    // The Electrum one-liner: `host:port:s` (TLS) or `host:port:t`
    // (plain TCP), the form every Electrum client has read since the
    // start and the one node dashboards print in their QR codes.
    if let Some((head, flag)) = text.rsplit_once(':')
        && flag.len() == 1
    {
        let tls = match flag.to_ascii_lowercase().as_str() {
            "s" => true,
            "t" => false,
            other => {
                return Err(reject(format!(
                    "{other} is not an Electrum connection type: s for TLS, t for plain TCP"
                )));
            }
        };
        let (host, port) = split_host_port(head)?;
        return Ok(electrum(host, port, tls));
    }

    let (host, port) = split_host_port(text)?;
    if !host.contains('.') && !host.contains(':') && host != "localhost" {
        return Err(reject(format!(
            "{host} does not look like a server address"
        )));
    }
    // Nothing said whether the socket is encrypted. The port answers
    // when it is one of the conventional ones; otherwise TLS, the way
    // every Electrum client has always read a bare address.
    let tls = match port {
        Some(p) if PLAIN_PORTS.contains(&p) => false,
        Some(p) if TLS_PORTS.contains(&p) => true,
        _ => true,
    };
    Ok(electrum(host, port, tls))
}

fn strip_path(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> ScannedBackend {
        parse_backend(text).expect("parsed")
    }

    #[test]
    fn electrum_one_liner_reads_its_flag() {
        let tor = ok("gerfautexample123.onion:50001:t");
        assert_eq!(tor.kind, ScannedBackendKind::Electrum);
        assert_eq!(tor.url, "tcp://gerfautexample123.onion:50001");
        assert!(tor.onion);
        assert!(!tor.tls);

        let tls = ok("electrum.example.org:50002:s");
        assert_eq!(tls.url, "ssl://electrum.example.org:50002");
        assert!(tls.tls);
        assert!(!tls.onion);
    }

    #[test]
    fn schemes_map_to_their_transport() {
        assert_eq!(
            ok("ssl://host.example:50002").url,
            "ssl://host.example:50002"
        );
        assert_eq!(
            ok("tcp://192.168.1.10:50001").url,
            "tcp://192.168.1.10:50001"
        );
        assert_eq!(ok("tls://host.example").url, "ssl://host.example:50002");
        assert_eq!(
            ok("electrum://host.example").url,
            "tcp://host.example:50001"
        );
    }

    #[test]
    fn http_is_an_esplora_endpoint() {
        let api = ok("https://mempool.example.org/api");
        assert_eq!(api.kind, ScannedBackendKind::Esplora);
        assert_eq!(api.url, "https://mempool.example.org/api");
        assert_eq!(api.host, "mempool.example.org");
        assert!(api.tls);

        let plain = ok("http://192.168.1.10:3002/");
        assert_eq!(plain.url, "http://192.168.1.10:3002");
        assert_eq!(plain.port, Some(3002));
        assert!(!plain.tls);
    }

    #[test]
    fn a_bare_address_reads_its_port_convention() {
        assert!(!ok("node.example.org:50001").tls);
        assert!(ok("node.example.org:50002").tls);
        // Nothing conventional about it: TLS, as every Electrum client
        // has always assumed.
        assert!(ok("node.example.org:57010").tls);
        assert_eq!(ok("node.example.org").url, "ssl://node.example.org:50002");
    }

    #[test]
    fn ipv6_keeps_its_brackets() {
        let one = ok("ssl://[2001:db8::1]:50002");
        assert_eq!(one.host, "2001:db8::1");
        assert_eq!(one.url, "ssl://[2001:db8::1]:50002");
        // Unbracketed, there is no room for a port to hide in.
        assert_eq!(ok("[2001:db8::1]").url, "ssl://[2001:db8::1]:50002");
    }

    #[test]
    fn localhost_is_a_server_address() {
        assert_eq!(ok("localhost:50001").url, "tcp://localhost:50001");
    }

    #[test]
    fn wallet_material_is_named_not_refused_blankly() {
        for (text, needle) in [
            ("ur:crypto-output/abcdef", "UR QR code"),
            ("xpub661MyMwAqRbcF", "extended public key"),
            ("wpkh([aabbccdd/84h/0h/0h]xpub.../0/*)", "descriptor"),
            ("bc1qexampleaddress", "Bitcoin address"),
            ("bitcoin:bc1qexample?amount=1", "payment request"),
        ] {
            let error = parse_backend(text).expect_err("refused");
            assert!(
                error.to_string().contains(needle),
                "{text} said {error}, expected {needle}"
            );
        }
    }

    #[test]
    fn nonsense_is_refused_with_a_reason() {
        assert!(parse_backend("").is_err());
        assert!(parse_backend("   ").is_err());
        assert!(parse_backend("hello world").is_err());
        assert!(parse_backend("host.example:not-a-port").is_err());
        assert!(parse_backend("ftp://host.example").is_err());
        assert!(parse_backend("host.example:50002:x").is_err());
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(
            ok("  ssl://host.example:50002\n").url,
            "ssl://host.example:50002"
        );
    }
}
