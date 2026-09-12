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

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use url::Url;

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
            // which has no room left for a port — but only if it reads
            // like one. `host.example:50002:50003` also has two colons,
            // and swallowing it whole would save an address that can
            // never connect and say nothing about why.
            Some((head, _)) if head.contains(':') => {
                if !rest
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
                {
                    return Err(reject(format!(
                        "{rest} has more than one colon and is not an IPv6 address; \
                         bracket it as [address]:port if it is"
                    )));
                }
                (rest.to_owned(), None)
            }
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
    // Host names have no case, and a QR code prints them in capitals.
    // The host is stored as the URL standard reads it, lower case and
    // decoded, so a `.ONION` read off a screen is the same hidden
    // service to every later check, and an accepted certificate is
    // keyed the same whatever the spelling.
    let host = super::canonical_host(&host)
        .map_err(|e| reject(format!("{host} is not a host name: {e}")))?;
    Ok((host, port))
}

fn electrum(host: String, port: Option<u16>, tls: bool) -> ScannedBackend {
    let onion = super::is_onion_host(&host);
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
            "http" | "https" => esplora(text),
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
    //
    // Only a letter is a flag. A one-character *digit* is a port, or the
    // last group of a bare IPv6 literal — `2001:db8::1` and
    // `host.example:5` both end in one character and neither is a
    // connection type.
    if let Some((head, flag)) = text.rsplit_once(':')
        && flag.len() == 1
        && flag.chars().all(|c| c.is_ascii_alphabetic())
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
    // every Electrum client has always read a bare address — except on
    // an onion, where the address is already the server's identity and
    // the electrs and Fulcrum instances node distributions ship listen
    // in the clear on 50001. Defaulting a scanned onion to TLS fills the
    // form with something that cannot connect.
    let tls = match port {
        Some(p) if PLAIN_PORTS.contains(&p) => false,
        Some(p) if TLS_PORTS.contains(&p) => true,
        _ => !super::is_onion_host(&host),
    };
    Ok(electrum(host, port, tls))
}

fn strip_path(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or_default()
}

/// An HTTP endpoint, read by the parser the HTTP client reads with:
/// what it takes for the host is what the client will connect to, and
/// what it refuses could never be connected to. The address is stored
/// back from its parts, the host in the case the parser gives it, the
/// userinfo and the path in their own, since a server may care about
/// those.
fn esplora(text: &str) -> CoreResult<ScannedBackend> {
    let parsed =
        Url::parse(text).map_err(|e| reject(format!("{text} is not a server address: {e}")))?;
    let host = super::host_of_parsed(&parsed).ok_or_else(|| reject("the address has no host"))?;
    let port = parsed.port();
    let onion = super::is_onion_host(&host);
    let tls = parsed.scheme() == "https";
    let mut url = format!("{}://", parsed.scheme());
    if !parsed.username().is_empty() || parsed.password().is_some() {
        url.push_str(parsed.username());
        if let Some(password) = parsed.password() {
            url.push(':');
            url.push_str(password);
        }
        url.push('@');
    }
    if host.contains(':') {
        let _ = write!(url, "[{host}]");
    } else {
        url.push_str(&host);
    }
    if let Some(port) = port {
        let _ = write!(url, ":{port}");
    }
    url.push_str(parsed.path().trim_end_matches('/'));
    if let Some(query) = parsed.query() {
        let _ = write!(url, "?{query}");
    }
    if let Some(fragment) = parsed.fragment() {
        let _ = write!(url, "#{fragment}");
    }
    Ok(ScannedBackend {
        kind: ScannedBackendKind::Esplora,
        url,
        host,
        port,
        tls,
        onion,
    })
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

    /// A one-character tail is only a connection flag when it is a
    /// letter. A digit there is a port, or the last group of a bare
    /// IPv6 literal — reading either as `s`/`t` refused an address that
    /// was perfectly good, with a message about Electrum transports.
    #[test]
    fn a_single_digit_tail_is_not_a_connection_flag() {
        let bare = ok("2001:db8::1");
        assert_eq!(bare.host, "2001:db8::1");
        assert_eq!(bare.url, "ssl://[2001:db8::1]:50002");

        let short_port = ok("node.example.org:5");
        assert_eq!(short_port.port, Some(5));
    }

    /// Two colons and no brackets is an IPv6 literal or it is nothing.
    /// Swallowing `host:50002:50003` whole saved a host that could never
    /// connect and said nothing about why.
    #[test]
    fn a_second_colon_that_is_not_ipv6_is_refused_with_a_reason() {
        let error = parse_backend("ssl://host.example:50002:50003").expect_err("refused");
        assert!(error.to_string().contains("bracket it"), "{error}");
        assert!(parse_backend("host.example:50002:50003").is_err());
    }

    /// An onion address is already the server's identity, and the
    /// electrs and Fulcrum instances node distributions ship listen in
    /// the clear. Filling the form with TLS gives an address that
    /// cannot connect.
    #[test]
    fn a_bare_onion_is_read_as_plain_tcp() {
        let onion = ok("gerfautexample123456.onion");
        assert!(onion.onion);
        assert!(!onion.tls);
        assert_eq!(onion.url, "tcp://gerfautexample123456.onion:50001");

        // An explicit port still rules, either way.
        assert!(ok("gerfautexample123456.onion:50002").tls);
        // And a clearnet host with nothing said is still TLS.
        assert!(ok("node.example.org").tls);
    }

    /// A node dashboard prints its onion address in a QR code, and a QR
    /// code prints capitals. The address stored is the lower-case one,
    /// so that everything downstream, the Tor check first, reads it as
    /// the hidden service it is.
    #[test]
    fn a_host_read_in_capitals_is_stored_in_lower_case() {
        const UPPER: &str =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.ONION";
        let lower = UPPER.to_ascii_lowercase();

        let bare = ok(UPPER);
        assert!(bare.onion);
        assert_eq!(bare.host, lower);
        assert_eq!(bare.url, format!("tcp://{lower}:50001"));

        let flagged = ok(&format!("{UPPER}:50001:T"));
        assert_eq!(flagged.url, format!("tcp://{lower}:50001"));

        let esplora = ok(&format!("HTTP://{UPPER}/Api/v1"));
        assert!(esplora.onion);
        assert_eq!(esplora.host, lower);
        // The path keeps its case: a server may care about it.
        assert_eq!(esplora.url, format!("http://{lower}/Api/v1"));

        let clearnet = ok("SSL://Electrum.Example.ORG:50002");
        assert!(!clearnet.onion);
        assert_eq!(clearnet.url, "ssl://electrum.example.org:50002");
        assert_eq!(
            ok("https://Mempool.Example.org/api").host,
            "mempool.example.org"
        );
    }

    /// The host is read by the parser the HTTP client reads with, so
    /// the scanner, the Tor check and the connection all mean the same
    /// machine: a `\` ends the host, `%2E` is a dot, a trailing dot is
    /// the same fully qualified name, and the userinfo before an `@`
    /// keeps its case while the host loses its own.
    #[test]
    fn the_host_is_read_the_way_the_client_reads_it() {
        let disguised = ok("https://evil.com\\.onion");
        assert_eq!(disguised.host, "evil.com");
        assert!(!disguised.onion);
        assert_eq!(disguised.url, "https://evil.com/.onion");

        let encoded = ok("https://evil%2Eonion");
        assert_eq!(encoded.host, "evil.onion");
        assert!(encoded.onion);
        assert_eq!(encoded.url, "https://evil.onion");

        let qualified = ok("https://x.onion.");
        assert_eq!(qualified.host, "x.onion");
        assert!(qualified.onion);
        assert_eq!(qualified.url, "https://x.onion");

        let with_userinfo = ok("https://user:Pass@Host.Example:3002/Api/?q=1");
        assert_eq!(with_userinfo.host, "host.example");
        assert_eq!(with_userinfo.port, Some(3002));
        assert_eq!(
            with_userinfo.url,
            "https://user:Pass@host.example:3002/Api?q=1"
        );
        // An onion in the userinfo is not an onion.
        let decoy = ok("https://x.onion@evil.com/api");
        assert_eq!(decoy.host, "evil.com");
        assert!(!decoy.onion);

        let electrum = ok("ssl://xxx.onion:50002");
        assert_eq!(electrum.host, "xxx.onion");
        assert_eq!(electrum.port, Some(50002));
        assert!(electrum.onion && electrum.tls);
        let encoded = ok("tcp://XXX%2Eonion:50001");
        assert_eq!(encoded.host, "xxx.onion");
        assert!(encoded.onion);
        assert_eq!(encoded.url, "tcp://xxx.onion:50001");
        let qualified = ok("xxx.onion.:50001:t");
        assert_eq!(qualified.host, "xxx.onion");
        assert!(qualified.onion);

        // What the standard refuses as a host is refused here, with
        // the reason.
        let error = parse_backend("ssl://evil.com\\.onion:50002").expect_err("refused");
        assert!(error.to_string().contains("not a host name"), "{error}");
        assert!(parse_backend("https://").is_err());
        assert!(parse_backend("https://host name/").is_err());
    }

    #[test]
    fn ipv6_keeps_its_brackets() {
        let one = ok("ssl://[2001:db8::1]:50002");
        assert_eq!(one.host, "2001:db8::1");
        assert_eq!(one.url, "ssl://[2001:db8::1]:50002");
        // Unbracketed, there is no room for a port to hide in.
        assert_eq!(ok("[2001:db8::1]").url, "ssl://[2001:db8::1]:50002");

        let web = ok("https://[2001:DB8::1]:3002/api");
        assert_eq!(web.host, "2001:db8::1");
        assert_eq!(web.port, Some(3002));
        assert_eq!(web.url, "https://[2001:db8::1]:3002/api");
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
