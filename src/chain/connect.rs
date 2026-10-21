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
/// Its refusals quote the address: what reaches it has been through
/// [`refuse_wallet_material`], so it holds no key, no seed and no space.
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
                if !is_bare_ipv6(rest) {
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
    refuse_wallet_material(text)?;

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
    // Only a letter is a flag, and only outside a bare IPv6 literal. A
    // one-character *digit* is a port, or the last group of such a
    // literal — `2001:db8::1` and `host.example:5` both end in one
    // character and neither is a connection type — and the last group
    // of `2001:db8::a` is a letter that is no connection type either.
    if let Some((head, flag)) = split_flag(text) {
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

/// Refuses a server address whose host is wallet material: a key or an
/// address pasted into the host field of the settings form, which the
/// form sends on behind `ssl://`, past the check on what the text
/// starts with. Taken for a host name, it would go to the system's
/// resolver in the clear the first time the server was tried. The host
/// is read as typed, since a base58 key or address only reads as one in
/// its own case, and as the URL parser reads it. A private key or a
/// seed phrase is refused first, unquoted ([`refuse_typed_secret`]).
pub(crate) fn refuse_wallet_material(text: &str) -> CoreResult<()> {
    refuse_typed_secret(text, "server")?;
    let canonical = super::host_of(text);
    for host in std::iter::once(typed_host(text)).chain(canonical.as_deref()) {
        if let Some(what) = wallet_material(host) {
            return Err(reject(format!(
                "the host is {what}, not the name of a server"
            )));
        }
    }
    Ok(())
}

/// Refuses an address typed by hand that holds a secret: a private key
/// anywhere in it, or a seed phrase in its host. The form puts a scheme
/// before what was typed and a port after it, which the check on the
/// whole text does not read as words ([`typed_words`]), and the URL
/// parser reads a host with its `%xx` escapes decoded, so the text is
/// read both as typed and decoded. A space in the host is refused next,
/// without quoting the text either: no host holds one, and words that
/// are not quite a seed phrase may still be one. `kind` names the field
/// in that refusal.
pub(crate) fn refuse_typed_secret(text: &str, kind: &'static str) -> CoreResult<()> {
    let decoded = percent_decoded(text);
    for form in [text, &decoded] {
        crate::input::reject_private_material(form)?;
        crate::input::reject_private_material(typed_words(form))?;
    }
    if text.trim().contains(char::is_whitespace)
        || typed_words(&decoded).contains(char::is_whitespace)
    {
        return Err(CoreError::InvalidInput {
            kind,
            detail: "the address has a space in it".to_owned(),
        });
    }
    Ok(())
}

/// The text with every `%xx` escape decoded, the way the URL parser
/// reads a host; an escape that does not name a byte stays as written,
/// and a byte that is not UTF-8 reads as the replacement character.
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .filter(|hex| bytes[i] == b'%' && hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The host of a server address as it was typed: after the scheme and
/// any userinfo, up to the port or the path. An IPv6 literal comes back
/// as its opening bracket and first group, which is no wallet material.
/// Spaces are kept, so a seed phrase comes back as its words.
fn typed_host(text: &str) -> &str {
    let text = text.trim();
    let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.split(':').next().unwrap_or_default()
}

/// What was typed as the host, read for the words of a seed phrase.
/// The settings form wraps what was typed: a scheme before it, a port
/// after it, and on the desktop brackets around a host with a colon, as
/// around an IPv6 literal. Typed with a scheme and a port of its own,
/// `ssl://words:50002` reaches the core as
/// `ssl://[ssl://words:50002]:50002`. Every bracket and scheme in front
/// is peeled off before the host is cut out, and a closing bracket
/// after it.
fn typed_words(text: &str) -> &str {
    let mut rest = text.trim();
    loop {
        let unbracketed = rest.trim_start_matches('[');
        let next = match unbracketed.split_once("://") {
            Some((scheme, after))
                if !scheme.is_empty()
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
            {
                after
            }
            _ => unbracketed,
        };
        if next == rest {
            return typed_host(rest).trim_end_matches(']');
        }
        rest = next;
    }
}

/// What a host is when it is wallet material rather than a name: a
/// Bitcoin address, on any network and in either case bech32 allows,
/// or an extended key. Both carry a checksum, so no server name passes
/// for one.
fn wallet_material(host: &str) -> Option<&'static str> {
    use bdk_wallet::bitcoin::address::{Address, NetworkUnchecked};
    use bdk_wallet::bitcoin::base58;
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.parse::<Address<NetworkUnchecked>>().is_ok() {
        return Some("a Bitcoin address");
    }
    if base58::decode_check(host).is_ok_and(|data| data.len() == 78) {
        return Some("an extended public key");
    }
    None
}

/// The form a custom backend address is stored in, read the way a
/// scan is: the host in lower case, its trailing dot dropped, an IPv6
/// literal in brackets, an Electrum address with its port, and a bare
/// `host:port` as TLS, the way the Electrum client reads it, unless
/// the one-line form says otherwise. An address the parser cannot
/// read is refused with the reason: stored as typed,
/// `tcp://x.onion:50001:extra` would reach the sync as an address the
/// URL parser gives up on, no onion to its eyes, and go to the
/// resolver in the clear. An address already in this form comes back
/// byte for byte, so the certificate accepted for it stays keyed to
/// it.
pub(crate) fn stored_form(kind: ScannedBackendKind, url: &str) -> CoreResult<String> {
    let text = url.trim();
    let scanned = match kind {
        ScannedBackendKind::Esplora => {
            if !text.contains("://") {
                return Err(reject("an Esplora address starts with http:// or https://"));
            }
            parse_backend(text)?
        }
        ScannedBackendKind::Electrum => {
            if text.contains("://") || split_flag(text).is_some() {
                parse_backend(text)?
            } else if is_bare_ipv6(text) {
                // In brackets, so the parser tells the address from a
                // port.
                parse_backend(&format!("ssl://[{text}]"))?
            } else {
                parse_backend(&format!("ssl://{text}"))?
            }
        }
    };
    if scanned.kind != kind {
        return Err(reject(match kind {
            ScannedBackendKind::Esplora => "an Esplora address starts with http:// or https://",
            ScannedBackendKind::Electrum => "an Electrum address starts with ssl:// or tcp://",
        }));
    }
    Ok(scanned.url)
}

fn strip_path(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or_default()
}

/// Whether the text can only be a bare IPv6 literal: hex digits,
/// colons and dots and nothing else, with more than one colon. Its
/// last group is often one character long, and in `2001:db8::a` that
/// character is a letter, without being a connection flag.
fn is_bare_ipv6(text: &str) -> bool {
    text.matches(':').count() > 1
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

/// The connection flag of an Electrum one-liner split off the rest,
/// `host:port` and `s` for `host:port:s`. Any single letter is taken
/// for a flag, so that one which is not `s` or `t` is refused by name
/// rather than read as a port. `None` when the text has no such tail,
/// or is a bare IPv6 literal, whose last group may be one hex letter.
fn split_flag(text: &str) -> Option<(&str, &str)> {
    if is_bare_ipv6(text) {
        return None;
    }
    let (head, flag) = text.rsplit_once(':')?;
    (flag.len() == 1 && flag.chars().all(|c| c.is_ascii_alphabetic())).then_some((head, flag))
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

    /// What the settings store is what a scan would have read, and an
    /// address in that form already is stored as it is.
    #[test]
    fn a_stored_address_is_read_the_way_a_scan_is() {
        use ScannedBackendKind::{Electrum, Esplora};
        let stored = |kind, url| stored_form(kind, url).unwrap();
        assert_eq!(
            stored(Electrum, "SSL://Node.Example.ORG.:50002"),
            "ssl://node.example.org:50002"
        );
        assert_eq!(
            stored(Electrum, "ssl://node.example.org:50002"),
            "ssl://node.example.org:50002"
        );
        assert_eq!(
            stored(Electrum, "tcp://x.onion:50001"),
            "tcp://x.onion:50001"
        );
        // A bare address is TLS, the way the connection reads it,
        // whatever its port; the one-line form says its transport.
        assert_eq!(
            stored(Electrum, "node.example.org:50001"),
            "ssl://node.example.org:50001"
        );
        assert_eq!(
            stored(Electrum, "node.example.org:50001:t"),
            "tcp://node.example.org:50001"
        );
        assert_eq!(stored(Electrum, "2001:DB8::1"), "ssl://[2001:db8::1]:50002");
        // A last group of one hex letter is no connection flag.
        assert_eq!(stored(Electrum, "2001:db8::a"), "ssl://[2001:db8::a]:50002");
        assert_eq!(
            stored(Electrum, "[2001:db8::a]:50002"),
            "ssl://[2001:db8::a]:50002"
        );
        assert_eq!(
            stored(Electrum, "node.example.org:50002:t"),
            "tcp://node.example.org:50002"
        );
        assert_eq!(
            stored(Electrum, " ssl://node.example.org:50002 "),
            "ssl://node.example.org:50002"
        );
        assert_eq!(
            stored(Esplora, "HTTPS://Esplora.Example.ORG./api/"),
            "https://esplora.example.org/api"
        );
        assert_eq!(
            stored(Esplora, "https://esplora.example.org/api"),
            "https://esplora.example.org/api"
        );
        assert_eq!(stored(Esplora, "http://x.onion"), "http://x.onion");

        let refused = |kind, url: &str| stored_form(kind, url).unwrap_err().to_string();
        assert!(
            refused(Electrum, "tcp://x.onion:50001:extra").contains("more than one colon"),
            "{}",
            refused(Electrum, "tcp://x.onion:50001:extra")
        );
        assert!(refused(Electrum, "ssl://x.onion:99999").contains("99999 is not a port number"));
        assert!(refused(Electrum, "https://node.example.org").contains("ssl:// or tcp://"));
        assert!(
            refused(Esplora, "ssl://esplora.example.org:50002").contains("http:// or https://")
        );
        assert!(refused(Esplora, "esplora.example.org/api").contains("http:// or https://"));
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
    /// letter outside a bare IPv6 literal. A digit there is a port, or
    /// the last group of such a literal, and a hex letter is its last
    /// group as well — reading any of them as `s`/`t` refused an
    /// address that was perfectly good, with a message about Electrum
    /// transports.
    #[test]
    fn a_one_character_tail_is_a_flag_only_outside_an_ipv6_literal() {
        let bare = ok("2001:db8::1");
        assert_eq!(bare.host, "2001:db8::1");
        assert_eq!(bare.url, "ssl://[2001:db8::1]:50002");

        let lettered = ok("2001:db8::a");
        assert_eq!(lettered.host, "2001:db8::a");
        assert_eq!(lettered.url, "ssl://[2001:db8::a]:50002");
        assert_eq!(ok("[2001:db8::a]:50002").url, "ssl://[2001:db8::a]:50002");

        let short_port = ok("node.example.org:5");
        assert_eq!(short_port.port, Some(5));

        // The one-liner reads its flag as before.
        assert_eq!(ok("host.example:50002:t").url, "tcp://host.example:50002");
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

    /// A key or an address pasted into the host field reaches the
    /// parser behind the scheme the form puts in front of it, past the
    /// check on what the text starts with. Taken for a host name, it
    /// would go to the system's resolver. Whatever form the address
    /// takes, it is refused, and stored in none.
    #[test]
    fn wallet_material_in_the_host_is_refused() {
        use ScannedBackendKind::{Electrum, Esplora};
        let tpub = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let segwit = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let legacy = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let nested = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        let test = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        for (kind, text) in [
            (Electrum, format!("ssl://{tpub}:50002")),
            (Electrum, format!("tcp://{xpub}:50001")),
            (Electrum, format!("electrum://{xpub}.:50001")),
            (Electrum, format!("ssl://{segwit}:50002")),
            (Electrum, format!("ssl://{}:50002", segwit.to_uppercase())),
            (Electrum, format!("{legacy}:50002:s")),
            (Electrum, format!("{nested}:50001")),
            (Electrum, format!("tls://{test}")),
            (Esplora, format!("https://{test}/api")),
            (Esplora, format!("https://user:pass@{nested}:3002/api")),
            (Esplora, format!("http://{tpub}/api")),
        ] {
            let error = parse_backend(&text).unwrap_err().to_string();
            assert!(
                error.contains("not the name of a server"),
                "{text}: {error}"
            );
            assert!(stored_form(kind, &text).is_err(), "{text}");
            assert!(refuse_wallet_material(&text).is_err(), "{text}");
        }
        // A private key is refused as one, and never quoted back.
        let tprv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
        let error = parse_backend(&format!("ssl://{tprv}:50002")).unwrap_err();
        assert!(
            matches!(error, CoreError::PrivateMaterialRejected),
            "{error}"
        );
        // A server whose name merely starts like a key still reads.
        assert_eq!(ok("ssl://xpub.example.org:50002").host, "xpub.example.org");
        assert_eq!(ok("tcp://tpubnode.example:50001").host, "tpubnode.example");
        assert_eq!(ok("https://bc1.example.org/api").host, "bc1.example.org");
        assert_eq!(ok("[2001:db8::1]:50002").host, "2001:db8::1");
    }

    /// A seed phrase or a private key typed into the host field reaches
    /// the parser between a scheme and a port, `ssl://` before it and
    /// `:50002` after it: the first word and the last are then no words,
    /// and the whole was quoted back in the refusal of its second colon.
    /// Every form of it is refused as private material, and none is
    /// quoted.
    #[test]
    fn a_secret_typed_as_a_host_is_refused_unquoted() {
        use ScannedBackendKind::{Electrum, Esplora};
        let twelve = ["abandon"; 11].join(" ") + " about";
        let twenty_four = ["abandon"; 23].join(" ") + " art";
        // Spelled as an extended private key: the check reads the
        // prefix, so no key is needed to show it.
        let xprv = "xprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
        let tprv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L";
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        for secret in [twelve.as_str(), twenty_four.as_str(), xprv, tprv, wif] {
            let electrum = [
                format!("{secret}:50002"),
                format!("{secret}:50002:s"),
                format!("ssl://{secret}"),
                format!("ssl://{secret}:50002"),
                // What the settings form sends for `secret:50002` typed
                // in the host field, the port in its own.
                format!("ssl://{secret}:50002:50002"),
                format!("tcp://{secret}:50001:50001"),
                // The same from the desktop, which brackets a host that
                // holds a colon, as it would an IPv6 literal.
                format!("ssl://[{secret}:50002]:50002"),
                format!("ssl://[{secret}]:50002"),
                // Typed with a scheme of its own, from either app.
                format!("ssl://[ssl://{secret}:50002]:50002"),
                format!("ssl://tcp://{secret}:50001:50002"),
            ];
            let esplora = [
                format!("https://{secret}"),
                format!("https://{secret}:3002/api"),
                format!("http://{secret}:3000"),
            ];
            let typed = electrum
                .iter()
                .map(|text| (Electrum, text))
                .chain(esplora.iter().map(|text| (Esplora, text)));
            for (kind, text) in typed {
                for error in [
                    parse_backend(text).unwrap_err(),
                    stored_form(kind, text).unwrap_err(),
                    refuse_wallet_material(text).unwrap_err(),
                ] {
                    assert!(
                        matches!(error, CoreError::PrivateMaterialRejected),
                        "{text}: {error}"
                    );
                }
            }
        }

        // The URL parser reads a host with its escapes decoded: a seed
        // or a key spelled in them is refused as one.
        let escaped = twelve.replace(' ', "%20");
        for text in [
            format!("ssl://{escaped}:50002:50002"),
            format!("ssl://[{escaped}:50002]:50002"),
            format!("https://{escaped}/api"),
            format!("https://%61{}:3002", &escaped[1..]),
            format!("ssl://%78{}:50002", &xprv[1..]),
            format!("tcp://%35{}:50001", &wif[1..]),
        ] {
            let error = parse_backend(&text).unwrap_err();
            assert!(
                matches!(error, CoreError::PrivateMaterialRejected),
                "{text}: {error}"
            );
            assert!(refuse_typed_secret(&text, "server").is_err(), "{text}");
        }

        // Words that are not quite a seed phrase are still never quoted:
        // no host holds a space.
        for text in [
            format!("ssl://{}:50002:50002", ["abandon"; 11].join(" ")),
            format!("ssl://Abandon {}:50002:50002", ["abandon"; 11].join(" ")),
            format!("https://{} about/api", ["abandon"; 10].join(" ")),
            format!("{}://node.example.org", ["abandon"; 12].join(" ")),
            format!("ssl://{}:50002", ["abandon"; 11].join("%20")),
        ] {
            let error = parse_backend(&text).unwrap_err().to_string();
            assert!(error.contains("has a space in it"), "{text}: {error}");
            assert!(!error.contains("abandon"), "{text}: {error}");
        }
    }

    /// A server name in a refusal says which part was read wrong: once
    /// the address is known to hold no secret, it is still quoted.
    #[test]
    fn an_ordinary_host_is_still_named_in_its_refusals() {
        for (text, quoted) in [
            (
                "ssl://node.example.org:50002:50002",
                "node.example.org:50002:50002 has more than one colon",
            ),
            ("ssl://node.example.org:99999", "99999 is not a port number"),
            (
                "ssl://evil.com\\.onion:50002",
                "evil.com\\.onion is not a host name",
            ),
            (
                "nodeexample:50002",
                "nodeexample does not look like a server address",
            ),
            (
                "https://node.example.org:99999",
                "https://node.example.org:99999",
            ),
        ] {
            let error = parse_backend(text).unwrap_err().to_string();
            assert!(error.contains(quoted), "{text}: {error}");
        }
        assert_eq!(
            stored_form(ScannedBackendKind::Electrum, "node.example.org:50002").unwrap(),
            "ssl://node.example.org:50002"
        );
        assert_eq!(
            ok("https://esplora.example.org/api").url,
            "https://esplora.example.org/api"
        );
        // An escape in a path is no host: it reads as it did.
        assert_eq!(
            ok("https://esplora.example.org/a%20b").url,
            "https://esplora.example.org/a%20b"
        );
        assert_eq!(
            ok("ssl://node%2Eexample.org:50002").host,
            "node.example.org"
        );
    }
}
