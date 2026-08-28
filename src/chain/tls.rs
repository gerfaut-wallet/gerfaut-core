//! TLS for Electrum servers, with trust on first use.
//!
//! Most Electrum servers people run — electrs and Fulcrum in the lead —
//! present a certificate no public authority vouches for. A client has
//! three options: refuse them (Gerfaut used to, so self-hosting did not
//! work), accept anything (a lie: the connection is then unauthenticated
//! under a padlock), or do what SSH does — show the fingerprint, let the
//! user accept it once, remember it, and shout when it changes.
//!
//! The third one is implemented here, and the check happens **inside the
//! handshake of the connection that carries the data**. Probing the
//! certificate on one connection and then opening a second one with
//! verification off would leave a window for a man in the middle to let
//! the probe through and answer the real connection itself.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

/// What the handshake concluded about the server's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A public certificate authority vouches for it, and it matches the
    /// host: nothing to ask the user.
    Trusted,
    /// No authority vouches for it, but it is exactly the certificate
    /// the user accepted for this host.
    Pinned,
    /// No authority vouches for it and this host has no accepted
    /// fingerprint yet. The user decides, with the certificate's own
    /// words in front of them.
    Unknown {
        fingerprint: String,
        reason: String,
        /// What the certificate calls itself, when it says so.
        subject: Option<String>,
        /// When it stops being valid, in seconds since the epoch.
        expires: Option<i64>,
    },
    /// This host has an accepted fingerprint and the server presents a
    /// different certificate. Never accepted silently.
    Changed { stored: String, presented: String },
}

/// Why a connection could not be opened.
#[derive(Debug, Clone)]
pub(crate) enum ConnectError {
    /// The certificate was refused; the verdict says what to tell the user.
    Certificate(Verdict),
    /// Everything else: name resolution, refused connection, timeout.
    Io(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Io(detail) => write!(f, "{detail}"),
            ConnectError::Certificate(Verdict::Unknown {
                fingerprint,
                reason,
                ..
            }) => write!(
                f,
                "the server's certificate is not vouched for by any public authority ({reason}); \
                 its fingerprint is {fingerprint} — accept it in Settings to connect"
            ),
            ConnectError::Certificate(Verdict::Changed { stored, presented }) => write!(
                f,
                "the server's certificate changed: this host was accepted as {stored} and now \
                 presents {presented} — check with whoever runs it before accepting the new one"
            ),
            // Trusted and Pinned never reach an error.
            ConnectError::Certificate(_) => write!(f, "certificate refused"),
        }
    }
}

/// SHA-256 of the certificate, in the shape every tool prints it:
/// uppercase hex pairs joined by colons, the same string `openssl x509
/// -noout -fingerprint -sha256` returns. One format everywhere means a
/// user can compare it by eye without converting anything.
pub fn fingerprint_of(der: &[u8]) -> String {
    let digest = sha256::Hash::hash(der);
    digest
        .to_byte_array()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What the certificate says about itself: the name it carries and the
/// day it stops being valid. Both are `None` when it cannot be read,
/// which never blocks anything — the fingerprint is what is trusted.
fn describe(der: &[u8]) -> (Option<String>, Option<i64>) {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => (
            Some(cert.subject().to_string()).filter(|s| !s.is_empty()),
            Some(cert.validity().not_after.timestamp()),
        ),
        Err(_) => (None, None),
    }
}

/// The public key bytes a signature verifier needs, straight out of the
/// certificate: the `subjectPublicKey` of its `SubjectPublicKeyInfo`.
fn public_key_of(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(cert.public_key().subject_public_key.data.to_vec())
}

/// Whether a string is a fingerprint in that shape. Guards the stored
/// map against anything else finding its way in.
pub fn is_fingerprint(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 32
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The crypto provider both this module and `electrum-client` use.
fn provider() -> Arc<CryptoProvider> {
    // `electrum-client` installs the same ring provider the first time
    // it opens a TLS connection; installing it here first is harmless
    // and makes this module usable on its own.
    if CryptoProvider::get_default().is_none() {
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    }
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Verifier that decides between the public authorities and the
/// fingerprint the user accepted, and records what it saw so the caller
/// can tell the user exactly what happened.
#[derive(Debug)]
struct Tofu {
    webpki: Arc<WebPkiServerVerifier>,
    pin: Option<String>,
    verdict: Mutex<Option<Verdict>>,
    provider: Arc<CryptoProvider>,
}

impl Tofu {
    fn record(&self, verdict: Verdict) {
        if let Ok(mut slot) = self.verdict.lock() {
            *slot = Some(verdict);
        }
    }

    /// Verifies the handshake signature against the key inside the
    /// certificate itself.
    ///
    /// `webpki` refuses to read a certificate older than X.509 v3, which
    /// several long-lived Electrum servers still present. Refusing them
    /// outright would send their users back to turning verification off
    /// somewhere else, so the signature is checked here instead — the
    /// same check, over the same bytes, on a certificate the user has
    /// accepted by fingerprint. It never applies to the public-authority
    /// path: a certificate meant to be vouched for must parse.
    fn verify_with_own_key(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        original: rustls::Error,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if !matches!(
            self.verdict.lock().ok().and_then(|v| v.clone()),
            Some(Verdict::Pinned)
        ) {
            return Err(original);
        }
        let Some(key) = public_key_of(cert.as_ref()) else {
            return Err(original);
        };
        let algorithms = &self.provider.signature_verification_algorithms;
        let verified = algorithms
            .mapping
            .iter()
            .filter(|(scheme, _)| *scheme == dss.scheme)
            .flat_map(|(_, algorithms)| algorithms.iter())
            .any(|algorithm| {
                algorithm
                    .verify_signature(&key, message, dss.signature())
                    .is_ok()
            });
        if verified {
            Ok(HandshakeSignatureValid::assertion())
        } else {
            Err(original)
        }
    }
}

impl ServerCertVerifier for Tofu {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = fingerprint_of(end_entity.as_ref());
        match self.pin.as_deref() {
            // An accepted fingerprint replaces the authority chain
            // entirely: a self-signed certificate has no chain to walk,
            // and its name rarely matches the host it is reached at.
            Some(pinned) if pinned == presented => {
                self.record(Verdict::Pinned);
                Ok(ServerCertVerified::assertion())
            }
            Some(pinned) => {
                self.record(Verdict::Changed {
                    stored: pinned.to_owned(),
                    presented,
                });
                Err(rustls::Error::General(
                    "the server's certificate changed".to_owned(),
                ))
            }
            None => match self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(verified) => {
                    self.record(Verdict::Trusted);
                    Ok(verified)
                }
                Err(error) => {
                    let (subject, expires) = describe(end_entity.as_ref());
                    self.record(Verdict::Unknown {
                        fingerprint: presented,
                        reason: reason_of(&error),
                        subject,
                        expires,
                    });
                    Err(error)
                }
            },
        }
    }

    // Whichever way the certificate is trusted, the server still has to
    // prove it holds the matching private key: these two stay real. An
    // accepted fingerprint says which certificate to expect, not that
    // whoever presents a copy of it may speak for the server.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
        .or_else(|error| self.verify_with_own_key(message, cert, dss, error))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
        .or_else(|error| self.verify_with_own_key(message, cert, dss, error))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Short reason, in the words a user can act on.
fn reason_of(error: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match error {
        rustls::Error::InvalidCertificate(C::UnknownIssuer) => {
            "self-signed, or signed by an authority this machine does not know".to_owned()
        }
        rustls::Error::InvalidCertificate(C::Expired) => "expired".to_owned(),
        rustls::Error::InvalidCertificate(C::NotValidYet) => "not valid yet".to_owned(),
        rustls::Error::InvalidCertificate(C::NotValidForName) => {
            "issued for a different host name".to_owned()
        }
        other => other.to_string(),
    }
}

/// Opens a TLS connection to `host:port`.
///
/// `pin` is the fingerprint the user accepted for this host, if any.
/// The returned stream is ready to carry Electrum traffic: the
/// handshake is complete, so a certificate problem surfaces here and
/// never half-way through a sync.
pub(crate) fn connect(
    host: &str,
    port: u16,
    pin: Option<&str>,
    timeout: Duration,
) -> Result<rustls::StreamOwned<ClientConnection, TcpStream>, ConnectError> {
    let provider = provider();
    let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| ConnectError::Io(e.to_string()))?;
    let verifier = Arc::new(Tofu {
        webpki,
        pin: pin.map(str::to_owned),
        verdict: Mutex::new(None),
        provider: provider.clone(),
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ConnectError::Io(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    // An IP address is a legitimate way to reach one's own server; it
    // becomes the SNI-less variant of the name, which rustls handles.
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| ConnectError::Io(format!("{host} is not a usable host name")))?;
    let mut session = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| ConnectError::Io(e.to_string()))?;

    let mut socket = tcp_connect(host, port, timeout)?;
    // Finish the handshake now: a refused certificate is a connection
    // error, not a surprise on the first read.
    if let Err(error) = session.complete_io(&mut socket) {
        return Err(match verifier.verdict.lock().ok().and_then(|v| v.clone()) {
            Some(verdict @ (Verdict::Unknown { .. } | Verdict::Changed { .. })) => {
                ConnectError::Certificate(verdict)
            }
            _ => ConnectError::Io(error.to_string()),
        });
    }

    Ok(rustls::StreamOwned::new(session, socket))
}

/// The verdict a completed or refused handshake produced, for the
/// settings screen. Reuses the connection path above so what the user
/// is told is what a sync would actually meet.
pub(crate) fn inspect(
    host: &str,
    port: u16,
    pin: Option<&str>,
    timeout: Duration,
) -> Result<Verdict, ConnectError> {
    match connect(host, port, pin, timeout) {
        Ok(_) => Ok(if pin.is_some() {
            Verdict::Pinned
        } else {
            Verdict::Trusted
        }),
        Err(ConnectError::Certificate(verdict)) => Ok(verdict),
        Err(other) => Err(other),
    }
}

/// Connects to the first address the host resolves to that answers.
fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, ConnectError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|e| ConnectError::Io(format!("{host} does not resolve: {e}")))?;
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(socket) => {
                socket
                    .set_read_timeout(Some(timeout))
                    .and_then(|()| socket.set_write_timeout(Some(timeout)))
                    .map_err(|e| ConnectError::Io(e.to_string()))?;
                return Ok(socket);
            }
            Err(error) => last = Some(error.to_string()),
        }
    }
    Err(ConnectError::Io(last.unwrap_or_else(|| {
        format!("{host}:{port} has no address to connect to")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_read_for_what_it_says_about_itself() {
        // Anything that is not a certificate simply says nothing, and
        // never stands in the way of showing the fingerprint.
        assert_eq!(describe(b"not a certificate"), (None, None));
        assert_eq!(public_key_of(b"not a certificate"), None);
    }

    #[test]
    fn a_fingerprint_reads_like_openssl_prints_it() {
        // SHA-256 of the empty input, the one digest every tool agrees on.
        let printed = fingerprint_of(&[]);
        assert_eq!(
            printed,
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:\
             27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
                .replace(' ', "")
        );
        assert!(is_fingerprint(&printed));
    }

    #[test]
    fn anything_that_is_not_a_fingerprint_is_refused() {
        assert!(!is_fingerprint(""));
        assert!(!is_fingerprint("AB:CD"));
        assert!(!is_fingerprint("ZZ:".repeat(31).trim_end_matches(':')));
        // The right length in the wrong shape stays out.
        assert!(!is_fingerprint(&"AB".repeat(32)));
    }

    #[test]
    fn an_unusable_host_name_is_an_io_error_not_a_certificate_one() {
        let error = connect("not a host", 50002, None, Duration::from_millis(200))
            .expect_err("connecting to a broken name must fail");
        assert!(matches!(error, ConnectError::Io(_)));
    }
}
