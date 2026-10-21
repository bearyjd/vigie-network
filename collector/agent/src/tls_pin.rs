//! TLS client configuration that authenticates the server by SPKI pin only.
//!
//! The server certificate is self-signed and the router may have a wrong clock, so the chain,
//! host name and validity period are deliberately NOT checked. What is checked instead:
//!   1. SHA-256 of the certificate's SubjectPublicKeyInfo DER equals one of the configured pins;
//!   2. the TLS handshake signature verifies under that certificate's key (so the peer really holds
//!      the private key), using the ring provider's algorithms.
//!
//! Only TLS 1.2 and 1.3 exist in this build (rustls has no older protocol code).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::transport::Pin;

/// One DER TLV: (content, whole element, bytes after it). Lengths above 64 KiB are refused.
fn tlv(input: &[u8], want_tag: u8) -> Option<(&[u8], &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag != want_tag {
        return None;
    }
    let (&l0, rest) = rest.split_first()?;
    let (len, hdr): (usize, usize) = match l0 {
        0..=0x7f => (usize::from(l0), 2),
        0x81 => (usize::from(*rest.first()?), 3),
        0x82 => (
            usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?])),
            4,
        ),
        _ => return None,
    };
    let total = hdr.checked_add(len)?;
    if input.len() < total {
        return None;
    }
    Some((&input[hdr..total], &input[..total], &input[total..]))
}

/// The whole SubjectPublicKeyInfo element (tag and length included) of an X.509 certificate.
/// Strict about structure: no trailing bytes, fields in RFC 5280 order.
pub fn spki_der(cert: &[u8]) -> Option<&[u8]> {
    let (cert_body, _, trailing) = tlv(cert, 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (mut f, _, _) = tlv(cert_body, 0x30)?; // tbsCertificate
    if f.first() == Some(&0xa0) {
        f = tlv(f, 0xa0)?.2; // [0] version
    }
    f = tlv(f, 0x02)?.2; // serialNumber
    for tag in [0x30, 0x30, 0x30, 0x30] {
        f = tlv(f, tag)?.2; // signature, issuer, validity, subject
    }
    Some(tlv(f, 0x30)?.1)
}

/// SHA-256 of the SPKI DER: the value `deploy/gen-certs.sh` prints and the config file holds.
pub fn spki_pin(cert: &[u8]) -> Option<Pin> {
    spki_der(cert).map(|s| Sha256::digest(s).into())
}

/// Equal-length byte comparison that does not stop at the first difference.
fn ct_eq(a: &Pin, b: &Pin) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug)]
pub struct PinVerifier {
    pins: Vec<Pin>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    pub fn new(pins: &[Pin], provider: &CryptoProvider) -> Self {
        Self {
            pins: pins.to_vec(),
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let pin = spki_pin(end_entity.as_ref())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        // Compare against every pin without an early exit.
        let hits = self
            .pins
            .iter()
            .fold(0u8, |n, p| n | u8::from(ct_eq(p, &pin)));
        if hits == 1 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// TLS 1.3 + 1.2 client config (ring provider) that accepts exactly the pinned keys.
pub fn client_config(pins: &[Pin]) -> Result<ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier::new(pins, &provider));
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // One request per connection: a session cache would only cost RAM.
    cfg.resumption = Resumption::disabled();
    Ok(cfg)
}
