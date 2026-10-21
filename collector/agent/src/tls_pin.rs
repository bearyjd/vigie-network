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
use webpki::EndEntityCert;

use crate::transport::Pin;

/// SHA-256 of the certificate's SubjectPublicKeyInfo DER (tag and length included): the value
/// `deploy/gen-certs.sh` prints and the config file holds. The certificate is parsed by webpki (the
/// same parser the handshake signature check uses), so anything it refuses has no pin.
pub fn spki_pin(cert: &[u8]) -> Option<Pin> {
    let der = CertificateDer::from(cert);
    let cert = EndEntityCert::try_from(&der).ok()?;
    Some(Sha256::digest(cert.subject_public_key_info().as_ref()).into())
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
