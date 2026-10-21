//! SPKI-pin verifier: what the HTTPS transport accepts and refuses at the TLS layer.
//! Every case goes through a real handshake against a local rustls server.

mod tls_common;

use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tls_common::*;
use vigie_agent::https::HttpsTransport;
use vigie_agent::sender::{Transport, TransportError};
use vigie_agent::tls_pin::{spki_pin, PinVerifier};
use vigie_agent::transport::PinnedTransport;

/// POST against a server presenting `cert`, handshake-signing with `signer`, client pinned to `pins`.
fn try_post(
    cert: &Ident,
    signer: &Ident,
    pins: &[String],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<u16, TransportError> {
    let srv = spawn(
        server_config(&cert.cert, &signer.key, versions),
        respond(ok_response("{}")),
    );
    let pt = PinnedTransport::new(&srv.url(), pins).unwrap();
    let mut t = HttpsTransport::new(pt)
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    let r = t.post(&headers(), b"{}").map(|r| r.status);
    let _ = srv.request();
    r
}

fn pins(a: &Ident, b: &Ident) -> Vec<String> {
    vec![a.pin_hex(), b.pin_hex()]
}

#[test]
fn matching_first_pin_is_accepted() {
    let (srv, other) = (Ident::new(), Ident::new());
    assert_eq!(
        try_post(&srv, &srv, &pins(&srv, &other), BOTH).unwrap(),
        200
    );
}

#[test]
fn matching_second_pin_is_accepted() {
    let (srv, other) = (Ident::new(), Ident::new());
    assert_eq!(
        try_post(&srv, &srv, &pins(&other, &srv), BOTH).unwrap(),
        200
    );
}

#[test]
fn wrong_pins_are_refused() {
    let (srv, a, b) = (Ident::new(), Ident::new(), Ident::new());
    let e = try_post(&srv, &srv, &pins(&a, &b), BOTH).unwrap_err();
    assert!(e.0.contains("certificate"), "{e:?}");
}

#[test]
fn reissued_cert_with_the_same_key_is_accepted() {
    let (orig, other) = (Ident::new(), Ident::new());
    let renewed = orig.reissue(987_654_321, (2026, 6, 1), (2031, 6, 1));
    assert_ne!(orig.cert, renewed.cert);
    assert_eq!(
        try_post(&renewed, &renewed, &pins(&orig, &other), BOTH).unwrap(),
        200
    );
}

#[test]
fn different_key_with_identical_subject_is_refused() {
    let (orig, other) = (Ident::new(), Ident::new());
    let impostor = Ident::new(); // same names and dates, fresh key
    assert!(try_post(&impostor, &impostor, &pins(&orig, &other), BOTH).is_err());
}

#[test]
fn expired_and_not_yet_valid_certs_are_accepted_when_the_pin_matches() {
    // The router clock may be wrong, so validity is deliberately ignored. This is a documented
    // property, not an oversight: the pin is the only trust anchor.
    let (other, expired, future) = (Ident::new(), Ident::new(), Ident::new());
    let old = expired.reissue(5, (2001, 1, 1), (2002, 1, 1));
    let new = future.reissue(6, (2080, 1, 1), (2090, 1, 1));
    assert_eq!(
        try_post(&old, &old, &pins(&old, &other), BOTH).unwrap(),
        200
    );
    assert_eq!(
        try_post(&new, &new, &pins(&new, &other), BOTH).unwrap(),
        200
    );
}

#[test]
fn handshake_signed_by_a_different_key_is_refused() {
    // The server presents the pinned certificate (public data) but cannot sign with its key.
    let (genuine, attacker) = (Ident::new(), Ident::new());
    for v in [
        &[&rustls::version::TLS13][..],
        &[&rustls::version::TLS12][..],
    ] {
        let r = try_post(&genuine, &attacker, &pins(&genuine, &genuine), v);
        assert!(
            r.is_err(),
            "forged handshake signature accepted ({v:?} only)"
        );
    }
}

#[test]
fn both_tls_versions_work_and_nothing_older_exists() {
    let srv = Ident::new();
    let p = pins(&srv, &srv);
    assert_eq!(
        try_post(&srv, &srv, &p, &[&rustls::version::TLS13]).unwrap(),
        200
    );
    assert_eq!(
        try_post(&srv, &srv, &p, &[&rustls::version::TLS12]).unwrap(),
        200
    );
}

#[test]
fn garbage_certificate_is_refused_not_a_panic() {
    let v = verifier(&[[0u8; 32]]);
    let name = ServerName::try_from("localhost").unwrap();
    for junk in [
        &b""[..],
        b"\x30\x00",
        b"\x30\x84\xff\xff\xff\xff",
        &[0u8; 64],
    ] {
        let cert = CertificateDer::from(junk.to_vec());
        assert!(v
            .verify_server_cert(
                &cert,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(Duration::ZERO)
            )
            .is_err());
    }
}

fn verifier(pins: &[[u8; 32]]) -> PinVerifier {
    PinVerifier::new(pins, &rustls::crypto::ring::default_provider())
}

#[test]
fn spki_pin_matches_independent_computation_and_openssl() {
    let id = Ident::new();
    assert_eq!(spki_pin(id.cert.as_ref()), Some(id.pin()));
    // Truncated or padded DER has no pin.
    let mut padded = id.cert.to_vec();
    padded.push(0);
    assert_eq!(spki_pin(&padded), None);
    assert_eq!(spki_pin(&id.cert[..id.cert.len() - 1]), None);

    // The value operators get from deploy/gen-certs.sh is
    // `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`.
    let dir = std::env::temp_dir().join(format!("vigie-pin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let crt = dir.join("c.der");
    std::fs::write(&crt, &id.cert).unwrap();
    let script = format!(
        "openssl x509 -inform der -in {} -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -r | cut -d' ' -f1",
        crt.display()
    );
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
    {
        Ok(o) if o.status.success() => {
            assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), id.pin_hex());
        }
        _ => eprintln!("openssl not usable here: skipped the gen-certs.sh cross-check"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_pins_accepts_nothing() {
    let srv = Ident::new();
    assert!(try_post(&srv, &srv, &[Ident::new().pin_hex()], BOTH).is_err());
    let v = verifier(&[]);
    let name = ServerName::try_from("localhost").unwrap();
    assert!(v
        .verify_server_cert(
            &srv.cert,
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(Duration::ZERO)
        )
        .is_err());
}

#[test]
fn old_tls_versions_are_refused_by_openssl_server() {
    // rustls has no TLS 1.0/1.1 code at all, so there is nothing to enable by mistake. This is
    // an end-to-end check where the local openssl and crypto policy allow starting such a server.
    let id = Ident::new();
    let dir = std::env::temp_dir().join(format!("vigie-old-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("c.der"), &id.cert).unwrap();
    std::fs::write(dir.join("k.der"), id.key.serialize_der()).unwrap();
    let sh = |c: String| std::process::Command::new("sh").arg("-c").arg(c).output();
    let d = dir.display();
    let ok = sh(format!(
        "openssl x509 -inform der -in {d}/c.der -out {d}/c.pem && openssl pkey -inform der -in {d}/k.der -out {d}/k.pem"
    ))
    .is_ok_and(|o| o.status.success());
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = ok.then(|| {
        std::process::Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-tls1_1",
                "-no_tls1_2",
                "-no_tls1_3",
            ])
            .args([
                "-cert",
                &format!("{d}/c.pem"),
                "-key",
                &format!("{d}/k.pem"),
                "-www",
                "-quiet",
            ])
            .args(["-cipher", "ALL:@SECLEVEL=0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    });
    if let Some(Ok(mut child)) = child {
        std::thread::sleep(Duration::from_millis(500));
        if child.try_wait().unwrap().is_none() {
            let url = format!("https://127.0.0.1:{port}/v1/batch");
            let pt = PinnedTransport::new(&url, &[id.pin_hex()]).unwrap();
            let mut t = HttpsTransport::new(pt)
                .unwrap()
                .with_timeout(Duration::from_secs(3));
            assert!(
                t.post(&headers(), b"{}").is_err(),
                "TLS < 1.2 must not complete"
            );
        } else {
            eprintln!("openssl refused to start a TLS 1.1 server: skipped");
        }
        let _ = child.kill();
        let _ = child.wait();
    } else {
        eprintln!("openssl unavailable: skipped");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// DER header length and content length of the element at the start of `d` (long forms up to 0x82).
fn der_lens(d: &[u8]) -> (usize, usize) {
    match d[1] {
        l @ 0..=0x7f => (2, usize::from(l)),
        0x81 => (3, usize::from(d[2])),
        0x82 => (4, usize::from(u16::from_be_bytes([d[2], d[3]]))),
        l => panic!("unexpected DER length form {l:#x}"),
    }
}

/// `SEQUENCE { content }` with a minimal definite length.
fn der_seq(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    match content.len() {
        n @ 0..=0x7f => out.push(n as u8),
        n @ 0x80..=0xff => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// The certificate with its outer signatureAlgorithm and/or signatureValue removed. The old
/// hand-written walker only read as far as the SPKI, so it still pinned such a certificate;
/// webpki (the parser the handshake signature check uses anyway) refuses it.
fn without_outer_signature(cert: &[u8], keep_alg: bool) -> Vec<u8> {
    let (h, _) = der_lens(cert);
    let body = &cert[h..];
    let (th, tl) = der_lens(body);
    let tbs = &body[..th + tl];
    let rest = &body[th + tl..];
    let (ah, al) = der_lens(rest);
    let mut inner = tbs.to_vec();
    if keep_alg {
        inner.extend_from_slice(&rest[..ah + al]);
    }
    der_seq(&inner)
}

#[test]
fn certificate_webpki_rejects_is_never_pinned() {
    let id = Ident::new();
    for keep_alg in [false, true] {
        let bad = without_outer_signature(id.cert.as_ref(), keep_alg);
        assert_ne!(bad, id.cert.to_vec());
        assert_eq!(spki_pin(&bad), None, "keep_alg={keep_alg}");
        let v = verifier(&[id.pin()]);
        let r = v.verify_server_cert(
            &CertificateDer::from(bad),
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(r.is_err(), "keep_alg={keep_alg}: pinned a malformed cert");
    }
}

#[test]
fn handshake_with_a_malformed_certificate_fails_cleanly() {
    let id = Ident::new();
    let bad = Ident {
        key: rcgen::KeyPair::try_from(id.key.serialize_der().as_slice()).unwrap(),
        cert: CertificateDer::from(without_outer_signature(id.cert.as_ref(), false)),
    };
    let e = try_post(&bad, &id, &[id.pin_hex()], BOTH).unwrap_err();
    assert!(e.0.contains("receive") || e.0.contains("send") || e.0.contains("tls"), "{e:?}");
}
