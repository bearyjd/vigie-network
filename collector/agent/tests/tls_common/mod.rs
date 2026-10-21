//! Shared helpers for the HTTPS transport tests: throwaway self-signed identities, a scripted
//! rustls server on localhost, and a `Headers` fixture. Test code only.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;

use rcgen::{date_time_ymd, CertificateParams, KeyPair, PublicKeyData, SerialNumber};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion};
use sha2::{Digest, Sha256};
use vigie_agent::sender::Headers;

pub struct Ident {
    pub key: KeyPair,
    pub cert: CertificateDer<'static>,
}

impl Ident {
    /// Fresh key, valid self-signed cert for `localhost` / 127.0.0.1.
    pub fn new() -> Self {
        Self::from_key(KeyPair::generate().unwrap(), 1, (2020, 1, 1), (2099, 1, 1))
    }

    /// Same key, new serial and validity window (a reissued certificate).
    pub fn reissue(&self, serial: u64, from: (i32, u8, u8), to: (i32, u8, u8)) -> Self {
        let key = KeyPair::try_from(self.key.serialize_der().as_slice()).unwrap();
        Self::from_key(key, serial, from, to)
    }

    pub fn from_key(key: KeyPair, serial: u64, from: (i32, u8, u8), to: (i32, u8, u8)) -> Self {
        let mut p = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        p.serial_number = Some(SerialNumber::from(serial));
        p.not_before = date_time_ymd(from.0, from.1, from.2);
        p.not_after = date_time_ymd(to.0, to.1, to.2);
        let cert = p.self_signed(&key).unwrap().der().clone();
        Self { key, cert }
    }

    /// SHA-256 of the SPKI DER as computed by rcgen (independent of our own parser).
    pub fn pin(&self) -> [u8; 32] {
        Sha256::digest(self.key.subject_public_key_info()).into()
    }

    pub fn pin_hex(&self) -> String {
        hex(&self.pin())
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);
impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn server_config(
    cert: &CertificateDer<'static>,
    signer: &KeyPair,
    versions: &[&'static SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signer.serialize_der()));
    let sk = rustls::crypto::ring::sign::any_supported_type(&der).unwrap();
    // `CertifiedKey::new` does not check that the key matches the cert: tests rely on that to
    // present cert A while signing the handshake with key B.
    let ck = Arc::new(CertifiedKey::new(vec![cert.clone()], sk));
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(ck))),
    )
}

pub const BOTH: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];

pub type Conn = StreamOwned<ServerConnection, TcpStream>;
pub type Script = Box<dyn FnOnce(&mut Conn) + Send>;

pub struct TestServer {
    pub addr: SocketAddr,
    handle: JoinHandle<Option<Vec<u8>>>,
}

impl TestServer {
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}/v1/batch", self.addr.port())
    }
    /// The request the server read (headers + body), or None if the handshake failed.
    pub fn request(self) -> Option<Vec<u8>> {
        self.handle.join().unwrap()
    }
}

/// One-connection TLS server. After the handshake it reads one HTTP request, then runs `script`
/// (which writes the response, stalls, drips, drops the socket, ...).
pub fn spawn(cfg: Arc<ServerConfig>, script: Script) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().ok()?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok()?;
        let mut conn = StreamOwned::new(ServerConnection::new(cfg).ok()?, tcp);
        while conn.conn.is_handshaking() {
            conn.conn.complete_io(&mut conn.sock).ok()?;
        }
        let req = read_request(&mut conn)?;
        script(&mut conn);
        Some(req)
    });
    TestServer { addr, handle }
}

fn read_request(c: &mut Conn) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let cl = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + cl {
                return Some(buf);
            }
        }
        let n = c.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

pub fn respond(raw: Vec<u8>) -> Script {
    Box::new(move |c| {
        let _ = c.write_all(&raw);
        let _ = c.flush();
    })
}

pub fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nDate: Tue, 20 Oct 2026 21:59:38 GMT\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

pub fn headers() -> Headers {
    Headers {
        collector_id: "rtr-1".into(),
        key_id: "k1".into(),
        boot_id: "boot-a".into(),
        seq: "1".into(),
        sent_ts: "1792000000".into(),
        batch_id: "01927f3e-8a1b-7c2d-9e4f-000000000001".into(),
        signature: "ab".repeat(32),
    }
}
