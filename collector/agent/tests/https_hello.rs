//! What the transport offers in its TLS ClientHello (read raw off the wire).

mod tls_common;

use std::io::Read;
use std::time::Duration;

use tls_common::*;
use vigie_agent::https::HttpsTransport;
use vigie_agent::sender::Transport;
use vigie_agent::transport::PinnedTransport;

const MODERN: [u16; 10] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9, 0x00ff,
];

fn client_hello(host: &str) -> Vec<u8> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut rec = vec![0u8; 5];
        s.read_exact(&mut rec).unwrap();
        let len = usize::from(u16::from_be_bytes([rec[3], rec[4]]));
        rec.resize(5 + len, 0);
        s.read_exact(&mut rec[5..]).unwrap();
        rec
    });
    let url = format!("https://{host}:{port}/v1/batch");
    let pt = PinnedTransport::new(&url, &[Ident::new().pin_hex()]).unwrap();
    let mut t = HttpsTransport::new(pt)
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    assert!(t.post(&headers(), b"{}").is_err());
    h.join().unwrap()
}

struct Hello {
    suites: Vec<u16>,
    versions: Vec<u16>,
    sni: Option<Vec<u8>>,
}

fn parse(rec: &[u8]) -> Hello {
    assert_eq!(rec[0], 0x16, "handshake record");
    let b = &rec[5..];
    assert_eq!(b[0], 1, "ClientHello");
    assert_eq!(&b[4..6], &[3, 3], "legacy_version is TLS 1.2");
    let mut i = 6 + 32;
    i += 1 + usize::from(b[i]); // session id
    let cs_len = usize::from(u16::from_be_bytes([b[i], b[i + 1]]));
    let suites = b[i + 2..i + 2 + cs_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    i += 2 + cs_len;
    i += 1 + usize::from(b[i]); // compression methods
    let ext_end = i + 2 + usize::from(u16::from_be_bytes([b[i], b[i + 1]]));
    i += 2;
    let (mut versions, mut sni) = (Vec::new(), None);
    while i < ext_end {
        let ty = u16::from_be_bytes([b[i], b[i + 1]]);
        let l = usize::from(u16::from_be_bytes([b[i + 2], b[i + 3]]));
        let data = &b[i + 4..i + 4 + l];
        match ty {
            0 => sni = Some(data.to_vec()),
            0x002b => {
                versions = data[1..]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
            _ => {}
        }
        i += 4 + l;
    }
    Hello {
        suites,
        versions,
        sni,
    }
}

#[test]
fn offers_only_tls12_13_and_modern_suites() {
    let h = parse(&client_hello("127.0.0.1"));
    assert!(!h.versions.is_empty());
    assert!(
        h.versions.iter().all(|v| *v == 0x0303 || *v == 0x0304),
        "{:x?}",
        h.versions
    );
    assert!(h.suites.iter().all(|s| MODERN.contains(s)), "{:x?}", h.suites);
}

#[test]
fn ip_literal_sends_no_sni_but_a_dns_name_does() {
    assert!(parse(&client_hello("127.0.0.1")).sni.is_none());
    // `localhost` resolves to loopback; the hello must carry it as SNI.
    let sni = parse(&client_hello("localhost")).sni.expect("SNI for a DNS name");
    assert!(sni.windows(9).any(|w| w == b"localhost"));
}
