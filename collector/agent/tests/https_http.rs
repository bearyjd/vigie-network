//! HTTP layer of the HTTPS transport against a local rustls server: request shape, reply parsing
//! and the hard limits (size cap, chunked, deadline, slowloris).

mod tls_common;

use std::io::Write;
use std::time::{Duration, Instant};

use tls_common::*;
use vigie_agent::httpdate::parse_imf_fixdate;
use vigie_agent::https::HttpsTransport;
use vigie_agent::sender::{HttpReply, Transport, TransportError};
use vigie_agent::transport::PinnedTransport;

/// The documented response cap (status line + headers + body), pinned here on purpose.
const CAP: usize = 64 * 1024;

fn post_with(
    script: Script,
    timeout: Duration,
    body: &[u8],
) -> (Result<HttpReply, TransportError>, Option<Vec<u8>>, Duration) {
    let id = Ident::new();
    let srv = spawn(server_config(&id.cert, &id.key, BOTH), script);
    let pt = PinnedTransport::new(&srv.url(), &[id.pin_hex(), id.pin_hex()]).unwrap();
    let mut t = HttpsTransport::new(pt).unwrap().with_timeout(timeout);
    let start = Instant::now();
    let r = t.post(&headers(), body);
    let took = start.elapsed();
    (r, srv.request(), took)
}

fn post(script: Script) -> Result<HttpReply, TransportError> {
    post_with(script, Duration::from_secs(5), b"{\"a\":1}").0
}

#[test]
fn full_post_sends_the_envelope_and_parses_date_and_duplicate() {
    let (r, req, _) = post_with(
        respond(ok_response("{\"duplicate\":true}")),
        Duration::from_secs(5),
        b"{\"a\":1}",
    );
    let r = r.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.date, parse_imf_fixdate("Tue, 20 Oct 2026 21:59:38 GMT"));
    assert_eq!(r.body, b"{\"duplicate\":true}");

    let req = String::from_utf8(req.unwrap()).unwrap();
    let (head, body) = req.split_once("\r\n\r\n").unwrap();
    assert_eq!(body, "{\"a\":1}");
    let mut lines = head.split("\r\n");
    assert_eq!(lines.next().unwrap(), "POST /v1/batch HTTP/1.1");
    let has = |h: &str| head.lines().any(|l| l.eq_ignore_ascii_case(h));
    assert!(head.lines().any(|l| l.starts_with("Host: 127.0.0.1:")));
    assert!(has("Content-Length: 7"));
    assert!(has("Connection: close"));
    assert!(has("Content-Type: application/json"));
    for (name, value) in headers().pairs() {
        assert!(has(&format!("{name}: {value}")), "missing {name}");
    }
}

#[test]
fn error_statuses_are_passed_through_not_swallowed() {
    let raw = b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n".to_vec();
    let r = post(respond(raw)).unwrap();
    assert_eq!((r.status, r.date, r.body.len()), (429, None, 0));
}

#[test]
fn server_that_drops_the_socket_without_close_notify_is_fine_once_the_body_is_complete() {
    let r = post(Box::new(|c: &mut Conn| {
        let _ = c.write_all(&ok_response("{}"));
        let _ = c.flush();
        // Dropped here with no close_notify.
        let _ = c.sock.shutdown(std::net::Shutdown::Both);
    }))
    .unwrap();
    assert_eq!(r.status, 200);
}

#[test]
fn truncated_body_is_an_error() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"duplicate\":".to_vec();
    let script: Script = Box::new(move |c| {
        let _ = c.write_all(&raw);
        let _ = c.flush();
        c.conn.send_close_notify();
        let _ = c.flush();
    });
    assert!(post(script).is_err());
}

#[test]
fn chunked_response_is_refused() {
    // Even when a Content-Length is also present (request-smuggling style framing conflict).
    let both = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
    assert!(post(respond(both.to_vec())).is_err());
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{\"duplicate\":true}\r\n0\r\n\r\n";
    assert!(post(respond(raw.to_vec())).is_err());
}

#[test]
fn response_without_content_length_is_refused() {
    let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"duplicate\":true}";
    assert!(post(respond(raw.to_vec())).is_err());
}

#[test]
fn oversized_responses_are_refused() {
    // Declared too big: refused without reading it all.
    let declared = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        CAP + 1
    );
    assert!(post(respond(declared.into_bytes())).is_err());

    // Honest length, just over the cap in total (headers count).
    let body = vec![b'x'; CAP];
    let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(&body);
    assert!(post(respond(raw)).is_err());

    // Endless header block.
    let script: Script = Box::new(|c| {
        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nX-Pad: ");
        let chunk = vec![b'a'; 8192];
        for _ in 0..64 {
            if c.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = c.flush();
    });
    assert!(post(script).is_err());
}

#[test]
fn a_response_exactly_at_the_cap_is_accepted() {
    let head = "HTTP/1.1 200 OK\r\nContent-Length: ";
    let n = CAP - head.len() - 4 - 5; // 5 digits
    let mut raw = format!("{head}{n}\r\n\r\n").into_bytes();
    raw.extend(std::iter::repeat_n(b'x', n));
    assert_eq!(raw.len(), CAP);
    assert_eq!(post(respond(raw)).unwrap().body.len(), n);
}

#[test]
fn silent_server_hits_the_deadline() {
    let (r, _, took) = post_with(
        Box::new(|_c| std::thread::sleep(Duration::from_secs(4))),
        Duration::from_millis(700),
        b"{}",
    );
    assert!(r.is_err());
    assert!(took < Duration::from_millis(2500), "{took:?}");
}

#[test]
fn slowloris_drip_is_cut_off_by_the_overall_deadline() {
    // One byte every 100 ms never trips a per-read timeout; the overall deadline must.
    let script: Script = Box::new(|c| {
        for b in b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nX: "
            .iter()
            .cycle()
            .take(200)
        {
            if c.write_all(&[*b]).and_then(|()| c.flush()).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let (r, _, took) = post_with(script, Duration::from_millis(800), b"{}");
    assert!(r.is_err());
    assert!(took < Duration::from_millis(2500), "{took:?}");
}

#[test]
fn unreachable_server_fails_fast() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("https://127.0.0.1:{port}/v1/batch");
    let pt = PinnedTransport::new(&url, &[Ident::new().pin_hex()]).unwrap();
    let mut t = HttpsTransport::new(pt)
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    let start = Instant::now();
    assert!(t.post(&headers(), b"{}").is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn header_values_with_control_characters_are_not_sent() {
    let id = Ident::new();
    let srv = spawn(
        server_config(&id.cert, &id.key, BOTH),
        respond(ok_response("{}")),
    );
    let pt = PinnedTransport::new(&srv.url(), &[id.pin_hex()]).unwrap();
    let mut t = HttpsTransport::new(pt)
        .unwrap()
        .with_timeout(Duration::from_millis(800));
    let mut h = headers();
    h.collector_id = "rtr-1\r\nX-Evil: 1".into();
    assert!(t.post(&h, b"{}").is_err());
    // Nothing reached the server: a bare connect/close unblocks it, and it saw no request.
    drop(std::net::TcpStream::connect(srv.addr).unwrap());
    assert!(srv.request().is_none());
}

#[test]
fn urls_without_https_or_with_userinfo_cannot_become_a_transport() {
    let pin = Ident::new().pin_hex();
    for bad in [
        "http://127.0.0.1:1/v1/batch",
        "https://user:pw@127.0.0.1:1/v1/batch",
        "https://127.0.0.1:1%40x/v1/batch",
    ] {
        assert!(
            PinnedTransport::new(bad, std::slice::from_ref(&pin)).is_err(),
            "{bad}"
        );
    }
}
