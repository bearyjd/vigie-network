//! Blocking HTTPS POST over an SPKI-pinned TLS connection (one request per connection).
//!
//! Hard limits, all enforced here: the whole exchange (connect, handshake, request, response) has
//! one monotonic deadline, so a peer that drips a byte at a time cannot hold the agent; the response
//! (status line, headers and body together) is capped at 64 KiB; chunked encoding and responses
//! without `Content-Length` are refused (a body delimited only by connection close can be
//! truncated by an attacker, and the server always sends a length).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::httpdate::parse_imf_fixdate;
use crate::sender::{Headers, HttpReply, Transport, TransportError};
use crate::tls_pin::client_config;
use crate::transport::PinnedTransport;

/// Status line + headers + body.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpsTransport {
    target: PinnedTransport,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    timeout: Duration,
}

fn err<E: std::fmt::Display>(what: &str, e: E) -> TransportError {
    TransportError(format!("{what}: {e}"))
}

/// `[::1]` -> `::1`; other hosts unchanged.
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

impl HttpsTransport {
    /// Built only from a validated `PinnedTransport` (https, no userinfo, valid pins).
    /// SNI is the DNS name from the URL; IP literals carry no SNI.
    pub fn new(target: PinnedTransport) -> Result<Self, TransportError> {
        let config = client_config(target.pins()).map_err(|e| err("tls config", e))?;
        let server_name = ServerName::try_from(bare_host(target.host()).to_string())
            .map_err(|e| err("server host", e))?;
        Ok(Self {
            target,
            config: Arc::new(config),
            server_name,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Overall deadline for one `post` (default 30 s).
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    fn request_bytes(&self, headers: &Headers, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let t = &self.target;
        let host = if t.port() == 443 {
            t.host().to_string()
        } else {
            format!("{}:{}", t.host(), t.port())
        };
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vigie-collector\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            t.path(),
            body.len()
        );
        for (name, value) in headers.pairs() {
            if value.bytes().any(|b| b < b' ' || b == 0x7f) {
                return Err(TransportError(format!(
                    "header {name} has a control character"
                )));
            }
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        req.push_str("\r\n");
        let mut out = req.into_bytes();
        out.extend_from_slice(body);
        Ok(out)
    }

    fn connect(&self, end: Instant) -> Result<TcpStream, TransportError> {
        let t = &self.target;
        let addrs = (bare_host(t.host()), t.port())
            .to_socket_addrs()
            .map_err(|e| err("resolve", e))?;
        let mut last = TransportError("no address".into());
        for addr in addrs {
            let left = remaining(end).map_err(|e| err("connect", e))?;
            match TcpStream::connect_timeout(&addr, left.min(CONNECT_TIMEOUT)) {
                Ok(s) => return Ok(s),
                Err(e) => last = err("connect", e),
            }
        }
        Err(last)
    }
}

fn remaining(end: Instant) -> io::Result<Duration> {
    end.checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"))
}

/// A `TcpStream` whose every read and write is bounded by one overall deadline.
struct Deadline {
    tcp: TcpStream,
    end: Instant,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(remaining(self.end)?))?;
        self.tcp.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(remaining(self.end)?))?;
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

impl Transport for HttpsTransport {
    fn post(&mut self, headers: &Headers, body: &[u8]) -> Result<HttpReply, TransportError> {
        let request = self.request_bytes(headers, body)?;
        let end = Instant::now() + self.timeout;
        let tcp = self.connect(end)?;
        let conn = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(|e| err("tls", e))?;
        let mut tls = StreamOwned::new(conn, Deadline { tcp, end });
        tls.write_all(&request).map_err(|e| err("send", e))?;
        tls.flush().map_err(|e| err("send", e))?;
        read_reply(&mut tls).map_err(|e| err("receive", e))
    }
}

struct Head {
    status: u16,
    date: Option<u64>,
    content_length: usize,
    body_start: usize,
}

/// Reads exactly one response: stops as soon as `Content-Length` body bytes are in, so a server
/// that closes without TLS close_notify (common) is fine once the body is complete.
fn read_reply<R: Read>(r: &mut R) -> Result<HttpReply, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut head: Option<Head> = None;
    let mut tmp = [0u8; 4096];
    loop {
        if head.is_none() {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                head = Some(parse_head(&buf[..pos], pos + 4)?);
            } else if buf.len() > MAX_RESPONSE_BYTES {
                return Err("response headers exceed 64 KiB".into());
            }
        }
        if let Some(h) = &head {
            let total = h.body_start + h.content_length;
            if total > MAX_RESPONSE_BYTES {
                return Err("response exceeds 64 KiB".into());
            }
            if buf.len() >= total {
                return Ok(HttpReply {
                    status: h.status,
                    date: h.date,
                    body: buf[h.body_start..total].to_vec(),
                });
            }
        }
        let n = r.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the full response".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_RESPONSE_BYTES + 4 {
            return Err("response exceeds 64 KiB".into());
        }
    }
}

fn parse_head(raw: &[u8], body_start: usize) -> Result<Head, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "response head is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let status = parse_status(lines.next().unwrap_or(""))?;
    let (mut date, mut content_length) = (None, None);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed header line")?;
        if name.is_empty() || name.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err("malformed header name".into());
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => return Err("Transfer-Encoding is not supported".into()),
            "content-length" => {
                if content_length.is_some() {
                    return Err("duplicate Content-Length".into());
                }
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid Content-Length".into());
                }
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "invalid Content-Length")?,
                );
            }
            "date" if date.is_none() => date = parse_imf_fixdate(value),
            _ => {}
        }
    }
    Ok(Head {
        status,
        date,
        content_length: content_length.ok_or("missing Content-Length")?,
        body_start,
    })
}

fn parse_status(line: &str) -> Result<u16, String> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .ok_or("not an HTTP/1.x response")?;
    let code = rest.get(..3).ok_or("malformed status line")?;
    if !code.bytes().all(|b| b.is_ascii_digit())
        || rest.as_bytes().get(3).is_some_and(|&b| b != b' ')
    {
        return Err("malformed status line".into());
    }
    match code.parse::<u16>() {
        Ok(s @ 200..=599) => Ok(s),
        _ => Err("unexpected status code".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(raw: &[u8]) -> Result<HttpReply, String> {
        read_reply(&mut &raw[..])
    }

    #[test]
    fn parses_status_date_and_body() {
        let r = reply(b"HTTP/1.1 200 OK\r\ndate: Tue, 20 Oct 2026 21:59:38 GMT\r\nContent-Length: 18\r\n\r\n{\"duplicate\":true}")
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.date, parse_imf_fixdate("Tue, 20 Oct 2026 21:59:38 GMT"));
        assert!(r.date.is_some());
        assert_eq!(r.body, b"{\"duplicate\":true}");
    }

    #[test]
    fn refuses_what_it_does_not_understand() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok",
            b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/2 200\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(reply(raw).is_err(), "{}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn caps_the_response() {
        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_RESPONSE_BYTES
        );
        assert!(reply(big.as_bytes()).is_err());
        let mut endless = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        endless.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_BYTES * 2));
        assert!(reply(&endless).is_err());
        let ok_len = MAX_RESPONSE_BYTES - 60;
        let mut fits = format!("HTTP/1.1 200 OK\r\nContent-Length: {ok_len}\r\n\r\n").into_bytes();
        fits.extend(std::iter::repeat_n(b'x', ok_len));
        assert_eq!(reply(&fits).unwrap().body.len(), ok_len);
    }

    #[test]
    fn missing_date_or_bad_date_is_none() {
        let r = reply(b"HTTP/1.1 503 X\r\nDate: yesterday\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!((r.status, r.date), (503, None));
    }
}
