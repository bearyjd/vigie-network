//! SSDP (HTTPU) header extractor with hard length caps. Never panics.

pub const MAX_PACKET: usize = 2048;
pub const MAX_LINES: usize = 32;
pub const MAX_VALUE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Notify,
    MSearch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    NotSsdp,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "packet exceeds size cap",
            Self::NotSsdp => "not a NOTIFY or M-SEARCH request",
        })
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub method: Method,
    pub server: Option<String>,
    pub usn: Option<String>,
    pub nt: Option<String>,
    pub st: Option<String>,
    pub user_agent: Option<String>,
}

fn clean(v: &str) -> String {
    v.trim()
        .chars()
        .take(MAX_VALUE)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub fn parse(buf: &[u8]) -> Result<Parsed, ParseError> {
    if buf.len() > MAX_PACKET {
        return Err(ParseError::TooLarge);
    }
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n").take(MAX_LINES);
    let first = lines.next().unwrap_or("");
    let method = if first.starts_with("NOTIFY ") {
        Method::Notify
    } else if first.starts_with("M-SEARCH ") {
        Method::MSearch
    } else {
        return Err(ParseError::NotSsdp);
    };
    let mut out = Parsed {
        method,
        server: None,
        usn: None,
        nt: None,
        st: None,
        user_agent: None,
    };
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let slot = match k.trim().to_ascii_uppercase().as_str() {
            "SERVER" => &mut out.server,
            "USN" => &mut out.usn,
            "NT" => &mut out.nt,
            "ST" => &mut out.st,
            "USER-AGENT" => &mut out.user_agent,
            _ => continue,
        };
        slot.get_or_insert_with(|| clean(v));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTIFY: &str = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nNT: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\nSERVER: Linux/4.9 UPnP/1.0 Foo/1.2\r\n\r\n";

    #[test]
    fn parses_notify() {
        let p = parse(NOTIFY.as_bytes()).unwrap();
        assert_eq!(p.method, Method::Notify);
        assert_eq!(p.nt.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(p.usn.as_deref(), Some("uuid:abc::upnp:rootdevice"));
        assert_eq!(p.server.as_deref(), Some("Linux/4.9 UPnP/1.0 Foo/1.2"));
    }

    #[test]
    fn parses_msearch_lowercase_headers() {
        let m = "M-SEARCH * HTTP/1.1\r\nhost: 239.255.255.250:1900\r\nman: \"ssdp:discover\"\r\nst: ssdp:all\r\nuser-agent: Roku/9\r\n\r\n";
        let p = parse(m.as_bytes()).unwrap();
        assert_eq!(p.method, Method::MSearch);
        assert_eq!(p.st.as_deref(), Some("ssdp:all"));
        assert_eq!(p.user_agent.as_deref(), Some("Roku/9"));
    }

    #[test]
    fn rejects_non_ssdp_and_oversize() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\n"), Err(ParseError::NotSsdp));
        assert_eq!(parse(b""), Err(ParseError::NotSsdp));
        assert_eq!(
            parse(&vec![b'N'; MAX_PACKET + 1]),
            Err(ParseError::TooLarge)
        );
    }

    #[test]
    fn caps_value_length_and_strips_controls() {
        let long = "x".repeat(5000.min(MAX_PACKET - 100));
        let m = format!("NOTIFY * HTTP/1.1\r\nSERVER: {long}\r\nUSN: a\u{7}b\r\n\r\n");
        let p = parse(m.as_bytes()).unwrap();
        assert_eq!(p.server.unwrap().len(), MAX_VALUE);
        assert_eq!(p.usn.as_deref(), Some("a?b"));
    }

    #[test]
    fn stops_at_blank_line_and_line_cap() {
        let m = "NOTIFY * HTTP/1.1\r\nNT: a\r\n\r\nSERVER: ignored\r\n";
        assert_eq!(parse(m.as_bytes()).unwrap().server, None);
        let mut m = String::from("NOTIFY * HTTP/1.1\r\n");
        for _ in 0..MAX_LINES {
            m.push_str("X: y\r\n");
        }
        m.push_str("SERVER: late\r\n");
        assert_eq!(parse(m.as_bytes()).unwrap().server, None);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut s: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..20_000 {
            let len = (next() % 400) as usize;
            let mut junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse(&junk);
            let mut m = NOTIFY.as_bytes().to_vec();
            for _ in 0..(next() % 5 + 1) {
                let i = (next() as usize) % m.len();
                m[i] = next() as u8;
            }
            let _ = parse(&m);
            junk.splice(0..0, b"NOTIFY * HTTP/1.1\r\n".iter().copied());
            let _ = parse(&junk);
        }
    }
}
