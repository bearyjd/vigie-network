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
    Malformed,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "bare LF or obs-fold continuation line",
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
        .map(|c| if crate::is_unsafe_char(c) { '?' } else { c })
        .collect()
}

fn has_bare_lf(buf: &[u8]) -> bool {
    buf.iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || buf[i - 1] != b'\r'))
}

pub fn parse(buf: &[u8]) -> Result<Parsed, ParseError> {
    if buf.len() > MAX_PACKET {
        return Err(ParseError::TooLarge);
    }
    if has_bare_lf(buf) {
        return Err(ParseError::Malformed);
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
        if line.starts_with([' ', '\t']) {
            return Err(ParseError::Malformed);
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
        assert_eq!(parse(&vec![b'N'; 2048 + 1]), Err(ParseError::TooLarge));
    }

    #[test]
    fn caps_value_length_and_strips_controls() {
        let long = "x".repeat(5000.min(2048 - 100));
        let m = format!("NOTIFY * HTTP/1.1\r\nSERVER: {long}\r\nUSN: a\u{7}b\r\n\r\n");
        let p = parse(m.as_bytes()).unwrap();
        assert_eq!(p.server.unwrap().len(), 256);
        assert_eq!(p.usn.as_deref(), Some("a?b"));
    }

    #[test]
    fn stops_at_blank_line_and_line_cap() {
        let m = "NOTIFY * HTTP/1.1\r\nNT: a\r\n\r\nSERVER: ignored\r\n";
        assert_eq!(parse(m.as_bytes()).unwrap().server, None);
        let mut m = String::from("NOTIFY * HTTP/1.1\r\n");
        for _ in 0..32 {
            m.push_str("X: y\r\n");
        }
        m.push_str("SERVER: late\r\n");
        assert_eq!(parse(m.as_bytes()).unwrap().server, None);
    }

    #[test]
    fn first_duplicate_header_wins() {
        let m = "NOTIFY * HTTP/1.1\r\nSERVER: first\r\nSERVER: second\r\n\r\n";
        assert_eq!(
            parse(m.as_bytes()).unwrap().server.as_deref(),
            Some("first")
        );
    }

    #[test]
    fn method_requires_following_space() {
        assert_eq!(
            parse(b"NOTIFYx * HTTP/1.1\r\n\r\n"),
            Err(ParseError::NotSsdp)
        );
        assert_eq!(
            parse(b"M-SEARCHx * HTTP/1.1\r\n\r\n"),
            Err(ParseError::NotSsdp)
        );
        assert!(parse(b"NOTIFY * HTTP/1.1\r\n\r\n").is_ok());
        assert!(parse(b"M-SEARCH * HTTP/1.1\r\n\r\n").is_ok());
    }

    fn server_after(fillers: usize) -> String {
        let mut m = String::from("NOTIFY * HTTP/1.1\r\n");
        for _ in 0..fillers {
            m.push_str("X: y\r\n");
        }
        m.push_str("SERVER: s\r\n\r\n");
        m
    }

    #[test]
    fn line_cap_boundary() {
        // SERVER sits at 0-based line index 1 + fillers; lines 0..MAX_LINES are kept.
        for (fillers, kept) in [(32 - 3, true), (32 - 2, true), (32 - 1, false)] {
            let p = parse(server_after(fillers).as_bytes()).unwrap();
            assert_eq!(p.server.is_some(), kept, "fillers={fillers}");
        }
    }

    fn padded(total: usize) -> Vec<u8> {
        let head = "NOTIFY * HTTP/1.1\r\nX: ";
        let tail = "\r\n\r\n";
        let mut m = String::from(head);
        m.push_str(&"y".repeat(total - head.len() - tail.len()));
        m.push_str(tail);
        assert_eq!(m.len(), total);
        m.into_bytes()
    }

    #[test]
    fn packet_size_boundary() {
        assert!(parse(&padded(2048 - 1)).is_ok());
        assert!(parse(&padded(2048)).is_ok());
        assert_eq!(parse(&padded(2048 + 1)), Err(ParseError::TooLarge));
    }

    #[test]
    fn value_length_boundary() {
        for (n, want) in [(256 - 1, 256 - 1), (256, 256), (256 + 1, 256)] {
            let m = format!("NOTIFY * HTTP/1.1\r\nSERVER: {}\r\n\r\n", "x".repeat(n));
            assert_eq!(parse(m.as_bytes()).unwrap().server.unwrap().len(), want);
        }
    }

    #[test]
    fn rejects_obs_fold_continuations() {
        for fold in [" SERVER: evil", "\tSERVER: evil"] {
            let m = format!("NOTIFY * HTTP/1.1\r\nNT: a\r\n{fold}\r\n\r\n");
            assert_eq!(parse(m.as_bytes()), Err(ParseError::Malformed), "{fold:?}");
        }
    }

    #[test]
    fn rejects_bare_lf() {
        for m in [
            "NOTIFY * HTTP/1.1\nNT: a\n\n",
            "NOTIFY * HTTP/1.1\r\nNT: a\nSERVER: x\r\n\r\n",
        ] {
            assert_eq!(parse(m.as_bytes()), Err(ParseError::Malformed), "{m:?}");
        }
    }

    #[test]
    fn strips_bidi_and_line_separators() {
        let m = "NOTIFY * HTTP/1.1\r\nUSN: a\u{202E}b\u{2066}c\u{2069}d\u{2028}e\u{2029}f\r\n\r\n";
        assert_eq!(
            parse(m.as_bytes()).unwrap().usn.as_deref(),
            Some("a?b?c?d?e?f")
        );
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
