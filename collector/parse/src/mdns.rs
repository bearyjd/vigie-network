//! Minimal mDNS (DNS wire format) name extractor. Never panics, never allocates unbounded.

/// Largest packet we will look at (mDNS caps at 9000 bytes).
pub const MAX_PACKET: usize = 9000;
/// Maximum records examined per packet (questions + answers + authority + additional).
pub const MAX_RECORDS: usize = 128;
/// Maximum compression-pointer jumps while decoding one name.
pub const MAX_JUMPS: usize = 8;
/// Maximum decoded name length in bytes (RFC 1035: 255).
pub const MAX_NAME: usize = 255;

const TYPE_PTR: u16 = 12;
const TYPE_SRV: u16 = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    TooLarge,
    Truncated,
    BadLabel,
    NameTooLong,
    PointerLoop,
    TooManyRecords,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "packet shorter than DNS header",
            Self::TooLarge => "packet exceeds size cap",
            Self::Truncated => "record runs past end of packet",
            Self::BadLabel => "invalid label",
            Self::NameTooLong => "name exceeds 255 bytes",
            Self::PointerLoop => "compression pointer loop or excessive jumps",
            Self::TooManyRecords => "record count exceeds cap",
        })
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub is_response: bool,
    /// Owner / question / PTR-target / SRV-target names, in order of appearance (not deduped).
    pub names: Vec<String>,
    /// Subset of `names` that are service types (`_x._tcp.local` / `_x._udp.local`) or
    /// subtype/instance names reduced to their service-type suffix.
    pub services: Vec<String>,
}

fn be16(buf: &[u8], at: usize) -> Result<u16, ParseError> {
    let b = buf.get(at..at + 2).ok_or(ParseError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Decode a possibly-compressed name at `start`. Returns the name and the offset just past the
/// name's first (uncompressed) encoding in the record stream.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut out = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(pos).ok_or(ParseError::Truncated)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((out, end.unwrap_or(pos + 1)));
                }
                let label = buf
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(ParseError::Truncated)?;
                if out.len() + len + 1 > MAX_NAME {
                    return Err(ParseError::NameTooLong);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                // Lossy but safe: control bytes and non-ASCII are replaced.
                out.extend(label.iter().map(|&b| {
                    if (0x20..0x7F).contains(&b) {
                        b as char
                    } else {
                        '?'
                    }
                }));
                pos += 1 + len;
            }
            0xC0 => {
                let target =
                    ((len & 0x3F) << 8) | *buf.get(pos + 1).ok_or(ParseError::Truncated)? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(ParseError::PointerLoop);
                }
                pos = target;
            }
            _ => return Err(ParseError::BadLabel),
        }
    }
}

fn service_suffix(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let idx = lower
        .match_indices("._tcp.")
        .chain(lower.match_indices("._udp."))
        .map(|(i, _)| i)
        .min()
        .or_else(|| {
            // Names that start directly with the service label, e.g. "_http._tcp.local".
            lower.starts_with('_').then_some(0)
        })?;
    // Walk back to the start of the "_service" label.
    let head = &lower[..idx];
    let start = if idx == 0 {
        0
    } else {
        head.rfind('.').map_or(0, |d| d + 1)
    };
    let candidate = &lower[start..];
    (candidate.starts_with('_') && (candidate.contains("._tcp.") || candidate.contains("._udp.")))
        .then(|| candidate.to_string())
}

pub fn parse(buf: &[u8]) -> Result<Parsed, ParseError> {
    if buf.len() > MAX_PACKET {
        return Err(ParseError::TooLarge);
    }
    if buf.len() < 12 {
        return Err(ParseError::TooShort);
    }
    let flags = be16(buf, 2)?;
    let qd = be16(buf, 4)? as usize;
    let others = be16(buf, 6)? as usize + be16(buf, 8)? as usize + be16(buf, 10)? as usize;
    if qd + others > MAX_RECORDS {
        return Err(ParseError::TooManyRecords);
    }
    let mut out = Parsed {
        is_response: flags & 0x8000 != 0,
        ..Parsed::default()
    };
    let mut pos = 12usize;
    for _ in 0..qd {
        let (name, next) = read_name(buf, pos)?;
        be16(buf, next)?; // qtype
        be16(buf, next + 2)?; // qclass
        pos = next + 4;
        out.push_name(name);
    }
    for _ in 0..others {
        let (name, next) = read_name(buf, pos)?;
        let rtype = be16(buf, next)?;
        let rdlen = be16(buf, next + 8)? as usize;
        let rdata = next + 10;
        if rdata + rdlen > buf.len() {
            return Err(ParseError::Truncated);
        }
        out.push_name(name);
        match rtype {
            TYPE_PTR => out.push_name(read_name(&buf[..rdata + rdlen], rdata)?.0),
            // SRV rdata: priority(2) weight(2) port(2) target
            TYPE_SRV if rdlen >= 7 => out.push_name(read_name(&buf[..rdata + rdlen], rdata + 6)?.0),
            _ => {}
        }
        pos = rdata + rdlen;
    }
    Ok(out)
}

impl Parsed {
    fn push_name(&mut self, name: String) {
        if name.is_empty() {
            return;
        }
        if let Some(svc) = service_suffix(&name) {
            self.services.push(svc);
        }
        self.names.push(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in labels {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn header(flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut v = vec![0, 0];
        for x in [flags, qd, an, ns, ar] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        v
    }

    fn query(labels: &[&str]) -> Vec<u8> {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend(name(labels));
        p.extend_from_slice(&[0, 12, 0, 1]);
        p
    }

    fn rr(owner: Vec<u8>, rtype: u16, rdata: Vec<u8>) -> Vec<u8> {
        let mut v = owner;
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&[0x80, 1, 0, 0, 0, 120]);
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend(rdata);
        v
    }

    #[test]
    fn parses_service_query() {
        let p = parse(&query(&["_airplay", "_tcp", "local"])).unwrap();
        assert!(!p.is_response);
        assert_eq!(p.names, vec!["_airplay._tcp.local"]);
        assert_eq!(p.services, vec!["_airplay._tcp.local"]);
    }

    #[test]
    fn parses_ptr_response_with_compression() {
        let mut p = header(0x8400, 0, 1, 0, 0);
        let owner_off = p.len();
        let owner = name(&["_http", "_tcp", "local"]);
        p.extend(rr(owner.clone(), 12, {
            let mut r = name(&["My Printer"]);
            r.pop(); // drop terminator, then point back at owner (offset)
            r.extend_from_slice(&[0xC0, owner_off as u8]);
            r
        }));
        let parsed = parse(&p).unwrap();
        assert!(parsed.is_response);
        assert_eq!(
            parsed.names,
            vec!["_http._tcp.local", "My Printer._http._tcp.local"]
        );
        assert_eq!(
            parsed.services,
            vec!["_http._tcp.local", "_http._tcp.local"]
        );
    }

    #[test]
    fn parses_srv_target() {
        let mut p = header(0x8400, 0, 1, 0, 0);
        let mut rdata = vec![0, 0, 0, 0, 0x1F, 0x90];
        rdata.extend(name(&["tv-livingroom", "local"]));
        p.extend(rr(name(&["Tv", "_googlecast", "_tcp", "local"]), 33, rdata));
        let parsed = parse(&p).unwrap();
        assert_eq!(
            parsed.names,
            vec!["Tv._googlecast._tcp.local", "tv-livingroom.local"]
        );
        assert_eq!(parsed.services, vec!["_googlecast._tcp.local"]);
    }

    #[test]
    fn rejects_short_and_oversize() {
        assert_eq!(parse(&[0; 5]), Err(ParseError::TooShort));
        assert_eq!(parse(&vec![0; MAX_PACKET + 1]), Err(ParseError::TooLarge));
    }

    #[test]
    fn rejects_truncated_name_and_record() {
        let q = query(&["_airplay", "_tcp", "local"]);
        for cut in 12..q.len() {
            assert!(parse(&q[..cut]).is_err(), "cut {cut}");
        }
        let mut p = header(0x8400, 0, 1, 0, 0);
        p.extend(rr(name(&["a", "local"]), 16, vec![1, 2, 3, 4]));
        assert_eq!(parse(&p[..p.len() - 2]), Err(ParseError::Truncated));
    }

    #[test]
    fn rejects_pointer_loops() {
        // self-referential pointer
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::PointerLoop));
        // two-pointer cycle
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[0xC0, 14, 0xC0, 12, 0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::PointerLoop));
    }

    #[test]
    fn rejects_forward_pointer_out_of_range() {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[0xC0, 0xFF, 0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::Truncated));
    }

    #[test]
    fn rejects_reserved_label_bits() {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[0x40, 0, 0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::BadLabel));
    }

    #[test]
    fn caps_name_length() {
        let label = "a".repeat(63);
        let labels: Vec<&str> = (0..6).map(|_| label.as_str()).collect();
        assert_eq!(parse(&query(&labels)), Err(ParseError::NameTooLong));
    }

    #[test]
    fn caps_record_count() {
        let p = header(0, 0xFFFF, 0, 0, 0);
        assert_eq!(parse(&p), Err(ParseError::TooManyRecords));
    }

    #[test]
    fn sanitizes_non_ascii() {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[3, b'a', 0xFF, 0x07, 0, 0, 12, 0, 1]);
        assert_eq!(parse(&p).unwrap().names, vec!["a??"]);
    }

    /// Property-style: xorshift-generated garbage and mutated valid packets never panic.
    #[test]
    fn random_bytes_never_panic() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let valid = query(&["_airplay", "_tcp", "local"]);
        for _ in 0..20_000 {
            let len = (next() % 300) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse(&junk);
            let mut m = valid.clone();
            for _ in 0..(next() % 4 + 1) {
                let i = (next() as usize) % m.len();
                m[i] = next() as u8;
            }
            let _ = parse(&m);
            // header-plausible garbage
            let mut h = header(next() as u16, 2, 2, 1, 1);
            h.extend(junk);
            let _ = parse(&h);
        }
    }
}
