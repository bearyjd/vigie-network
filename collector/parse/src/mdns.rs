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
    BadOpcode,
    BadRcode,
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
            Self::BadOpcode => "opcode is not QUERY",
            Self::BadRcode => "response with nonzero rcode",
        })
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub is_response: bool,
    /// True when the packet declared more than `MAX_RECORDS` records and only the first
    /// `MAX_RECORDS` were examined.
    pub truncated: bool,
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

/// Decode a possibly-compressed name at `start` into its labels. Also returns the offset just
/// past the name's first (uncompressed) encoding in the record stream. Labels may legitimately
/// contain '.' (DNS-SD instance names), so they are kept separate rather than joined early.
fn read_name(buf: &[u8], start: usize) -> Result<(Vec<String>, usize), ParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut wire = 0usize;
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(pos).ok_or(ParseError::Truncated)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((labels, end.unwrap_or(pos + 1)));
                }
                let raw = buf
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(ParseError::Truncated)?;
                wire += len + usize::from(!labels.is_empty());
                if wire > MAX_NAME {
                    return Err(ParseError::NameTooLong);
                }
                labels.push(clean_label(raw));
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

fn clean_label(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if crate::is_unsafe_char(c) { '?' } else { c })
        .collect()
}

/// `_svc._tcp.local`-style suffix of a name, matched label by label so a '.' inside one label
/// cannot forge a service type.
fn service_suffix(labels: &[String]) -> Option<String> {
    let i = labels.windows(2).position(|w| {
        w[0].starts_with('_')
            && !w[0].contains('.')
            && (w[1].eq_ignore_ascii_case("_tcp") || w[1].eq_ignore_ascii_case("_udp"))
    })?;
    let suffix = &labels[i..];
    if suffix.iter().any(|l| l.contains('.')) {
        return None;
    }
    Some(suffix.join(".").to_ascii_lowercase())
}

pub fn parse(buf: &[u8]) -> Result<Parsed, ParseError> {
    if buf.len() > MAX_PACKET {
        return Err(ParseError::TooLarge);
    }
    if buf.len() < 12 {
        return Err(ParseError::TooShort);
    }
    let flags = be16(buf, 2)?;
    if (flags >> 11) & 0xF != 0 {
        return Err(ParseError::BadOpcode);
    }
    let is_response = flags & 0x8000 != 0;
    if is_response && flags & 0xF != 0 {
        return Err(ParseError::BadRcode);
    }
    let qd = be16(buf, 4)? as usize;
    let others = be16(buf, 6)? as usize + be16(buf, 8)? as usize + be16(buf, 10)? as usize;
    let qd_take = qd.min(MAX_RECORDS);
    let rr_take = others.min(MAX_RECORDS - qd_take);
    let mut out = Parsed {
        is_response,
        truncated: qd + others > MAX_RECORDS,
        ..Parsed::default()
    };
    let mut pos = 12usize;
    for _ in 0..qd_take {
        let (name, next) = read_name(buf, pos)?;
        be16(buf, next)?; // qtype
        be16(buf, next + 2)?; // qclass
        pos = next + 4;
        out.push_name(name);
    }
    for _ in 0..rr_take {
        let (name, next) = read_name(buf, pos)?;
        let rtype = be16(buf, next)?;
        let rdlen = be16(buf, next + 8)? as usize;
        let rdata = next + 10;
        if rdata + rdlen > buf.len() {
            return Err(ParseError::Truncated);
        }
        out.push_name(name);
        // Names inside rdata may not read past the record's own rdlen.
        let scope = &buf[..rdata + rdlen];
        match rtype {
            TYPE_PTR => out.push_name(read_name(scope, rdata)?.0),
            // SRV rdata: priority(2) weight(2) port(2) target
            TYPE_SRV if rdlen >= 7 => out.push_name(read_name(scope, rdata + 6)?.0),
            _ => {}
        }
        pos = rdata + rdlen;
    }
    Ok(out)
}

impl Parsed {
    fn push_name(&mut self, labels: Vec<String>) {
        if labels.is_empty() {
            return;
        }
        if let Some(svc) = service_suffix(&labels) {
            self.services.push(svc);
        }
        self.names.push(labels.join("."));
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

    fn many_questions(n: usize) -> Vec<u8> {
        let mut p = header(0, n as u16, 0, 0, 0);
        for _ in 0..n {
            p.extend(name(&["a"]));
            p.extend_from_slice(&[0, 12, 0, 1]);
        }
        p
    }

    #[test]
    fn record_count_boundary_truncates_instead_of_dropping() {
        for (n, trunc, kept) in [
            (MAX_RECORDS - 1, false, MAX_RECORDS - 1),
            (MAX_RECORDS, false, MAX_RECORDS),
            (MAX_RECORDS + 1, true, MAX_RECORDS),
            (400, true, MAX_RECORDS),
        ] {
            let r = parse(&many_questions(n)).unwrap();
            assert_eq!((r.truncated, r.names.len()), (trunc, kept), "n={n}");
        }
    }

    #[test]
    fn packet_size_boundary() {
        let mut p = query(&["a", "local"]);
        p.resize(MAX_PACKET - 1, 0);
        assert!(parse(&p).is_ok());
        p.resize(MAX_PACKET, 0);
        assert!(parse(&p).is_ok());
        p.resize(MAX_PACKET + 1, 0);
        assert_eq!(parse(&p), Err(ParseError::TooLarge));
    }

    fn lens_query(lens: &[usize]) -> Vec<u8> {
        let labels: Vec<String> = lens.iter().map(|n| "a".repeat(*n)).collect();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        query(&refs)
    }

    #[test]
    fn name_length_boundary() {
        // decoded length including dots: 254, 255 ok; 256 rejected
        assert_eq!(
            parse(&lens_query(&[63, 63, 63, 62])).unwrap().names[0].len(),
            254
        );
        assert_eq!(
            parse(&lens_query(&[63, 63, 63, 63])).unwrap().names[0].len(),
            255
        );
        assert_eq!(
            parse(&lens_query(&[63, 63, 63, 62, 1])),
            Err(ParseError::NameTooLong)
        );
        assert_eq!(parse(&lens_query(&[63])).unwrap().names[0].len(), 63);
    }

    /// Question whose name is a pointer chain of exactly `k` jumps ending at a real name.
    fn jump_chain(k: usize) -> Vec<u8> {
        let chain_start = 18usize; // 12 header + 2 pointer + 4 qtype/qclass
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[0xC0, chain_start as u8, 0, 12, 0, 1]);
        for i in 1..k {
            p.extend_from_slice(&[0xC0, (chain_start + 2 * i) as u8]);
        }
        p.extend(name(&["a", "local"]));
        p
    }

    #[test]
    fn jump_limit_boundary() {
        for k in [1, MAX_JUMPS - 1, MAX_JUMPS] {
            assert_eq!(
                parse(&jump_chain(k)).unwrap().names,
                vec!["a.local"],
                "k={k}"
            );
        }
        assert_eq!(
            parse(&jump_chain(MAX_JUMPS + 1)),
            Err(ParseError::PointerLoop)
        );
        assert_eq!(parse(&jump_chain(40)), Err(ParseError::PointerLoop));
    }

    fn one_record(rtype: u16, rdata: Vec<u8>, tail: &[u8]) -> Vec<u8> {
        let mut p = header(0x8400, 0, 1, 0, 0);
        p.extend(rr(name(&["s", "local"]), rtype, rdata));
        p.extend_from_slice(tail);
        p
    }

    #[test]
    fn srv_minimum_rdlen() {
        // 6 bytes = priority/weight/port only: no target, must not be read
        assert_eq!(
            parse(&one_record(33, vec![0; 6], &[])).unwrap().names,
            vec!["s.local"]
        );
        // 7 bytes: the target starts at byte 6 and must be examined (reserved label bits)
        assert_eq!(
            parse(&one_record(33, vec![0, 0, 0, 0, 0, 0, 0x40], &[])),
            Err(ParseError::BadLabel)
        );
    }

    #[test]
    fn ptr_name_cut_at_rdlen() {
        // rdlen ends after "ab" although the label says 3; trailing bytes would complete it
        let p = one_record(12, vec![3, b'a', b'b'], &[b'c', 0]);
        assert_eq!(parse(&p), Err(ParseError::Truncated));
    }

    #[test]
    fn srv_target_cut_at_rdlen() {
        let p = one_record(33, vec![0, 0, 0, 0, 0, 0, 3, b'a', b'b'], &[b'c', 0]);
        assert_eq!(parse(&p), Err(ParseError::Truncated));
    }

    #[test]
    fn rdata_must_fit_exactly() {
        let p = one_record(16, vec![1, 2, 3, 4], &[]);
        assert!(parse(&p).is_ok());
        assert_eq!(parse(&p[..p.len() - 1]), Err(ParseError::Truncated));
    }

    #[test]
    fn ignores_non_query_opcode_and_error_responses() {
        let mut p = header(5 << 11, 1, 0, 0, 0);
        p.extend(name(&["a"]));
        p.extend_from_slice(&[0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::BadOpcode));
        let mut p = header(0x8400 | 3, 1, 0, 0, 0);
        p.extend(name(&["a"]));
        p.extend_from_slice(&[0, 12, 0, 1]);
        assert_eq!(parse(&p), Err(ParseError::BadRcode));
        // a query with a nonzero rcode field is merely odd, not an error response
        let mut p = header(3, 1, 0, 0, 0);
        p.extend(name(&["a"]));
        p.extend_from_slice(&[0, 12, 0, 1]);
        assert!(parse(&p).is_ok());
    }

    fn services_of(labels: &[&str]) -> Vec<String> {
        parse(&query(labels)).unwrap().services
    }

    #[test]
    fn service_suffix_cases() {
        assert_eq!(
            services_of(&["_printer", "_sub", "_http", "_tcp", "local"]),
            vec!["_http._tcp.local"]
        );
        assert_eq!(
            services_of(&["My Mac", "_Airplay", "_TCP", "Local"]),
            vec!["_airplay._tcp.local"]
        );
        assert_eq!(
            services_of(&["_services", "_dns-sd", "_udp", "local"]),
            vec!["_dns-sd._udp.local"]
        );
        assert!(services_of(&["host", "_tcp", "local"]).is_empty());
        assert!(services_of(&["_tcp", "local"]).is_empty());
        assert!(services_of(&["_http", "tcp", "local"]).is_empty());
    }

    #[test]
    fn dots_inside_a_label_cannot_forge_a_service_type() {
        assert!(services_of(&["x._http._tcp", "local"]).is_empty());
        assert!(services_of(&["_http", "x._tcp", "local"]).is_empty());
        // the genuine suffix after a forged-looking instance label is still found
        assert_eq!(
            services_of(&["a._b._tcp", "_real", "_udp", "local"]),
            vec!["_real._udp.local"]
        );
    }

    #[test]
    fn labels_decode_as_lossy_utf8() {
        let mut p = header(0, 1, 0, 0, 0);
        p.extend_from_slice(&[5, b'c', b'a', b'f', 0xC3, 0xA9]); // "café"
        p.extend_from_slice(&[4, b'a', 0xFF, 0x07, 0x0A]); // invalid byte, controls
        p.extend_from_slice(&[3, 0xE2, 0x80, 0xAE, 0, 0, 12, 0, 1]); // U+202E bidi override
        assert_eq!(parse(&p).unwrap().names, vec!["café.a\u{FFFD}??.?"]);
    }

    fn full_response() -> Vec<u8> {
        let mut p = header(0x8400, 0, 3, 0, 0);
        let svc_off = p.len();
        let mut ptr = name(&["Printer"]);
        ptr.pop();
        ptr.extend_from_slice(&[0xC0, svc_off as u8]);
        p.extend(rr(name(&["_http", "_tcp", "local"]), 12, ptr));
        let mut srv = vec![0, 0, 0, 0, 0x1F, 0x90];
        srv.extend(name(&["printer", "local"]));
        p.extend(rr(name(&["Printer", "_http", "_tcp", "local"]), 33, srv));
        p.extend(rr(
            name(&["Printer", "_http", "_tcp", "local"]),
            16,
            vec![4, b'a', b'=', b'b', b'c'],
        ));
        p
    }

    #[test]
    fn full_response_exercises_rdata_paths() {
        let r = parse(&full_response()).unwrap();
        assert_eq!(r.names.len(), 5);
        assert!(r.names.contains(&"Printer._http._tcp.local".to_string()));
        assert!(r.names.contains(&"printer.local".to_string()));
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
        let seeds = [query(&["_airplay", "_tcp", "local"]), full_response()];
        for round in 0..40_000usize {
            let len = (next() % 300) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse(&junk);
            let valid = &seeds[round % seeds.len()];
            let _ = parse(&valid[..(next() as usize) % (valid.len() + 1)]);
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
