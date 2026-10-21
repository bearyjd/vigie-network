//! Parser for `/proc/net/nf_conntrack` lines (format assumed from kernel docs; see
//! docs/spikes/conntrack-helper.md). Never panics on any input.

use std::io::{self, BufRead, BufReader, Read};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// conntrack zone; the same tuple in two zones is two distinct flows.
    pub zone: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub key: FlowKey,
    pub orig: Counters,
    pub reply: Counters,
    /// The line carried `bytes=` for the original direction (conntrack accounting is on).
    pub acct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    BadHeader,
    Truncated,
    BadField,
}

#[derive(Default)]
struct Tuple {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
    id: Option<u16>,
    zone: u32,
    acct: bool,
}

fn num<T: std::str::FromStr>(v: &str) -> Result<T, ParseError> {
    v.parse().map_err(|_| ParseError::BadField)
}

/// Parses one line. Layout: `l3name l3num protoname protonum timeout [state] <orig tuple + counters>
/// [flags] <reply tuple + counters> extras...`. Only the original tuple identifies a flow.
pub fn parse_line(line: &str) -> Result<Flow, ParseError> {
    let mut it = line.split_whitespace();
    let l3 = it.next().ok_or(ParseError::Empty)?;
    let v6 = match l3 {
        "ipv4" => false,
        "ipv6" => true,
        _ => return Err(ParseError::BadHeader),
    };
    let mut hdr = |bad: ParseError| it.next().ok_or(bad);
    hdr(ParseError::Truncated)?; // l3num
    hdr(ParseError::Truncated)?; // protoname
    let proto: u8 = hdr(ParseError::Truncated)?
        .parse()
        .map_err(|_| ParseError::BadHeader)?;
    hdr(ParseError::Truncated)?
        .parse::<u64>()
        .map_err(|_| ParseError::BadHeader)?; // timeout

    let mut section = 0u8;
    let (mut orig_t, mut orig, mut reply) =
        (Tuple::default(), Counters::default(), Counters::default());
    for tok in it {
        let Some((k, v)) = tok.split_once('=') else {
            continue; // state words and [FLAGS] are not used
        };
        if k == "src" {
            section = (section + 1).min(3);
        }
        match (section, k) {
            (1, "src") => orig_t.src = Some(num(v)?),
            (1, "dst") => orig_t.dst = Some(num(v)?),
            (1, "sport") => orig_t.sport = Some(num(v)?),
            (1, "dport") => orig_t.dport = Some(num(v)?),
            (1, "id") => orig_t.id = Some(num(v)?),
            (1, "packets") => orig.packets = num(v)?,
            (1, "bytes") => {
                orig.bytes = num(v)?;
                orig_t.acct = true;
            }
            (2, "packets") => reply.packets = num(v)?,
            (2, "bytes") => reply.bytes = num(v)?,
            (_, "zone") => orig_t.zone = num(v)?,
            _ => {}
        }
    }
    let (Some(src), Some(dst)) = (orig_t.src, orig_t.dst) else {
        return Err(ParseError::Truncated);
    };
    if src.is_ipv6() != v6 || dst.is_ipv6() != v6 {
        return Err(ParseError::BadField);
    }
    if matches!(proto, 6 | 17) && (orig_t.sport.is_none() || orig_t.dport.is_none()) {
        return Err(ParseError::Truncated);
    }
    Ok(Flow {
        key: FlowKey {
            proto,
            src,
            dst,
            sport: orig_t.sport.or(orig_t.id).unwrap_or(0),
            dport: orig_t.dport.unwrap_or(0),
            zone: orig_t.zone,
        },
        orig,
        reply,
        acct: orig_t.acct,
    })
}

/// Longest line accepted; the kernel's longest realistic line is well under 1 KiB.
pub const MAX_LINE_BYTES: usize = 4096;
/// Hard cap on bytes read per sample (16384 entries is ~3 MB; this allows 10x headroom).
pub const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

/// What a scan saw besides the flows it handed out.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    /// Non-blank lines skipped (unparseable, over-long, or not UTF-8).
    pub skipped: usize,
    pub parsed: usize,
    /// Parsed lines without `bytes=` (kernel accounting off, `nf_conntrack_acct=0`).
    pub no_acct: usize,
}

/// Streams a whole sample: each parsed flow goes to `on_flow` and is not retained. Bounded in
/// memory per line and in total input.
pub fn scan_flows<R: Read>(r: R, mut on_flow: impl FnMut(Flow)) -> io::Result<ScanStats> {
    let mut rd = BufReader::new(r.take(MAX_INPUT_BYTES));
    let mut st = ScanStats::default();
    let mut buf = Vec::with_capacity(512);
    loop {
        buf.clear();
        let n = (&mut rd)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') && n == MAX_LINE_BYTES {
            // Over-long line: count once and discard through its newline.
            st.skipped += 1;
            loop {
                buf.clear();
                let m = (&mut rd)
                    .take(MAX_LINE_BYTES as u64)
                    .read_until(b'\n', &mut buf)?;
                if m == 0 || buf.last() == Some(&b'\n') {
                    break;
                }
            }
            continue;
        }
        match std::str::from_utf8(&buf).map(parse_line) {
            Ok(Ok(f)) => {
                st.parsed += 1;
                st.no_acct += usize::from(!f.acct);
                on_flow(f);
            }
            Ok(Err(ParseError::Empty)) => {}
            _ => st.skipped += 1,
        }
    }
    Ok(st)
}

/// Collecting convenience over [`scan_flows`] (tests and tools; the daemon streams).
pub fn read_flows<R: Read>(r: R) -> io::Result<(Vec<Flow>, usize)> {
    let mut flows = Vec::new();
    let st = scan_flows(r, |f| flows.push(f))?;
    Ok((flows, st.skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.8.10 dst=93.184.216.34 sport=51234 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=192.168.8.10 sport=443 dport=51234 packets=8 bytes=9000 [ASSURED] mark=0 zone=0 use=2";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tcp_tuple_and_counters() {
        let f = parse_line(TCP).unwrap();
        assert_eq!(
            f.key,
            FlowKey {
                proto: 6,
                src: ip("192.168.8.10"),
                dst: ip("93.184.216.34"),
                sport: 51234,
                dport: 443,
                zone: 0
            }
        );
        assert_eq!(
            f.orig,
            Counters {
                packets: 10,
                bytes: 1200
            }
        );
        assert_eq!(
            f.reply,
            Counters {
                packets: 8,
                bytes: 9000
            }
        );
        assert!(f.acct);
    }

    #[test]
    fn zone_is_part_of_the_key() {
        let a = parse_line(&TCP.replace("zone=0", "zone=5")).unwrap();
        let b = parse_line(TCP).unwrap();
        assert_eq!((a.key.zone, b.key.zone), (5, 0));
        assert_ne!(a.key, b.key);
        assert_eq!(
            parse_line(&TCP.replace("zone=0", "zone=x")),
            Err(ParseError::BadField)
        );
    }

    #[test]
    fn missing_bytes_marks_accounting_off() {
        let l = "ipv4     2 udp      17 25 src=192.168.8.11 dst=1.1.1.1 sport=5 dport=53 src=1.1.1.1 dst=192.168.8.11 sport=53 dport=5 mark=0 use=2";
        assert!(!parse_line(l).unwrap().acct);
        let data = format!("{TCP}\n{l}\n{l}\nbogus\n");
        let st = scan_flows(data.as_bytes(), |_| {}).unwrap();
        assert_eq!((st.parsed, st.no_acct, st.skipped), (3, 2, 1));
    }

    #[test]
    fn udp_line_with_unreplied_flag() {
        let l = "ipv4     2 udp      17 25 src=192.168.8.11 dst=239.255.255.250 sport=50000 dport=1900 packets=3 bytes=540 [UNREPLIED] src=239.255.255.250 dst=192.168.8.11 sport=1900 dport=50000 packets=0 bytes=0 mark=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!(f.orig.bytes, 540);
        assert_eq!(f.reply, Counters::default());
    }

    #[test]
    fn ipv6_addresses() {
        let l = "ipv6     10 udp      17 20 src=fd12:3456:789a::11 dst=2001:4860:4860::8888 sport=41000 dport=53 packets=1 bytes=90 src=2001:4860:4860::8888 dst=fd12:3456:789a::11 sport=53 dport=41000 packets=1 bytes=150 mark=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!(f.key.src, ip("fd12:3456:789a::11"));
        assert_eq!(f.key.dst, ip("2001:4860:4860::8888"));
        assert_eq!(f.reply.bytes, 150);
    }

    #[test]
    fn icmp_uses_id_as_sport_and_zero_dport() {
        let l = "ipv4     2 icmp     1 29 src=192.168.8.10 dst=1.1.1.1 type=8 code=0 id=4242 packets=4 bytes=336 src=1.1.1.1 dst=192.168.8.10 type=0 code=0 id=4242 packets=4 bytes=336 mark=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!((f.key.proto, f.key.sport, f.key.dport), (1, 4242, 0));
        assert_eq!(f.orig.packets, 4);
    }

    #[test]
    fn other_protocol_without_ports() {
        let l = "ipv4     2 gre      47 599 src=192.168.8.13 dst=198.51.100.7 packets=5 bytes=500 src=198.51.100.7 dst=192.168.8.13 packets=5 bytes=500 mark=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!((f.key.proto, f.key.sport, f.key.dport), (47, 0, 0));
        assert_eq!(f.reply.bytes, 500);
    }

    #[test]
    fn missing_counters_are_zero() {
        let l = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.8.14 dst=93.184.216.34 sport=51235 dport=443 src=93.184.216.34 dst=192.168.8.14 sport=443 dport=51235 mark=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!(f.orig, Counters::default());
        assert_eq!(f.reply, Counters::default());
    }

    #[test]
    fn extra_keys_secctx_and_zone_are_ignored() {
        let l = "ipv4     2 tcp      6 118 SYN_SENT src=192.168.8.12 dst=203.0.113.9 sport=33333 dport=8443 packets=1 bytes=60 [UNREPLIED] src=203.0.113.9 dst=192.168.8.12 sport=8443 dport=33333 packets=0 bytes=0 mark=0 secctx=system_u:object_r:unlabeled_t zone=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!(f.orig.bytes, 60);
        assert_eq!(f.reply.bytes, 0);
    }

    #[test]
    fn nat_original_tuple_is_the_key() {
        let l = "ipv4     2 tcp      6 431990 ESTABLISHED src=192.168.8.20 dst=198.51.100.50 sport=60000 dport=443 packets=100 bytes=8000 src=198.51.100.50 dst=203.0.113.1 sport=443 dport=60000 packets=90 bytes=70000 [ASSURED] mark=0 zone=0 use=2";
        let f = parse_line(l).unwrap();
        assert_eq!(f.key.src, ip("192.168.8.20"));
        assert_eq!(f.key.dst, ip("198.51.100.50"));
        assert_eq!(f.reply.bytes, 70000);
    }

    #[test]
    fn garbage_is_rejected_with_specific_errors() {
        assert_eq!(parse_line(""), Err(ParseError::Empty));
        assert_eq!(parse_line("   \t "), Err(ParseError::Empty));
        assert_eq!(parse_line("hello world"), Err(ParseError::BadHeader));
        assert_eq!(parse_line("ipv4 2 tcp 6 43"), Err(ParseError::Truncated));
        assert_eq!(
            parse_line("ipv4 2 tcp 6 100 ESTABLISHED src=192.168.8.1 dst=bogus sport=1 dport=2"),
            Err(ParseError::BadField)
        );
        assert_eq!(
            parse_line("ipv4 2 tcp 6 100 ESTABLISHED src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2 packets=zzz bytes=1"),
            Err(ParseError::BadField)
        );
        // tcp without ports = truncated mid-tuple
        assert_eq!(
            parse_line("ipv4 2 tcp 6 100 ESTABLISHED src=1.1.1.1 dst=2.2.2.2"),
            Err(ParseError::Truncated)
        );
        // address family must match the header
        assert_eq!(
            parse_line("ipv4 2 udp 17 5 src=fd00::1 dst=2.2.2.2 sport=1 dport=2"),
            Err(ParseError::BadField)
        );
    }

    #[test]
    fn never_panics_on_every_prefix_and_byte_noise() {
        for end in 0..=TCP.len() {
            let _ = parse_line(&TCP[..end]);
        }
        let mut seed: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..2000 {
            let mut s = String::new();
            for tok in TCP.split(' ') {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                match (seed >> 60) % 4 {
                    0 => {}
                    1 => s.push_str("=="),
                    _ => s.push_str(tok),
                }
                s.push(' ');
            }
            let _ = parse_line(&s);
        }
        let _ = parse_line(&"src=".repeat(10_000));
        let _ = parse_line("ipv4 2 tcp 6 99999999999999999999999 src=1.1.1.1");
    }
}
