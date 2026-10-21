import subprocess, sys

ROOT = sys.argv[1]
WHICH = sys.argv[2] if len(sys.argv) > 2 else "all"
M = ROOT + "/parse/src/mdns.rs"
S = ROOT + "/parse/src/ssdp.rs"
N = ROOT + "/net-spike/src/"
PARSE_MUTS = [
    (M, "buf.len() > MAX_PACKET", "buf.len() >= MAX_PACKET"),
    (M, "buf.len() < 12", "buf.len() <= 12"),
    (M, "buf.len() < 12", "buf.len() < 11"),
    (M, "MAX_RECORDS: usize = 128", "MAX_RECORDS: usize = 127"),
    (M, "MAX_RECORDS: usize = 128", "MAX_RECORDS: usize = 129"),
    (M, "MAX_NAME: usize = 255", "MAX_NAME: usize = 254"),
    (M, "MAX_NAME: usize = 255", "MAX_NAME: usize = 256"),
    (M, "MAX_JUMPS: usize = 8", "MAX_JUMPS: usize = 7"),
    (M, "MAX_JUMPS: usize = 8", "MAX_JUMPS: usize = 9"),
    (M, "MAX_JUMPS: usize = 8", "MAX_JUMPS: usize = 1000"),
    (M, "jumps > MAX_JUMPS", "jumps >= MAX_JUMPS"),
    (M, "MAX_PACKET: usize = 9000", "MAX_PACKET: usize = 9001"),
    (M, "MAX_PACKET: usize = 9000", "MAX_PACKET: usize = 8999"),
    (M, "rdlen >= 7", "rdlen > 7"),
    (M, "rdlen >= 7", "rdlen >= 6"),
    (M, "rdata + rdlen > buf.len()", "rdata + rdlen >= buf.len()"),
    (M, "rdata + rdlen > buf.len()", "rdata + rdlen > buf.len() + 1"),
    (M, "let scope = &buf[..rdata + rdlen];", "let scope = buf;"),
    (M, "wire > MAX_NAME", "wire >= MAX_NAME"),
    (M, "len + usize::from(!labels.is_empty())", "len"),
    (M, "rdata + 6", "rdata + 5"),
    (M, "rdata + 6", "rdata + 7"),
    (M, "&& !w[0].contains('.')", ""),
    (M, "if suffix.iter().any(|l| l.contains('.')) {", "if false {"),
    (M, "qd + others > MAX_RECORDS", "qd + others >= MAX_RECORDS"),
    (M, "(flags >> 11) & 0xF != 0", "(flags >> 12) & 0xF != 0"),
    (M, "(flags >> 11) & 0xF != 0", "(flags >> 11) & 0x7 != 0"),
    (M, "flags & 0xF != 0", "flags & 0x7 != 0"),
    (M, "flags & 0x8000 != 0", "flags & 0x4000 != 0"),
    (M, 'eq_ignore_ascii_case("_tcp")', 'eq_ignore_ascii_case("_tc")'),
    (M, 'eq_ignore_ascii_case("_udp")', 'eq_ignore_ascii_case("_ud")'),
    (M, ".to_ascii_lowercase()", ""),
    (M, "w[0].starts_with('_')", "true"),
    (M, "rtype {\n            TYPE_PTR", "rtype {\n            TYPE_SRV"),
    (M, "TYPE_PTR: u16 = 12", "TYPE_PTR: u16 = 13"),
    (M, "TYPE_SRV: u16 = 33", "TYPE_SRV: u16 = 34"),
    (M, "qd.min(MAX_RECORDS)", "qd"),
    (M, "MAX_RECORDS - qd_take", "MAX_RECORDS"),
    (S, "buf.len() > MAX_PACKET", "buf.len() >= MAX_PACKET"),
    (S, "MAX_PACKET: usize = 2048", "MAX_PACKET: usize = 2049"),
    (S, "MAX_LINES: usize = 32", "MAX_LINES: usize = 31"),
    (S, "MAX_LINES: usize = 32", "MAX_LINES: usize = 33"),
    (S, "MAX_VALUE: usize = 256", "MAX_VALUE: usize = 255"),
    (S, "MAX_VALUE: usize = 256", "MAX_VALUE: usize = 257"),
    (S, "i == 0 || ", ""),
    (S, "buf[i - 1] != b'\\r'", "buf[i - 1] != b'\\n'"),
    (S, "starts_with([' ', '\\t'])", "starts_with(' ')"),
    (S, "starts_with([' ', '\\t'])", "starts_with('\\t')"),
    (S, '"NOTIFY "', '"NOTIFY"'),
    (S, '"M-SEARCH "', '"M-SEARCH"'),
    (S, "if line.is_empty() {\n            break;", "if line.is_empty() {\n            continue;"),
    (S, ".trim()\n        .chars()", ".chars()"),
    (S, "get_or_insert_with(|| clean(v))", "insert(clean(v))"),
]

NET_MUTS = [
    (N + "sock.rs", "SocketAddrV4::new(group, port)", "SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)"),
    (N + "sock.rs", "    s.set_multicast_all_v4(false)?;\n", ""),
    (N + "sock.rs", "    s.set_multicast_all_v6(false)?;\n", ""),
    (N + "sock.rs", "set_multicast_all_v4(false)", "set_multicast_all_v4(true)"),
    (N + "sock.rs", "set_multicast_all_v6(false)", "set_multicast_all_v6(true)"),
    (N + "sock.rs", "set_reuse_address(true)", "set_reuse_address(false)"),
    (N + "sock.rs", "set_reuse_port(true)", "set_reuse_port(false)"),
    (N + "sock.rs", "Ipv4Addr::new(224, 0, 0, 251), 5353", "Ipv4Addr::new(224, 0, 0, 251), 5354"),
    (N + "sock.rs", "Ipv4Addr::new(224, 0, 0, 251)", "Ipv4Addr::new(224, 0, 0, 252)"),
    (N + "sock.rs", "Ipv4Addr::new(239, 255, 255, 250), 1900", "Ipv4Addr::new(239, 255, 255, 250), 1901"),
    (N + "sock.rs", "Ipv4Addr::new(239, 255, 255, 250)", "Ipv4Addr::new(239, 255, 255, 251)"),
    (N + "sock.rs", "SocketAddrV6::new(group, 5353, 0, idx)", "SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 5353, 0, idx)"),
    (N + "sock.rs", "SocketAddrV6::new(group, 5353, 0, idx)", "SocketAddrV6::new(group, 5354, 0, idx)"),
    (N + "sock.rs", "SocketAddrV6::new(group, 5353, 0, idx)", "SocketAddrV6::new(group, 5353, 0, 0)"),
    (N + "sock.rs", "let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);\n    s.set_only_v6", "let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfc);\n    s.set_only_v6"),
    (N + "sock.rs", "let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);\n    s.set_only_v6", "let group = Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 0xfb);\n    s.set_only_v6"),
    (N + "sock.rs", "set_only_v6(true)", "set_only_v6(false)"),
    (N + "sock.rs", "set_read_timeout(Some(POLL))", "set_read_timeout(None)"),
    (N + "sock.rs", "const POLL: Duration = Duration::from_millis(50);", "const POLL: Duration = Duration::from_millis(51);"),
    (N + "sock.rs", "RCVBUF: usize = 256 * 1024", "RCVBUF: usize = 1"),
    (N + "sock.rs", "set_recv_buffer_size(RCVBUF)?;", ""),
    (N + "sock.rs", "iface.is_empty() || iface.contains('/')", "iface.contains('/')"),
    (N + "sock.rs", "iface.is_empty() || iface.contains('/')", "iface.is_empty()"),
    (N + "main.rs", "BURST: usize = 64", "BURST: usize = 65"),
    (N + "main.rs", "BURST: usize = 64", "BURST: usize = 63"),
    (N + "main.rs", "RECV_BUF: usize = 9216", "RECV_BUF: usize = 512"),
    (N + "main.rs", "MAX_SECS: u64 = 3600", "MAX_SECS: u64 = 3601"),
    (N + "main.rs", "if *e.kind() == IntErrorKind::PosOverflow", "if false"),
    (N + "main.rs", "Fail(\n                            3,", "Fail(\n                            1,"),
    (N + "main.rs", "Fail(2, format!(\"mDNS", "Fail(1, format!(\"mDNS"),
    (N + "main.rs", "sleep(ERROR_BACKOFF);", ""),
    (N + "main.rs", "self.packets += 1;", ""),
    (N + "main.rs", "st.read_errors += s.tracker.total;", "st.read_errors = s.tracker.total;"),
    (N + "main.rs", "(!found.is_empty()).then_some(found)", "Some(found)"),
    (N + "main.rs", "let mut prefix = 24u8;", "let mut prefix = 23u8;"),
    (N + "main.rs", "(1..=32).contains(&prefix)", "(1..=31).contains(&prefix)"),
    (N + "main.rs", "(1..=32).contains(&prefix)", "(2..=32).contains(&prefix)"),
    (N + "main.rs", "if v6 && iface.is_none()", "if false"),
    (N + "main.rs", "Err(e) if is_timeout(e.kind()) => {\n                    self.tracker.on_ok();", "Err(e) if is_timeout(e.kind()) => {"),
    (N + "main.rs", "Ok((n, from)) => {\n                    self.tracker.on_ok();", "Ok((n, from)) => {"),
    (N + "main.rs", "let mut secs = 30u64;", "let mut secs = 31u64;"),
    (N + "main.rs", "Kind::Ssdp => st.on_ssdp(f, from, &buf[..n])", "Kind::Ssdp => st.on_mdns(f, from, &buf[..n])"),
    (N + "main.rs", "Kind::Mdns4 | Kind::Mdns6 => st.on_mdns", "Kind::Mdns4 => st.on_mdns"),
    (N + "evidence.rs", "PER_SOURCE: usize = 64", "PER_SOURCE: usize = 63"),
    (N + "evidence.rs", "PER_SOURCE: usize = 64", "PER_SOURCE: usize = 65"),
    (N + "evidence.rs", "MAX_ITEMS: usize = 256", "MAX_ITEMS: usize = 255"),
    (N + "evidence.rs", "MAX_ITEMS: usize = 256", "MAX_ITEMS: usize = 257"),
    (N + "evidence.rs", "MAX_SOURCES: usize = 256", "MAX_SOURCES: usize = 255"),
    (N + "evidence.rs", "MAX_SOURCES: usize = 256", "MAX_SOURCES: usize = 257"),
    (N + "evidence.rs", "set.len() >= MAX_ITEMS", "set.len() > MAX_ITEMS"),
    (N + "evidence.rs", "used >= PER_SOURCE", "used > PER_SOURCE"),
    (N + "evidence.rs", "self.per_source.len() >= MAX_SOURCES", "self.per_source.len() > MAX_SOURCES"),
    (N + "evidence.rs", "(new_source && ", "(false && "),
    (N + "evidence.rs", "if !already {", "if true {"),
    (N + "evidence.rs", "(!already\n                && (", "(false\n                && ("),
    (N + "filter.rs", "if src == lan {", "if false {"),
    (N + "filter.rs", "32 - u32::from(prefix.min(32))", "31 - u32::from(prefix.min(32))"),
    (N + "filter.rs", "& 0xFFC0 == 0xFE80", "& 0xFF80 == 0xFE80"),
    (N + "filter.rs", "& 0xFFC0 == 0xFE80", "& 0xFFC0 == 0xFE00"),
    (N + "filter.rs", 'scope == "20"', 'scope == "00"'),
    (N + "filter.rs", "addr.len() == 32", "addr.len() == 31"),
    (N + "filter.rs", "name == iface &&", "true &&"),
    (N + "filter.rs", "self.include_own && v == Verdict::Own", "v == Verdict::Own"),
    (N + "recv.rs", "self.consecutive >= MAX_CONSECUTIVE_ERRORS", "self.consecutive > MAX_CONSECUTIVE_ERRORS"),
    (N + "recv.rs", "self.consecutive = 0;", ""),
    (N + "recv.rs", "ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted", "ErrorKind::TimedOut | ErrorKind::Interrupted"),
    (N + "recv.rs", "ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted", "ErrorKind::WouldBlock | ErrorKind::Interrupted"),
    (N + "recv.rs", "ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted", "ErrorKind::WouldBlock | ErrorKind::TimedOut"),
    (N + "recv.rs", "ERROR_BACKOFF: Duration = Duration::from_millis(50);", "ERROR_BACKOFF: Duration = Duration::from_millis(5);"),
    (N + "stats.rs", "self.mdns_truncated += u64::from(p.truncated)", "self.mdns_truncated += 1"),
    (N + "stats.rs", "self.own_packets += 1;", "self.own_packets += 2;"),
    (N + "stats.rs", "self.offlink_packets += 1;", "self.offlink_packets += 2;"),
    (N + "stats.rs", "p.server.or(p.user_agent)", "p.server"),
    (N + "stats.rs", "p.nt.or(p.st)", "p.nt"),
    (N + "stats.rs", "self.evidence.admit(ip, &mut self.mdns_services, n)", "self.mdns_services.insert(n)"),
    (N + "stats.rs", "self.evidence.admit(ip, &mut self.mdns_names, n)", "self.mdns_names.insert(n)"),
    (N + "stats.rs", "self.evidence.admit(ip, set, v)", "set.insert(v)"),
]
MUTS = (PARSE_MUTS if WHICH in ("parse", "all") else []) + (NET_MUTS if WHICH in ("net", "all") else [])
PKG = {"parse": ["-p", "vigie-parse"], "net": ["-p", "net-spike"], "all": []}[WHICH]

survived = []
for path, old, new in MUTS:
    src = open(path).read()
    if src.count(old) != 1:
        print("NOMATCH/AMBIG", src.count(old), path.split("/")[-1], repr(old))
        continue
    open(path, "w").write(src.replace(old, new))
    try:
        r = subprocess.run(["cargo", "test", *PKG, "--quiet"], cwd=ROOT, capture_output=True, text=True)
        status = "killed" if r.returncode != 0 else "SURVIVED"
        if "could not compile" in r.stderr + r.stdout:
            status = "compile-error"
    finally:
        open(path, "w").write(src)
    if status != "killed":
        survived.append((path.split("/")[-1], old, new, status))
    print(status, path.split("/")[-1], repr(old), "->", repr(new))
print("TOTAL", len(MUTS), "SURVIVED/OTHER", len(survived))
for s in survived:
    print(s)
