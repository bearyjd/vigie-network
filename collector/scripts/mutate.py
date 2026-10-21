import subprocess, sys

ROOT = sys.argv[1]
M = ROOT + "/parse/src/mdns.rs"
S = ROOT + "/parse/src/ssdp.rs"
MUTS = [
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

survived = []
for path, old, new in MUTS:
    src = open(path).read()
    if src.count(old) != 1:
        print("NOMATCH/AMBIG", src.count(old), path.split("/")[-1], repr(old))
        continue
    open(path, "w").write(src.replace(old, new))
    try:
        r = subprocess.run(["cargo", "test", "-p", "vigie-parse", "--quiet"], cwd=ROOT, capture_output=True, text=True)
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
