//! Round-5 property test: two clients' packets interleaved (B inserted at every line boundary
//! of A, and line by line) x 62 poll-split masks, with and without a foreign line after every
//! line, through the real `Agent::poll_log`. Synthetic data only.
use super::*;
use vigie_agent::model::Lease;

const FIX: &str = include_str!("../../tests/fixtures/dhcp-actual-order.synthetic.log");

fn a_lines() -> Vec<String> {
    FIX.lines().map(|l| format!("{l}\n")).collect()
}
/// Client B: same shape, its own MAC/IP/vendor/name/options; `pid` and serial chosen.
fn b_lines(pid: u32, serial: u32) -> Vec<String> {
    a_lines()
        .iter()
        .map(|l| {
            l.replacen("[123]: 1 ", &format!("[{pid}]: {serial} "), 1)
                .replace("02:00:00:00:00:01", "02:00:00:00:00:02")
                .replace("192.0.2.10 02", "192.0.2.11 02")
                .replace("fixture-vendor", "vend-b")
                .replace("fixture-client", "host-b")
                .replace("1:netmask, 3:router", "42:ntp, 3:router")
                .replace("6:dns-server, 15:domain-name", "6:dns-server")
        })
        .collect()
}

fn play(sched: &[Vec<String>], tag: &str) -> Vec<Lease> {
    let (mut a, path) = log_agent(tag);
    let mut out = Vec::new();
    for (t, chunk) in sched.iter().enumerate() {
        append(&path, &chunk.concat());
        a.poll_log(1 + t as u64);
        out.extend(a.window.take_identity().leases);
    }
    for t in 0..3 {
        a.poll_log(100 + t);
        out.extend(a.window.take_identity().leases);
    }
    std::fs::remove_file(path).ok();
    out
}

type Fp = Vec<(String, Vec<u8>, Option<String>)>;
fn fps(v: &[Lease]) -> Fp {
    let mut f: Fp = v
        .iter()
        .filter(|l| !l.opt55.is_empty() || l.opt60.is_some())
        .map(|l| (l.mac.clone(), l.opt55.clone(), l.opt60.clone()))
        .collect();
    f.sort();
    f
}
/// Max number of poll ends between two consecutive lines of the same client (src tag).
fn max_gap(src: &[u8], mask: u64) -> usize {
    let mut worst = 0;
    for c in *b"AB" {
        let mut last: Option<usize> = None;
        for (i, s) in src.iter().enumerate() {
            if *s == c {
                if let Some(l) = last {
                    let ends = (l..i).filter(|k| (mask >> k) & 1 == 1).count();
                    worst = worst.max(ends);
                }
                last = Some(i);
            }
        }
    }
    worst
}

/// Safety: no cross-attribution, hostnames, option sets are prefixes of the client's own list.
fn unsafe_reason(v: &[Lease]) -> Option<String> {
    for l in v {
        let (host, vend, lists): (&str, &str, Vec<Vec<u8>>) = match l.mac.as_str() {
            "02:00:00:00:00:01" => (
                "fixture-client",
                "fixture-vendor",
                vec![vec![], vec![1, 3], vec![1, 3, 6, 15]],
            ),
            "02:00:00:00:00:02" => (
                "host-b",
                "vend-b",
                vec![vec![], vec![42, 3], vec![42, 3, 6]],
            ),
            m => return Some(format!("unknown mac {m}")),
        };
        if l.hostname.as_deref() != Some(host) {
            return Some(format!("CROSS host {l:?}"));
        }
        if l.opt60.as_deref().is_some_and(|v| v != vend) {
            return Some(format!("CROSS vendor {l:?}"));
        }
        if !lists.contains(&l.opt55) {
            return Some(format!("CROSS opts {l:?}"));
        }
    }
    None
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Merge order: true = take from A. `kind`: block insertion of B at k, or line alternation.
fn merges(n: usize) -> Vec<Vec<bool>> {
    let mut v = Vec::new();
    for k in 0..=n {
        let mut m = vec![true; k];
        m.extend(vec![false; n]);
        m.extend(vec![true; n - k]);
        v.push(m);
    }
    for off in 0..n {
        // A0..A(off-1), then alternate B,A
        let mut m = vec![true; off];
        let (mut ra, mut rb) = (n - off, n);
        while ra + rb > 0 {
            if rb > 0 {
                m.push(false);
                rb -= 1;
            }
            if ra > 0 {
                m.push(true);
                ra -= 1;
            }
        }
        v.push(m);
    }
    v
}

fn merged(order: &[bool], a: &[String], b: &[String]) -> Vec<String> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    for &t in order {
        if t {
            out.push(a[i].clone());
            i += 1
        } else {
            out.push(b[j].clone());
            j += 1
        }
    }
    out
}

fn split(ls: &[String], mask: u64) -> Vec<Vec<String>> {
    let (mut out, mut cur) = (Vec::new(), Vec::new());
    for (i, l) in ls.iter().enumerate() {
        cur.push(l.clone());
        if i + 1 == ls.len() || (mask >> i) & 1 == 1 {
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

fn run_family(
    label: &str,
    b: Vec<String>,
    noise: Option<Vec<String>>,
) -> (usize, usize, usize, Vec<String>) {
    let a = a_lines();
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let (mut runs, mut unsafe_n, mut mism) = (0, 0, 0);
    let mut first = Vec::new();
    let mut buckets: std::collections::BTreeMap<char, (usize, String)> = Default::default();
    for (mi, order) in merges(a.len()).iter().enumerate() {
        let mut ls = merged(order, &a, &b);
        let mut src: Vec<u8> = order.iter().map(|t| if *t { b'A' } else { b'B' }).collect();
        if let Some(nz) = &noise {
            // insert a noise line after every line
            ls = ls
                .into_iter()
                .flat_map(|l| std::iter::once(l).chain(nz.iter().cloned()))
                .collect();
            src = src.into_iter().flat_map(|c| [c, b'N']).collect();
        }
        let n = ls.len();
        let base = play(&[ls.clone()], &format!("{label}-{mi}-base"));
        {
            let full_a = vec![1u8, 3, 6, 15];
            let full_b = vec![42u8, 3, 6];
            let cls: String = ["02:00:00:00:00:01", "02:00:00:00:00:02"]
                .iter()
                .map(|m| {
                    let full = if m.ends_with('1') { &full_a } else { &full_b };
                    let f: Vec<_> = fps(&base).into_iter().filter(|x| &x.0 == m).collect();
                    match f.last() {
                        None => 'n',
                        Some((_, o, v)) => {
                            if o == full && v.is_some() {
                                'F'
                            } else if !o.is_empty() && v.is_none() {
                                'V'
                            } else if o != full && !o.is_empty() {
                                'T'
                            } else {
                                'o'
                            }
                        }
                    }
                })
                .collect();
            first.push(format!(
                "{label} merge={mi} {} base={cls}",
                order
                    .iter()
                    .map(|t| if *t { 'A' } else { 'B' })
                    .collect::<String>()
            ));
        }
        if let Some(r) = unsafe_reason(&base) {
            unsafe_n += 1;
            first.push(format!("{label} merge={mi} UNSPLIT {r}"));
        }
        let mut masks = vec![0u64, (1u64 << (n - 1)) - 1];
        for _ in 0..60 {
            masks.push(rng.next() & ((1u64 << (n - 1)) - 1));
        }
        for mask in masks {
            runs += 1;
            let got = play(&split(&ls, mask), &format!("{label}-{mi}-{mask}"));
            if let Some(r) = unsafe_reason(&got) {
                unsafe_n += 1;
                if first.len() < 40 {
                    first.push(format!("{label} merge={mi} mask={mask:b} {r}"));
                }
            } else if fps(&got) != fps(&base) {
                if max_gap(&src, mask) <= 1 {
                    mism += 1;
                }
                // bucket: per MAC whose result differs from base
                let mut bk = 'd';
                for m in ["02:00:00:00:00:01", "02:00:00:00:00:02"] {
                    let g: Vec<_> = fps(&got).into_iter().filter(|x| x.0 == m).collect();
                    let b: Vec<_> = fps(&base).into_iter().filter(|x| x.0 == m).collect();
                    if g == b {
                        continue;
                    }
                    let full: Vec<u8> = if m.ends_with('1') {
                        vec![1, 3, 6, 15]
                    } else {
                        vec![42, 3, 6]
                    };
                    let c = match g.as_slice() {
                        [] => 'd',
                        [(_, o, Some(_))] if o != &full => 's',
                        _ if matches!(b.as_slice(), [(_, o, Some(_))] if o == &full) => 'X',
                        _ => 'x',
                    };
                    if c == 'x' || c == 'X' || (c == 's' && bk == 'd') {
                        bk = c;
                    }
                }
                let e = buckets.entry(bk).or_insert((0usize, String::new()));
                e.0 += 1;
                if e.1.is_empty() {
                    e.1 = format!(
                        "order={} mask={mask:b} got={:?} base={:?}",
                        src.iter().map(|c| *c as char).collect::<String>(),
                        fps(&got),
                        fps(&base)
                    );
                }
                if false {
                    first.push(format!(
                        "{label} merge={mi} order={:?} mask={mask:b} got={:?} base={:?}",
                        order
                            .iter()
                            .map(|t| if *t { 'A' } else { 'B' })
                            .collect::<String>(),
                        fps(&got),
                        fps(&base)
                    ));
                }
            }
        }
    }
    for (k, (n, ex)) in &buckets {
        first.push(format!("BUCKET {k} n={n} e.g. {ex}"));
    }
    (runs, unsafe_n, mism, first)
}

#[test]
fn r5_prop_two_clients() {
    let noise = |pid: u32, rest: &str| {
        Some(vec![format!(
            "Oct 20 14:00:00 dnsmasq[{pid}]: 55 192.0.2.99/5353 {rest}\n"
        )])
    };
    let fams = vec![
        ("pid2", b_lines(456, 1), None),
        ("samepid", b_lines(123, 2), None),
        (
            "pid2-dnsq",
            b_lines(456, 1),
            noise(789, "query[A] example.test from 192.0.2.99"),
        ),
        (
            "samepid-dnsq",
            b_lines(456, 1),
            noise(123, "query[A] example.test from 192.0.2.99"),
        ),
        (
            "pid2-fwd",
            b_lines(456, 1),
            noise(789, "forwarded example.test to 192.0.2.1"),
        ),
    ];
    for (label, b, nz) in fams {
        let (runs, unsafe_n, mism, report) = run_family(label, b, nz);
        assert_eq!(runs, 1302, "{label}");
        // Never another client's host, vendor or options; a realistic schedule (no client
        // quiet for two polls mid-packet) changes nothing.
        assert_eq!((unsafe_n, mism), (0, 0), "{label}: {report:#?}");
        for line in &report {
            // Only the allowed buckets exist: `d` (fingerprint safely dropped) and `s` (the
            // documented post-ACK stall). `x`/`X`: a bad result from an interleaving.
            assert!(!line.starts_with("BUCKET x"), "{label}: {line}");
            assert!(!line.starts_with("BUCKET X"), "{label}: {line}");
            // The unsplit stream is clean for every client: published whole (F) or not at
            // all (n), never vendor-less (V).
            if let Some((_, base)) = line
                .split_once(" base=")
                .filter(|_| line.contains(" merge="))
            {
                // (One pid writing two packets alternately is not a real log: there the
                // next packet's line ends the block, options-less (o) or cut (T), as documented.)
                let ok = |c: char| {
                    c == 'F' || c == 'n' || (matches!(c, 'o' | 'T') && label.starts_with("samepid"))
                };
                assert!(base.chars().all(ok), "{label}: {line}");
            }
        }
    }
}
