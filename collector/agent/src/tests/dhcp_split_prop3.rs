//! Round-6 property test (synthetic data only): THREE clients on three pids, and a second pid emitting a
//! complete packet for the SAME MAC, x poll splits, through the real `Agent::poll_log`.
use super::*;
use std::collections::BTreeMap;
use vigie_agent::model::Lease;

const FIX: &str = include_str!("../../tests/fixtures/dhcp-actual-order.synthetic.log");
const MA: &str = "02:00:00:00:00:01";
const MB: &str = "02:00:00:00:00:02";
const MC: &str = "02:00:00:00:00:03";

fn a_lines() -> Vec<String> {
    FIX.lines().map(|l| format!("{l}\n")).collect()
}
fn other(
    pid: u32,
    serial: u32,
    mac: &str,
    ip: &str,
    (v, h): (&str, &str),
    (o1, o2): (&str, &str),
) -> Vec<String> {
    a_lines()
        .iter()
        .map(|l| {
            l.replacen("[123]: 1 ", &format!("[{pid}]: {serial} "), 1)
                .replace("192.0.2.10 02:00:00:00:00:01", &format!("{ip} {mac}"))
                .replace("fixture-vendor", v)
                .replace("fixture-client", h)
                .replace("1:netmask, 3:router", o1)
                .replace("6:dns-server, 15:domain-name", o2)
        })
        .collect()
}
fn b() -> Vec<String> {
    other(
        456,
        1,
        MB,
        "192.0.2.11",
        ("vend-b", "host-b"),
        ("42:ntp, 3:router", "6:dns-server"),
    )
}
fn c() -> Vec<String> {
    other(
        789,
        1,
        MC,
        "192.0.2.12",
        ("vend-c", "host-c"),
        ("43:vs, 3:router", "12:hostname"),
    )
}
fn a2p(pid: u32) -> Vec<String> {
    other(
        pid,
        2,
        MA,
        "192.0.2.13",
        ("fixture-vendor", "fixture-client"),
        ("1:netmask, 3:router", "6:dns-server, 15:domain-name"),
    )
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
fn own(mac: &str) -> (&'static str, &'static str, Vec<Vec<u8>>) {
    match mac {
        MA => (
            "fixture-client",
            "fixture-vendor",
            vec![vec![], vec![1, 3], vec![1, 3, 6, 15]],
        ),
        MB => (
            "host-b",
            "vend-b",
            vec![vec![], vec![42, 3], vec![42, 3, 6]],
        ),
        MC => (
            "host-c",
            "vend-c",
            vec![vec![], vec![43, 3], vec![43, 3, 12]],
        ),
        _ => ("?", "?", vec![]),
    }
}
fn unsafe_reason(v: &[Lease]) -> Option<String> {
    for l in v {
        let (h, ve, lists) = own(&l.mac);
        if l.hostname.as_deref() != Some(h)
            || l.opt60.as_deref().is_some_and(|x| x != ve)
            || !lists.contains(&l.opt55)
        {
            return Some(format!("CROSS {l:?}"));
        }
    }
    None
}
/// Final per-MAC state: (ip, opts, vendor) of the last emitted lease.
type St = BTreeMap<String, (String, Vec<u8>, Option<String>)>;
fn fin(v: &[Lease]) -> St {
    v.iter()
        .map(|l| {
            (
                l.mac.clone(),
                (l.ip.clone(), l.opt55.clone(), l.opt60.clone()),
            )
        })
        .collect()
}
fn last_ack_ip(ls: &[String]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in ls {
        if let Some(i) = l.find("DHCPACK(") {
            let t: Vec<&str> = l[i..].split_whitespace().collect();
            m.insert(t[2].to_string(), t[1].to_string());
        }
    }
    m
}
fn class(s: &St, mac: &str) -> char {
    let full = own(mac).2.pop_last();
    match s.get(mac) {
        None => '-',
        Some((_, o, v)) if o.is_empty() && v.is_none() => 'n',
        Some((_, o, Some(_))) if Some(o) == full.as_ref() => 'F',
        Some((_, o, None)) if !o.is_empty() => 'V',
        Some((_, o, _)) if o.is_empty() => 'o',
        _ => 'T',
    }
}
trait PopLast {
    fn pop_last(self) -> Option<Vec<u8>>;
}
impl PopLast for Vec<Vec<u8>> {
    fn pop_last(mut self) -> Option<Vec<u8>> {
        self.pop()
    }
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
fn max_gap(src: &[u8], mask: u64) -> usize {
    let mut worst = 0;
    let mut last: BTreeMap<u8, usize> = BTreeMap::new();
    for (i, s) in src.iter().enumerate() {
        if *s == b'N' {
            continue;
        }
        if let Some(l) = last.get(s) {
            worst = worst.max((*l..i).filter(|k| (mask >> k) & 1 == 1).count());
        }
        last.insert(*s, i);
    }
    worst
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
fn interleave(srcs: &[Vec<String>], order: &[usize]) -> (Vec<String>, Vec<u8>) {
    let mut idx = vec![0; srcs.len()];
    let (mut out, mut tag) = (Vec::new(), Vec::new());
    for &s in order {
        out.push(srcs[s][idx[s]].clone());
        idx[s] += 1;
        tag.push(b'A' + s as u8);
    }
    (out, tag)
}
fn orders(lens: &[usize], rng: &mut Rng, nrand: usize) -> Vec<Vec<usize>> {
    let mut v = Vec::new();
    // structured: source 1 block at boundary k of 0, source 2 block at boundary j (of the result)
    let n0 = lens[0];
    for k in 0..=n0 {
        let mut base: Vec<usize> = vec![0; k];
        base.extend(vec![1; lens[1]]);
        base.extend(vec![0; n0 - k]);
        if lens.len() == 2 {
            v.push(base);
            continue;
        }
        for j in (0..=base.len()).step_by(3) {
            let mut o = base[..j].to_vec();
            o.extend(vec![2; lens[2]]);
            o.extend(base[j..].iter().copied());
            v.push(o);
        }
    }
    for _ in 0..nrand {
        let mut rem = lens.to_vec();
        let mut o = Vec::new();
        while rem.iter().any(|r| *r > 0) {
            let live: Vec<usize> = (0..rem.len()).filter(|i| rem[*i] > 0).collect();
            let s = live[(rng.next() as usize) % live.len()];
            rem[s] -= 1;
            o.push(s);
        }
        v.push(o);
    }
    v
}

fn family(
    label: &str,
    srcs: Vec<Vec<String>>,
    noise: Option<String>,
    nrand: usize,
    nmask: usize,
) -> (usize, usize, usize, Vec<String>) {
    let mut rng = Rng(0x2545F4914F6CDD1D);
    let lens: Vec<usize> = srcs.iter().map(|s| s.len()).collect();
    let mut rep = Vec::new();
    let (mut runs, mut bad_unsplit, mut cross, mut ipbad, mut mism) = (0, 0, 0, 0, 0);
    let mut base_cls: BTreeMap<String, usize> = BTreeMap::new();
    let mut mism_cls: BTreeMap<String, usize> = BTreeMap::new();
    let macs: Vec<String> = {
        let mut m: Vec<String> = srcs
            .iter()
            .map(|s| last_ack_ip(s).into_keys().next().unwrap())
            .collect();
        m.dedup();
        m.sort();
        m.dedup();
        m
    };
    for (oi, ord) in orders(&lens, &mut rng, nrand).iter().enumerate() {
        let (mut ls, mut tag) = interleave(&srcs, ord);
        if let Some(nz) = &noise {
            // one noise line at a pseudo-random position
            let p = (rng.next() as usize) % (ls.len() + 1);
            ls.insert(p, nz.clone());
            tag.insert(p, b'N');
        }
        let want_ip = last_ack_ip(&ls);
        let base = play(&[ls.clone()], &format!("{label}-{oi}-b"));
        let fb = fin(&base);
        let cls: String = macs.iter().map(|m| class(&fb, m)).collect();
        *base_cls.entry(cls.clone()).or_default() += 1;
        if unsafe_reason(&base).is_some() || cls.chars().any(|c| matches!(c, 'V' | 'T' | 'o')) {
            bad_unsplit += 1;
            if rep.len() < 12 {
                rep.push(format!(
                    "{label} UNSPLIT cls={cls} tag={} {:?}",
                    String::from_utf8_lossy(&tag),
                    unsafe_reason(&base)
                ));
            }
        }
        let n = ls.len();
        let mut masks = vec![0u64, (1u64 << (n - 1)) - 1];
        for _ in 0..nmask {
            masks.push(rng.next() & ((1u64 << (n - 1)) - 1));
        }
        for mask in masks {
            runs += 1;
            let got = play(&split(&ls, mask), &format!("{label}-{oi}-{mask}"));
            if let Some(r) = unsafe_reason(&got) {
                cross += 1;
                if rep.len() < 24 {
                    rep.push(format!(
                        "{label} {r} tag={} mask={mask:b}",
                        String::from_utf8_lossy(&tag)
                    ));
                }
            }
            let fg = fin(&got);
            for (m, ip) in &want_ip {
                if fg.get(m).map(|x| &x.0) != Some(ip) {
                    ipbad += 1;
                    if rep.len() < 24 {
                        rep.push(format!(
                            "{label} IP {m} want {ip} got {:?} tag={} mask={mask:b}",
                            fg.get(m),
                            String::from_utf8_lossy(&tag)
                        ));
                    }
                }
            }
            if fg != fb && max_gap(&tag, mask) <= 1 {
                mism += 1;
                let gc: String = macs.iter().map(|m| class(&fg, m)).collect();
                *mism_cls.entry(format!("{cls}->{gc}")).or_default() += 1;
                if rep.len() < 24 {
                    rep.push(format!(
                        "{label} MISM {cls}->{gc} tag={} mask={mask:b}",
                        String::from_utf8_lossy(&tag)
                    ));
                }
            }
        }
    }
    let counts = (bad_unsplit, cross, ipbad);
    rep.insert(0, format!("{label}: runs={runs} bad_unsplit={bad_unsplit} cross={cross} ipbad={ipbad} realistic_mism={mism} base_classes={base_cls:?} mism_classes={mism_cls:?}"));
    (counts.0, counts.1, counts.2, rep)
}

#[test]
fn r6_prop_three_clients_and_same_mac_second_pid() {
    let fwd = "Oct 20 14:00:00 dnsmasq[999]: forwarded example.test to 192.0.2.1\n".to_string();
    let fams = [
        ("abc", vec![a_lines(), b(), c()], None, 40, 3),
        ("a-a2", vec![a_lines(), a2p(456)], None, 30, 4),
        (
            "a-(b;a2)",
            vec![a_lines(), [b(), a2p(456)].concat()],
            None,
            30,
            4,
        ),
        ("a-b-a2p321", vec![a_lines(), b(), a2p(321)], None, 40, 3),
        ("abc+fwd", vec![a_lines(), b(), c()], Some(fwd), 40, 3),
    ];
    for (label, srcs, noise, nrand, nmask) in fams {
        let (bad_unsplit, cross, ipbad, rep) = family(label, srcs, noise, nrand, nmask);
        // Never another client's data, never a truncated or vendor-less result from the
        // unsplit stream, never an address that is not the last ACKed one.
        assert_eq!((bad_unsplit, cross, ipbad), (0, 0, 0), "{label}: {rep:#?}");
    }
}
