use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::dnsmasq::{parse_line, DhcpAssembler, DnsCorrelator, LogEvent};
use vigie_agent::leases::parse_leases;
use vigie_agent::model::Family;
use vigie_agent::neigh::{distinct_macs, ip_to_mac, parse_ip_neigh};
use vigie_agent::tail::Tail;

const DNS_FIXTURE: &str = include_str!("fixtures/dnsmasq-queries-extra.log");
const DHCP_FIXTURE: &str = include_str!("../../../tests/fixtures/p0/dnsmasq-dhcp-sample.log");

// ---- ip neigh ----

const NEIGH: &str = "\
192.168.1.50 dev br-lan lladdr AA:BB:CC:DD:EE:01 REACHABLE
192.168.1.51 dev br-lan lladdr aa:bb:cc:dd:ee:02 STALE
192.168.1.52 dev br-lan  FAILED
192.168.1.53 dev br-lan  INCOMPLETE
192.168.1.55 dev br-lan lladdr aa:bb:cc:dd:ee:03 FAILED
fe80::a1 dev br-lan lladdr aa:bb:cc:dd:ee:01 router STALE
2001:db8::5 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE
2001:db8::5 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE
2001:DB8::6 dev br-lan lladdr AA-BB-CC-DD-EE-01 DELAY
192.168.1.54 dev br-lan lladdr 00:00:00:00:00:00 PERMANENT
ff02::fb dev br-lan lladdr 33:33:00:00:00:fb NOARP
not an entry at all
";

#[test]
fn neigh_keeps_only_lladdr_entries_normalized_and_deduped() {
    let n = parse_ip_neigh(NEIGH);
    let pairs: Vec<(&str, &str, Family)> = n
        .iter()
        .map(|x| (x.ip.as_str(), x.mac.as_str(), x.family))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("192.168.1.50", "aa:bb:cc:dd:ee:01", Family::Inet),
            ("192.168.1.51", "aa:bb:cc:dd:ee:02", Family::Inet),
            ("fe80::a1", "aa:bb:cc:dd:ee:01", Family::Inet6),
            ("2001:db8::5", "aa:bb:cc:dd:ee:01", Family::Inet6),
            ("2001:db8::6", "aa:bb:cc:dd:ee:01", Family::Inet6),
        ]
    );
}

#[test]
fn neigh_dedupes_by_mac_and_maps_ip_to_mac() {
    let n = parse_ip_neigh(NEIGH);
    assert_eq!(
        distinct_macs(&n),
        vec!["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    );
    let m = ip_to_mac(&n);
    assert_eq!(m.len(), 5);
    assert_eq!(m["2001:db8::5"], "aa:bb:cc:dd:ee:01");
    assert_eq!(m["192.168.1.51"], "aa:bb:cc:dd:ee:02");
}

// ---- dhcp.leases ----

#[test]
fn leases_file_parsing() {
    let text = "\
1760003600 aa:bb:cc:dd:ee:01 192.168.1.50 Pixel-8 01:aa:bb:cc:dd:ee:01
1760003600 AA:BB:CC:DD:EE:02 192.168.1.51 * *
duid 00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:01
1760003600 12345 fd00::5 host2 00:01:00:01
1760003600 zz:bb:cc:dd:ee:03 192.168.1.52 bad *
badline
";
    let l = parse_leases(text);
    assert_eq!(l.len(), 2);
    assert_eq!(l[0].mac, "aa:bb:cc:dd:ee:01");
    assert_eq!(l[0].ip, "192.168.1.50");
    assert_eq!(l[0].hostname.as_deref(), Some("Pixel-8"));
    assert_eq!(l[1].mac, "aa:bb:cc:dd:ee:02");
    assert_eq!(l[1].hostname, None);
}

// ---- dnsmasq log lines ----

#[test]
fn query_and_answer_lines() {
    let q = parse_line(
        "Oct 20 14:00:01 dnsmasq[1234]: 1 192.168.1.50/53422 query[A] example.com from 192.168.1.50",
    );
    assert_eq!(
        q,
        Some(LogEvent::Query {
            id: "1".into(),
            client_ip: "192.168.1.50".into(),
            qtype: "A".into(),
            name: "example.com".into()
        })
    );
    let a = parse_line(
        "Oct 20 14:00:01 dnsmasq[1234]: 1 192.168.1.50/53422 reply example.com is 93.184.216.34",
    );
    assert_eq!(
        a,
        Some(LogEvent::Answer {
            id: "1".into(),
            client_ip: "192.168.1.50".into(),
            ip: "93.184.216.34".into()
        })
    );
    // cached answers and v6 clients
    assert!(matches!(
        parse_line("Oct 20 14:00:02 dnsmasq[1]: 2 fe80::1/53423 cached x.test is 2606:2800::1"),
        Some(LogEvent::Answer { .. })
    ));
    // non-IP answers, forwarded lines, name with spaces, startup chatter: no event
    for none in [
        "Oct 20 14:00:03 dnsmasq[1]: 3 192.168.1.51/40000 reply www.apple.com is <CNAME>",
        "Oct 20 14:00:03 dnsmasq[1]: 3 192.168.1.51/40000 forwarded www.apple.com to 9.9.9.9",
        "Oct 20 14:00:04 dnsmasq[1]: 4 192.168.1.51/1 config tracker.test is NXDOMAIN",
        "Oct 20 14:00:08 dnsmasq[1]: 7 192.168.1.50/1 query[TXT] weird name from 192.168.1.50",
        "Oct 20 14:00:07 dnsmasq[1234]: started, version 2.85 cachesize 150",
        "this line is garbage",
        "",
    ] {
        assert_eq!(parse_line(none), None, "{none}");
    }
}

#[test]
fn dns_fixture_correlates_answers_and_attributes_macs() {
    let mut map = HashMap::new();
    map.insert("192.168.1.50".to_string(), "aa:bb:cc:dd:ee:01".to_string());
    map.insert("192.168.1.51".to_string(), "aa:bb:cc:dd:ee:02".to_string());
    map.insert(
        "fe80::1c2d:3e4f:5a6b:7c8d".to_string(),
        "aa:bb:cc:dd:ee:03".to_string(),
    );
    map.insert("192.168.1.60".to_string(), "aa:bb:cc:dd:ee:04".to_string());
    let mut c = DnsCorrelator::default();
    for line in DNS_FIXTURE.lines() {
        if let Some(ev) = parse_line(line) {
            c.feed(&ev, 1_760_000_000);
        }
    }
    let q = c.take_ready(&map);
    let view: Vec<(&str, &str, &str, Option<&str>)> = q
        .iter()
        .map(|d| {
            (
                d.mac.as_str(),
                d.qtype.as_str(),
                d.qname.as_str(),
                d.answer_ip.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        view,
        vec![
            (
                "aa:bb:cc:dd:ee:01",
                "A",
                "example.com",
                Some("93.184.216.34")
            ),
            (
                "aa:bb:cc:dd:ee:01",
                "AAAA",
                "example.com",
                Some("2606:2800:220:1:248:1893:25c8:1946")
            ),
            (
                "aa:bb:cc:dd:ee:02",
                "HTTPS",
                "www.apple.com",
                Some("23.45.67.89")
            ),
            ("aa:bb:cc:dd:ee:03", "A", "tracker.bad.example", None),
            (
                "aa:bb:cc:dd:ee:04",
                "PTR",
                "50.1.168.192.in-addr.arpa",
                None
            ),
        ],
        "192.168.1.99 has no neighbor entry and is dropped"
    );
    assert!(q.iter().all(|d| d.ts == 1_760_000_000));
    assert!(c.take_ready(&map).is_empty(), "drained");
}

// ---- DHCP log (formats ASSUMED from dnsmasq docs; not verified on the router) ----

#[test]
fn dhcp_fixture_assembles_leases_with_fingerprint() {
    let mut a = DhcpAssembler::default();
    let leases: Vec<_> = DHCP_FIXTURE
        .lines()
        .filter_map(parse_line)
        .filter_map(|ev| a.feed(&ev))
        .collect();
    assert_eq!(leases.len(), 7);
    let l = &leases[0];
    assert_eq!(l.mac, "c2:11:22:33:44:01");
    assert_eq!(l.ip, "192.168.1.50");
    assert_eq!(l.hostname.as_deref(), Some("Pixel-8"));
    assert_eq!(l.opt55, vec![1, 3, 6, 15, 26, 28, 51, 58, 59]);
    assert_eq!(l.opt60.as_deref(), Some("android-dhcp-14"));
    let iphone = &leases[3];
    assert_eq!(iphone.mac, "6a:aa:bb:cc:dd:01");
    assert_eq!(iphone.opt55, vec![1, 121, 3, 6, 15, 119, 252]);
    assert_eq!(
        iphone.opt60, None,
        "no vendor class line for this transaction"
    );
    assert_eq!(leases[5].hostname.as_deref(), Some("DiskStation"));
}

// ---- never panic on garbage ----

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn parsers_never_panic_on_random_and_mutated_input() {
    let seeds: Vec<&str> = DNS_FIXTURE
        .lines()
        .chain(DHCP_FIXTURE.lines())
        .chain(NEIGH.lines())
        .collect();
    let mut st = 0x9E37_79B9_7F4A_7C15u64;
    let mut a = DhcpAssembler::default();
    let mut c = DnsCorrelator::default();
    let map = HashMap::new();
    for i in 0..30_000 {
        let line: String = if i % 2 == 0 {
            let len = (xorshift(&mut st) % 200) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| xorshift(&mut st) as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            let mut b = seeds[(xorshift(&mut st) as usize) % seeds.len()]
                .as_bytes()
                .to_vec();
            for _ in 0..(1 + xorshift(&mut st) % 4) {
                if b.is_empty() {
                    break;
                }
                let at = (xorshift(&mut st) as usize) % b.len();
                match xorshift(&mut st) % 3 {
                    0 => b[at] = xorshift(&mut st) as u8,
                    1 => b.truncate(at),
                    _ => b.insert(at, xorshift(&mut st) as u8),
                }
            }
            String::from_utf8_lossy(&b).into_owned()
        };
        if let Some(ev) = parse_line(&line) {
            a.feed(&ev);
            c.feed(&ev, 1);
        }
        let _ = parse_ip_neigh(&line);
        let _ = parse_leases(&line);
        if i % 1000 == 0 {
            let _ = c.take_ready(&map);
        }
    }
}

// ---- tail ----

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-tail-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

fn append(p: &PathBuf, s: &str) {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

#[test]
fn tail_starts_at_end_and_returns_only_new_complete_lines() {
    let d = tmpdir();
    let p = d.join("dnsmasq.log");
    append(&p, "old1\nold2\n");
    let mut t = Tail::new(p.clone());
    assert_eq!(
        t.poll().unwrap(),
        Vec::<String>::new(),
        "history is skipped"
    );
    append(&p, "new1\nnew2\npart");
    assert_eq!(t.poll().unwrap(), vec!["new1", "new2"]);
    append(&p, "ial\n");
    assert_eq!(
        t.poll().unwrap(),
        vec!["partial"],
        "partial line carried over"
    );
    assert!(t.poll().unwrap().is_empty());
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn tail_survives_rename_rotation_without_losing_lines() {
    let d = tmpdir();
    let p = d.join("dnsmasq.log");
    append(&p, "x\n");
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    append(&p, "a1\n");
    fs::rename(&p, d.join("dnsmasq.log.1")).unwrap();
    append(&p, "b1\nb2\n");
    assert_eq!(t.poll().unwrap(), vec!["a1", "b1", "b2"]);
    append(&p, "b3\n");
    assert_eq!(t.poll().unwrap(), vec!["b3"], "follows the new file");
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn tail_handles_truncation_and_missing_file() {
    let d = tmpdir();
    let p = d.join("dnsmasq.log");
    let mut t = Tail::new(p.clone());
    assert!(t.poll().unwrap().is_empty(), "missing file is not an error");
    append(&p, "first\n");
    assert_eq!(
        t.poll().unwrap(),
        vec!["first"],
        "a file that appears later is read from the start"
    );
    append(&p, "second\n");
    fs::write(&p, "").unwrap();
    append(&p, "c\n");
    assert_eq!(
        t.poll().unwrap(),
        vec!["c"],
        "truncated in place (watchdog) restarts at 0"
    );
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn tail_bounds_line_length_and_per_poll_bytes() {
    let d = tmpdir();
    let p = d.join("dnsmasq.log");
    append(&p, "");
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    append(&p, &format!("{}\nshort\n", "z".repeat(100_000)));
    assert_eq!(t.poll().unwrap(), vec!["short"], "overlong line dropped");
    // 40,000 lines of ~30 bytes = ~1.2 MB: more than one poll's byte budget, nothing lost.
    let mut all = String::new();
    for i in 0..40_000 {
        all.push_str(&format!("line-number-{i:08}-padding\n"));
    }
    append(&p, &all);
    let mut got = 0usize;
    let mut polls = 0;
    loop {
        let l = t.poll().unwrap();
        if l.is_empty() {
            break;
        }
        got += l.len();
        polls += 1;
        assert!(polls < 100);
    }
    assert_eq!(got, 40_000);
    assert!(polls >= 2, "read in bounded chunks");
    fs::remove_dir_all(d).unwrap();
}
