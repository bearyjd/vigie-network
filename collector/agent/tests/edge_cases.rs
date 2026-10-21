//! Edge cases found by the mutation run (boundaries the first test pass did not pin down).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::dnsmasq::{parse_line, DnsCorrelator};
use vigie_agent::model::*;
use vigie_agent::neigh::parse_ip_neigh;
use vigie_agent::spool::Spool;
use vigie_agent::tail::Tail;

fn enc(seq: u64) -> EncodedBatch {
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq,
        batch_id: format!("01927f3e-8a1b-7c2d-9e4f-{seq:012x}"),
        window_start: 1,
        window_end: 2,
    };
    encode(
        &meta,
        &Sections::default(),
        &BTreeMap::new(),
        &Health::default(),
    )
}

#[test]
fn spool_keeps_a_batch_that_exactly_fills_it() {
    let one = enc(1).len();
    let mut sp = Spool::new(one * 2);
    sp.push(enc(1));
    sp.push(enc(2));
    assert_eq!(sp.len(), 2, "an exact fit is not an overflow");
    assert_eq!(sp.dropped_unreported(), 0);
    sp.push(enc(3));
    assert_eq!(sp.len(), 2);
    assert_eq!(sp.dropped_unreported(), 1);
}

#[test]
fn multicast_mac_with_unicast_ip_is_not_a_neighbor() {
    let n = parse_ip_neigh(
        "192.168.1.77 dev br-lan lladdr 01:00:5e:00:00:01 REACHABLE\n\
         192.168.1.78 dev br-lan lladdr 02:00:5e:00:00:01 REACHABLE\n",
    );
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].ip, "192.168.1.78");
}

#[test]
fn first_ip_answer_wins() {
    let mut c = DnsCorrelator::default();
    for l in [
        "Oct 20 14:00:01 dnsmasq[1]: 9 192.168.1.50/1 query[A] multi.test from 192.168.1.50",
        "Oct 20 14:00:01 dnsmasq[1]: 9 192.168.1.50/1 reply multi.test is 198.51.100.1",
        "Oct 20 14:00:01 dnsmasq[1]: 9 192.168.1.50/1 reply multi.test is 198.51.100.2",
    ] {
        c.feed(&parse_line(l).unwrap(), 5);
    }
    let mut map = HashMap::new();
    map.insert("192.168.1.50".to_string(), "aa:bb:cc:dd:ee:01".to_string());
    let q = c.take_ready(&map);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].answer_ip.as_deref(), Some("198.51.100.1"));
}

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-edge-{}-{}",
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
fn tail_drains_a_rotated_file_backlog_before_switching() {
    let d = tmpdir();
    let p = d.join("dnsmasq.log");
    append(&p, "");
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    let mut backlog = String::new();
    for i in 0..40_000 {
        backlog.push_str(&format!("old-{i:08}-padding-padding\n"));
    }
    append(&p, &backlog);
    fs::rename(&p, d.join("dnsmasq.log.1")).unwrap();
    append(&p, "new-1\n");
    let mut got: Vec<String> = Vec::new();
    for _ in 0..10 {
        got.extend(t.poll().unwrap());
    }
    assert_eq!(got.len(), 40_001, "nothing lost across the rotation");
    assert_eq!(
        got.last().map(String::as_str),
        Some("new-1"),
        "new file read last"
    );
    assert_eq!(got[0], "old-00000000-padding-padding");
    fs::remove_dir_all(d).unwrap();
}
