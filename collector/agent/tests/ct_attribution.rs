//! Sticky IP -> MAC memory and the split of the unmapped counters (expected exclusions vs a
//! genuine attribution failure).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;

use vigie_agent::builder::{build_with_drops, BATCH_CAP};
use vigie_agent::ctfold::CtAccum;
use vigie_agent::ctparse::{Kind, Record, Snapshot};
use vigie_agent::ctsock::CtShared;
use vigie_agent::ipmemory::{IpMemory, IP_MEMORY_CAP, IP_MEMORY_TTL_S};
use vigie_agent::model::{Health, Meta, Proto, Sections};
use vigie_agent::ownaddr::{parse_fib_trie, parse_if_inet6, OwnAddrs};
use vigie_agent::window::Window;
use vigie_agent::wiring::Sources;

const A: &str = "aa:bb:cc:dd:ee:01";
const B: &str = "aa:bb:cc:dd:ee:02";
const ULA: &str = "fd00::10";

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(i, m)| ((*i).to_string(), (*m).to_string()))
        .collect()
}

fn rec(src: &str, kind: Kind, up: u64, down: u64, flows: u64) -> Record {
    Record {
        src: src.parse().unwrap(),
        kind,
        dst: Some("1.1.1.1".parse().unwrap()),
        dport: Some(443),
        proto: Proto::Tcp,
        bytes_up: up,
        bytes_down: down,
        flows,
    }
}

fn snap(records: Vec<Record>) -> Snapshot {
    Snapshot {
        records,
        ..Snapshot::default()
    }
}

// ---- IpMemory ----

#[test]
fn an_expired_neighbor_entry_still_attributes_within_the_ttl() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(ULA, A)]), 100);
    let got = m.overlay(&HashMap::new(), 100 + IP_MEMORY_TTL_S);
    assert_eq!(got.get(ULA).map(String::as_str), Some(A));
}

#[test]
fn after_the_ttl_the_memory_no_longer_attributes() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(ULA, A)]), 100);
    let got = m.overlay(&HashMap::new(), 100 + IP_MEMORY_TTL_S + 1);
    assert!(got.is_empty());
    m.observe(&HashMap::new(), 100 + IP_MEMORY_TTL_S + 1);
    assert!(m.is_empty(), "expired entries are purged");
}

#[test]
fn a_reassigned_address_uses_the_new_mac() {
    let mut m = IpMemory::default();
    m.observe(&map(&[(ULA, A)]), 100);
    let now = map(&[(ULA, B)]);
    assert_eq!(m.overlay(&now, 101).get(ULA).map(String::as_str), Some(B));
    m.observe(&now, 101);
    // The table loses it again: the memory holds the NEW owner, never the old one.
    let got = m.overlay(&HashMap::new(), 102);
    assert_eq!(got.get(ULA).map(String::as_str), Some(B));
}

#[test]
fn the_memory_is_capped_and_evicts_the_oldest() {
    let mut m = IpMemory::default();
    for i in 0..(IP_MEMORY_CAP + 10) {
        m.observe(&map(&[(&format!("fd00::{i:x}"), A)]), 100);
    }
    assert_eq!(m.len(), IP_MEMORY_CAP);
    let got = m.overlay(&HashMap::new(), 100);
    assert!(!got.contains_key("fd00::0"), "oldest evicted");
    assert!(got.contains_key(&format!("fd00::{:x}", IP_MEMORY_CAP + 9)));
}

// ---- CtAccum split ----

#[test]
fn unmapped_sources_split_into_expected_and_suspect() {
    let own: HashSet<IpAddr> = ["192.168.8.1".parse().unwrap()].into();
    let mut acc = CtAccum::default();
    acc.add_snapshot_with_own(
        &snap(vec![
            rec("192.168.8.1", Kind::Tuple, 1, 2, 1),
            rec("0.0.0.0", Kind::OtherGlobal, 10, 20, 5),
            rec("fd00::99", Kind::Tuple, 100, 200, 2),
            rec("192.168.8.10", Kind::Other, 3, 4, 1),
        ]),
        &map(&[("192.168.8.10", A)]),
        &own,
    );
    assert_eq!(acc.take_lan_unmapped(), (300, 2));
    let (rows, ub, uf) = acc.take();
    assert_eq!(rows.len(), 1);
    assert_eq!((ub, uf), (33, 6), "own address plus the global remainder");
    assert_eq!(acc.take_lan_unmapped(), (0, 0), "reset by take");
}

#[test]
fn without_known_own_addresses_everything_unmapped_is_suspect() {
    let mut acc = CtAccum::default();
    acc.add_snapshot(
        &snap(vec![rec("192.168.8.1", Kind::Tuple, 1, 2, 1)]),
        &HashMap::new(),
    );
    assert_eq!(acc.take_lan_unmapped(), (3, 1));
}

// ---- own addresses ----

#[test]
fn fib_trie_local_entries_are_parsed() {
    let t = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 192.168.8.0\n        /32 link BROADCAST\n     |-- 192.168.8.1\n        /32 host LOCAL\n     |-- 192.168.8.255\n        /32 link BROADCAST\nLocal:\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
    let got: Vec<String> = parse_fib_trie(t).iter().map(|a| a.to_string()).collect();
    assert_eq!(got, ["192.168.8.1", "127.0.0.1"]);
}

#[test]
fn if_inet6_addresses_are_parsed_and_garbage_skipped() {
    let t = "fe800000000000000000000000000001 02 40 20 80 br-lan\n00000000000000000000000000000001 01 80 10 80 lo\nnothex\nabcd 01\n";
    let got: Vec<String> = parse_if_inet6(t).iter().map(|a| a.to_string()).collect();
    assert_eq!(got, ["fe80::1", "::1"]);
}

fn ok_reader() -> Option<HashSet<IpAddr>> {
    Some(["fd00::1".parse().unwrap()].into())
}
fn failing_reader() -> Option<HashSet<IpAddr>> {
    None
}

#[test]
fn own_addresses_include_the_lan_address_and_refresh_periodically() {
    let lan = Ipv4Addr::new(192, 168, 8, 1);
    let mut o = OwnAddrs::new(lan, ok_reader);
    assert!(o.set().is_empty(), "nothing read yet");
    o.refresh(0);
    assert!(o.set().contains(&IpAddr::V4(lan)) && o.set().contains(&"fd00::1".parse().unwrap()));
}

#[test]
fn a_read_failure_treats_nothing_as_own() {
    let mut o = OwnAddrs::new(Ipv4Addr::new(192, 168, 8, 1), failing_reader);
    o.refresh(0);
    assert!(o.set().is_empty(), "not even the configured address");
}

// ---- through Sources ----

fn batch_truncated(w: &mut Window) -> BTreeMap<String, u64> {
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    };
    let (sections, drops) = w.take_with_drops();
    build_with_drops(&meta, sections, &Health::default(), BATCH_CAP, &drops).truncated
}

#[test]
fn a_flow_outliving_its_neighbor_entry_is_attributed_then_goes_suspect_after_the_ttl() {
    let (tx, rx) = sync_channel(8);
    let shared = Arc::new(CtShared::default());
    shared.connected.store(true, Ordering::Relaxed);
    let mut s = Sources::from_parts(Some((rx, shared)), None, 0)
        .with_own_addrs(OwnAddrs::new(Ipv4Addr::new(192, 168, 8, 1), ok_reader));
    let mut w = Window::default();
    let flow = || snap(vec![rec(ULA, Kind::Tuple, 10, 20, 1)]);

    tx.send(flow()).unwrap();
    s.pump(&mut w, &map(&[(ULA, A)]), 10); // table still has it
    tx.send(flow()).unwrap();
    s.pump(&mut w, &HashMap::new(), 20); // entry expired: memory attributes
    s.finish_window(&mut w, 60);
    assert!(batch_truncated(&mut w).is_empty(), "no unmapped counter");

    tx.send(flow()).unwrap();
    s.pump(&mut w, &HashMap::new(), 20 + IP_MEMORY_TTL_S + 1);
    s.finish_window(&mut w, 20 + IP_MEMORY_TTL_S + 2);
    let t = batch_truncated(&mut w);
    assert_eq!(t.get("ct_lan_unmapped_bytes"), Some(&30));
    assert_eq!(t.get("ct_lan_unmapped_flows"), Some(&1));
    assert!(!t.contains_key("ct_unmapped_bytes"));
}

// ---- key cap ----

#[test]
fn the_lan_unmapped_pair_survives_the_key_cap_before_larger_counts() {
    let mut d: BTreeMap<String, u64> = (0..24)
        .map(|i| {
            (
                format!("drop_{}", (b'a' + i as u8) as char),
                1000 + i as u64,
            )
        })
        .collect();
    d.insert("ct_lan_unmapped_bytes".into(), 1);
    d.insert("ct_lan_unmapped_flows".into(), 1);
    d.insert("ct_unmapped_bytes".into(), 5000);
    d.insert("ct_unmapped_flows".into(), 5000);
    let meta = Meta {
        collector_id: "c1".into(),
        key_id: "k1".into(),
        boot_id: "boot1".into(),
        seq: 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: 1_760_000_000,
        window_end: 1_760_000_060,
    };
    let b = build_with_drops(
        &meta,
        Sections::default(),
        &Health::default(),
        BATCH_CAP,
        &d,
    );
    assert!(b.truncated.len() <= 16);
    assert_eq!(b.truncated.get("ct_lan_unmapped_bytes"), Some(&1));
    assert_eq!(b.truncated.get("ct_lan_unmapped_flows"), Some(&1));
    assert!(
        !b.truncated.contains_key("ct_unmapped_flows"),
        "companion yields first"
    );
    assert!(b.truncated.contains_key("ct_unmapped_bytes"));
}
