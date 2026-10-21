//! IP -> MAC mapping of helper snapshots and per-window accumulation.

use std::collections::HashMap;

use vigie_agent::ctfold::{CtAccum, MAX_KEYS};
use vigie_agent::ctparse::{parse_snapshot, Kind, Record, Snapshot};
use vigie_agent::model::{Neighbor, Proto};
use vigie_agent::neigh::ip_to_mac;

const A: &str = "aa:bb:cc:dd:ee:01";
const B: &str = "aa:bb:cc:dd:ee:02";

fn table(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    let n: Vec<Neighbor> = pairs
        .iter()
        .map(|(i, m)| Neighbor::new(i, m).unwrap())
        .collect();
    ip_to_mac(&n)
}

fn rec(src: &str, dst: &str, port: u16, up: u64, down: u64, flows: u64) -> Record {
    Record {
        src: src.parse().unwrap(),
        kind: Kind::Tuple,
        dst: Some(dst.parse().unwrap()),
        dport: Some(port),
        proto: Proto::Tcp,
        bytes_up: up,
        bytes_down: down,
        flows,
    }
}

fn other(src: &str, kind: Kind, up: u64, down: u64, flows: u64) -> Record {
    Record {
        src: src.parse().unwrap(),
        kind,
        dst: None,
        dport: None,
        proto: Proto::Other,
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

#[test]
fn mapped_rows_carry_the_mac_and_unmapped_bytes_fold_into_counters() {
    let t = table(&[("192.168.8.10", A)]);
    let mut acc = CtAccum::default();
    acc.add_snapshot(
        &snap(vec![
            rec("192.168.8.10", "1.1.1.1", 443, 10, 20, 1),
            rec("192.168.8.99", "1.1.1.1", 443, 7, 3, 2),
            other("0.0.0.0", Kind::OtherGlobal, 100, 200, 5),
        ]),
        &t,
    );
    let (rows, ub, uf) = acc.take();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].mac.as_str(), rows[0].bytes_up, rows[0].bytes_down),
        (A, 10, 20)
    );
    assert_eq!(rows[0].dst_ip.as_deref(), Some("1.1.1.1"));
    assert_eq!(
        (ub, uf),
        (310, 7),
        "unmapped host (10) plus the global remainder (300)"
    );
    let (again, ub, uf) = acc.take();
    assert!(
        again.is_empty() && ub == 0 && uf == 0,
        "take empties the accumulator"
    );
}

#[test]
fn a_mapped_other_record_becomes_the_macs_other_bucket() {
    let t = table(&[("192.168.8.10", A)]);
    let mut acc = CtAccum::default();
    acc.add_snapshot(&snap(vec![other("192.168.8.10", Kind::Other, 5, 6, 7)]), &t);
    let (rows, ..) = acc.take();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].dst_ip.clone(), rows[0].dst_port, rows[0].proto),
        (None, None, Proto::Other)
    );
    assert_eq!(
        (rows[0].bytes_up, rows[0].bytes_down, rows[0].flows),
        (5, 6, 7)
    );
}

#[test]
fn two_ips_of_one_mac_merge_and_ipv6_privacy_addresses_map() {
    let t = table(&[
        ("192.168.8.10", A),
        ("fd00::1", A),
        ("2001:db8::aaaa:1", A), // a privacy address the kernel still knows
        ("192.168.8.11", B),
    ]);
    let mut acc = CtAccum::default();
    acc.add_snapshot(
        &snap(vec![
            rec("192.168.8.10", "1.1.1.1", 443, 1, 2, 1),
            rec("fd00::1", "1.1.1.1", 443, 10, 20, 2),
            rec("2001:DB8::AAAA:1", "1.1.1.1", 443, 100, 200, 4),
            rec("192.168.8.11", "1.1.1.1", 443, 1000, 2000, 8),
        ]),
        &t,
    );
    let (rows, ub, _) = acc.take();
    assert_eq!(ub, 0);
    let a = rows.iter().find(|r| r.mac == A).unwrap();
    assert_eq!(
        (a.bytes_up, a.bytes_down, a.flows),
        (111, 222, 7),
        "summed within one sample"
    );
    assert_eq!(rows.iter().filter(|r| r.mac == A).count(), 1);
    assert_eq!(rows.iter().find(|r| r.mac == B).unwrap().bytes_up, 1000);
}

#[test]
fn a_privacy_address_missing_from_the_table_folds_to_unmapped() {
    let t = table(&[("fd00::1", A)]);
    let mut acc = CtAccum::default();
    acc.add_snapshot(
        &snap(vec![rec("fd00::dead:beef", "1.1.1.1", 443, 9, 1, 1)]),
        &t,
    );
    let (rows, ub, uf) = acc.take();
    assert!(rows.is_empty());
    assert_eq!((ub, uf), (10, 1));
}

#[test]
fn across_samples_bytes_add_but_flows_take_the_maximum() {
    let t = table(&[("192.168.8.10", A)]);
    let mut acc = CtAccum::default();
    acc.add_snapshot(
        &snap(vec![rec("192.168.8.10", "1.1.1.1", 443, 10, 20, 3)]),
        &t,
    );
    acc.add_snapshot(
        &snap(vec![rec("192.168.8.10", "1.1.1.1", 443, 1, 2, 5)]),
        &t,
    );
    acc.add_snapshot(
        &snap(vec![rec("192.168.8.10", "1.1.1.1", 443, 1, 2, 2)]),
        &t,
    );
    let (rows, ..) = acc.take();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].bytes_up, rows[0].bytes_down, rows[0].flows),
        (12, 24, 5)
    );
}

#[test]
fn counters_saturate_instead_of_wrapping() {
    let t = table(&[("192.168.8.10", A)]);
    let mut acc = CtAccum::default();
    for _ in 0..3 {
        acc.add_snapshot(
            &snap(vec![rec("192.168.8.10", "1.1.1.1", 1, u64::MAX, 0, 1)]),
            &t,
        );
        acc.add_snapshot(
            &snap(vec![other(
                "9.9.9.9",
                Kind::Other,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            )]),
            &t,
        );
    }
    let (rows, ub, uf) = acc.take();
    assert_eq!(rows[0].bytes_up, u64::MAX);
    assert_eq!((ub, uf), (u64::MAX, u64::MAX));
}

#[test]
fn the_row_cap_folds_extra_keys_into_the_macs_other_bucket_without_losing_bytes() {
    let t = table(&[("192.168.8.10", A)]);
    let mut acc = CtAccum::default();
    let total = MAX_KEYS + 50;
    let recs: Vec<Record> = (0..total)
        .map(|i| {
            rec(
                "192.168.8.10",
                &format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255),
                80,
                1,
                1,
                1,
            )
        })
        .collect();
    acc.add_snapshot(&snap(recs), &t);
    let (rows, ..) = acc.take();
    assert!(rows.len() <= MAX_KEYS + 1, "{} rows", rows.len());
    assert_eq!(
        rows.iter().map(|r| r.bytes_up).sum::<u64>(),
        total as u64,
        "bytes conserved"
    );
    assert!(
        rows.iter().any(|r| r.dst_ip.is_none()),
        "overflow bucket exists"
    );
}

#[test]
fn a_whole_parsed_line_maps_end_to_end() {
    let line = r#"{"v":1,"seq":1,"ts":1,"interval_s":60,"records":[{"src":"FD00:0:0:0:0:0:0:1","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":5,"bytes_down":6,"flows":1}]}"#;
    let s = parse_snapshot(line.as_bytes()).unwrap();
    let mut acc = CtAccum::default();
    acc.add_snapshot(&s, &table(&[("fd00::1", A)]));
    let (rows, ub, _) = acc.take();
    assert_eq!(
        (rows.len(), ub),
        (1, 0),
        "uppercase unabbreviated IPv6 still maps"
    );
    assert_eq!(rows[0].proto, Proto::Udp);
}
