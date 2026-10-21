//! Hand-rolled JSON for the snapshot line. Every emitted string is an IP literal or a fixed
//! protocol name, so no escaping is ever needed.

use crate::agg::{Record, Snapshot};
use std::fmt::Write;

pub struct Meta {
    pub seq: u64,
    pub ts: u64,
    pub interval_s: u64,
    pub skipped_lines: usize,
    /// Some parsed lines had no `bytes=`: kernel accounting is off, so their counters are zeros.
    pub acct_off: bool,
}

pub fn proto_name(p: u8) -> String {
    match p {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        58 => "icmpv6".to_string(),
        n => format!("proto-{n}"),
    }
}

fn push_record(out: &mut String, r: &Record) {
    let _ = write!(out, r#"{{"src":"{}","#, r.src);
    match (r.dst, r.dport, r.proto) {
        (Some(dst), Some(dport), Some(proto)) => {
            let _ = write!(
                out,
                r#""dst":"{dst}","dport":{dport},"proto":"{}","#,
                proto_name(proto)
            );
        }
        _ if r.global => out.push_str(r#""other_global":true,"#),
        _ => out.push_str(r#""other":true,"#),
    }
    let _ = write!(
        out,
        r#""bytes_up":{},"bytes_down":{},"packets_up":{},"packets_down":{},"flows":{},"new_flows":{}}}"#,
        r.bytes_up, r.bytes_down, r.packets_up, r.packets_down, r.flows, r.new_flows
    );
}

/// One snapshot as a single JSON object (no trailing newline).
pub fn snapshot_json(meta: &Meta, snap: &Snapshot) -> String {
    let mut out = String::with_capacity(160 + snap.records.len() * 190);
    let _ = write!(
        out,
        r#"{{"v":1,"seq":{},"ts":{},"interval_s":{},"skipped_lines":{},"acct_off":{},"folded":{},"evicted":{},"recounted_flows":{},"table_pressure":{},"records":["#,
        meta.seq,
        meta.ts,
        meta.interval_s,
        meta.skipped_lines,
        meta.acct_off,
        snap.folded,
        snap.evicted,
        snap.recounted_flows,
        snap.table_pressure
    );
    for (i, r) in snap.records.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_record(&mut out, r);
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn protocol_names() {
        assert_eq!(proto_name(6), "tcp");
        assert_eq!(proto_name(17), "udp");
        assert_eq!(proto_name(1), "icmp");
        assert_eq!(proto_name(58), "icmpv6");
        assert_eq!(proto_name(47), "proto-47");
    }

    #[test]
    fn snapshot_line_format() {
        let snap = Snapshot {
            records: vec![
                Record {
                    src: ip("192.168.8.10"),
                    dst: Some(ip("93.184.216.34")),
                    dport: Some(443),
                    proto: Some(6),
                    bytes_up: 1,
                    bytes_down: 2,
                    packets_up: 3,
                    packets_down: 4,
                    flows: 5,
                    new_flows: 6,
                    global: false,
                },
                Record {
                    src: ip("fd00::1"),
                    dst: None,
                    dport: None,
                    proto: None,
                    bytes_up: 7,
                    bytes_down: 8,
                    packets_up: 9,
                    packets_down: 10,
                    flows: 11,
                    new_flows: 12,
                    global: false,
                },
                Record {
                    src: ip("0.0.0.0"),
                    dst: None,
                    dport: None,
                    proto: None,
                    bytes_up: 1,
                    bytes_down: 1,
                    packets_up: 1,
                    packets_down: 1,
                    flows: 1,
                    new_flows: 0,
                    global: true,
                },
            ],
            folded: 3,
            evicted: 1,
            recounted_flows: 4,
            table_pressure: true,
        };
        let meta = Meta {
            seq: 9,
            ts: 1_700_000_000,
            interval_s: 60,
            skipped_lines: 2,
            acct_off: true,
        };
        let line = snapshot_json(&meta, &snap);
        let expected = concat!(
            r#"{"v":1,"seq":9,"ts":1700000000,"interval_s":60,"skipped_lines":2,"acct_off":true,"folded":3,"evicted":1,"recounted_flows":4,"table_pressure":true,"records":["#,
            r#"{"src":"192.168.8.10","dst":"93.184.216.34","dport":443,"proto":"tcp","bytes_up":1,"bytes_down":2,"packets_up":3,"packets_down":4,"flows":5,"new_flows":6},"#,
            r#"{"src":"fd00::1","other":true,"bytes_up":7,"bytes_down":8,"packets_up":9,"packets_down":10,"flows":11,"new_flows":12},"#,
            r#"{"src":"0.0.0.0","other_global":true,"bytes_up":1,"bytes_down":1,"packets_up":1,"packets_down":1,"flows":1,"new_flows":0}]}"#
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn empty_snapshot_is_valid() {
        let meta = Meta {
            seq: 0,
            ts: 0,
            interval_s: 1,
            skipped_lines: 0,
            acct_off: false,
        };
        let line = snapshot_json(&meta, &Snapshot::default());
        assert!(line.ends_with(r#""records":[]}"#), "{line}");
    }
}
