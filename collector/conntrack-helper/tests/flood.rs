//! Attacker-shaped input: 16384 distinct spoofed sources must not black out monitoring.

use std::fmt::Write;
use vigie_conntrack::agg::{AggConfig, Aggregator, DEFAULT_OTHER_K, DEFAULT_TOP_N};
use vigie_conntrack::json::{snapshot_json, Meta};
use vigie_conntrack::parse::scan_flows;
use vigie_conntrack::sock::MAX_SNAPSHOT_BYTES;

pub const SOURCES: usize = 16_384;

/// One conntrack line per distinct IPv6 source (the shape the router's table can reach).
pub fn spoofed_table(n: usize) -> String {
    let mut s = String::with_capacity(n * 230);
    for i in 0..n {
        let src = format!("2001:db8:{:x}:{:x}::{:x}", i >> 8, i & 255, i + 1);
        let port = 1024 + i % 60000;
        let _ = writeln!(
            s,
            "ipv6     10 tcp      6 100 SYN_SENT src={src} dst=fd00::1 sport={port} dport=443 packets=1 bytes={} src=fd00::1 dst={src} sport=443 dport={port} packets=1 bytes=60 mark=0 zone=0 use=2",
            1000 + i
        );
    }
    s
}

#[test]
fn distinct_source_flood_fits_in_a_small_snapshot_and_keeps_every_byte() {
    let table = spoofed_table(SOURCES);
    let want: u64 = (0..SOURCES as u64).map(|i| 1000 + i + 60).sum();
    let mut agg = Aggregator::new(AggConfig {
        baseline_first: false,
        ..AggConfig::default()
    });
    agg.begin();
    let st = scan_flows(table.as_bytes(), |f| agg.add(&f)).unwrap();
    assert_eq!((st.parsed, st.skipped), (SOURCES, 0));
    let snap = agg.finish();
    let line = snapshot_json(
        &Meta {
            seq: 1,
            ts: 1,
            interval_s: 60,
            skipped_lines: 0,
            acct_off: false,
        },
        &snap,
    );
    assert!(line.len() < 256 * 1024, "snapshot is {} bytes", line.len());
    assert!(line.len() < MAX_SNAPSHOT_BYTES);
    assert!(snap.records.len() <= DEFAULT_TOP_N + DEFAULT_OTHER_K + 1);
    let got: u64 = snap.records.iter().map(|r| r.bytes_up + r.bytes_down).sum();
    assert_eq!(got, want, "bytes lost or invented by folding");
    assert!(line.contains(r#""other_global":true"#));
}
