//! Memory bound: the real daemon, fed a full-size attacker-shaped table (16384 distinct
//! sources, the router's nf_conntrack_max), must keep its peak RSS (VmHWM) under budget.

use std::fmt::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_vigie-conntrack");

const ENTRIES: usize = 16_384;
/// Attacker-shaped worst case: 16384 DISTINCT sources, so no record merges. The target is
/// <= 8 MB peak RSS on the static musl build, whose idle RSS is ~1 MB; this test runs the glibc
/// debug build (idle ~2.5 MB of libc and unoptimised code), so it bounds the GROWTH over idle
/// to 7 MB, plus a loose absolute ceiling. Measured growth ~6.1 MB; musl `--once` is in
/// docs/spikes/conntrack-helper.md.
const GROWTH_BUDGET_KB: u64 = 7 * 1024;
const ABSOLUTE_CEILING_KB: u64 = 12 * 1024;

fn read_status(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap()
}

fn status_kb(status: &str, field: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| {
            v.trim_start_matches(':')
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap()
}

/// Generated, not committed: one line per distinct IPv6 source.
fn synthetic_table(bytes: usize) -> String {
    let mut s = String::with_capacity(ENTRIES * 260);
    for i in 0..ENTRIES {
        let src = format!("2001:db8:{:x}:{:x}::{:x}", i >> 8, i & 255, i + 1);
        let port = 1024 + i % 60000;
        let _ = writeln!(
            s,
            "ipv6     10 tcp      6 431999 ESTABLISHED src={src} dst=fd00::1 sport={port} dport=443 packets=10 bytes={bytes} src=fd00::1 dst={src} sport=443 dport={port} packets=8 bytes={} [ASSURED] mark=0 zone=0 use=2",
            bytes * 9
        );
    }
    s
}

#[test]
fn full_table_of_distinct_sources_stays_within_memory_budget() {
    let dir = std::env::temp_dir().join(format!("vigie-rss-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let table = dir.join("nf_conntrack");
    std::fs::write(&table, "").unwrap();
    let ct = dir.join("nf_conntrack_max");
    std::fs::write(&ct, "16384\n").unwrap();
    let mut child = Command::new(BIN)
        .args(["--interval", "1", "--file", table.to_str().unwrap()])
        .args(["--conntrack-max-file", ct.to_str().unwrap()])
        .args(["--socket", dir.join("c.sock").to_str().unwrap()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(1500));
    let idle = status_kb(&read_status(child.id()), "VmHWM");
    // Swap the table in atomically; the second table has bigger counters so the next sample
    // computes deltas over the full state.
    for (i, bytes) in [1200, 5000].into_iter().enumerate() {
        let next = dir.join(format!("next{i}"));
        std::fs::write(&next, synthetic_table(bytes)).unwrap();
        std::fs::rename(&next, &table).unwrap();
        sleep(Duration::from_millis(1700));
    }
    let status = read_status(child.id());
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    let (rss, hwm) = (status_kb(&status, "VmRSS"), status_kb(&status, "VmHWM"));
    eprintln!(
        "daemon, {ENTRIES} distinct sources: idle VmHWM={idle} kB, VmRSS={rss} kB VmHWM={hwm} kB"
    );
    assert!(
        hwm.saturating_sub(idle) <= GROWTH_BUDGET_KB,
        "peak RSS grew {} kB over idle, budget {GROWTH_BUDGET_KB} kB",
        hwm.saturating_sub(idle)
    );
    assert!(hwm <= ABSOLUTE_CEILING_KB, "peak RSS {hwm} kB");
}
