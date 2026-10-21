//! Memory bound: the real daemon, fed a full-size table (16384 entries, the router's
//! nf_conntrack_max), must keep its peak RSS (VmHWM) under budget.

use std::fmt::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_vigie-conntrack");

const ENTRIES: usize = 16_384;
/// Measured peak is ~17 MB (host, glibc) for a full 16384-entry table, i.e. roughly 1 KB/entry;
/// the typical ~800 entries cost ~1 MB. Budget leaves headroom for allocator differences.
const BUDGET_KB: u64 = 24 * 1024;

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

fn synthetic_table(bytes: usize) -> String {
    let mut s = String::with_capacity(ENTRIES * 260);
    for i in 0..ENTRIES {
        let _ = writeln!(
            s,
            "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.{}.{} dst=10.{}.{}.{} sport={} dport=443 packets=10 bytes={bytes} src=10.{}.{}.{} dst=192.168.{}.{} sport=443 dport={} packets=8 bytes={} [ASSURED] mark=0 zone=0 use=2",
            i % 4, i % 250 + 1, i / 250, i % 200, i % 250 + 1, 1024 + i % 60000,
            i / 250, i % 200, i % 250 + 1, i % 4, i % 250 + 1, 1024 + i % 60000, bytes * 9
        );
    }
    s
}

#[test]
fn full_conntrack_table_stays_within_memory_budget() {
    let dir = std::env::temp_dir().join(format!("vigie-rss-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let table = dir.join("nf_conntrack");
    std::fs::write(&table, synthetic_table(1200)).unwrap();
    let mut child = Command::new(BIN)
        .args(["--interval", "1", "--file", table.to_str().unwrap()])
        .args(["--socket", dir.join("c.sock").to_str().unwrap()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(1500));
    // Replace the table atomically with bigger counters so the second sample computes deltas.
    let next = dir.join("next");
    std::fs::write(&next, synthetic_table(5000)).unwrap();
    std::fs::rename(&next, &table).unwrap();
    sleep(Duration::from_millis(2000));
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    let (rss, hwm) = (status_kb(&status, "VmRSS"), status_kb(&status, "VmHWM"));
    eprintln!("daemon with {ENTRIES} entries, 2+ samples: VmRSS={rss} kB VmHWM={hwm} kB");
    assert!(hwm <= BUDGET_KB, "peak RSS {hwm} kB exceeds {BUDGET_KB} kB");
}
