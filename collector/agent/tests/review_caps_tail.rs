//! Test gaps found by the mutation run: the final body (with its per-send tail) never exceeds
//! the cap, and two tail edge cases.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::builder::{build_with_drops, BATCH_CAP, SERVER_MAX_BODY};
use vigie_agent::model::*;
use vigie_agent::tail::Tail;

fn mac_n(n: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", (n >> 8) & 0xff, n & 0xff)
}

#[test]
fn cap_is_within_the_server_limit() {
    const { assert!(SERVER_MAX_BODY == 512 * 1024) };
    const { assert!(BATCH_CAP <= 512 * 1024) };
    const { assert!(BATCH_CAP <= SERVER_MAX_BODY) };
}

#[test]
fn final_bytes_never_exceed_cap_sweep() {
    let meta = Meta {
        collector_id: "c".repeat(64),
        key_id: "k".repeat(64),
        boot_id: "b".repeat(64),
        seq: u64::MAX >> 1,
        batch_id: "01927f3e-8a1b-7c2d-9e4f-0123456789ab".into(),
        window_start: MAX_EPOCH - 100,
        window_end: MAX_EPOCH - 1,
    };
    let mut drops = std::collections::BTreeMap::new();
    for k in [
        "dns_quota_dropped",
        "dns_dropped",
        "sightings_dropped",
        "dns_pending_evicted",
        "dns_client_throttled",
        "tail_truncated",
        "tail_bytes_skipped",
    ] {
        drops.insert(k.to_string(), u64::MAX);
    }
    let health = Health {
        dns_log_quiet: true,
        rss_kb: Some(u64::MAX),
        spool_batches: Some(u64::MAX),
        uptime_s: Some(u64::MAX),
    };
    for name_len in [1usize, 31, 100, 200, 252] {
        for host_len in [0usize, 63, 253] {
            let dns = (0..6000)
                .map(|i| {
                    let label = "d".repeat(name_len.saturating_sub(8).max(1));
                    DnsQuery::new(
                        meta.window_start,
                        &mac_n(i % 300),
                        &format!("{label}{i:06}.x"),
                        "A",
                        Some("203.0.113.9"),
                    )
                    .unwrap()
                })
                .collect();
            let leases = (0..1200)
                .map(|i| {
                    Lease::new(
                        &mac_n(i),
                        "10.1.2.3",
                        Some(&"h".repeat(host_len)),
                        &[1, 3, 6, 15, 26, 28, 51, 58, 59],
                        Some(&"v".repeat(200)),
                    )
                    .unwrap()
                })
                .collect();
            let conntrack = (0..6000u16)
                .map(|i| ConntrackSummary {
                    mac: mac_n(usize::from(i) % 500),
                    dst_ip: Some(format!("2001:db8::{i:x}:ffff:ffff:ffff")),
                    dst_port: Some(i),
                    proto: Proto::Tcp,
                    bytes_up: u64::MAX,
                    bytes_down: u64::MAX,
                    flows: u64::MAX,
                })
                .collect();
            let sightings = (0..1500)
                .map(|i| {
                    Sighting::new(
                        &mac_n(i),
                        SightingKind::Mdns,
                        Some(&"n".repeat(name_len)),
                        Some(&"s".repeat(100)),
                        Some(&"u".repeat(200)),
                    )
                    .unwrap()
                })
                .collect();
            let neigh = (0..2500)
                .map(|i| Neighbor::new(&format!("2001:db8::{i:x}:1:2:3:4"), &mac_n(i)).unwrap())
                .collect();
            let input = Sections {
                leases,
                neigh,
                dns,
                conntrack,
                sightings,
            };
            let b = build_with_drops(&meta, input, &health, BATCH_CAP, &drops);
            let n = b.encoded.body(MAX_EPOCH, u64::MAX).len();
            assert!(
                n > BATCH_CAP * 3 / 4,
                "the sweep must press on the cap, got {n}"
            );
            assert!(
                n <= BATCH_CAP,
                "name_len={name_len} host_len={host_len}: {n} > {BATCH_CAP}"
            );
            assert!(
                b.encoded.len() <= BATCH_CAP,
                "spool accounting also within the cap"
            );
            assert!(
                b.encoded.len() >= n,
                "spool accounting covers the real wire size"
            );
        }
    }
}

// ---- tail ----

static N: AtomicU32 = AtomicU32::new(0);

fn tmp() -> PathBuf {
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
        .append(true)
        .create(true)
        .open(p)
        .unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

#[test]
fn half_line_carried_then_file_truncated_does_not_glue_old_and_new() {
    let d = tmp();
    let log = d.join("dnsmasq.log");
    fs::write(&log, "first\n").unwrap();
    let mut t = Tail::new(log.clone());
    assert!(t.poll().unwrap().is_empty(), "first open starts at the end");
    append(&log, "second\nhalf-of-a-li");
    assert_eq!(
        t.poll().unwrap(),
        vec!["second"],
        "the half line stays carried"
    );
    // The root watchdog truncates in place; dnsmasq then writes a fresh, shorter line.
    fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(0)
        .unwrap();
    append(&log, "new\n");
    assert_eq!(
        t.poll().unwrap(),
        vec!["new"],
        "no 'half-of-a-linew' hybrid"
    );
    append(&log, "after\n");
    assert_eq!(t.poll().unwrap(), vec!["after"]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rotation_with_unread_bytes_in_the_old_file_delivers_them_first() {
    let d = tmp();
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    append(&log, "old1\nold2\n");
    // Rotate before the next poll: unread lines are still in the renamed file.
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\nnew2\n").unwrap();
    assert_eq!(
        t.poll().unwrap(),
        vec!["old1", "old2", "new1", "new2"],
        "nothing lost, order kept"
    );
    append(&log, "new3\n");
    assert_eq!(t.poll().unwrap(), vec!["new3"]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rotation_drops_only_the_unterminated_tail_of_the_old_file() {
    let d = tmp();
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    append(&log, "old1\nunterminated");
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["old1", "new1"]);
    fs::remove_dir_all(d).unwrap();
}
