//! Re-review item 2: truncate-and-refill forgery. A DHCP client controls bytes inside log lines
//! (vendor class, hostname). If the log is truncated and refilled so the tail's cursor lands in
//! the middle of such a line, the rest of that line must never be read as a log line of its own.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::dnsmasq::{parse_line, DhcpAssembler, LogEvent};
use vigie_agent::tail::Tail;

static N: AtomicU32 = AtomicU32::new(0);

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-integ-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&d).unwrap();
    d.join("dnsmasq.log")
}

const FORGED: &str = "dnsmasq[1]: 9 DHCPACK(br-lan) 10.0.0.9 de:ad:be:ef:00:09 forged";

fn leases_from(lines: &[String]) -> usize {
    let mut a = DhcpAssembler::default();
    let mut n = 0;
    for s in lines {
        match parse_line(s) {
            Some(ev) => n += usize::from(a.feed(&ev).is_some()),
            None => a.break_context(),
        }
    }
    n
}

#[test]
fn prefix_is_anchored_not_searched_for() {
    for pad in [100usize, 200, 240] {
        for filler in ["x", " ", "]: ", "Oct 20 14:00:00 "] {
            let pad_s = filler.repeat(pad / filler.len());
            let line = format!("{pad_s}{FORGED}");
            assert_eq!(parse_line(&line), None, "pad {pad} filler {filler:?}");
        }
    }
    // The real prefix still parses, with and without a padded day, with either program name.
    for p in [
        "Oct 20 14:00:00 dnsmasq[1]: ",
        "Oct  5 04:00:00 dnsmasq[1]: ",
        "Oct 20 14:00:00 dnsmasq-dhcp[1234]: ",
    ] {
        let rest = "9 DHCPACK(br-lan) 10.0.0.9 c2:11:22:33:44:01";
        assert!(
            matches!(
                parse_line(&format!("{p}{rest}")),
                Some(LogEvent::DhcpAck { .. })
            ),
            "{p}"
        );
    }
}

#[test]
fn malformed_prefixes_are_rejected() {
    let rest = "9 DHCPACK(br-lan) 10.0.0.9 c2:11:22:33:44:01";
    for p in [
        "Oct 20 14:00:00 xdnsmasq[1]: ",
        "Oct 20 14:00:00 dnsmasq-evil[1]: ",
        "Oct 20 14:00:00 dnsmasq[]: ",
        "Oct 20 14:00:00 dnsmasq[1a]: ",
        "Oct 20 14:00:00 dnsmasq[1]:",
        "Xyz 20 14:00:00 dnsmasq[1]: ",
        "Oct 20 14:0:00 dnsmasq[1]: ",
        "Oct 20 14-00-00 dnsmasq[1]: ",
        "Oct 20 14:00-00 dnsmasq[1]: ",
        "Oct 20 xx:00:00 dnsmasq[1]: ",
        "Oct 20 14:xx:00 dnsmasq[1]: ",
        "Oct 20 14:00:xx dnsmasq[1]: ",
        "Oct 20 14:00:0 dnsmasq[1]: ",
        "Oct 20 14:00:00 host dnsmasq[1]: ",
        " Oct 20 14:00:00 dnsmasq[1]: ",
        "Oct 200 14:00:00 dnsmasq[1]: ",
    ] {
        assert_eq!(parse_line(&format!("{p}{rest}")), None, "{p:?}");
    }
}

/// Fill the file so that the old cursor lands exactly on `FORGED`-bearing text.
fn refill_with_forgery(pos: usize, full_prefix: bool) -> String {
    let head = "Oct 20 14:00:00 dnsmasq-dhcp[5]: 1 vendor class: ";
    let tail_line = if full_prefix {
        format!("Oct 20 14:00:00 {FORGED}")
    } else {
        FORGED.to_string()
    };
    let mut s = String::from(head);
    while s.len() < pos {
        s.push('p');
    }
    s.truncate(pos);
    s.push_str(&tail_line);
    s.push('\n');
    s
}

#[test]
fn truncate_and_refill_landing_inside_a_line_forges_nothing() {
    for (pad, full) in [(100usize, false), (200, false), (240, false), (200, true)] {
        let p = tmp();
        let old =
            "Oct 20 14:00:00 dnsmasq[1]: 1 192.168.1.9/5353 query[A] a.test from 192.168.1.9\n"
                .repeat(4);
        fs::write(&p, &old).unwrap();
        let mut t = Tail::new(p.clone());
        assert!(t.poll().unwrap().is_empty());
        // In place (same inode), larger than the old file: `len < pos` cannot see it.
        let pos = old.len();
        let _ = pad;
        fs::write(&p, refill_with_forgery(pos, full) + &"z".repeat(pad)).unwrap();
        let lines = t.poll().unwrap();
        assert_eq!(leases_from(&lines), 0, "pad {pad} full {full}: {lines:?}");
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("Oct 20 14:00:00 dnsmasq[1]: 9")
                    || l.starts_with("dnsmasq[1]: 9")),
            "forged remainder surfaced as a line: {lines:?}"
        );
        let c = t.take_counts();
        assert_eq!(c.get("tail_truncated"), Some(&1), "{c:?}");
    }
}

#[test]
fn a_mismatch_restarts_at_zero_and_drops_the_partial_line() {
    let p = tmp();
    let old = "A".repeat(100) + "\n";
    fs::write(&p, &old).unwrap();
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    // A partial line is carried, then the file is replaced by different content of the same size.
    let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(b"partial-without-newline").unwrap();
    assert!(t.poll().unwrap().is_empty());
    let new = "B".repeat(100) + "\nfresh\n";
    fs::write(&p, &new).unwrap();
    let lines = t.poll().unwrap();
    assert_eq!(lines, vec!["B".repeat(100), "fresh".to_string()]);
    let c = t.take_counts();
    assert_eq!(c.get("tail_truncated"), Some(&1));
    assert_eq!(
        c.get("tail_bytes_skipped"),
        Some(&("partial-without-newline".len() as u64))
    );
    assert!(t.take_counts().is_empty(), "counters are drained");
}

#[test]
fn plain_appends_and_in_place_shrink_are_counted_correctly() {
    let p = tmp();
    fs::write(&p, "x\n".repeat(100)).unwrap();
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(b"one\ntwo\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["one", "two"]);
    f.write_all(b"three\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["three"]);
    assert!(t.take_counts().is_empty(), "no false positives on appends");
    fs::write(&p, "fresh\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["fresh"]);
    assert_eq!(t.take_counts().get("tail_truncated"), Some(&1));
}

#[test]
fn overlong_lines_are_counted_as_skipped_bytes() {
    let p = tmp();
    fs::write(&p, "").unwrap();
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(format!("{}\nok\n", "z".repeat(10_000)).as_bytes())
        .unwrap();
    assert_eq!(t.poll().unwrap(), vec!["ok"]);
    assert_eq!(t.take_counts().get("tail_bytes_skipped"), Some(&10_000));
}

#[test]
fn rename_rotation_is_not_a_truncation() {
    let p = tmp();
    fs::write(&p, "x\n".repeat(50)).unwrap();
    let mut t = Tail::new(p.clone());
    t.poll().unwrap();
    fs::rename(&p, p.with_extension("1")).unwrap();
    fs::write(&p, "new\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["new"]);
    assert!(t.take_counts().is_empty());
}
