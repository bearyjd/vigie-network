//! Third review item 2: a rotation whose new file cannot be opened must not discard the lines
//! already drained from the old file, and every loss is counted.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use vigie_agent::tail::Tail;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-r4-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn unreadable_is_enforced(d: &std::path::Path) -> bool {
    let p = d.join("probe");
    fs::write(&p, "x").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0)).unwrap();
    fs::File::open(&p).is_err()
}

#[test]
fn drained_lines_survive_an_unreadable_new_file_and_the_loss_is_counted() {
    let d = tmp("eacces");
    if !unreadable_is_enforced(&d) {
        println!("SKIP: file modes are not enforced for this user (root?)");
        return;
    }
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(b"old1\nold2\npartial")
        .unwrap();
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0)).unwrap();

    let lines = t.poll().expect("drained lines must be returned, not an error");
    assert_eq!(lines, vec!["old1", "old2"]);
    let c = t.take_counts();
    assert_eq!(c.get("tail_open_failed"), Some(&1), "{c:?}");
    assert_eq!(c.get("tail_bytes_skipped"), Some(&7), "partial carry: {c:?}");

    // Still unreadable: nothing drained, so the failure is reported as an error, once per poll.
    assert!(t.poll().is_err());
    // Readable again: the new file is read from its start.
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(t.poll().unwrap(), vec!["new1"]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_dropped_partial_line_on_rotation_is_counted() {
    let d = tmp("carry");
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(b"old1\nhalf-a-line")
        .unwrap();
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    assert_eq!(t.poll().unwrap(), vec!["old1", "new1"]);
    assert_eq!(t.take_counts().get("tail_bytes_skipped"), Some(&11), "half-a-line");
    fs::remove_dir_all(d).unwrap();
}
