//! Gap markers of `Tail::poll_with_gaps`: every switch to another file is a gap, and an error is
//! never swallowed just because only gap markers were drained before it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use vigie_agent::tail::Tail;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-gaps-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn append(p: &Path, text: &str) {
    let mut f = fs::OpenOptions::new().append(true).open(p).unwrap();
    f.write_all(text.as_bytes()).unwrap();
}
fn s(x: &str) -> Option<String> {
    Some(x.to_string())
}

#[test]
fn a_clean_rotation_is_still_a_gap() {
    let d = tmp("clean");
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    append(&log, "old1\n");
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    assert_eq!(
        t.poll_with_gaps().unwrap(),
        vec![s("old1"), None, s("new1")]
    );
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_rotation_dropping_a_partial_line_is_a_gap() {
    let d = tmp("partial");
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    append(&log, "old1\nhalf-a-line");
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    assert_eq!(
        t.poll_with_gaps().unwrap(),
        vec![s("old1"), None, s("new1")]
    );
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn two_rotations_before_one_poll_are_a_gap() {
    let d = tmp("double");
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    fs::rename(&log, d.join("dnsmasq.log.2")).unwrap();
    fs::write(&log, "middle\n").unwrap();
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    assert_eq!(t.poll_with_gaps().unwrap(), vec![None, s("new1")]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn an_error_with_only_gap_markers_surfaces_and_the_gap_is_kept() {
    let d = tmp("err");
    let probe = d.join("probe");
    fs::write(&probe, "x").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&probe).is_ok() {
        println!("SKIP: file modes are not enforced for this user (root?)");
        return;
    }
    let log = d.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    fs::rename(&log, d.join("dnsmasq.log.1")).unwrap();
    fs::write(&log, "new1\n").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o000)).unwrap();
    // Nothing but the rotation gap was drained: the failure is reported, as `poll` does.
    assert!(t.poll_with_gaps().is_err());
    assert!(t.poll().is_err());
    // Every failed poll is counted, also the ones that return nothing but the error.
    assert_eq!(t.take_counts().get("tail_open_failed"), Some(&2));
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(t.poll_with_gaps().unwrap(), vec![None, s("new1")]);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_reset_gap_found_before_a_failing_stat_is_reported_on_the_next_poll() {
    let d = tmp("pending");
    let sub = d.join("logs");
    fs::create_dir_all(&sub).unwrap();
    let log = sub.join("dnsmasq.log");
    fs::write(&log, "seed\n").unwrap();
    let mut t = Tail::new(log.clone());
    t.poll().unwrap();
    // Truncated in place (a cursor reset), and the directory cannot be searched right now.
    fs::write(&log, "").unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::metadata(&log).is_ok() {
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        println!("SKIP: directory modes are not enforced for this user (root?)");
        return;
    }
    assert!(t.poll_with_gaps().is_err());
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(t.poll_with_gaps().unwrap(), vec![None]);
    fs::remove_dir_all(d).unwrap();
}
