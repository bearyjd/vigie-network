use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_vigie-conntrack");

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/conntrack/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigie-bin-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::DirBuilder::new().mode(0o755).create(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    d
}

/// A conntrack_max file so daemon tests do not depend on the host's real kernel limit.
fn ct_max_file(dir: &std::path::Path, value: &str) -> String {
    let p = dir.join("nf_conntrack_max");
    fs::write(&p, value).unwrap();
    p.to_str().unwrap().to_string()
}

fn wait_for(path: &std::path::Path) {
    let t = Instant::now();
    while !path.exists() && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn once_file_prints_one_json_line_and_exits() {
    let out = Command::new(BIN)
        .args(["--once", "--file", &fixture("ipv4_tcp_udp.txt")])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with(r#"{"v":1,"#), "{text}");
    assert!(text.contains(
        r#""src":"192.168.8.10","dst":"8.8.8.8","dport":53,"proto":"udp","bytes_up":70,"bytes_down":120"#
    ));
}

#[test]
fn once_reports_skipped_lines() {
    let out = Command::new(BIN)
        .args(["--once", "--file", &fixture("nat_and_odd.txt")])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains(r#""skipped_lines":4"#));
}

#[test]
fn missing_file_and_bad_flag_exit_nonzero_with_message() {
    let out = Command::new(BIN)
        .args(["--once", "--file", "/nonexistent/ct"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/ct"));
    let out = Command::new(BIN).arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}

#[test]
fn daemon_refuses_world_writable_socket_dir() {
    let d = tmpdir("ww");
    fs::set_permissions(&d, fs::Permissions::from_mode(0o777)).unwrap();
    let out = Command::new(BIN)
        .args(["--socket", d.join("c.sock").to_str().unwrap()])
        .args(["--conntrack-max-file", &ct_max_file(&d, "16384")])
        .args(["--file", &fixture("ipv6.txt")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("world-writable"));
}

#[test]
fn daemon_serves_snapshots_on_a_0600_socket() {
    let d = tmpdir("daemon");
    let sock = d.join("c.sock");
    let mut child = Command::new(BIN)
        .args(["--socket", sock.to_str().unwrap(), "--interval", "1"])
        .args(["--conntrack-max-file", &ct_max_file(&d, "16384")])
        .args(["--file", &fixture("ipv4_tcp_udp.txt")])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&sock);
    let meta = fs::symlink_metadata(&sock).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    let c = UnixStream::connect(&sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(line.starts_with(r#"{"v":1,"seq":"#), "{line:?}");
    assert!(line.ends_with("]}\n"));
    // the file never changes between samples, so every delta is zero
    assert!(line.contains(r#""dport":53,"proto":"udp","bytes_up":0,"bytes_down":0"#));
}

/// Every `"bytes_up":N` / `"bytes_down":N` in the line is zero.
fn all_bytes_zero(line: &str) -> bool {
    ["\"bytes_up\":", "\"bytes_down\":"].iter().all(|key| {
        line.split(key)
            .skip(1)
            .all(|rest| rest.starts_with("0,") || rest.starts_with("0}"))
    })
}

#[test]
fn first_daemon_snapshot_is_a_baseline_with_zero_bytes() {
    let d = tmpdir("first");
    let sock = d.join("c.sock");
    let table = d.join("table");
    let mut child = Command::new(BIN)
        .args(["--socket", sock.to_str().unwrap(), "--interval", "1"])
        .args(["--conntrack-max-file", &ct_max_file(&d, "16384")])
        .args(["--file", table.to_str().unwrap()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&sock);
    // The daemon is up but has no table yet, so the reader is connected before the first
    // successful sample: the line it gets IS the daemon's first snapshot.
    let c = UnixStream::connect(&sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let staged = d.join("table.new");
    fs::copy(fixture("ipv4_tcp_udp.txt"), &staged).unwrap();
    fs::rename(&staged, &table).unwrap();
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(line.starts_with(r#"{"v":1,"seq":1,"#), "{line:?}");
    assert!(line.contains(r#""dport":53,"proto":"udp""#), "{line}");
    assert!(
        all_bytes_zero(&line),
        "first snapshot leaked history: {line}"
    );
    assert!(
        fs::read_to_string(fixture("ipv4_tcp_udp.txt"))
            .unwrap()
            .contains("bytes="),
        "fixture must carry real counters or this proves nothing"
    );
}

#[test]
fn daemon_refuses_a_kernel_table_larger_than_max_flows() {
    let d = tmpdir("ctmax");
    let sock = d.join("c.sock");
    let out = Command::new(BIN)
        .args(["--socket", sock.to_str().unwrap()])
        .args(["--conntrack-max-file", &ct_max_file(&d, "262144\n")])
        .args(["--file", &fixture("ipv6.txt")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("nf_conntrack_max is 262144"), "{err}");
    assert!(!sock.exists(), "must refuse before binding");
    // an explicit --max-flows is the owner's decision
    let mut child = Command::new(BIN)
        .args(["--socket", sock.to_str().unwrap(), "--max-flows", "300000"])
        .args(["--conntrack-max-file", &ct_max_file(&d, "262144\n")])
        .args(["--file", &fixture("ipv6.txt")])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&sock);
    let up = sock.exists();
    let _ = child.kill();
    let _ = child.wait();
    assert!(up, "explicit --max-flows must be honoured");
}

#[test]
fn shared_uids_are_refused_without_the_explicit_flag() {
    for uid in ["0", "65534"] {
        let out = Command::new(BIN)
            .args(["--once", "--uid", uid, "--file", &fixture("ipv6.txt")])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "uid {uid}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-shared-uid"));
    }
}

#[test]
fn once_reports_acct_off_only_when_bytes_are_missing() {
    let run = |name: &str| {
        let out = Command::new(BIN)
            .args(["--once", "--file", &fixture(name)])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    assert!(run("nat_and_odd.txt").contains(r#""acct_off":true"#));
    assert!(run("ipv4_tcp_udp.txt").contains(r#""acct_off":false"#));
}

#[test]
fn daemon_creates_a_missing_socket_dir_0755() {
    let d = tmpdir("mkdir");
    let dir = d.join("vigie");
    let sock = dir.join("c.sock");
    let mut child = Command::new(BIN)
        .args(["--socket", sock.to_str().unwrap()])
        .args(["--conntrack-max-file", &ct_max_file(&d, "16384")])
        .args(["--file", &fixture("ipv6.txt")])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&sock);
    let mode = fs::metadata(&dir).map(|m| m.permissions().mode() & 0o7777);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(mode.unwrap(), 0o755);
}

#[test]
fn daemon_refuses_group_writable_socket_dir() {
    let d = tmpdir("gw");
    fs::set_permissions(&d, fs::Permissions::from_mode(0o775)).unwrap();
    let out = Command::new(BIN)
        .args(["--socket", d.join("c.sock").to_str().unwrap()])
        .args(["--conntrack-max-file", &ct_max_file(&d, "16384")])
        .args(["--file", &fixture("ipv6.txt")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("writable"));
}
