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
        .args(["--file", &fixture("ipv4_tcp_udp.txt")])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while !sock.exists() && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
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
