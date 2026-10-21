//! Third review item 3: the built binary refuses euid 0 before it loads any config. Run under
//! `unshare -Ur` (uid 0 inside a user namespace); skipped, with a printed reason, without it.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_vigie-collector");
const BAD_CONFIG: &str = "/nonexistent/vigie-collector.conf";

fn can_unshare() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn code(root: bool, extra: &[&str]) -> i32 {
    let mut c = if root {
        let mut c = Command::new("unshare");
        c.args(["-Ur", BIN]);
        c
    } else {
        Command::new(BIN)
    };
    c.args(["--config", BAD_CONFIG]).args(extra);
    c.output().unwrap().status.code().expect("exit code")
}

#[test]
fn root_is_refused_before_the_config_is_read() {
    if !can_unshare() {
        println!("SKIP: `unshare -Ur` is unavailable here; euid 0 refusal not exercised");
        return;
    }
    assert_eq!(code(true, &[]), 77, "euid 0, no --allow-root");
}

#[test]
fn allow_root_gets_past_the_gate_to_the_config_error() {
    if !can_unshare() {
        println!("SKIP: `unshare -Ur` is unavailable here");
        return;
    }
    assert_eq!(code(true, &["--allow-root"]), 78);
}

#[test]
fn a_non_root_caller_reaches_the_config_error() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    if vigie_agent::procstat::parse_euid(&status) == Some(0) {
        println!("SKIP: test runner is root");
        return;
    }
    assert_eq!(code(false, &[]), 78);
}
