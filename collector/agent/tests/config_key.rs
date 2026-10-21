use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use vigie_agent::config::*;
use vigie_agent::dropin::*;

const PIN_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PIN_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn good() -> String {
    format!(
        "# Vigie collector\nserver_url=https://vigie.example.lan:8443/v1/batch\ncollector_id=router-1\nkey_id=k2026-10\npin1={PIN_A}\npin2={PIN_B}\n"
    )
}

#[test]
fn parses_a_valid_config_with_defaults() {
    let c = parse_config(&good()).unwrap();
    assert_eq!(c.server_url, "https://vigie.example.lan:8443/v1/batch");
    assert_eq!(c.collector_id, "router-1");
    assert_eq!(c.key_id, "k2026-10");
    assert_eq!(c.pins, [PIN_A.to_string(), PIN_B.to_string()]);
    assert_eq!(c.key_file, PathBuf::from("/etc/vigie/key"));
    assert_eq!(c.dnsmasq_log, PathBuf::from("/tmp/vigie/dnsmasq.log"));
    assert_eq!(c.leases_file, PathBuf::from("/tmp/dhcp.leases"));
}

#[test]
fn rejects_bad_configs() {
    let bad = |from: &str, to: &str| parse_config(&good().replace(from, to)).is_err();
    assert!(bad("https://", "http://"), "plain http is refused");
    assert!(
        bad("collector_id=router-1", "collector_id=a|b"),
        "'|' would break the signing string"
    );
    assert!(bad("collector_id=router-1", "collector_id="), "empty id");
    assert!(
        bad(&format!("pin2={PIN_B}"), &format!("pin2={PIN_A}")),
        "two distinct pins required"
    );
    assert!(
        bad(&format!("pin2={PIN_B}"), "pin2=abc"),
        "pin must be 64 hex chars"
    );
    assert!(
        bad(
            &format!("pin1={PIN_A}"),
            &format!("pin1={}", PIN_A.to_uppercase())
        ),
        "pins are lowercase hex"
    );
    assert!(bad("key_id=k2026-10", "key_id=k 1"));
    assert!(
        bad("pin1=", "bogus_option=1\npin1="),
        "unknown keys are typos, not ignored"
    );
    assert!(
        parse_config(&good().replace("pin2", "#pin2")).is_err(),
        "second pin missing"
    );
    assert!(
        parse_config(&format!("{}collector_id=x\n", good())).is_err(),
        "duplicate key"
    );
    assert!(parse_config(&good().replace("server_url=", "no_equals_sign\nserver_url=")).is_err());
    assert!(parse_config("").is_err());
}

#[test]
fn key_metadata_rules() {
    assert_eq!(check_key_meta(0o100600, 65534, 65534, true), Ok(()));
    assert_eq!(check_key_meta(0o100400, 65534, 65534, true), Ok(()));
    for mode in [0o100640, 0o100604, 0o100644, 0o100660, 0o100666, 0o100602] {
        assert_eq!(
            check_key_meta(mode, 65534, 65534, true),
            Err(KeyError::BadMode(mode & 0o7777)),
            "{mode:o}"
        );
    }
    assert_eq!(
        check_key_meta(0o100600, 0, 65534, true),
        Err(KeyError::WrongOwner)
    );
    assert_eq!(
        check_key_meta(0o120600, 65534, 65534, false),
        Err(KeyError::NotRegularFile)
    );
}

#[test]
fn key_hex_rules() {
    let ok = "00ff".repeat(16);
    assert_eq!(parse_key_hex(&format!("{ok}\n")).unwrap().len(), 32);
    assert_eq!(parse_key_hex(&"ab".repeat(31)), Err(KeyError::TooShort));
    assert_eq!(parse_key_hex(&"zz".repeat(32)), Err(KeyError::NotHex));
    assert_eq!(
        parse_key_hex(&"ab".repeat(31).replace('a', "g")),
        Err(KeyError::NotHex)
    );
    assert_eq!(parse_key_hex(&"ab".repeat(600)), Err(KeyError::TooLarge));
    assert_eq!(
        parse_key_hex(&format!("{}a", "ab".repeat(32))),
        Err(KeyError::NotHex),
        "odd length"
    );
}

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-cfg-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn load_key_checks_the_real_file() {
    let d = tmpdir();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap(); // not umask-dependent
    let k = d.join("key");
    fs::write(&k, format!("{}\n", "ab".repeat(32))).unwrap();
    fs::set_permissions(&k, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        matches!(load_key(&k), Err(KeyError::BadMode(0o644))),
        "world-readable key refused"
    );
    fs::set_permissions(&k, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load_key(&k).unwrap(), vec![0xab; 32]);
    let link = d.join("link");
    symlink(&k, &link).unwrap();
    assert_eq!(
        load_key(&link),
        Err(KeyError::NotRegularFile),
        "symlinks refused"
    );
    assert!(matches!(load_key(&d.join("missing")), Err(KeyError::Io(_))));
    fs::remove_dir_all(d).unwrap();
}

// ---- dnsmasq drop-in ----

#[test]
fn dropin_content_is_exact() {
    assert_eq!(
        dropin_content("/tmp/vigie"),
        "log-queries=extra\nlog-dhcp\nlog-facility=/tmp/vigie/dnsmasq.log\n"
    );
    assert_eq!(DROPIN_PATH, "/tmp/dnsmasq.d/vigie.conf");
}

#[test]
fn dropin_verification() {
    let want = dropin_content("/tmp/vigie");
    assert_eq!(check_dropin(Some(&want), "/tmp/vigie"), DropinState::Ok);
    assert_eq!(
        check_dropin(Some(&want.replace('\n', "\r\n")), "/tmp/vigie"),
        DropinState::Ok,
        "CRLF tolerated"
    );
    assert_eq!(check_dropin(None, "/tmp/vigie"), DropinState::Missing);
    assert_eq!(
        check_dropin(Some("log-queries\nlog-dhcp\n"), "/tmp/vigie"),
        DropinState::Differs,
        "plain log-queries lacks extra"
    );
    assert_eq!(check_dropin(Some(""), "/tmp/vigie"), DropinState::Differs);
}

#[test]
fn dns_log_quiet_needs_five_silent_windows_with_flows() {
    let mut q = QuietDetector::default();
    for i in 1..QUIET_WINDOWS {
        assert!(!q.observe(0, 50, DropinState::Ok), "window {i}");
    }
    assert!(
        q.observe(0, 50, DropinState::Ok),
        "fifth silent window with flows"
    );
    assert!(q.observe(0, 50, DropinState::Ok), "stays quiet");
    assert!(!q.observe(3, 50, DropinState::Ok), "any query clears it");
    for _ in 0..10 {
        assert!(
            !q.observe(0, 0, DropinState::Ok),
            "no flows: an idle network is not quiet"
        );
    }
    let mut q = QuietDetector::default();
    assert!(
        q.observe(0, 0, DropinState::Missing),
        "missing drop-in is reported at once"
    );
    assert!(!q.observe(1, 0, DropinState::Ok));
}

#[test]
fn flows_resume_after_quiet_windows_only_count_consecutive() {
    let mut q = QuietDetector::default();
    for _ in 0..4 {
        q.observe(0, 9, DropinState::Ok);
    }
    q.observe(1, 9, DropinState::Ok);
    assert!(
        !q.observe(0, 9, DropinState::Ok),
        "counter restarted by the query"
    );
}

// ---- the root-run shell scripts (dist/) ----

fn dist(name: &str) -> String {
    format!("{}/deploy/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// The scripts verify root ownership; unprivileged tests trust the current user instead.
fn trust_env() -> Vec<(&'static str, String)> {
    let m = fs::metadata("/proc/self").unwrap();
    vec![
        ("VIGIE_TRUSTED_UID", m.uid().to_string()),
        ("VIGIE_OWNER", format!("{}:{}", m.uid(), m.gid())),
        ("VIGIE_LOG_ALLOWED_UIDS", m.uid().to_string()),
    ]
}

fn run_dropin(
    args: &[&str],
    dropin_dir: &Path,
    log_dir: &Path,
    reload_log: &Path,
) -> (i32, String) {
    let out = Command::new("sh")
        .arg(dist("vigie-dnsmasq-dropin.sh"))
        .args(args)
        .env("VIGIE_DROPIN_DIR", dropin_dir)
        .env("VIGIE_LOG_DIR", log_dir)
        .envs(trust_env())
        .env(
            "VIGIE_RELOAD_CMD",
            format!("echo reloaded >> {}", reload_log.display()),
        )
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn dropin_script_creates_repairs_and_reloads_only_on_change() {
    let d = tmpdir();
    let (dropin, logd, reload) = (d.join("dnsmasq.d"), d.join("vigie"), d.join("reload.log"));
    let file = dropin.join("vigie.conf");
    let want = dropin_content(logd.to_str().unwrap());

    assert_eq!(
        run_dropin(&["check"], &dropin, &logd, &reload).0,
        1,
        "missing before ensure"
    );
    assert_eq!(run_dropin(&["ensure"], &dropin, &logd, &reload).0, 0);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        want,
        "script and Rust agree on the content"
    );
    assert_eq!(
        fs::read_to_string(&reload).unwrap().lines().count(),
        1,
        "reloaded after create"
    );
    let mode = fs::metadata(logd.join("dnsmasq.log"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640, "log is readable by the vigie group only");
    assert_eq!(run_dropin(&["check"], &dropin, &logd, &reload).0, 0);

    run_dropin(&["ensure"], &dropin, &logd, &reload);
    assert_eq!(
        fs::read_to_string(&reload).unwrap().lines().count(),
        1,
        "no reload when already correct"
    );

    fs::write(&file, "log-queries\n").unwrap();
    assert_eq!(
        run_dropin(&["check"], &dropin, &logd, &reload).0,
        2,
        "differs"
    );
    run_dropin(&["ensure"], &dropin, &logd, &reload);
    assert_eq!(fs::read_to_string(&file).unwrap(), want, "repaired");
    assert_eq!(fs::read_to_string(&reload).unwrap().lines().count(), 2);

    fs::remove_file(&file).unwrap();
    run_dropin(&["ensure"], &dropin, &logd, &reload);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        want,
        "recreated after GL.iNet clears the dir"
    );
    assert_eq!(run_dropin(&["bogus"], &dropin, &logd, &reload).0, 64);
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn watchdog_script_truncates_only_above_the_limit() {
    let d = tmpdir();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o750)).unwrap();
    let log = d.join("dnsmasq.log");
    let run = |limit: &str| {
        Command::new("sh")
            .arg(dist("vigie-log-watchdog.sh"))
            .env("VIGIE_LOG_FILE", &log)
            .env("VIGIE_LOG_MAX_BYTES", limit)
            .envs(trust_env())
            .status()
            .unwrap()
            .code()
            .unwrap()
    };
    fs::write(&log, vec![b'x'; 5000]).unwrap();
    assert_eq!(run("5000"), 0);
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        5000,
        "at the limit: untouched"
    );
    assert_eq!(run("4999"), 0);
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        0,
        "above the limit: truncated"
    );
    assert_eq!(run("1"), 0, "empty file fine");
    fs::remove_file(&log).unwrap();
    assert_eq!(run("1"), 0, "missing file fine");
    fs::remove_dir_all(d).unwrap();
}
