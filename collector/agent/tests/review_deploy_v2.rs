//! Re-review items 2d, 3, 4 (init guard), 5, 8: deploy script behaviour. The scripts run as
//! root on the router; tests run unprivileged and reach the trust anchors only through the
//! `VIGIE_TEST=1` hooks, which production ignores.

mod common;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-v2-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

fn script(name: &str) -> String {
    format!("{}/deploy/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn me() -> (u32, u32) {
    let m = fs::metadata("/proc/self").unwrap();
    (m.uid(), m.gid())
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn stub(dir: &Path, name: &str, body: &str) {
    fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
}

fn real(cmd: &str) -> String {
    let o = Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

fn trusted(c: &mut Command) -> &mut Command {
    let (uid, gid) = me();
    c.env("VIGIE_TEST", "1")
        .env("VIGIE_TRUSTED_UID", uid.to_string())
        .env("VIGIE_OWNER", format!("{uid}:{gid}"))
        .env("VIGIE_LOG_ALLOWED_UIDS", uid.to_string())
}

fn dropin(dd: &Path, ld: &Path, path: Option<&str>) -> Output {
    let mut c = Command::new("sh");
    c.arg(script("vigie-dnsmasq-dropin.sh")).arg("ensure");
    trusted(&mut c)
        .env("VIGIE_DROPIN_DIR", dd)
        .env("VIGIE_LOG_DIR", ld)
        .env("VIGIE_RELOAD_CMD", "true");
    if let Some(p) = path {
        c.env("PATH", p);
    }
    c.output().unwrap()
}

// ---- item 3: ensure_dir never adopts a directory it did not create ----

/// A `mkdir` that loses the race: the attacker's directory appears first, ours then fails.
fn racing_path(d: &Path, attacker_mode: &str) -> String {
    let bin = d.join("bin");
    stub(
        &bin,
        "mkdir",
        &format!(
            "for last; do :; done\n{} -m {attacker_mode} \"$last\"\nexit 1",
            real("mkdir")
        ),
    );
    stub(
        &bin,
        "logger",
        &format!("printf '%s\\n' \"$*\" >> '{}'", d.join("syslog").display()),
    );
    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap())
}

#[test]
fn a_directory_that_wins_the_mkdir_race_is_refused_not_adopted() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    let path = racing_path(&d, "0777");
    let o = dropin(&dd, &ld, Some(&path));
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert_eq!(
        mode(&ld),
        0o777,
        "an existing directory is never chmod'ed by path"
    );
    let syslog = fs::read_to_string(d.join("syslog")).unwrap_or_default();
    assert!(
        syslog.contains("vigie") && syslog.contains("refusing"),
        "loud syslog line expected, got {syslog:?}"
    );
    assert!(!ld.join("dnsmasq.log").exists());
}

#[test]
fn a_raced_directory_with_a_good_mode_but_foreign_owner_is_refused_too() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    let path = racing_path(&d, "0750");
    let (uid, _) = me();
    let mut c = Command::new("sh");
    c.arg(script("vigie-dnsmasq-dropin.sh")).arg("ensure");
    let o = trusted(&mut c)
        .env("VIGIE_TRUSTED_UID", (uid + 1).to_string())
        .env("VIGIE_DROPIN_DIR", &dd)
        .env("VIGIE_LOG_DIR", &ld)
        .env("VIGIE_RELOAD_CMD", "true")
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert!(err(&o).contains("owned"), "{}", err(&o));
    let syslog = fs::read_to_string(d.join("syslog")).unwrap_or_default();
    assert!(syslog.contains("refusing"), "{syslog:?}");
}

#[test]
fn a_preexisting_good_directory_is_accepted_and_left_alone() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    fs::create_dir_all(&ld).unwrap();
    fs::set_permissions(&ld, fs::Permissions::from_mode(0o700)).unwrap();
    let o = dropin(&dd, &ld, None);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(mode(&ld), 0o700, "mode of an existing directory unchanged");
}

#[test]
fn log_dir_we_create_is_traversable_for_dnsmasq() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&dd, &ld, None).status.success());
    assert_eq!(mode(&ld), 0o751);
    assert_eq!(mode(&ld.join("dnsmasq.log")), 0o640);
}

// ---- item 8: env overrides only under VIGIE_TEST=1 ----

#[test]
fn overrides_are_ignored_without_vigie_test() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&dd, &ld, None).status.success());
    let (uid, gid) = me();
    let run = |test: bool| {
        let mut c = Command::new("sh");
        c.arg(script("vigie-dnsmasq-dropin.sh")).arg("check");
        c.env("VIGIE_DROPIN_DIR", &dd)
            .env("VIGIE_LOG_DIR", &ld)
            .env("VIGIE_TRUSTED_UID", uid.to_string())
            .env("VIGIE_OWNER", format!("{uid}:{gid}"));
        if test {
            c.env("VIGIE_TEST", "1");
        }
        c.output().unwrap().status.code()
    };
    assert_eq!(run(true), Some(0), "sanity: honoured under VIGIE_TEST");
    assert_ne!(run(false), Some(0), "production ignores the overrides");
}

#[test]
fn watchdog_ignores_overrides_in_production() {
    let d = tmpdir();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o750)).unwrap();
    let log = d.join("dnsmasq.log");
    fs::write(&log, vec![b'x'; 100]).unwrap();
    let (uid, _) = me();
    let o = Command::new("sh")
        .arg(script("vigie-log-watchdog.sh"))
        .env("VIGIE_LOG_FILE", &log)
        .env("VIGIE_LOG_MAX_BYTES", "1")
        .env("VIGIE_TRUSTED_UID", uid.to_string())
        .env("VIGIE_LOG_ALLOWED_UIDS", uid.to_string())
        .output()
        .unwrap();
    let _ = o;
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        100,
        "override not honoured"
    );
    assert!(!d.join("dnsmasq.log.1").exists());
}

// ---- item 2d: the watchdog rotates by rename + SIGUSR2 ----

fn watchdog(log: &Path, max: &str, signal: &str) -> Output {
    let mut c = Command::new("sh");
    c.arg(script("vigie-log-watchdog.sh"));
    trusted(&mut c)
        .env("VIGIE_LOG_FILE", log)
        .env("VIGIE_LOG_MAX_BYTES", max)
        .env("VIGIE_SIGNAL_CMD", signal)
        .envs(common::fake_dnsmasq_env())
        .output()
        .unwrap()
}

fn log_dir() -> (PathBuf, PathBuf) {
    let d = tmpdir();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o751)).unwrap();
    let log = d.join("dnsmasq.log");
    (d, log)
}

#[test]
fn watchdog_rotates_by_rename_and_signals_dnsmasq() {
    let (d, log) = log_dir();
    fs::write(&log, vec![b'x'; 150]).unwrap();
    let ino = fs::metadata(&log).unwrap().ino();
    let sig = d.join("signalled");
    let o = watchdog(&log, "100", &format!("echo usr2 >> {}", sig.display()));
    assert!(o.status.success(), "{}", err(&o));
    let old = d.join("dnsmasq.log.1");
    assert_eq!(fs::metadata(&old).unwrap().len(), 150, "content kept");
    assert_eq!(
        fs::metadata(&old).unwrap().ino(),
        ino,
        "renamed, not copied"
    );
    assert_eq!(fs::metadata(&log).unwrap().len(), 0);
    assert_ne!(fs::metadata(&log).unwrap().ino(), ino);
    assert_eq!(
        mode(&log),
        0o640,
        "new file ready before dnsmasq reopens it"
    );
    assert_eq!(fs::read_to_string(&sig).unwrap().trim(), "usr2");
}

#[test]
fn watchdog_truncates_in_place_only_as_an_emergency_above_twice_the_cap() {
    let (d, log) = log_dir();
    fs::write(&log, vec![b'x'; 250]).unwrap();
    let ino = fs::metadata(&log).unwrap().ino();
    let o = watchdog(&log, "100", "true");
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(fs::metadata(&log).unwrap().len(), 0);
    assert_eq!(
        fs::metadata(&log).unwrap().ino(),
        ino,
        "same file: in place"
    );
    assert!(!d.join("dnsmasq.log.1").exists());
    // A previous rotation that dnsmasq never reopened keeps growing: bounded the same way.
    fs::write(&log, "").unwrap();
    fs::write(d.join("dnsmasq.log.1"), vec![b'y'; 250]).unwrap();
    assert!(watchdog(&log, "100", "true").status.success());
    assert_eq!(fs::metadata(d.join("dnsmasq.log.1")).unwrap().len(), 0);
}

#[test]
fn watchdog_refuses_a_symlinked_rotation_target() {
    let (d, log) = log_dir();
    fs::write(&log, vec![b'x'; 150]).unwrap();
    let victim = d.join("victim");
    fs::write(&victim, "precious").unwrap();
    std::os::unix::fs::symlink(&victim, d.join("dnsmasq.log.1")).unwrap();
    let o = watchdog(&log, "100", "true");
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert_eq!(fs::metadata(&log).unwrap().len(), 150, "nothing rotated");
}

// ---- item 4: init script fails closed without the vigie user ----

#[test]
fn init_start_refuses_when_the_vigie_user_is_missing() {
    let d = tmpdir();
    let bin = d.join("bin");
    stub(&bin, "id", "exit 1");
    stub(
        &bin,
        "logger",
        &format!("printf '%s\\n' \"$*\" >> '{}'", d.join("syslog").display()),
    );
    let sh = real("sh");
    let o = Command::new(&sh)
        .arg("-c")
        .arg(format!(
            ". '{}'; procd_open_instance() {{ echo OPENED; }}; start_service",
            script("vigie-collector.init")
        ))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("OPENED"));
    assert!(
        fs::read_to_string(d.join("syslog"))
            .unwrap()
            .contains("vigie user missing"),
        "the refusal must be logged"
    );
}

// ---- item 5: the print helper picks a free uid and installs nothing under /tmp ----

fn print_cmds(passwd: &str, envs: &[(&str, &str)]) -> Output {
    let d = tmpdir();
    let pw = d.join("passwd");
    fs::write(&pw, passwd).unwrap();
    let gr = d.join("group");
    fs::write(&gr, "root:x:0:\n").unwrap();
    let mut c = Command::new("sh");
    c.arg(script("vigie-print-install-commands.sh"))
        .env("VIGIE_TEST", "1")
        .env("VIGIE_PASSWD", &pw)
        .env("VIGIE_GROUP_FILE", &gr)
        .current_dir(&d);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().unwrap()
}

#[test]
fn print_helper_picks_the_first_free_uid_in_6700_6799() {
    let o = print_cmds(
        "root:x:0:0::/:/bin/sh\nfoo:x:6700:6700::/:/bin/false\nbar:x:6701:1::/:/x\n",
        &[],
    );
    assert!(o.status.success(), "{}", err(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("vigie:x:6702:6702"), "{out}");
}

#[test]
fn print_helper_refuses_a_uid_that_is_in_use_or_out_of_range() {
    let pw = "foo:x:6750:6750::/:/bin/false\n";
    assert!(!print_cmds(pw, &[("VIGIE_UID", "6750")]).status.success());
    assert!(!print_cmds("", &[("VIGIE_UID", "1000")]).status.success());
    assert!(print_cmds(pw, &[("VIGIE_UID", "6751")]).status.success());
    let full: String = (6700..6800)
        .map(|u| format!("u{u}:x:{u}:{u}::/:/x\n"))
        .collect();
    assert!(!print_cmds(&full, &[]).status.success(), "range exhausted");
}

#[test]
fn print_helper_does_not_create_tmp_vigie() {
    let o = print_cmds("", &[]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        !out.contains("install -d -m 0750 -o root -g vigie /tmp/vigie"),
        "{out}"
    );
    assert!(
        !out.contains("install -d") || !out.contains("/tmp/vigie\n"),
        "{out}"
    );
    assert!(
        out.contains("--uid"),
        "the conntrack helper gets the uid: {out}"
    );
}
