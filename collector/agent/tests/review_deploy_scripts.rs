//! Security review items 2 and 3: the root-run deploy scripts must not follow symlinks or trust
//! directories in world-writable /tmp. Tests run unprivileged, so the trust anchor (uid 0 and
//! `root:vigie` in production) is overridden through env hooks that an attacker cannot reach
//! (cron/procd start the scripts with a clean environment).

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vigie-deploy-{}-{}",
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
    // /proc/self is owned by the process's own uid/gid.
    let m = fs::metadata("/proc/self").unwrap();
    (m.uid(), m.gid())
}

fn sh(name: &str, args: &[&str], envs: &[(&str, String)]) -> Output {
    let (uid, gid) = me();
    let mut c = Command::new("sh");
    c.arg(script(name)).args(args);
    c.env("VIGIE_TRUSTED_UID", uid.to_string())
        .env("VIGIE_OWNER", format!("{uid}:{gid}"))
        .env("VIGIE_LOG_ALLOWED_UIDS", uid.to_string());
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn dropin(args: &[&str], dropin_dir: &Path, log_dir: &Path, extra: &[(&str, String)]) -> Output {
    let mut envs = vec![
        ("VIGIE_DROPIN_DIR", dropin_dir.display().to_string()),
        ("VIGIE_LOG_DIR", log_dir.display().to_string()),
        ("VIGIE_RELOAD_CMD", "true".to_string()),
    ];
    envs.extend(extra.iter().cloned());
    sh("vigie-dnsmasq-dropin.sh", args, &envs)
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn good_dir(p: &Path, m: u32) {
    fs::create_dir_all(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}

#[test]
fn ensure_creates_private_log_dir_and_group_readable_log() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    let o = dropin(&["ensure"], &dd, &ld, &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(mode(&ld), 0o750, "log dir is not world-readable");
    assert_eq!(
        mode(&ld.join("dnsmasq.log")),
        0o640,
        "log is not world-readable"
    );
    assert_eq!(mode(&dd), 0o755);
    assert_eq!(mode(&dd.join("vigie.conf")), 0o644);
}

#[test]
fn ensure_refuses_a_preplanted_symlink_log() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    good_dir(&ld, 0o750);
    let victim = d.join("victim");
    fs::write(&victim, "precious").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&victim, ld.join("dnsmasq.log")).unwrap();
    let o = dropin(&["ensure"], &dd, &ld, &[]);
    assert!(!o.status.success(), "must refuse");
    assert!(err(&o).contains("symlink"), "message: {}", err(&o));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert_eq!(mode(&victim), 0o600, "chmod must not follow the link");
    assert!(
        !dd.join("vigie.conf").exists(),
        "nothing written after a refusal"
    );
}

#[test]
fn ensure_refuses_symlinked_directories() {
    let d = tmpdir();
    let target = d.join("elsewhere");
    good_dir(&target, 0o750);
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    symlink(&target, &ld).unwrap();
    let o = dropin(&["ensure"], &dd, &ld, &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    assert!(
        fs::read_dir(&target).unwrap().next().is_none(),
        "target untouched"
    );

    let d2 = tmpdir();
    let target2 = d2.join("elsewhere");
    good_dir(&target2, 0o755);
    let (dd2, ld2) = (d2.join("dnsmasq.d"), d2.join("vigie"));
    symlink(&target2, &dd2).unwrap();
    let o = dropin(&["ensure"], &dd2, &ld2, &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    assert!(fs::read_dir(&target2).unwrap().next().is_none());
}

#[test]
fn ensure_refuses_a_symlinked_conf_file() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    good_dir(&dd, 0o755);
    let victim = d.join("victim");
    fs::write(&victim, "precious").unwrap();
    symlink(&victim, dd.join("vigie.conf")).unwrap();
    let o = dropin(&["ensure"], &dd, &ld, &[]);
    assert!(!o.status.success());
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
}

#[test]
fn ensure_refuses_directories_not_owned_by_the_trusted_uid() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    good_dir(&ld, 0o750);
    good_dir(&dd, 0o755);
    let (uid, _) = me();
    let other = (uid + 1).to_string();
    let o = dropin(&["ensure"], &dd, &ld, &[("VIGIE_TRUSTED_UID", other)]);
    assert!(
        !o.status.success(),
        "attacker-owned directory must be refused"
    );
    assert!(err(&o).contains("owned"), "{}", err(&o));
    assert!(fs::read_dir(&dd).unwrap().next().is_none());
    assert!(fs::read_dir(&ld).unwrap().next().is_none());
}

#[test]
fn ensure_refuses_group_or_world_writable_directories() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    good_dir(&ld, 0o770);
    let o = dropin(&["ensure"], &dd, &ld, &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("writable"), "{}", err(&o));
}

#[test]
fn ensure_uses_an_unpredictable_temp_name_inside_the_verified_dir() {
    let d = tmpdir();
    let (dd, ld, bin) = (d.join("dnsmasq.d"), d.join("vigie"), d.join("bin"));
    fs::create_dir_all(&bin).unwrap();
    let rec = d.join("mv.log");
    let real_mv = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v mv"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let wrapper = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\nexec {} \"$@\"\n",
        rec.display(),
        real_mv.trim()
    );
    fs::write(bin.join("mv"), wrapper).unwrap();
    fs::set_permissions(bin.join("mv"), fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    for _ in 0..2 {
        fs::remove_file(dd.join("vigie.conf")).ok();
        let o = dropin(&["ensure"], &dd, &ld, &[("PATH", path.clone())]);
        assert!(o.status.success(), "{}", err(&o));
    }
    let names: Vec<String> = fs::read_to_string(&rec)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    assert_eq!(names.len(), 2);
    assert_ne!(names[0], names[1], "temp name is random per run");
    for n in &names {
        let p = Path::new(n);
        assert_eq!(
            p.parent().unwrap(),
            dd,
            "temp file lives in the verified dir"
        );
        let base = p.file_name().unwrap().to_str().unwrap();
        assert!(!base.contains(".tmp."), "predictable pattern: {base}");
        assert!(!base.ends_with(&std::process::id().to_string()));
    }
    assert!(
        fs::read_dir(&dd).unwrap().count() == 1,
        "no temp files left behind"
    );
}

#[test]
fn check_reports_a_symlinked_conf_as_not_ok() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    let real = d.join("real.conf");
    fs::rename(dd.join("vigie.conf"), &real).unwrap();
    symlink(&real, dd.join("vigie.conf")).unwrap();
    assert_eq!(dropin(&["check"], &dd, &ld, &[]).status.code(), Some(2));
}

// ---- watchdog ----

fn watchdog(log: &Path, max: &str, extra: &[(&str, String)]) -> Output {
    let mut envs = vec![
        ("VIGIE_LOG_FILE", log.display().to_string()),
        ("VIGIE_LOG_MAX_BYTES", max.to_string()),
    ];
    envs.extend(extra.iter().cloned());
    sh("vigie-log-watchdog.sh", &[], &envs)
}

#[test]
fn watchdog_refuses_a_symlinked_log_and_leaves_the_target_alone() {
    let d = tmpdir();
    let ld = d.join("vigie");
    good_dir(&ld, 0o750);
    let victim = d.join("victim");
    fs::write(&victim, vec![b'x'; 100]).unwrap();
    symlink(&victim, ld.join("dnsmasq.log")).unwrap();
    let o = watchdog(&ld.join("dnsmasq.log"), "1", &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    assert_eq!(
        fs::metadata(&victim).unwrap().len(),
        100,
        "victim not truncated"
    );
}

#[test]
fn watchdog_refuses_untrusted_directory_and_foreign_owned_log() {
    let d = tmpdir();
    let ld = d.join("vigie");
    good_dir(&ld, 0o750);
    let log = ld.join("dnsmasq.log");
    fs::write(&log, vec![b'x'; 100]).unwrap();
    let (uid, _) = me();
    let o = watchdog(&log, "1", &[("VIGIE_TRUSTED_UID", (uid + 1).to_string())]);
    assert!(!o.status.success());
    assert_eq!(fs::metadata(&log).unwrap().len(), 100);
    let o = watchdog(
        &log,
        "1",
        &[("VIGIE_LOG_ALLOWED_UIDS", (uid + 1).to_string())],
    );
    assert!(!o.status.success(), "log owned by a non-allowed uid");
    assert_eq!(fs::metadata(&log).unwrap().len(), 100);
    let o = watchdog(&log, "1", &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        0,
        "trusted setup still truncates"
    );
}

// ---- syntax and the owner-run install helper ----

#[test]
fn all_scripts_parse() {
    for s in [
        "vigie-dnsmasq-dropin.sh",
        "vigie-log-watchdog.sh",
        "vigie-lib.sh",
        "vigie-collector.init",
        "vigie-print-install-commands.sh",
    ] {
        let o = Command::new("sh")
            .arg("-n")
            .arg(script(s))
            .output()
            .unwrap();
        assert!(o.status.success(), "{s}: {}", err(&o));
    }
}

#[test]
fn init_script_runs_the_agent_as_the_dedicated_vigie_user() {
    let t = fs::read_to_string(script("vigie-collector.init")).unwrap();
    assert!(t.contains("procd_set_param user vigie"));
    assert!(!t.contains("param user nobody"));
}

#[test]
fn install_helper_prints_user_creation_commands_and_changes_nothing() {
    let d = tmpdir();
    let o = Command::new("sh")
        .arg(script("vigie-print-install-commands.sh"))
        .env("VIGIE_UID", "6700")
        .env("VIGIE_GID", "6700")
        .env("HOME", &d)
        .current_dir(&d)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    for needle in [
        "/etc/passwd",
        "/etc/group",
        "/bin/false",
        "vigie:x:6700:6700",
        "install -d -m 0750 -o root -g vigie /tmp/vigie",
        "chown vigie:vigie /etc/vigie/key",
        "chmod 0600 /etc/vigie/key",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
    }
    assert!(
        fs::read_dir(&d).unwrap().next().is_none(),
        "helper wrote files"
    );
    let bad = Command::new("sh")
        .arg(script("vigie-print-install-commands.sh"))
        .env("VIGIE_UID", "0; rm -rf /")
        .output()
        .unwrap();
    assert!(!bad.status.success(), "non-numeric uid is rejected");
}
