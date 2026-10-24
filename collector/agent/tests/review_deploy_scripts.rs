//! Security review items 2 and 3: the root-run deploy scripts must not follow symlinks or trust
//! directories in world-writable /tmp. Tests run unprivileged, so the trust anchor (uid 0 and
//! `root:vigie` in production) is overridden through env hooks that an attacker cannot reach
//! (cron/procd start the scripts with a clean environment).

mod common;
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
    c.env("VIGIE_TEST", "1")
        .env("VIGIE_TRUSTED_UID", uid.to_string())
        .env("VIGIE_OWNER", format!("{uid}:{gid}"))
        .env("VIGIE_LOG_ALLOWED_UIDS", uid.to_string());
    c.envs(common::fake_dnsmasq_env());
    if let Some((_, value)) = envs.iter().find(|(key, _)| *key == "VIGIE_LOG_DIR") {
        c.envs(common::fake_logfs_env(Path::new(value)));
    } else if let Some((_, value)) = envs.iter().find(|(key, _)| *key == "VIGIE_LOG_FILE") {
        c.envs(common::fake_logfs_env(Path::new(value).parent().unwrap()));
    }
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
    assert_eq!(mode(&ld), 0o751, "log dir: traverse-only for others");
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
    good_dir(&ld, 0o751);
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
    good_dir(&ld, 0o751);
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
    assert_eq!(
        names.len(),
        4,
        "config and reload confirmation publish atomically"
    );
    assert_eq!(
        names.iter().collect::<std::collections::HashSet<_>>().len(),
        4,
        "temp names are unique"
    );
    for n in &names {
        let p = Path::new(n);
        assert_eq!(
            p.parent().unwrap(),
            if p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("vigie.conf.")
            {
                &dd
            } else {
                &ld
            },
            "temp file lives in its verified destination directory"
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
    good_dir(&ld, 0o751);
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
    good_dir(&ld, 0o751);
    let log = ld.join("dnsmasq.log");
    fs::write(&log, vec![b'x'; 100]).unwrap();
    let (uid, _) = me();
    let o = watchdog(&log, "1", &[("VIGIE_TRUSTED_UID", (uid + 1).to_string())]);
    assert!(!o.status.success());
    assert_eq!(fs::metadata(&log).unwrap().len(), 100);
    // A log owned by a non-allowed uid is covered in review4_deploy.rs (stat stub).
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
        "vigie-run.sh",
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
    let cfg = tmpdir();
    fs::write(cfg.join("passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
    fs::write(cfg.join("group"), "root:x:0:\n").unwrap();
    let o = Command::new("sh")
        .arg(script("vigie-print-install-commands.sh"))
        .env("VIGIE_TEST", "1")
        .env("VIGIE_PASSWD", cfg.join("passwd"))
        .env("VIGIE_GROUP_FILE", cfg.join("group"))
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

// A published config is not proof that dnsmasq accepted its reload.
#[test]
fn reload_failure_is_propagated_and_matching_file_retried_until_confirmed() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    let calls = d.join("reload-calls");
    let fail = format!("echo x >> '{}'; exit 37", calls.display());
    let o = dropin(&["ensure"], &dd, &ld, &[("VIGIE_RELOAD_CMD", fail.clone())]);
    assert_eq!(o.status.code(), Some(37), "{}", err(&o));
    assert!(
        dd.join("vigie.conf").is_file(),
        "config publication preceded reload"
    );
    assert!(
        !dropin(&["check"], &dd, &ld, &[]).status.success(),
        "failed reload cannot be healthy"
    );
    assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 1);
    let o = dropin(&["ensure"], &dd, &ld, &[("VIGIE_RELOAD_CMD", fail)]);
    assert_eq!(
        o.status.code(),
        Some(37),
        "matching config still requires reload"
    );
    assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 2);
    let success = format!("echo x >> '{}'", calls.display());
    assert!(dropin(
        &["ensure"],
        &dd,
        &ld,
        &[("VIGIE_RELOAD_CMD", success.clone())]
    )
    .status
    .success());
    assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 3);
    assert!(dropin(&["check"], &dd, &ld, &[]).status.success());
    assert!(
        dropin(&["ensure"], &dd, &ld, &[("VIGIE_RELOAD_CMD", success)])
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(&calls).unwrap().lines().count(),
        3,
        "confirmed application avoids redundant reload"
    );
}

#[test]
fn matching_config_without_confirmation_requires_reload() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    // Simulate a process dying after reload or config publication but before confirmation.
    let applied = ld.join(".dnsmasq-applied");
    if applied.exists() {
        fs::remove_file(&applied).unwrap();
    }
    assert!(!dropin(&["check"], &dd, &ld, &[]).status.success());
    assert_eq!(
        dropin(
            &["ensure"],
            &dd,
            &ld,
            &[("VIGIE_RELOAD_CMD", "exit 37".into())]
        )
        .status
        .code(),
        Some(37)
    );
}

#[test]
fn applied_confirmation_cannot_be_symlinked_or_writable_by_untrusted_users() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    let applied = ld.join(".dnsmasq-applied");
    let victim = d.join("confirmation-victim");
    fs::write(&victim, "precious").unwrap();
    if applied.exists() {
        fs::remove_file(&applied).unwrap();
    }
    symlink(&victim, &applied).unwrap();
    assert!(!dropin(&["check"], &dd, &ld, &[]).status.success());
    assert!(!dropin(&["ensure"], &dd, &ld, &[]).status.success());
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    fs::remove_file(&applied).unwrap();
    fs::write(&applied, fs::read(dd.join("vigie.conf")).unwrap()).unwrap();
    fs::set_permissions(&applied, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!dropin(&["check"], &dd, &ld, &[]).status.success());
    assert!(!dropin(&["ensure"], &dd, &ld, &[]).status.success());
}

#[test]
fn changed_config_invalidates_prior_confirmation_before_failed_reload() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    assert_eq!(mode(&ld.join(".dnsmasq-applied")), 0o600);
    fs::write(dd.join("vigie.conf"), "# replaced by firmware\n").unwrap();
    assert_eq!(
        dropin(
            &["ensure"],
            &dd,
            &ld,
            &[("VIGIE_RELOAD_CMD", "exit 37".into())]
        )
        .status
        .code(),
        Some(37)
    );
    assert!(
        !ld.join(".dnsmasq-applied").exists(),
        "old confirmation cannot survive publication"
    );
    assert!(!dropin(&["check"], &dd, &ld, &[]).status.success());
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    assert!(dropin(&["check"], &dd, &ld, &[]).status.success());
}

#[test]
fn killed_reload_process_leaves_no_success_confirmation() {
    let d = tmpdir();
    let (dd, ld) = (d.join("dnsmasq.d"), d.join("vigie"));
    // The substituted reload child kills only its own invoking ensure process.
    let o = dropin(
        &["ensure"],
        &dd,
        &ld,
        &[("VIGIE_RELOAD_CMD", "kill -KILL \"$PPID\"".into())],
    );
    assert!(!o.status.success());
    assert!(dd.join("vigie.conf").is_file());
    assert!(!ld.join(".dnsmasq-applied").exists());
    assert!(!dropin(&["check"], &dd, &ld, &[]).status.success());
    assert!(dropin(&["ensure"], &dd, &ld, &[]).status.success());
    assert!(dropin(&["check"], &dd, &ld, &[]).status.success());
}

fn prepare_state(root: &Path, extra: &[(&str, String)]) -> Output {
    let (uid, gid) = me();
    let bin = root.parent().unwrap().join("state-bin");
    fs::create_dir_all(&bin).unwrap();
    let real_id = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v id"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let fake_id = format!("#!/bin/sh\nif [ \"${{2:-}}\" = vigie ]; then case $1 in -u) echo {uid};; -g) echo {gid};; *) exit 1;; esac; else exec {} \"$@\"; fi\n",real_id.trim());
    fs::write(bin.join("id"), fake_id).unwrap();
    fs::set_permissions(bin.join("id"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut envs = vec![
        ("VIGIE_STATE_ROOT", root.display().to_string()),
        (
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        ),
    ];
    envs.extend(extra.iter().cloned());
    sh("vigie-state-dir.sh", &[], &envs)
}

#[test]
fn state_root_is_trusted_and_resets_only_known_failure_leaf() {
    let d = tmpdir();
    let root = d.join("vigie-collector-root");
    let legacy = d.join("vigie-collector");
    good_dir(&legacy, 0o700);
    fs::write(legacy.join("fails"), "legacy evidence").unwrap();
    let out = prepare_state(&root, &[]);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(mode(&root), 0o711);
    assert_eq!(mode(&root.join("state")), 0o700);
    fs::write(root.join("state/fails"), "old count").unwrap();
    fs::write(root.join("state/unknown"), "retain").unwrap();
    assert!(prepare_state(&root, &[]).status.success());
    assert!(!root.join("state/fails").exists());
    assert_eq!(
        fs::read_to_string(root.join("state/unknown")).unwrap(),
        "retain"
    );
    assert_eq!(
        fs::read_to_string(legacy.join("fails")).unwrap(),
        "legacy evidence"
    );
}

#[test]
fn state_parent_symlink_or_unsafe_mode_cannot_trigger_root_cleanup() {
    let d = tmpdir();
    let root = d.join("root");
    let target = d.join("target");
    good_dir(&target, 0o711);
    fs::write(target.join("keep"), "precious").unwrap();
    symlink(&target, &root).unwrap();
    assert!(!prepare_state(&root, &[]).status.success());
    assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "precious");
    fs::remove_file(&root).unwrap();
    good_dir(&root, 0o777);
    assert!(!prepare_state(&root, &[]).status.success());
    assert_eq!(mode(&root), 0o777, "never repair untrusted geometry");
}

#[test]
fn state_child_symlink_and_directory_failure_leaf_are_refused_without_recursion() {
    let d = tmpdir();
    let root = d.join("root");
    good_dir(&root, 0o711);
    let victim = d.join("victim");
    good_dir(&victim, 0o700);
    fs::write(victim.join("keep"), "precious").unwrap();
    symlink(&victim, root.join("state")).unwrap();
    assert!(!prepare_state(&root, &[]).status.success());
    assert_eq!(fs::read_to_string(victim.join("keep")).unwrap(), "precious");
    fs::remove_file(root.join("state")).unwrap();
    good_dir(&root.join("state/fails"), 0o700);
    fs::write(root.join("state/fails/keep"), "retain").unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!prepare_state(&root, &[]).status.success());
    assert_eq!(
        fs::read_to_string(root.join("state/fails/keep")).unwrap(),
        "retain"
    );
}

#[test]
fn state_failure_symlink_unlinks_only_itself_and_untrusted_owner_is_refused() {
    let d = tmpdir();
    let root = d.join("root");
    assert!(prepare_state(&root, &[]).status.success());
    let victim = d.join("victim");
    fs::write(&victim, "precious").unwrap();
    symlink(&victim, root.join("state/fails")).unwrap();
    assert!(prepare_state(&root, &[]).status.success());
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert!(
        !prepare_state(&root, &[("VIGIE_TRUSTED_UID", (me().0 + 1).to_string())])
            .status
            .success()
    );
}

#[test]
fn watchdog_signal_failure_is_returned_to_operator() {
    let d = tmpdir();
    let ld = d.join("vigie");
    good_dir(&ld, 0o751);
    let log = ld.join("dnsmasq.log");
    fs::write(&log, vec![b'x'; 15]).unwrap();
    let out = watchdog(&log, "10", &[("VIGIE_SIGNAL_CMD", "exit 37".into())]);
    assert_eq!(out.status.code(), Some(37), "{}", err(&out));
    assert_eq!(
        fs::read(ld.join("dnsmasq.log.1")).unwrap().len(),
        15,
        "rotated evidence retained"
    );
}
