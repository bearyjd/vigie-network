//! Third review items 4-8: watchdog ownership of the new log, allowed owners, pid discovery,
//! the VIGIE_TEST gate, and procd respawn limits. Shell scripts run unprivileged under the
//! `VIGIE_TEST=1` hooks; `chown`, `stat`, `id`, `ubus`, `pidof` and `logger` are stubs on PATH.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn script(name: &str) -> String {
    format!("{}/deploy/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn me() -> (u32, u32) {
    let m = fs::metadata("/proc/self").unwrap();
    (m.uid(), m.gid())
}

fn real(cmd: &str) -> String {
    let o = Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

/// A scratch world: log dir, fake /proc, fake /var/run/dnsmasq, stub bin dir, syslog capture.
struct World {
    d: PathBuf,
    log: PathBuf,
}

impl World {
    fn new() -> Self {
        let d = std::env::temp_dir().join(format!(
            "vigie-r4d-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(d.join("logs")).unwrap();
        fs::set_permissions(d.join("logs"), fs::Permissions::from_mode(0o751)).unwrap();
        for sub in ["bin", "proc", "run"] {
            fs::create_dir_all(d.join(sub)).unwrap();
        }
        let w = World {
            log: d.join("logs/dnsmasq.log"),
            d,
        };
        w.stub("logger", &format!("echo \"$*\" >> '{}'", w.syslog_path().display()));
        w.stub("chown", &format!("echo \"$*\" >> '{}'", w.chown_path().display()));
        w.stub("pidof", "exit 1");
        w.stub("ubus", "exit 1");
        w
    }
    fn syslog_path(&self) -> PathBuf {
        self.d.join("syslog")
    }
    fn chown_path(&self) -> PathBuf {
        self.d.join("chownlog")
    }
    fn syslog(&self) -> String {
        fs::read_to_string(self.syslog_path()).unwrap_or_default()
    }
    fn chowned(&self) -> String {
        fs::read_to_string(self.chown_path()).unwrap_or_default()
    }
    fn stub(&self, name: &str, body: &str) {
        let p = self.d.join("bin").join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn proc_pid(&self, pid: u32, uid: u32) {
        let p = self.d.join("proc").join(pid.to_string());
        fs::create_dir_all(&p).unwrap();
        fs::write(
            p.join("status"),
            format!("Name:\tdnsmasq\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t0\t0\t0\t0\n"),
        )
        .unwrap();
    }
    fn pidfile(&self, name: &str, pid: u32) {
        fs::write(self.d.join("run").join(name), format!("{pid}\n")).unwrap();
    }
    fn fill(&self, n: usize) {
        fs::write(&self.log, vec![b'x'; n]).unwrap();
    }
    fn watchdog(&self, signal: &str, extra: &[(&str, String)]) -> Output {
        let (uid, gid) = me();
        let mut c = Command::new("sh");
        c.arg(script("vigie-log-watchdog.sh"))
            .env("PATH", format!("{}:{}", self.d.join("bin").display(), std::env::var("PATH").unwrap()))
            .env("VIGIE_TEST", "1")
            .env("VIGIE_TRUSTED_UID", uid.to_string())
            .env("VIGIE_OWNER", format!("{uid}:{gid}"))
            .env("VIGIE_LOG_FILE", &self.log)
            .env("VIGIE_LOG_MAX_BYTES", "100")
            .env("VIGIE_SIGNAL_CMD", signal)
            .env("VIGIE_PROC_DIR", self.d.join("proc"))
            .env("VIGIE_RUN_DIR", self.d.join("run"))
            .env("VIGIE_WAIT_SECS", "1");
        for (k, v) in extra {
            c.env(k, v);
        }
        c.output().unwrap()
    }
    fn rotated(&self) -> bool {
        self.log.with_extension("log.1").exists()
    }
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---- item 4: the new log belongs to the uid dnsmasq runs as ----

#[test]
fn new_log_is_chowned_to_the_resolved_dnsmasq_uid_with_group_vigie_and_mode_0640() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.cfg01.pid", 1234);
    w.fill(150);
    let o = w.watchdog("true", &[]);
    assert!(o.status.success(), "{}", err(&o));
    let (_, gid) = me();
    assert!(
        w.chowned().contains(&format!("4242:{gid}")),
        "chown args: {:?}",
        w.chowned()
    );
    assert_eq!(fs::metadata(&w.log).unwrap().permissions().mode() & 0o7777, 0o640);
    assert!(w.rotated());
}

#[test]
fn uid_zero_is_refused_warned_and_nothing_is_rotated() {
    let w = World::new();
    w.proc_pid(1234, 0);
    w.pidfile("dnsmasq.cfg01.pid", 1234);
    w.fill(150);
    let o = w.watchdog("true", &[]);
    assert!(!o.status.success());
    assert!(!w.rotated(), "old file kept, no rotation");
    assert_eq!(fs::metadata(&w.log).unwrap().len(), 150);
    assert!(w.syslog().contains("uid 0"), "{:?}", w.syslog());
    assert!(w.chowned().is_empty());
}

#[test]
fn an_unresolvable_uid_is_refused_warned_and_nothing_is_rotated() {
    let w = World::new();
    w.fill(150); // no pid source at all
    let o = w.watchdog("true", &[]);
    assert!(!o.status.success());
    assert!(!w.rotated());
    assert!(w.syslog().contains("vigie"), "warned: {:?}", w.syslog());
    // A pid whose status has no usable Uid line is unresolved too.
    let w = World::new();
    w.pidfile("dnsmasq.cfg01.pid", 77);
    fs::create_dir_all(w.d.join("proc/77")).unwrap();
    fs::write(w.d.join("proc/77/status"), "Name:\tdnsmasq\n").unwrap();
    w.fill(150);
    assert!(!w.watchdog("true", &[]).status.success());
    assert!(!w.rotated());
}

#[test]
fn a_real_uid_that_differs_from_the_effective_uid_is_unresolved() {
    let w = World::new();
    let p = w.d.join("proc/55");
    fs::create_dir_all(&p).unwrap();
    fs::write(p.join("status"), "Uid:\t0\t4242\t4242\t4242\n").unwrap();
    w.pidfile("dnsmasq.x.pid", 55);
    w.fill(150);
    assert!(!w.watchdog("true", &[]).status.success());
    assert!(!w.rotated());
}

#[test]
fn an_empty_new_log_after_the_signal_while_the_old_one_grew_is_warned_about() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    let old = w.log.with_extension("log.1");
    // dnsmasq ignored SIGUSR2: it keeps writing to the renamed file.
    let o = w.watchdog(&format!("echo more >> '{}'", old.display()), &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(w.syslog().contains("still empty"), "{:?}", w.syslog());
}

#[test]
fn no_warning_when_dnsmasq_writes_to_the_new_log() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    let o = w.watchdog(&format!("echo line >> '{}'", w.log.display()), &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(!w.syslog().contains("still empty"), "{:?}", w.syslog());
    // Quiet router: new file empty but the old one did not grow either: no warning.
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    assert!(w.watchdog("true", &[]).status.success());
    assert!(!w.syslog().contains("still empty"), "{:?}", w.syslog());
}

// ---- item 5: only root and the resolved dnsmasq uid may own the log ----

fn owner_stub(w: &World, uid: u32) {
    let real_stat = real("stat");
    w.stub(
        "stat",
        &format!("case \"$*\" in \"-c %u \"*dnsmasq.log) echo {uid};; *) exec {real_stat} \"$@\";; esac"),
    );
}

#[test]
fn a_log_owned_by_neither_root_nor_the_dnsmasq_uid_is_refused() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    owner_stub(&w, 31337);
    let o = w.watchdog("true", &[]);
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert!(!w.rotated());
}

#[test]
fn nobody_is_not_implicitly_allowed() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    owner_stub(&w, 31337);
    let real_id = real("id");
    w.stub(
        "id",
        &format!("case \"$*\" in \"-u nobody\"|\"-u dnsmasq\") echo 31337;; *) exec {real_id} \"$@\";; esac"),
    );
    let o = w.watchdog("true", &[]);
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert!(!w.rotated());
}

#[test]
fn a_log_owned_by_the_resolved_dnsmasq_uid_is_accepted() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.fill(150);
    owner_stub(&w, 4242);
    let o = w.watchdog("true", &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(w.rotated());
}

// ---- item 6: pid discovery order ----

#[test]
fn the_procd_instance_pid_wins_over_pidfiles_and_pidof() {
    let w = World::new();
    w.proc_pid(2000, 4242);
    w.proc_pid(1234, 1111);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.stub("pidof", "echo 1234");
    w.stub(
        "ubus",
        "echo '{ \"dnsmasq\": { \"instances\": { \"cfg01\": { \"running\": true, \"pid\": 2000 } } } }'",
    );
    w.fill(150);
    assert!(w.watchdog("true", &[]).status.success());
    assert!(w.chowned().contains("4242:"), "{:?}", w.chowned());
}

#[test]
fn a_pidfile_wins_over_pidof() {
    let w = World::new();
    w.proc_pid(1234, 4242);
    w.proc_pid(5555, 1111);
    w.pidfile("dnsmasq.x.pid", 1234);
    w.stub("pidof", "echo 5555");
    w.fill(150);
    assert!(w.watchdog("true", &[]).status.success());
    assert!(w.chowned().contains("4242:"), "{:?}", w.chowned());
}

#[test]
fn pidof_is_the_fallback_only_for_exactly_one_pid() {
    let w = World::new();
    w.proc_pid(7777, 4242);
    w.stub("pidof", "echo 7777");
    w.fill(150);
    assert!(w.watchdog("true", &[]).status.success());
    assert!(w.chowned().contains("4242:"));

    let w = World::new();
    w.proc_pid(7777, 4242);
    w.proc_pid(8888, 4242);
    w.stub("pidof", "echo 7777 8888");
    w.fill(150);
    assert!(!w.watchdog("true", &[]).status.success());
    assert!(!w.rotated(), "multiple matches: refuse");
}

#[test]
fn multiple_procd_or_pidfile_matches_are_refused() {
    let w = World::new();
    w.proc_pid(1, 4242);
    w.proc_pid(2, 4242);
    w.pidfile("dnsmasq.a.pid", 1);
    w.pidfile("dnsmasq.b.pid", 2);
    w.fill(150);
    assert!(!w.watchdog("true", &[]).status.success());
    assert!(!w.rotated());
}

// ---- item 7: the VIGIE_TEST gate ----

fn gate_run(w: &World, extra: &[(&str, String)]) -> Output {
    let initd = w.d.join("initd");
    fs::write(&initd, "").unwrap();
    let real_id = real("id");
    w.stub("id", &format!("[ \"$*\" = '-u' ] && echo 0 || exec {real_id} \"$@\""));
    let mut envs = vec![("VIGIE_INITD_FILE", initd.display().to_string())];
    envs.extend(extra.iter().cloned());
    w.watchdog("true", &envs) // no log file: a permitted run exits 0
}

#[test]
fn vigie_test_is_refused_for_root_on_a_router() {
    let w = World::new();
    let o = gate_run(&w, &[]);
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert!(err(&o).contains("VIGIE_TEST"), "{}", err(&o));
}

#[test]
fn the_force_flag_lets_a_root_test_harness_through() {
    let w = World::new();
    let o = gate_run(&w, &[("VIGIE_TEST_FORCE_ROOT", "1".into())]);
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn root_without_the_init_script_is_not_a_router() {
    let w = World::new();
    let real_id = real("id");
    w.stub("id", &format!("[ \"$*\" = '-u' ] && echo 0 || exec {real_id} \"$@\""));
    let o = w.watchdog("true", &[("VIGIE_INITD_FILE", w.d.join("absent").display().to_string())]);
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn a_tmp_without_the_sticky_bit_is_refused() {
    let w = World::new();
    let t = w.d.join("fake-tmp");
    fs::create_dir_all(&t).unwrap();
    fs::set_permissions(&t, fs::Permissions::from_mode(0o777)).unwrap();
    let o = w.watchdog("true", &[("VIGIE_TMP_ROOT", t.display().to_string())]);
    assert_eq!(o.status.code(), Some(70), "{}", err(&o));
    assert!(err(&o).contains("sticky"), "{}", err(&o));
    fs::set_permissions(&t, fs::Permissions::from_mode(0o1777)).unwrap();
    let o = w.watchdog("true", &[("VIGIE_TMP_ROOT", t.display().to_string())]);
    assert!(o.status.success(), "{}", err(&o));
}

// ---- item 8: procd respawn limit and the wrapper that says why ----

#[test]
fn init_limits_respawns_and_runs_the_agent_through_the_wrapper() {
    let t = fs::read_to_string(script("vigie-collector.init")).unwrap();
    assert!(t.contains("respawn 3600 5 5"), "{t}");
    assert!(!t.contains("respawn 3600 5 0"));
    assert!(t.contains("vigie-run.sh"), "{t}");
}

fn run_wrapper(w: &World, exit: i32, runs: usize) {
    let fake = w.d.join("collector");
    fs::write(&fake, format!("#!/bin/sh\nexit {exit}\n")).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let state = w.d.join("state");
    fs::create_dir_all(&state).unwrap();
    for _ in 0..runs {
        let o = Command::new("sh")
            .arg(script("vigie-run.sh"))
            .arg("--config")
            .arg("x")
            .env("PATH", format!("{}:{}", w.d.join("bin").display(), std::env::var("PATH").unwrap()))
            .env("VIGIE_TEST", "1")
            .env("VIGIE_COLLECTOR_BIN", &fake)
            .env("VIGIE_RUN_STATE_DIR", &state)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(exit), "wrapper passes the exit code through");
    }
}

#[test]
fn the_wrapper_logs_giving_up_once_the_retry_limit_is_reached() {
    let w = World::new();
    run_wrapper(&w, 78, 4);
    assert!(!w.syslog().contains("giving up"), "{:?}", w.syslog());
    run_wrapper(&w, 78, 1);
    assert_eq!(w.syslog().matches("giving up").count(), 1, "{:?}", w.syslog());
}

#[test]
fn the_wrapper_stays_quiet_for_other_exit_codes() {
    let w = World::new();
    run_wrapper(&w, 1, 7);
    assert!(w.syslog().is_empty(), "{:?}", w.syslog());
}

#[allow(dead_code)]
fn _unused(_: &Path) {}
