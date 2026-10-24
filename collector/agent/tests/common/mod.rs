//! Shared by the deploy-script tests: a fake /proc and pidfile so the watchdog can resolve "the
//! uid dnsmasq runs as" (this test process's own uid) without a real dnsmasq.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

pub fn fake_dnsmasq_env() -> Vec<(&'static str, String)> {
    let uid = fs::metadata("/proc/self").unwrap().uid();
    let d = std::env::temp_dir().join(format!(
        "vigie-fakeproc-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(d.join("proc/4321")).unwrap();
    fs::create_dir_all(d.join("run")).unwrap();
    fs::write(
        d.join("proc/4321/status"),
        format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )
    .unwrap();
    fs::write(d.join("run/dnsmasq.cfg01.pid"), "4321\n").unwrap();
    vec![
        ("VIGIE_PROC_DIR", d.join("proc").display().to_string()),
        ("VIGIE_RUN_DIR", d.join("run").display().to_string()),
        ("VIGIE_WAIT_SECS", "0".to_string()),
    ]
}

/// A premounted private-log fixture: kernel mount table and statfs are substituted, never mount.
/// Existing geometry is deliberately preserved so symlink/mode/ownership attacks reach guards.
pub fn fake_logfs_env(log_dir: &std::path::Path) -> Vec<(&'static str, String)> {
    use std::os::unix::fs::PermissionsExt;
    if fs::symlink_metadata(log_dir).is_err() {
        fs::create_dir(log_dir).unwrap();
        fs::set_permissions(log_dir, fs::Permissions::from_mode(0o751)).unwrap();
    }
    let d = std::env::temp_dir().join(format!(
        "vigie-fakemount-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir(&d).unwrap();
    fs::write(
        d.join("mountinfo"),
        format!(
            "20 1 0:42 / {} rw,nosuid,nodev,noexec - tmpfs vigie-logfs rw,size=20480k\n",
            log_dir.display()
        ),
    )
    .unwrap();
    fs::write(d.join("statfs"), "#!/bin/sh\nprintf '4096 5120\\n'\n").unwrap();
    fs::set_permissions(d.join("statfs"), fs::Permissions::from_mode(0o700)).unwrap();
    vec![
        ("VIGIE_LOGFS_DIR", log_dir.display().to_string()),
        (
            "VIGIE_LOGFS_MOUNTINFO",
            d.join("mountinfo").display().to_string(),
        ),
        (
            "VIGIE_LOGFS_STATFS_BIN",
            d.join("statfs").display().to_string(),
        ),
    ]
}
