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
