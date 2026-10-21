//! dnsmasq drop-in verification and DNS-log health.
//!
//! The unprivileged collector cannot write `/tmp/dnsmasq.d` or reload dnsmasq: the root-run
//! `deploy/vigie-dnsmasq-dropin.sh ensure` does that (at service start and from cron). The agent
//! only verifies the drop-in periodically (it is world-readable) and reports trouble through
//! the `dns_log_quiet` health flag. The content below must equal what the script writes (a test
//! runs the script and compares).

pub const DROPIN_PATH: &str = "/tmp/dnsmasq.d/vigie.conf";
pub const LOG_DIR: &str = "/tmp/vigie";
/// Consecutive 60 s windows with flows but no DNS queries before `dns_log_quiet` is raised.
pub const QUIET_WINDOWS: u32 = 5;

pub fn dropin_content(log_dir: &str) -> String {
    format!("log-queries=extra\nlog-dhcp\nlog-facility={log_dir}/dnsmasq.log\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropinState {
    Ok,
    Missing,
    Differs,
}

/// `current` is the drop-in file content, or `None` if it does not exist.
pub fn check_dropin(current: Option<&str>, log_dir: &str) -> DropinState {
    match current {
        None => DropinState::Missing,
        Some(c) if c.replace("\r\n", "\n") == dropin_content(log_dir) => DropinState::Ok,
        Some(_) => DropinState::Differs,
    }
}

/// Raises `dns_log_quiet` when the DNS log is not delivering queries: the drop-in is gone or
/// wrong (GL.iNet reload), or flows exist but no query appeared for `QUIET_WINDOWS` windows
/// (e.g. AdGuard Home took over DNS). An idle network (no flows) is not "quiet".
#[derive(Debug, Default)]
pub struct QuietDetector {
    quiet_windows: u32,
}

impl QuietDetector {
    pub fn observe(&mut self, queries: usize, flows: u64, dropin: DropinState) -> bool {
        if queries > 0 {
            self.quiet_windows = 0;
        } else if flows > 0 {
            self.quiet_windows = self.quiet_windows.saturating_add(1);
        } else {
            self.quiet_windows = 0;
        }
        dropin != DropinState::Ok || self.quiet_windows >= QUIET_WINDOWS
    }
}
