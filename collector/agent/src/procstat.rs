//! Facts about this process from `/proc/self/status`: resident set size (health block) and the
//! effective uid (std has no `geteuid` and the agent forbids `unsafe`).

pub fn parse_vm_rss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

/// Effective uid: the second field of the `Uid:` line (real, effective, saved, filesystem).
pub fn parse_euid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

pub fn read_status() -> Option<String> {
    std::fs::read_to_string("/proc/self/status").ok()
}

/// Why this process must not start, or `None`. The agent holds the HMAC key and parses
/// attacker-influenced log text, so effective root is refused unless `allow_root` (tests only).
/// An unreadable or unparseable status fails closed.
pub fn root_refusal(status: Option<&str>, allow_root: bool) -> Option<String> {
    if allow_root {
        return None;
    }
    match status.and_then(parse_euid) {
        Some(0) => Some(
            "refusing to run as root (euid 0); run as the dedicated `vigie` user \
             (--allow-root exists for tests only)"
                .into(),
        ),
        Some(_) => None,
        None => Some(
            "cannot determine the effective uid from /proc/self/status; refusing to start \
             (--allow-root exists for tests only)"
                .into(),
        ),
    }
}

pub fn read_rss_kb() -> Option<u64> {
    read_status().as_deref().and_then(parse_vm_rss_kb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vmrss() {
        assert_eq!(
            parse_vm_rss_kb("Name:\tx\nVmRSS:\t    468 kB\nThreads:\t1\n"),
            Some(468)
        );
        assert_eq!(parse_vm_rss_kb("VmRSS: lots"), None);
        assert_eq!(parse_vm_rss_kb(""), None);
    }
}
