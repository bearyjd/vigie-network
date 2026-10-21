//! Own resident set size from `/proc/self/status`, for the health block.

pub fn parse_vm_rss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

pub fn read_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .as_deref()
        .and_then(parse_vm_rss_kb)
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
