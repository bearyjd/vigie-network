//! The router's own addresses, so unmapped conntrack traffic they originate is counted as
//! expected (`ct_unmapped_*`) instead of as an attribution failure (`ct_lan_unmapped_*`).
//!
//! Read with std only: `/proc/net/fib_trie` (local IPv4) and `/proc/net/if_inet6` (IPv6), plus the
//! configured LAN address. Any read failure yields an EMPTY set: nothing is hidden, the traffic
//! falls into the suspect counter.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Monotonic seconds between re-reads of the router's addresses.
pub const OWN_REFRESH_S: u64 = 300;

/// IPv4 addresses the kernel lists as `host LOCAL` in `/proc/net/fib_trie`.
pub fn parse_fib_trie(text: &str) -> Vec<Ipv4Addr> {
    let mut last: Option<Ipv4Addr> = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(a) = t.strip_prefix("|-- ") {
            last = a.trim().parse().ok();
        } else if t.contains("host LOCAL") {
            out.extend(last.take());
        }
    }
    out
}

/// IPv6 addresses of `/proc/net/if_inet6` (first field: 32 hex digits).
pub fn parse_if_inet6(text: &str) -> Vec<Ipv6Addr> {
    text.lines()
        .filter_map(|l| {
            let h = l.split_whitespace().next()?;
            let v = u128::from_str_radix(h, 16).ok().filter(|_| h.len() == 32)?;
            Some(Ipv6Addr::from(v))
        })
        .collect()
}

/// The router's addresses from procfs; `None` when either file cannot be read.
pub fn read_local() -> Option<HashSet<IpAddr>> {
    let v4 = std::fs::read_to_string("/proc/net/fib_trie").ok()?;
    let v6 = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    Some(
        parse_fib_trie(&v4)
            .into_iter()
            .map(IpAddr::V4)
            .chain(parse_if_inet6(&v6).into_iter().map(IpAddr::V6))
            .collect(),
    )
}

/// The cached set and when to re-read it. `Default` has no reader: the set stays empty.
#[derive(Debug, Default)]
pub struct OwnAddrs {
    lan: Option<IpAddr>,
    read: Option<fn() -> Option<HashSet<IpAddr>>>,
    set: HashSet<IpAddr>,
    last: Option<u64>,
}

impl OwnAddrs {
    pub fn new(lan: Ipv4Addr, read: fn() -> Option<HashSet<IpAddr>>) -> Self {
        Self {
            lan: Some(IpAddr::V4(lan)),
            read: Some(read),
            ..Self::default()
        }
    }

    /// Re-reads when `OWN_REFRESH_S` passed. A failed read empties the set (fail towards suspect).
    pub fn refresh(&mut self, mono_s: u64) {
        let Some(read) = self.read else { return };
        if self
            .last
            .is_some_and(|t| mono_s.saturating_sub(t) < OWN_REFRESH_S)
        {
            return;
        }
        self.last = Some(mono_s);
        self.set = read()
            .map(|mut s| {
                s.extend(self.lan);
                s
            })
            .unwrap_or_default();
    }

    pub fn set(&self) -> &HashSet<IpAddr> {
        &self.set
    }
}
