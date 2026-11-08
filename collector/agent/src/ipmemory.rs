//! Last-known IP -> MAC memory, so a flow that outlives its neighbor-table entry is still
//! attributed (IPv6 ULA / link-local sources of real LAN devices expire from the table while
//! their conntrack flow lives on).
//!
//! IPv6 only: IPv4 addresses are reused by DHCP, so a remembered IPv4 pairing could bill a new
//! device's traffic to the old one; the attribution gaps this fixes are IPv6 ULA / link-local
//! sources. An address the current table reports FAILED or INCOMPLETE is never served either.
//!
//! Rules: the CURRENT table always wins and replaces the remembered MAC (an address that moved to
//! another device is never billed to the old one); a remembered entry is used only for an address
//! the current table lacks, and only within `IP_MEMORY_TTL_S` of the last time the table mapped
//! it. At most `IP_MEMORY_CAP` entries are held; the least recently seen are evicted.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

/// How long (monotonic seconds) a remembered pairing may attribute traffic after the table
/// last held it.
pub const IP_MEMORY_TTL_S: u64 = 2 * 3600;
/// Hard bound on remembered pairings.
pub const IP_MEMORY_CAP: usize = 4096;

#[derive(Debug, Default)]
pub struct IpMemory {
    /// ip -> (mac, monotonic second last seen in the table, store order)
    entries: HashMap<String, (String, u64, u64)>,
    seq: u64,
}

impl IpMemory {
    /// Records every pairing of the current table; drops expired entries; enforces the cap.
    pub fn observe(&mut self, current: &HashMap<String, String>, mono_s: u64) {
        self.entries
            .retain(|_, (_, seen, _)| mono_s.saturating_sub(*seen) <= IP_MEMORY_TTL_S);
        for (ip, mac) in current
            .iter()
            .filter(|(ip, _)| ip.parse::<Ipv6Addr>().is_ok())
        {
            self.seq += 1;
            self.entries
                .insert(ip.clone(), (mac.clone(), mono_s, self.seq));
        }
        if self.entries.len() > IP_MEMORY_CAP {
            let mut order: Vec<(u64, String)> = self
                .entries
                .iter()
                .map(|(ip, (_, _, q))| (*q, ip.clone()))
                .collect();
            order.sort_unstable();
            let excess = self.entries.len() - IP_MEMORY_CAP;
            for (_, ip) in order.into_iter().take(excess) {
                self.entries.remove(&ip);
            }
        }
    }

    /// The current table plus the unexpired remembered pairings it does not hold.
    pub fn overlay(
        &self,
        current: &HashMap<String, String>,
        failed: &HashSet<String>,
        mono_s: u64,
    ) -> HashMap<String, String> {
        let mut out = current.clone();
        for (ip, (mac, seen, _)) in &self.entries {
            if mono_s.saturating_sub(*seen) <= IP_MEMORY_TTL_S
                && !out.contains_key(ip)
                && !failed.contains(ip)
            {
                out.insert(ip.clone(), mac.clone());
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
