//! `ip neigh` text parser (`ip -4 neigh` and `ip -6 neigh` output).
//!
//! Only entries with a link-layer address are kept, so FAILED / INCOMPLETE entries (which have
//! none, or a stale one) never attribute traffic. MACs are normalized to lowercase colon form.
//! An IPv6 host has several addresses (privacy addresses rotate), so every distinct `(ip, mac)`
//! pair is kept for attribution, and `distinct_macs` gives the per-device (deduped by MAC) view.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use crate::model::Neighbor;

pub fn parse_ip_neigh(text: &str) -> Vec<Neighbor> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(n) = parse_entry(line) else { continue };
        if seen.insert((n.ip.clone(), n.mac.clone())) {
            out.push(n);
        }
    }
    out
}

fn parse_entry(line: &str) -> Option<Neighbor> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let ip: IpAddr = toks.first()?.parse().ok()?;
    if ip.is_multicast() || ip.is_unspecified() {
        return None;
    }
    let at = toks.iter().position(|t| *t == "lladdr")?;
    let mac = toks.get(at + 1)?;
    let state = toks.last()?;
    if matches!(*state, "FAILED" | "INCOMPLETE") {
        return None;
    }
    let n = Neighbor::new(&ip.to_string(), mac)?;
    // A unicast host never has a group (multicast) MAC.
    let first_octet = u8::from_str_radix(&n.mac[0..2], 16).ok()?;
    if first_octet & 1 == 1 {
        return None;
    }
    Some(n)
}

/// Distinct MACs, sorted.
pub fn distinct_macs(n: &[Neighbor]) -> Vec<String> {
    n.iter()
        .map(|x| x.mac.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// IP address (canonical text) to MAC, for attributing flows and DNS queries.
pub fn ip_to_mac(n: &[Neighbor]) -> HashMap<String, String> {
    n.iter().map(|x| (x.ip.clone(), x.mac.clone())).collect()
}
