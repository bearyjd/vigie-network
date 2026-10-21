//! dnsmasq `dhcp.leases` parser: `<expiry> <mac> <ip> <hostname|*> <client-id|*>` per line.
//! IPv6 lease lines (`<expiry> <iaid> <ipv6> ...`) and `duid` lines are skipped (no MAC).

use crate::model::Lease;

pub fn parse_leases(text: &str) -> Vec<Lease> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Lease> {
    let mut it = line.split_whitespace();
    let expiry = it.next()?;
    if expiry.parse::<u64>().is_err() {
        return None;
    }
    let mac = it.next()?;
    let ip = it.next()?;
    let host = it.next().filter(|h| *h != "*");
    Lease::new(mac, ip, host, &[], None)
}
