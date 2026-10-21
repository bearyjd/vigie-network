//! Per-run counters and bounded evidence sets.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use vigie_parse::{mdns, ssdp};

use crate::evidence::Evidence;
use crate::filter::{Filter, Verdict};

#[derive(Default)]
pub struct Stats {
    pub mdns4_packets: u64,
    pub mdns6_packets: u64,
    pub ssdp_packets: u64,
    pub own_packets: u64,
    pub offlink_packets: u64,
    pub read_errors: u64,
    pub parse_errors: u64,
    pub mdns_truncated: u64,
    pub mdns_names: BTreeSet<String>,
    pub mdns_services: BTreeSet<String>,
    pub ssdp_servers: BTreeSet<String>,
    pub ssdp_nt: BTreeSet<String>,
    pub ssdp_usn: BTreeSet<String>,
    pub ssdp_methods: BTreeMap<&'static str, u64>,
    pub evidence: Evidence,
}

impl Stats {
    /// Count and reject own / off-link sources; true when the packet may be parsed.
    fn gate(&mut self, f: &Filter, src: &SocketAddr) -> bool {
        match f.verdict(src) {
            Verdict::Accept => true,
            Verdict::Own => {
                self.own_packets += 1;
                false
            }
            Verdict::OffLink => {
                self.offlink_packets += 1;
                false
            }
        }
    }

    pub fn on_mdns(&mut self, f: &Filter, src: SocketAddr, pkt: &[u8]) {
        if !self.gate(f, &src) {
            return;
        }
        let ip = src.ip();
        match mdns::parse(pkt) {
            Ok(p) => {
                self.mdns_truncated += u64::from(p.truncated);
                for n in p.names {
                    self.evidence.admit(ip, &mut self.mdns_names, n);
                }
                for n in p.services {
                    self.evidence.admit(ip, &mut self.mdns_services, n);
                }
            }
            Err(_) => self.parse_errors += 1,
        }
    }

    pub fn on_ssdp(&mut self, f: &Filter, src: SocketAddr, pkt: &[u8]) {
        if !self.gate(f, &src) {
            return;
        }
        let ip = src.ip();
        let Ok(p) = ssdp::parse(pkt) else {
            self.parse_errors += 1;
            return;
        };
        let m = match p.method {
            ssdp::Method::Notify => "NOTIFY",
            ssdp::Method::MSearch => "M-SEARCH",
        };
        *self.ssdp_methods.entry(m).or_insert(0) += 1;
        let items = [
            (&mut self.ssdp_servers, p.server.or(p.user_agent)),
            (&mut self.ssdp_nt, p.nt.or(p.st)),
            (&mut self.ssdp_usn, p.usn),
        ];
        for (set, v) in items {
            if let Some(v) = v {
                self.evidence.admit(ip, set, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> Filter {
        Filter {
            lan: "192.168.1.1".parse().unwrap(),
            prefix: 24,
            own_v6: vec!["fe80::1".parse().unwrap()],
            include_own: false,
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// One-question mDNS query for `label` (single label, < 64 bytes).
    fn query(labels: &[&str]) -> Vec<u8> {
        let mut p = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in labels {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.extend_from_slice(&[0, 0, 12, 0, 1]);
        p
    }

    const NOTIFY: &str =
        "NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:a\r\nSERVER: S/1\r\n\r\n";

    #[test]
    fn on_link_mdns_is_parsed() {
        let mut s = Stats::default();
        s.on_mdns(
            &filter(),
            addr("192.168.1.50:5353"),
            &query(&["_airplay", "_tcp", "local"]),
        );
        assert!(s.mdns_names.contains("_airplay._tcp.local"));
        assert!(s.mdns_services.contains("_airplay._tcp.local"));
        assert_eq!(
            (s.own_packets, s.offlink_packets, s.parse_errors),
            (0, 0, 0)
        );
    }

    #[test]
    fn off_link_and_own_mdns_are_counted_not_parsed() {
        let mut s = Stats::default();
        let q = query(&["x", "local"]);
        s.on_mdns(&filter(), addr("10.0.0.9:5353"), &q);
        s.on_mdns(&filter(), addr("192.168.1.1:5353"), &q);
        s.on_mdns(&filter(), addr("[2001:db8::5]:5353"), &q);
        s.on_mdns(&filter(), addr("[fe80::1]:5353"), &q);
        assert!(s.mdns_names.is_empty());
        assert_eq!((s.offlink_packets, s.own_packets), (2, 2));
    }

    #[test]
    fn link_local_v6_mdns_is_parsed() {
        let mut s = Stats::default();
        s.on_mdns(&filter(), addr("[fe80::77]:5353"), &query(&["h", "local"]));
        assert!(s.mdns_names.contains("h.local"));
    }

    #[test]
    fn ssdp_is_filtered_like_mdns() {
        let mut s = Stats::default();
        s.on_ssdp(&filter(), addr("172.16.0.4:1900"), NOTIFY.as_bytes());
        assert_eq!((s.offlink_packets, s.ssdp_methods.len()), (1, 0));
        s.on_ssdp(&filter(), addr("192.168.1.50:1900"), NOTIFY.as_bytes());
        assert_eq!(s.ssdp_methods.get("NOTIFY"), Some(&1));
        assert!(s.ssdp_servers.contains("S/1"));
        assert!(s.ssdp_nt.contains("upnp:rootdevice"));
        assert!(s.ssdp_usn.contains("uuid:a"));
    }

    #[test]
    fn one_source_cannot_exceed_its_quota() {
        let mut s = Stats::default();
        for i in 0..20 {
            let label = format!("h{i}");
            s.on_mdns(
                &filter(),
                addr("192.168.1.66:5353"),
                &query(&[&label, "local"]),
            );
        }
        assert_eq!(s.mdns_names.len(), crate::evidence::PER_SOURCE);
        assert_eq!(s.evidence.dropped, 4);
    }

    #[test]
    fn truncated_and_malformed_packets_are_counted() {
        let mut s = Stats::default();
        let mut big = vec![0, 0, 0, 0, 0x01, 0xF4, 0, 0, 0, 0, 0, 0]; // 500 questions declared
        for _ in 0..500 {
            big.extend_from_slice(&[1, b'a', 0, 0, 12, 0, 1]);
        }
        s.on_mdns(&filter(), addr("192.168.1.50:5353"), &big);
        s.on_mdns(&filter(), addr("192.168.1.50:5353"), &[1, 2, 3]);
        s.on_ssdp(
            &filter(),
            addr("192.168.1.50:1900"),
            b"GET / HTTP/1.1\r\n\r\n",
        );
        assert_eq!((s.mdns_truncated, s.parse_errors), (1, 2));
    }
}
