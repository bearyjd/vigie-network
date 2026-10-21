//! Source-address filtering: only on-link neighbors are parsed; our own packets are counted apart.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Own,
    OffLink,
}

#[derive(Debug, Clone)]
pub struct Filter {
    pub lan: Ipv4Addr,
    pub prefix: u8,
    pub own_v6: Vec<Ipv6Addr>,
    /// Single-host testing only: treat our own packets as a peer's.
    pub include_own: bool,
}

pub fn classify_v4(src: Ipv4Addr, lan: Ipv4Addr, prefix: u8) -> Verdict {
    if src == lan {
        return Verdict::Own;
    }
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix.min(32)))
        .unwrap_or(0);
    if u32::from(src) & mask == u32::from(lan) & mask {
        Verdict::Accept
    } else {
        Verdict::OffLink
    }
}

pub fn classify_v6(src: &SocketAddrV6, own: &[Ipv6Addr]) -> Verdict {
    let ip = src.ip();
    if own.contains(ip) {
        Verdict::Own
    } else if ip.segments()[0] & 0xFFC0 == 0xFE80 {
        Verdict::Accept
    } else {
        Verdict::OffLink
    }
}

/// Link-local addresses of `iface` from the text of /proc/net/if_inet6.
pub fn parse_if_inet6(text: &str, iface: &str) -> Vec<Ipv6Addr> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let [addr, _idx, _plen, scope, _flags, name] = f[..] else {
                return None;
            };
            (name == iface && scope == "20" && addr.len() == 32)
                .then(|| u128::from_str_radix(addr, 16).ok().map(Ipv6Addr::from))?
        })
        .collect()
}

impl Filter {
    pub fn verdict(&self, src: &SocketAddr) -> Verdict {
        let v = match src {
            SocketAddr::V4(a) => classify_v4(*a.ip(), self.lan, self.prefix),
            SocketAddr::V6(a) => classify_v6(a, &self.own_v6),
        };
        if self.include_own && v == Verdict::Own {
            Verdict::Accept
        } else {
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> SocketAddrV6 {
        SocketAddrV6::new(s.parse().unwrap(), 5353, 0, 4)
    }

    #[test]
    fn v4_on_link_off_link_and_own() {
        let lan = v4("192.168.1.1");
        assert_eq!(classify_v4(v4("192.168.1.50"), lan, 24), Verdict::Accept);
        assert_eq!(classify_v4(v4("192.168.1.1"), lan, 24), Verdict::Own);
        assert_eq!(classify_v4(v4("192.168.2.5"), lan, 24), Verdict::OffLink);
        assert_eq!(classify_v4(v4("10.0.0.1"), lan, 24), Verdict::OffLink);
        assert_eq!(classify_v4(v4("0.0.0.0"), lan, 24), Verdict::OffLink);
    }

    #[test]
    fn v4_prefix_boundaries() {
        let lan = v4("192.168.1.1");
        assert_eq!(classify_v4(v4("192.168.1.255"), lan, 24), Verdict::Accept);
        assert_eq!(classify_v4(v4("192.168.0.255"), lan, 24), Verdict::OffLink);
        assert_eq!(classify_v4(v4("192.168.200.5"), lan, 16), Verdict::Accept);
        assert_eq!(classify_v4(v4("192.169.0.5"), lan, 16), Verdict::OffLink);
        assert_eq!(classify_v4(v4("192.168.1.2"), lan, 32), Verdict::OffLink);
        assert_eq!(classify_v4(v4("192.168.1.1"), lan, 32), Verdict::Own);
        assert_eq!(classify_v4(v4("192.168.1.0"), lan, 31), Verdict::Accept);
        assert_eq!(classify_v4(v4("192.168.1.2"), lan, 31), Verdict::OffLink);
        assert_eq!(classify_v4(v4("1.2.3.4"), lan, 0), Verdict::Accept);
    }

    #[test]
    fn v6_requires_link_local_and_flags_own() {
        let own = ["fe80::1".parse().unwrap()];
        assert_eq!(classify_v6(&v6("fe80::abcd"), &own), Verdict::Accept);
        assert_eq!(classify_v6(&v6("fe80::1"), &own), Verdict::Own);
        assert_eq!(classify_v6(&v6("2001:db8::1"), &own), Verdict::OffLink);
        assert_eq!(classify_v6(&v6("fd00::1"), &own), Verdict::OffLink);
        // fe80::/10 spans fe80..=febf
        assert_eq!(classify_v6(&v6("febf::1"), &own), Verdict::Accept);
        assert_eq!(classify_v6(&v6("fec0::1"), &own), Verdict::OffLink);
        assert_eq!(classify_v6(&v6("fe7f::1"), &own), Verdict::OffLink);
    }

    #[test]
    fn filter_dispatches_by_family() {
        let f = Filter {
            lan: v4("192.168.1.1"),
            prefix: 24,
            own_v6: vec!["fe80::1".parse().unwrap()],
            include_own: false,
        };
        assert_eq!(
            f.verdict(&"192.168.1.9:5353".parse().unwrap()),
            Verdict::Accept
        );
        assert_eq!(
            f.verdict(&"192.168.5.9:5353".parse().unwrap()),
            Verdict::OffLink
        );
        assert_eq!(f.verdict(&"[fe80::1]:5353".parse().unwrap()), Verdict::Own);
    }

    #[test]
    fn include_own_turns_own_into_accept_but_not_off_link() {
        let f = Filter {
            lan: v4("192.168.1.1"),
            prefix: 24,
            own_v6: vec!["fe80::1".parse().unwrap()],
            include_own: true,
        };
        assert_eq!(
            f.verdict(&"192.168.1.1:5353".parse().unwrap()),
            Verdict::Accept
        );
        assert_eq!(
            f.verdict(&"[fe80::1]:5353".parse().unwrap()),
            Verdict::Accept
        );
        assert_eq!(
            f.verdict(&"10.0.0.1:5353".parse().unwrap()),
            Verdict::OffLink
        );
    }

    #[test]
    fn if_inet6_keeps_only_link_local_of_the_named_interface() {
        let text = "\
fe800000000000000000000000000001 04 40 20 80 br-lan
fd123456789a00000000000000000001 04 40 00 80 br-lan
fe80000000000000aaaabbbbccccdddd 05 40 20 80 eth0
20010db8000000000000000000000001 04 40 00 80 br-lan
garbage line
";
        assert_eq!(
            parse_if_inet6(text, "br-lan"),
            vec!["fe80::1".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(parse_if_inet6(text, "nope"), Vec::<Ipv6Addr>::new());
    }
}
