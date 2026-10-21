//! LAN classification of flow sources, used to give LAN and WAN sources separate record quotas.

use std::net::IpAddr;

/// An address prefix. The network part is stored already masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: u128,
    bits: u8,
    v6: bool,
}

fn addr_bits(ip: IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(a) => (u128::from(u32::from(a)), false),
        IpAddr::V6(a) => (u128::from(a), true),
    }
}

impl Cidr {
    /// `a.b.c.d/n` or `x::y/n`; a bare address is a host prefix.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr, len) = s.split_once('/').map_or((s, None), |(a, l)| (a, Some(l)));
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid network {s:?}: bad address"))?;
        let (raw, v6) = addr_bits(ip);
        let max = if v6 { 128 } else { 32 };
        let bits = match len {
            None => max,
            Some(l) => match l.parse::<u8>() {
                Ok(n) if n <= max => n,
                _ => return Err(format!("invalid network {s:?}: bad prefix length")),
            },
        };
        Ok(Cidr {
            net: raw & mask(bits, v6),
            bits,
            v6,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (raw, v6) = addr_bits(ip);
        v6 == self.v6 && raw & mask(self.bits, v6) == self.net
    }
}

/// Mask of the top `bits` bits of a 32 or 128 bit address held in a u128.
fn mask(bits: u8, v6: bool) -> u128 {
    let width: u32 = if v6 { 128 } else { 32 };
    if bits == 0 {
        0
    } else {
        (u128::MAX << (128 - u32::from(bits))) >> (128 - width)
    }
}

/// RFC1918, CGNAT, IPv4 and IPv6 link-local-or-ULA: what a home router usually serves.
pub fn default_lan() -> Vec<Cidr> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fe80::/10",
        "fc00::/7",
    ]
    .iter()
    .filter_map(|s| Cidr::parse(s).ok())
    .collect()
}

pub fn is_lan(lan: &[Cidr], ip: IpAddr) -> bool {
    lan.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_networks_classify_lan_sources() {
        let lan = default_lan();
        assert_eq!(lan.len(), 6, "every default parsed");
        for s in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.8.50",
            "100.64.0.1",
            "100.127.255.255",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::7",
        ] {
            assert!(is_lan(&lan, ip(s)), "{s}");
        }
        for s in [
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "192.169.0.1",
            "2001:db8::1",
            "fec0::1",
            "fb00::1",
            "fe00::1",
        ] {
            assert!(!is_lan(&lan, ip(s)), "{s}");
        }
    }

    #[test]
    fn prefix_edges_and_families_do_not_mix() {
        let all4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all4.contains(ip("8.8.8.8")) && !all4.contains(ip("::1")));
        let host = Cidr::parse("192.168.1.5").unwrap();
        assert!(host.contains(ip("192.168.1.5")) && !host.contains(ip("192.168.1.6")));
        let n = Cidr::parse("192.168.1.77/24").unwrap();
        assert!(n.contains(ip("192.168.1.1")) && !n.contains(ip("192.168.2.1")));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")) && !v6.contains(ip("2001:db9::1")));
        assert!(
            !v6.contains(ip("32.1.13.184")),
            "v4 never matches a v6 prefix"
        );
        assert!(Cidr::parse("::/0").unwrap().contains(ip("fe80::1")));
    }

    #[test]
    fn bad_networks_are_rejected() {
        for s in [
            "",
            "nope",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/-1",
            "10.0.0.0/x",
            "1.2.3/8",
        ] {
            assert!(Cidr::parse(s).is_err(), "{s:?}");
        }
    }
}
