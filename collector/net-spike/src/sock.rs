//! Multicast socket setup using socket2's safe API.

use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

const POLL: Duration = Duration::from_millis(50);
const RCVBUF: usize = 256 * 1024;

fn base(domain: Domain) -> io::Result<Socket> {
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    s.set_read_timeout(Some(POLL))?;
    s.set_recv_buffer_size(RCVBUF)?;
    Ok(s)
}

/// Bind to the group address itself (not 0.0.0.0) so unicast datagrams meant for avahi on the
/// same port are never delivered here, and clear IP_MULTICAST_ALL so only groups this socket
/// joined are delivered.
fn v4(group: Ipv4Addr, port: u16, lan: Ipv4Addr) -> io::Result<UdpSocket> {
    let s = base(Domain::IPV4)?;
    s.set_multicast_all_v4(false)?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(group, port)).into())?;
    s.join_multicast_v4(&group, &lan)?;
    // Receive-only socket: IP_MULTICAST_LOOP is a *send* option and is deliberately not set.
    Ok(s.into())
}

pub fn mdns_v4(lan: Ipv4Addr) -> io::Result<UdpSocket> {
    v4(Ipv4Addr::new(224, 0, 0, 251), 5353, lan)
}

pub fn ssdp_v4(lan: Ipv4Addr) -> io::Result<UdpSocket> {
    v4(Ipv4Addr::new(239, 255, 255, 250), 1900, lan)
}

fn ifindex(iface: &str) -> io::Result<u32> {
    if iface.is_empty() || iface.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad interface name",
        ));
    }
    fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))?
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ifindex: {e}")))
}

pub fn mdns_v6(iface: &str) -> io::Result<UdpSocket> {
    let idx = ifindex(iface)?;
    let s = base(Domain::IPV6)?;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
    s.set_only_v6(true)?;
    s.set_multicast_all_v6(false)?;
    s.bind(&SocketAddr::V6(SocketAddrV6::new(group, 5353, 0, idx)).into())?;
    s.join_multicast_v6(&group, idx)?;
    Ok(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockRef;

    fn common(s: &UdpSocket) {
        let r = SockRef::from(s);
        assert!(r.reuse_address().unwrap(), "SO_REUSEADDR");
        assert!(r.reuse_port().unwrap(), "SO_REUSEPORT");
        assert_eq!(s.read_timeout().unwrap(), Some(Duration::from_millis(50)));
        // we ask for 256 KiB; the kernel clamps to rmem_max and reports double, but never ~2 KiB
        assert!(r.recv_buffer_size().unwrap() >= 100_000, "SO_RCVBUF");
    }

    #[test]
    fn mdns_v4_binds_group_and_clears_multicast_all() {
        let s = mdns_v4(Ipv4Addr::UNSPECIFIED).unwrap();
        assert_eq!(s.local_addr().unwrap(), "224.0.0.251:5353".parse().unwrap());
        assert!(!SockRef::from(&s).multicast_all_v4().unwrap());
        common(&s);
    }

    #[test]
    fn ssdp_v4_binds_group_and_clears_multicast_all() {
        let s = ssdp_v4(Ipv4Addr::UNSPECIFIED).unwrap();
        assert_eq!(
            s.local_addr().unwrap(),
            "239.255.255.250:1900".parse().unwrap()
        );
        assert!(!SockRef::from(&s).multicast_all_v4().unwrap());
        common(&s);
    }

    /// A plain v6 multicast join on `idx`, independent of our code: tells us whether this
    /// environment can join at all, so a failure of `mdns_v6` is never mistaken for "no support".
    fn baseline_join_works(idx: u32) -> bool {
        let Ok(s) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) else {
            return false;
        };
        let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
        s.join_multicast_v6(&group, idx).is_ok()
    }

    /// The first interface where a plain join works. `mdns_v6` MUST then succeed on it.
    fn v6_socket() -> Option<(UdpSocket, u32)> {
        for e in fs::read_dir("/sys/class/net").ok()?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(idx) = ifindex(&name) else { continue };
            if !baseline_join_works(idx) {
                continue;
            }
            match mdns_v6(&name) {
                Ok(s) => return Some((s, idx)),
                Err(e) => panic!("mdns_v6({name}) failed although a plain join works: {e}"),
            }
        }
        None
    }

    #[test]
    fn mdns_v6_binds_scoped_group_and_clears_multicast_all() {
        let Some((s, idx)) = v6_socket() else {
            eprintln!("skipped: no interface accepts the ff02::fb join in this environment");
            return;
        };
        let want = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
            5353,
            0,
            idx,
        ));
        assert_eq!(s.local_addr().unwrap(), want);
        let r = SockRef::from(&s);
        assert!(!r.multicast_all_v6().unwrap());
        assert!(r.only_v6().unwrap());
        common(&s);
    }

    #[test]
    fn ifindex_rejects_path_tricks() {
        assert!(ifindex("").is_err());
        assert!(ifindex("../lo").is_err());
        assert!(ifindex("lo/../lo").is_err()); // resolves to a real file, so only the '/' check stops it
        assert!(ifindex("no-such-iface").is_err());
    }
}
