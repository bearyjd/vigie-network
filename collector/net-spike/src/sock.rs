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
    s.set_multicast_loop_v4(false)?;
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
    s.set_multicast_loop_v6(false)?;
    Ok(s.into())
}
