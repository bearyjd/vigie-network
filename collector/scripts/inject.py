#!/usr/bin/env python3
"""Send one mDNS query, one SSDP NOTIFY and one SSDP M-SEARCH from a LAN host.

Run this on a LAN machine (not the router) while net-spike is listening, so the
"injected packets parsed" result is reproducible:

    python3 inject.py <this-host-lan-ipv4> [delay_seconds]

Expect in the net-spike JSON: mdns names/services containing _vigie-probe._tcp.local,
ssdp server "Vigie-Inject/1.0", and ssdp usn "uuid:vigie-inject::upnp:rootdevice".
"""
import socket
import sys
import time

src = sys.argv[1]
time.sleep(float(sys.argv[2]) if len(sys.argv) > 2 else 3.0)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)


def labels(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


mdns_query = b"\0\0\0\0\0\1\0\0\0\0\0\0" + labels("_vigie-probe._tcp.local") + b"\0\x0c\0\1"
if len(sys.argv) > 3 and sys.argv[3] == "unicast-only":
    # Name differs on purpose: it must NEVER appear in net-spike output (bound to the group).
    uni = b"\0\0\0\0\0\1\0\0\0\0\0\0" + labels("_vigie-unicast._tcp.local") + b"\0\x0c\0\1"
    s.sendto(uni, (src, 5353))
    print("sent 1 unicast datagram to", src)
    sys.exit(0)
s.sendto(mdns_query, ("224.0.0.251", 5353))
s.sendto(
    b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n"
    b"USN: uuid:vigie-inject::upnp:rootdevice\r\nSERVER: Vigie-Inject/1.0\r\n\r\n",
    ("239.255.255.250", 1900),
)
s.sendto(
    b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nUSER-AGENT: Vigie-Inject/1.0\r\n\r\n",
    ("239.255.255.250", 1900),
)
# A unicast datagram to 5353 on this host: with the group-address bind it must NOT reach net-spike.
s.sendto(mdns_query, (src, 5353))
print("sent 3 multicast + 1 unicast datagram from", src)
