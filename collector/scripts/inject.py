#!/usr/bin/env python3
"""Inject known packets at a running net-spike so the results are reproducible.

Run on a LAN machine that is NOT the router, while net-spike runs on the router:

    python3 inject.py <this-machine-lan-ip> <router-lan-ip> [delay_seconds]

Sends (multicast, must be received and parsed):
  * mDNS query for  _vigie-probe._tcp.local
  * SSDP NOTIFY  (SERVER Vigie-Inject/1.0, USN uuid:vigie-inject::upnp:rootdevice)
  * SSDP M-SEARCH (USER-AGENT Vigie-Inject/1.0)
and one UNICAST mDNS query for _vigie-unicast._tcp.local straight to <router-lan-ip>:5353.
That unicast datagram is meant for avahi; it must NOT appear in net-spike's output
(net-spike binds 224.0.0.251:5353, not 0.0.0.0:5353).
"""
import socket
import sys
import time

if len(sys.argv) < 3:
    sys.exit(__doc__)
src, router = sys.argv[1], sys.argv[2]
time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 3.0)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)


def query(name):
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    return b"\0\0\0\0\0\1\0\0\0\0\0\0" + labels + b"\0\x0c\0\1"


s.sendto(query("_vigie-probe._tcp.local"), ("224.0.0.251", 5353))
s.sendto(
    b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n"
    b"USN: uuid:vigie-inject::upnp:rootdevice\r\nSERVER: Vigie-Inject/1.0\r\n\r\n",
    ("239.255.255.250", 1900),
)
s.sendto(
    b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nUSER-AGENT: Vigie-Inject/1.0\r\n\r\n",
    ("239.255.255.250", 1900),
)
s.sendto(query("_vigie-unicast._tcp.local"), (router, 5353))
print(f"sent 3 multicast datagrams from {src} and 1 unicast datagram to {router}:5353")
