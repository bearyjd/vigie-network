"""Address and protocol normalization plus the PRP-003 section 6 match-key exclusions."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from .model import Network

ELIGIBLE_PROTOS = frozenset({"tcp", "udp"})
EXCLUDED_PORTS = frozenset({53, 853, 5353, 67, 68})
_PROTO_ALIASES = {"tcp6": "tcp", "udp6": "udp"}


def parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def norm_ip(text: str) -> str | None:
    """Canonical spelling (compressed IPv6, mapped IPv4 folded) or None when unparsable."""
    addr = parse_ip(text)
    return None if addr is None else str(addr)


def norm_proto(text: str) -> str:
    low = text.lower()
    return _PROTO_ALIASES.get(low, low)


def in_lan(text: str, lan: Iterable[Network]) -> bool:
    addr = parse_ip(text)
    return addr is not None and any(addr.version == n.version and addr in n for n in lan)


def dst_exclusion(text: str, lan: Iterable[Network], router_ips: frozenset[str]) -> str | None:
    """Exclusion reason for a destination, or None when eligible.

    LAN membership comes from the declared prefixes, never `is_private`: Python 3.12 marks the
    documentation ranges private, and a private address off the LAN (a VPN peer) is still WAN.
    """
    addr = parse_ip(text)
    if addr is None:
        return "invalid_dst"
    if str(addr) in router_ips:
        return "router_dst"
    if any(addr.version == n.version and addr in n for n in lan):
        return "lan_dst"
    if addr.is_multicast:
        return "multicast_dst"
    if addr.is_link_local:
        return "link_local_dst"
    if addr.is_loopback:
        return "loopback_dst"
    if addr.is_unspecified:
        return "unspecified_dst"
    if addr == ipaddress.IPv4Address("255.255.255.255"):
        return "broadcast_dst"
    return None
