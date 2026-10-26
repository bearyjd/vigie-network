"""One last observed source address per MAC; never an identity or current-IP claim."""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Mapping
from typing import TYPE_CHECKING

from vigie_pipeline.config import ACTIVITY_SKEW_S

if TYPE_CHECKING:
    from vigie_pipeline.sources import MacActivity


def address_candidate(
    raw: str,
    stamp: int,
    source: str,
    received_ts: float | None,
) -> tuple[int, int, str, str] | None:
    """Equal-time ties prefer lease over neighbour, then lexical canonical address.

    The raw lease/neighbour stamp is the collector's batch window end. It is a
    snapshot observation time, not a DHCP lease expiry or server receipt time.
    """
    # No lower lag bound: the upsert is monotonic by stamp, so a late batch cannot
    # win over newer data, and the delta-only collector never re-sends a pairing.
    if received_ts is None or stamp > received_ts + ACTIVITY_SKEW_S:
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:  # includes scoped "fe80::1%eth0" spellings
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_unspecified
        or ip.is_multicast
        or ip.is_loopback
        or ip.is_link_local
        or (ip.version == 4 and (ip.is_reserved or ip.packed[0] == 0))  # 240/4 incl. broadcast, 0/8
    ):
        return None
    return stamp, int(source == "lease"), str(ip), source


def save_last_ips(inv: sqlite3.Connection, acts: Mapping[str, MacActivity]) -> None:
    """Called inside the batch transaction; replay and arrival order cannot regress it."""
    inv.executemany(
        "INSERT INTO mac_last_ip (mac,ip,observed_at,source) VALUES (?,?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,observed_at=excluded.observed_at,"
        "source=excluded.source WHERE "
        "(excluded.observed_at,excluded.source='lease',excluded.ip) > "
        "(mac_last_ip.observed_at,mac_last_ip.source='lease',mac_last_ip.ip)",
        [
            (mac, act.last_ip[2], act.last_ip[0], act.last_ip[3])
            for mac, act in acts.items()
            if act.last_ip is not None
        ],
    )
