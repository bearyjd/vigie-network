"""One last observed source address per MAC; never an identity or current-IP claim."""
from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Mapping
from typing import TYPE_CHECKING

from vigie_pipeline.config import ACTIVITY_MAX_REPORT_LAG_S, ACTIVITY_SKEW_S

if TYPE_CHECKING:
    from vigie_pipeline.sources import MacActivity


def address_candidate(
    raw: str, stamp: int, source: str, received_ts: float | None,
) -> tuple[int, int, str, str] | None:
    """Equal-time ties prefer lease over neighbour, then lexical canonical address.

    The raw lease/neighbour stamp is the collector's batch window end. It is a
    snapshot observation time, not a DHCP lease expiry or server receipt time.
    """
    if received_ts is None or not (
        received_ts - ACTIVITY_MAX_REPORT_LAG_S <= stamp <= received_ts + ACTIVITY_SKEW_S
    ):
        return None
    try:
        if '%' in raw:
            return None
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or str(ip) == '255.255.255.255':
        return None
    return stamp, int(source == 'lease'), str(ip), source


def save_last_ips(inv: sqlite3.Connection, acts: Mapping[str, MacActivity]) -> None:
    """Called inside the batch transaction; replay and arrival order cannot regress it."""
    inv.executemany(
        "INSERT INTO mac_last_ip (mac,ip,observed_at,source) VALUES (?,?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,observed_at=excluded.observed_at,"
        "source=excluded.source WHERE "
        "(excluded.observed_at,excluded.source='lease',excluded.ip) > "
        "(mac_last_ip.observed_at,mac_last_ip.source='lease',mac_last_ip.ip)",
        [(mac, act.last_ip[2], act.last_ip[0], act.last_ip[3])
         for mac, act in acts.items() if act.last_ip is not None],
    )
