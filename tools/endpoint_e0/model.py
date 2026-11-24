"""Immutable records for the E0 feasibility report (docs/prp/003-endpoint-events.md section 6)."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class MacSpan:
    """Owner-scoped attribution: `mac` belongs to the device for router ts in [since, until)."""

    mac: str
    since: int | None = None
    until: int | None = None

    def covers(self, mac: str, ts: int) -> bool:
        if mac != self.mac:
            return False
        return (self.since is None or ts >= self.since) and (self.until is None or ts < self.until)


@dataclass(frozen=True)
class Scope:
    host_id: str
    device_id: str
    macs: tuple[MacSpan, ...]
    lan_prefixes: tuple[Network, ...]
    router_ips: frozenset[str]
    period_start: int
    period_end: int
    export_start: int
    skew_s: int = 0
    skew_supplied: bool = False


@dataclass(frozen=True)
class Batch:
    """An accepted batch's bounds (inventory `batches`); `reasons` empty means a clean window."""

    collector_id: str
    batch_id: str
    start: int | None
    end: int | None
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Flow:
    """One `raw_flow` row. `dst_ip` None is the collector's per-MAC `other` bucket."""

    collector_id: str
    batch_id: str
    ts: int
    mac: str
    dst_ip: str | None
    dst_port: int | None
    proto: str
    bytes_up: int
    bytes_down: int
    flows: int


@dataclass(frozen=True)
class RouterData:
    batches: Mapping[tuple[str, str], Batch]
    flows: tuple[Flow, ...]
    missing_shards: tuple[str, ...] = ()


@dataclass(frozen=True)
class Event:
    """An accepted endpoint event; `t` is the endpoint time corrected by the supplied skew."""

    t: int
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    dst_host: str


@dataclass(frozen=True)
class EventLog:
    events: tuple[Event, ...]
    read: int
    accepted: int
    duplicates: int
    rejected: Mapping[str, int] = field(default_factory=dict)
    no_app_identity: int = 0
