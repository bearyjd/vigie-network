"""Strict pydantic models for the collector batch (api/batch.schema.json is generated)."""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    model_validator,
)

MAX_WINDOW_SECONDS = 24 * 3600
FUTURE_WINDOW_SLACK = 300
MAX_SPOOL_AGE_SECONDS = 24 * 3600  # default; override via validation context 'max_spool_age_s'

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_IDENT_PATTERN = r"^[A-Za-z0-9_.-]{1,64}$"  # no '|' (signature field separator)
_INT64_MAX = 2**63 - 1


def _check_ip(value: str) -> str:
    ipaddress.ip_address(value)
    return value


def _check_uuid7(value: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 7 or str(parsed) != value:
        raise ValueError("batch_id must be a lowercase canonical UUIDv7")
    return value


Ident = Annotated[str, StringConstraints(pattern=_IDENT_PATTERN)]
Mac = Annotated[str, StringConstraints(max_length=17, pattern=_MAC_RE.pattern)]
IpStr = Annotated[str, StringConstraints(max_length=45), AfterValidator(_check_ip)]
Uuid7 = Annotated[str, StringConstraints(max_length=36), AfterValidator(_check_uuid7)]
Name = Annotated[str, StringConstraints(max_length=255)]
Qname = Annotated[str, StringConstraints(min_length=1, max_length=253)]
Count = Annotated[int, Field(ge=0, le=_INT64_MAX)]
EpochSeconds = Annotated[int, Field(ge=0, le=2**40)]
Port = Annotated[int, Field(ge=0, le=65535)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Lease(_Strict):
    mac: Mac
    ip: IpStr
    hostname: Annotated[str, StringConstraints(max_length=253)] | None = None
    opt55: Annotated[list[Annotated[int, Field(ge=0, le=255)]], Field(max_length=64)] = []
    opt60: Annotated[str, StringConstraints(max_length=255)] | None = None


class Neighbor(_Strict):
    ip: IpStr
    mac: Mac
    family: Literal["inet", "inet6"]


class DnsQuery(_Strict):
    ts: EpochSeconds
    mac: Mac
    qname: Qname
    qtype: Annotated[str, StringConstraints(pattern=r"^[A-Z0-9]{1,16}$")]
    answer_ip: IpStr | None = None


class ConntrackSummary(_Strict):
    mac: Mac
    dst_ip: IpStr | None = None  # None only for the per-MAC "other" overflow bucket
    dst_port: Port | None = None
    proto: Literal["tcp", "udp", "icmp", "icmpv6", "other"]
    bytes_up: Count
    bytes_down: Count
    flows: Count


class Sighting(_Strict):
    mac: Mac
    kind: Literal["mdns", "ssdp"]
    name: Name | None = None
    service: Name | None = None
    ua: Name | None = None


class Health(_Strict):
    dns_log_quiet: bool = False
    rss_kb: Count | None = None
    spool_batches: Count | None = None
    uptime_s: Count | None = None


TruncatedMap = Annotated[
    dict[Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,32}$")], Count],
    Field(max_length=16),
]


class Batch(_Strict):
    collector_id: Ident
    key_id: Ident
    boot_id: Ident
    seq: Annotated[int, Field(ge=0, le=_INT64_MAX)]
    batch_id: Uuid7
    window_start: EpochSeconds
    window_end: EpochSeconds
    sent_ts: EpochSeconds
    truncated: TruncatedMap = {}
    dropped_batches: Count = 0
    leases: Annotated[list[Lease], Field(max_length=1000)] = []
    neigh: Annotated[list[Neighbor], Field(max_length=2000)] = []
    dns: Annotated[list[DnsQuery], Field(max_length=5000)] = []
    conntrack: Annotated[list[ConntrackSummary], Field(max_length=5000)] = []
    sightings: Annotated[list[Sighting], Field(max_length=1000)] = []
    health: Health | None = None

    @model_validator(mode="after")
    def _check_window(self, info: ValidationInfo) -> Batch:
        max_age = (info.context or {}).get("max_spool_age_s", MAX_SPOOL_AGE_SECONDS)
        if self.window_end < self.sent_ts - max_age:
            raise ValueError("window_end older than the maximum spool age")
        if self.window_end < self.window_start:
            raise ValueError("window_end precedes window_start")
        if self.window_end - self.window_start > MAX_WINDOW_SECONDS:
            raise ValueError("window longer than 24h")
        if self.window_end > self.sent_ts + FUTURE_WINDOW_SLACK:
            raise ValueError("window_end is in the future relative to sent_ts")
        for q in self.dns:
            if not (
                self.window_start - FUTURE_WINDOW_SLACK
                <= q.ts
                <= self.window_end + FUTURE_WINDOW_SLACK
            ):
                raise ValueError("dns ts outside batch window")
        return self
