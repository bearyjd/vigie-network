"""Read a bounded NextDNS log interval and correlate it with observed router DNS."""

from __future__ import annotations

import http.client
import json
import re
import ssl
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlencode

from vigie_ingest.db import iso_utc

HOST = "api.nextdns.io"
PAGE_SIZE = 1000
MAX_PAGES = 10
MAX_PAGE_BYTES = 2 * 1024 * 1024
SOCKET_TIMEOUT_S = 5
TOLERANCE_S = 2
PADDING_S = 2 * TOLERANCE_S
MICROSECONDS = 1_000_000
THREAT_REASON = "threat-intelligence-feeds"

_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_LABEL = re.compile(r"[a-z0-9_-]{1,63}", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class ReportError(RuntimeError):
    """Fixed operator-facing message. Source data and credentials never enter exceptions."""


class ProviderError(ReportError):
    def __init__(self) -> None:
        super().__init__("NextDNS logs unavailable, invalid, or incomplete")


@dataclass(frozen=True)
class LocalQuery:
    ts: int
    name: str
    mac: str | None
    boundary: bool


@dataclass(frozen=True)
class ProviderQuery:
    stamp_us: int
    name: str
    eligible_verdict: bool


def canonical_name(raw: object) -> str | None:
    """Match ASCII DNS labels exactly, apart from case and the optional final root dot."""
    if not isinstance(raw, str) or len(raw) > 254 or not raw.isascii():
        return None
    if raw == ".":
        return raw  # The DNS root can appear in raw logs.
    name = raw.removesuffix(".").lower()
    if len(name) <= 253 and all(_LABEL.fullmatch(label) for label in name.split(".")):
        return name
    return None


def timestamp_us(raw: object) -> int:
    if not isinstance(raw, str) or not _TIMESTAMP.fullmatch(raw):
        raise ValueError("invalid UTC timestamp")
    delta = datetime.fromisoformat(raw) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * MICROSECONDS + delta.microseconds


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ProviderError()
        obj[key] = value
    return obj


def _page(resource: str, key: str, context: ssl.SSLContext) -> object:
    headers = {
        "X-Api-Key": key,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-store, no-cache",
    }
    # Direct HTTPS on the fixed host. http.client does not use proxy environment variables,
    # redirects, retry policy, or a response cache.
    connection = http.client.HTTPSConnection(HOST, timeout=SOCKET_TIMEOUT_S, context=context)
    try:
        connection.request("GET", resource, headers=headers)
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Encoding") not in (
            None,
            "identity",
        ):
            raise ProviderError()
        body = response.read(MAX_PAGE_BYTES + 1)
        if len(body) > MAX_PAGE_BYTES:
            raise ProviderError()
        # HTTPResponse.read(n) may return a short body on premature EOF with Content-Length.
        if response.length is not None and response.length != 0:
            raise ProviderError()
        return json.loads(body, object_pairs_hook=_object_pairs)
    except (OSError, ValueError, RecursionError, http.client.HTTPException) as exc:
        raise ProviderError() from exc
    finally:
        connection.close()


def _parse_page(value: object) -> tuple[list[object], str | None]:
    if not isinstance(value, dict) or "errors" in value:
        raise ProviderError()
    rows = value.get("data")
    meta = value.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if (
        not isinstance(rows, list)
        or len(rows) > PAGE_SIZE
        or not isinstance(pagination, dict)
        or "cursor" not in pagination
    ):
        raise ProviderError()
    cursor = pagination["cursor"]
    if cursor is not None and (
        not rows
        or not isinstance(cursor, str)
        or not 1 <= len(cursor) <= 1024
        or not cursor.isascii()
        or not cursor.isprintable()
    ):
        raise ProviderError()
    return rows, cursor


def _parse_query(row: object, device: str) -> ProviderQuery:
    if not isinstance(row, dict) or (name := canonical_name(row.get("domain"))) is None:
        raise ProviderError()
    try:
        stamp_us = timestamp_us(row.get("timestamp"))
    except ValueError as exc:
        raise ProviderError() from exc
    identity = row.get("device")
    reasons = row.get("reasons")
    eligible = (
        name != "."
        and isinstance(identity, dict)
        and identity.get("id") == device
        and row.get("status") == "blocked"
        and isinstance(reasons, list)
        and any(
            isinstance(reason, dict) and reason.get("id") == THREAT_REASON for reason in reasons
        )
    )
    return ProviderQuery(stamp_us, name, eligible)


def read_logs(profile: str, device: str, key: str, start: int, end: int) -> list[ProviderQuery]:
    # Construct the context directly so SSLKEYLOGFILE cannot enable TLS session-key logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    query = {
        "from": iso_utc(start),
        "to": iso_utc(end),
        "sort": "asc",
        "limit": str(PAGE_SIZE),
        "raw": "1",
    }
    rows: list[ProviderQuery] = []
    cursors: set[str] = set()
    for _ in range(MAX_PAGES):
        raw_rows, cursor = _parse_page(
            _page(f"/profiles/{profile}/logs?{urlencode(query)}", key, context),
        )
        for raw in raw_rows:
            row = _parse_query(raw, device)
            if not start * MICROSECONDS <= row.stamp_us < end * MICROSECONDS or (
                rows and row.stamp_us < rows[-1].stamp_us
            ):
                raise ProviderError()
            rows.append(row)
        if cursor is None:
            return rows
        if cursor in cursors:
            raise ProviderError()
        cursors.add(cursor)
        query["cursor"] = cursor
    raise ProviderError()


def count_matches(
    local: list[LocalQuery],
    provider: list[ProviderQuery],
    mac: str,
    start: int,
    end: int,
) -> int:
    """Require mutual uniqueness while retaining rows ineligible for a positive match."""
    clamped_names: set[str] = set()
    by_name: dict[str, list[int]] = defaultdict(list)
    for row in local:
        if row.boundary:
            # A deferred collector clock can place an older query at the start of its batch.
            clamped_names.add(row.name)
        else:
            by_name[row.name].append(row.ts * MICROSECONDS)
    remote: dict[str, list[ProviderQuery]] = defaultdict(list)
    for event in provider:
        remote[event.name].append(event)
    for stamps in by_name.values():
        stamps.sort()
    for events in remote.values():
        events.sort(key=lambda row: row.stamp_us)

    count = 0
    delta = TOLERANCE_S * MICROSECONDS
    interval_start_us = start * MICROSECONDS
    interval_end_us = end * MICROSECONDS
    for row in local:
        if row.boundary or row.mac != mac or not start <= row.ts < end or row.name in clamped_names:
            continue
        events = remote.get(row.name)
        if not events:
            continue
        stamp = row.ts * MICROSECONDS
        low = bisect_left(events, stamp - delta, key=lambda event: event.stamp_us)
        high = bisect_right(events, stamp + delta, key=lambda event: event.stamp_us)
        if high - low != 1:
            continue
        event = events[low]
        if not event.eligible_verdict or not interval_start_us <= event.stamp_us < interval_end_us:
            continue
        stamps = by_name[row.name]
        low = bisect_left(stamps, event.stamp_us - delta)
        high = bisect_right(stamps, event.stamp_us + delta)
        if high - low == 1:
            count += 1
    return count
