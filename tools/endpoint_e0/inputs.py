"""Strict parsing of the owner scope and the exported endpoint JSONL log.

Every endpoint field is attacker-controlled text (PRP-003 section 3), so the JSON rules mirror
the planned listener: duplicate keys, NaN/Infinity and integer literals over 10 digits are
rejected, the key set must equal the peer allowlist plus `host_id`, and control or bidi
characters reject the event. A bad event is counted by reason; caps and IO faults are fatal.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from . import netutil
from .model import Event, EventLog, MacSpan, Scope

MAX_SCOPE_BYTES = 1 << 20
MAX_EVENTS_FILE_BYTES = 256 << 20
MAX_LINE_BYTES = 8192
MAX_EVENTS = 500_000  # PRP-003 section 8: 200k per host per day, so 48 h fits with margin
MAX_LIST = 64
MAX_PERIOD_S = 7 * 86400
MAX_SKEW_S = 86400
MAX_TS = 1 << 40
MAX_EVENT_TS = 253_402_300_799  # 9999-12-31T23:59:59Z, the last second datetime can render
EVENT_KEYS = frozenset(
    {
        "time", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "dst_host",
        "process_path", "user_id", "Action", "Rule", "Type", "host_id",
    }
)  # fmt: skip
SCOPE_REQUIRED = frozenset(
    {
        "host_id", "device_id", "macs", "lan_prefixes", "router_ips", "period_start",
        "period_end", "export_start",
    }
)  # fmt: skip
SCOPE_OPTIONAL = frozenset({"skew_s"})
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_BAD_CHARS = re.compile("[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")


class InputError(Exception):
    """Fatal input problem: the report is not produced."""


class _DupKey(InputError):
    pass


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _DupKey(f"duplicate key {key!r}")
        out[key] = value
    return out


def _constant(name: str) -> object:
    raise InputError(f"non-finite number {name}")


def _int(text: str) -> int:
    if len(text.lstrip("-")) > 10:
        raise InputError("integer literal longer than 10 digits")
    return int(text)


def strict_loads(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_int=_int)
    except InputError:
        raise
    except (ValueError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from None


def _is_int(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _text(value: object, limit: int) -> bool:
    return isinstance(value, str) and len(value.encode()) <= limit and not _BAD_CHARS.search(value)


def _scope_int(raw: dict, key: str, low: int, high: int) -> int:
    value = raw[key]
    if not _is_int(value, low, high):
        raise InputError(f"scope {key} must be an integer in [{low}, {high}]")
    return value


def _mac_span(item: object) -> MacSpan:
    if not isinstance(item, dict) or not set(item) <= {"mac", "from", "until"}:
        raise InputError("scope macs entries need only mac, from, until")
    mac = item.get("mac")
    if not isinstance(mac, str) or not _MAC_RE.match(mac.lower()):
        raise InputError("scope mac must be a colon-separated MAC")
    bounds = {k: item.get(k) for k in ("from", "until")}
    for key, value in bounds.items():
        if value is not None and not _is_int(value, 0, MAX_TS):
            raise InputError(f"scope mac {key} must be an epoch integer")
    return MacSpan(mac.lower(), bounds["from"], bounds["until"])


def _bounded_list(raw: dict, key: str, allow_empty: bool) -> list:
    value = raw[key]
    if not isinstance(value, list) or len(value) > MAX_LIST or (not value and not allow_empty):
        raise InputError(f"scope {key} must be a list of 1..{MAX_LIST} entries")
    return value


def _networks(raw: dict) -> tuple:
    try:
        return tuple(
            ipaddress.ip_network(p, strict=False) for p in _bounded_list(raw, "lan_prefixes", False)
        )
    except (TypeError, ValueError):
        raise InputError("scope lan_prefixes must be CIDR strings") from None


def parse_scope(text: str) -> Scope:
    if len(text.encode()) > MAX_SCOPE_BYTES:
        raise InputError("scope exceeds the size cap")
    raw = strict_loads(text)
    if not isinstance(raw, dict) or not SCOPE_REQUIRED <= set(raw):
        raise InputError(f"scope needs keys {sorted(SCOPE_REQUIRED)}")
    if set(raw) - SCOPE_REQUIRED - SCOPE_OPTIONAL:
        raise InputError("scope has unexpected keys")
    for key in ("host_id", "device_id"):
        if not _text(raw[key], 128) or not raw[key]:
            raise InputError(f"scope {key} must be a short printable string")
    ips = _bounded_list(raw, "router_ips", True)
    routers = [netutil.norm_ip(ip) if isinstance(ip, str) else None for ip in ips]
    if None in routers:
        raise InputError("scope router_ips must be IP strings")
    start = _scope_int(raw, "period_start", 0, MAX_TS)
    end = _scope_int(raw, "period_end", start + 1, start + MAX_PERIOD_S)
    export = _scope_int(raw, "export_start", 0, MAX_TS)
    skew_supplied = "skew_s" in raw
    skew = _scope_int(raw, "skew_s", -MAX_SKEW_S, MAX_SKEW_S) if skew_supplied else 0
    return Scope(
        host_id=raw["host_id"],
        device_id=raw["device_id"],
        macs=tuple(_mac_span(m) for m in _bounded_list(raw, "macs", False)),
        lan_prefixes=_networks(raw),
        router_ips=frozenset(r for r in routers if r is not None),
        period_start=start,
        period_end=end,
        skew_s=skew,
        skew_supplied=skew_supplied,
        export_start=export,
    )


def _event_time(value: object) -> int | None:
    if _is_int(value, 0, MAX_TS):
        return value  # type: ignore[return-value]
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return None if parsed.tzinfo is None else int(parsed.timestamp())


def _check_values(obj: dict) -> tuple[int, str, str, str] | None:
    """(time, proto, src_ip, dst_ip) normalized, or None when any value is out of contract."""
    t = _event_time(obj["time"])
    src = netutil.norm_ip(obj["src_ip"]) if isinstance(obj["src_ip"], str) else None
    dst = netutil.norm_ip(obj["dst_ip"]) if isinstance(obj["dst_ip"], str) else None
    path = obj["process_path"]
    ok = (
        t is not None
        and src is not None
        and dst is not None
        and _text(obj["protocol"], 16)
        and all(_is_int(obj[k], 0, 65535) for k in ("src_port", "dst_port"))
        and _is_int(obj["user_id"], 0, 2**32 - 1)
        and _text(obj["dst_host"], 253)
        and _text(path, 4096)
        and isinstance(path, str)
        and path.startswith("/")
        and all(_text(obj[k], 256) for k in ("Action", "Rule", "host_id"))
    )
    return (t, netutil.norm_proto(obj["protocol"]), src, dst) if ok else None  # type: ignore[return-value]


def _classify(line: bytes, sc: Scope) -> tuple[str, object]:
    """('ok', (dedup_key, Event)) or (reason, None)."""
    if len(line) > MAX_LINE_BYTES:
        return "frame_bad", None
    try:
        obj = strict_loads(line.decode("utf-8"))
    except _DupKey:
        return "dup_key", None
    except (InputError, UnicodeDecodeError):
        return "json_bad", None
    if not isinstance(obj, dict):
        return "json_bad", None
    if set(obj) - EVENT_KEYS:
        return "unexpected_field", None
    if EVENT_KEYS - set(obj):
        return "missing_field", None
    if not _is_int(obj["Type"], 0, 2**31):
        return "bad_value", None
    if obj["Type"] != 0:
        return "type_skip", None
    values = _check_values(obj)
    if values is None:
        return "bad_value", None
    if obj["host_id"] != sc.host_id:
        return "host_id_mismatch", None
    t, proto, src, dst = values
    if not 0 <= t - sc.skew_s <= MAX_EVENT_TS:
        return "bad_value", None  # a corrected time datetime cannot render
    if not netutil.in_lan(src, sc.lan_prefixes):
        return "src_off_lan", None
    key = (t, proto, src, obj["src_port"], dst, obj["dst_port"])
    ev = Event(t - sc.skew_s, proto, src, obj["src_port"], dst, obj["dst_port"], obj["dst_host"])
    return "ok", (key, ev)


def parse_events(raw_lines: Iterable[bytes], sc: Scope) -> EventLog:
    seen: set[tuple] = set()
    events: list[Event] = []
    rejected: Counter[str] = Counter()
    read = duplicates = 0
    for raw in raw_lines:
        line = raw.strip()
        if not line:
            continue
        read += 1
        if read > MAX_EVENTS:
            raise InputError(f"event log exceeds {MAX_EVENTS} events")
        reason, payload = _classify(line, sc)
        if reason != "ok":
            rejected[reason] += 1
            continue
        key, ev = payload  # type: ignore[misc]
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        events.append(ev)
    events.sort(key=lambda e: (e.t, e.dst_ip, e.dst_port, e.proto, e.src_ip, e.src_port))
    return EventLog(
        events=tuple(events),
        read=read,
        accepted=len(events),
        duplicates=duplicates,
        rejected=dict(sorted(rejected.items())),
        no_app_identity=sum(1 for e in events if not e.dst_host),
    )


def _limited_lines(handle) -> Iterable[bytes]:
    while True:
        line = handle.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        tail = line
        while len(tail) > MAX_LINE_BYTES and not tail.endswith(b"\n"):
            tail = handle.readline(MAX_LINE_BYTES + 1)  # discard in bounded chunks
        yield line  # an oversize line is still counted as frame_bad


def read_events(path: Path, sc: Scope) -> EventLog:
    try:
        if path.stat().st_size > MAX_EVENTS_FILE_BYTES:
            raise InputError("events file exceeds the size cap")
        with path.open("rb") as handle:
            return parse_events(_limited_lines(handle), sc)
    except OSError as exc:
        raise InputError(f"cannot read events file: {exc.strerror}") from None


def read_scope(path: Path) -> Scope:
    try:
        if path.stat().st_size > MAX_SCOPE_BYTES:
            raise InputError("scope exceeds the size cap")
        return parse_scope(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        raise InputError("cannot read scope file") from None
