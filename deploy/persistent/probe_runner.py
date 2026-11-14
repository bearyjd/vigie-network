#!/usr/bin/env python3
"""Bounded DNS / reachability probe runner (slice 1: pure core, OFF by default).

Runs OUTSIDE the pipeline (which stays on Network=none), like ntfy_sender.py. This module holds
only the pure parts: strict config validation, a probe pass whose clock, resolver and connect
functions are all injected, hysteresis, and the bounded state document a later slice writes for
the pipeline to read. It opens no socket and reads no file at import time, and does nothing at all
when the config is disabled. Standard library only.

Probe targets come ONLY from the validated private config (at most 10, literal private IPs, no
hostnames). A result is `ok`, `latency_ms` and an error class from a fixed set: never response
content. Log lines and error messages carry the target id and error class only, never an address,
qname or port. The reply parser is a ported copy of run_soak.dns_probe (a parity test keeps them
equal); the soak's retry and hard-coded question are deliberately not ported.
"""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

log = logging.getLogger("probe_runner")

KINDS = frozenset({"dns_local", "dns_upstream", "tcp_lan"})
MAX_TARGETS = 10
MAX_CONFIG_BYTES = 16384
MAX_PATH = 4096
MIN_INTERVAL_S = 55.0  # a target is skipped if 0 <= now - last_attempt < 55
CLOCK_STEP_S = 60.0  # a last_attempt further in the future than this means the clock stepped back
DEADLINE_S = 25.0  # total wall-clock budget of one pass
MAX_TIMEOUT_S = 2.0
MAX_LATENCY_MS = 5000
OPEN_AFTER = 3
RECOVER_AFTER = 3
MAX_EPISODES_PER_DAY = 3
RING = 60
MAX_STATE_BYTES = 32768
MAX_STATE_READ = 65536
MAX_COUNT = 1000
MAX_EPOCH = 1e11
MAX_REPLY = 4096
STATE_VERSION = 1
DNS_ERRORS = frozenset({"malformed", "bad_id", "rcode", "no_answer", "timeout", "oserror"})
TCP_ERRORS = frozenset({"timeout", "refused", "unreachable", "other"})
ERROR_CLASSES = DNS_ERRORS | TCP_ERRORS
STATES = frozenset({"unknown", "ok", "outage"})
NOTES = frozenset({"skipped_deadline", "clock_step"})
ID_RE = re.compile(r"[a-z0-9_-]{1,32}")
LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
TOP_KEYS = frozenset({"enabled", "state_file", "targets"})
DNS_KEYS = frozenset({"id", "kind", "resolver", "qname", "timeout_s"})
TCP_KEYS = frozenset({"id", "kind", "address", "port", "timeout_s"})

DnsFn = Callable[[str, bytes, float], bytes]  # (resolver, query packet, timeout_s) -> reply
ConnectFn = Callable[[str, int, float], None]  # (address, port, timeout_s); raises OSError
Ring = tuple[tuple[int, bool, int | None, str | None], ...]


class ProbeError(Exception):
    """Fixed-message configuration, state or I/O error (never carries addresses or names)."""


@dataclass(frozen=True)
class Target:
    id: str
    kind: str
    host: str
    port: int
    qname: str | None
    timeout_s: float


@dataclass(frozen=True)
class ProbeConfig:
    enabled: bool
    state_file: str
    targets: tuple[Target, ...]


@dataclass(frozen=True)
class TargetState:
    id: str
    state: str = "unknown"
    consecutive_fail: int = 0
    consecutive_ok: int = 0
    last_ok_at: float | None = None
    last_error_class: str | None = None
    last_latency_ms: int | None = None
    episode_start: int | None = None  # kept after recovery: it is the recover event's token
    last_attempt: float | None = None
    ring: Ring = ()
    episodes_day: str | None = None
    episodes_today: int = 0
    flapping: bool = False
    note: str | None = None


@dataclass(frozen=True)
class State:
    written_at: float
    targets: tuple[TargetState, ...]


@dataclass(frozen=True)
class Result:
    ok: bool
    latency_ms: int
    error_class: str | None


def new_target_state(target_id: str) -> TargetState:
    return TargetState(id=target_id)


def empty_state() -> State:
    return State(written_at=0.0, targets=())


# ---------------------------------------------------------------- config validation
def _bad(index: int, what: str) -> ProbeError:
    return ProbeError(f"target {index}: invalid {what}")


def _private_ip(value: object) -> str | None:
    """Literal private unicast IP only: no hostname, scope id, v4-mapped, loopback, link-local
    (incl. cloud metadata), unspecified, multicast or reserved address."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if getattr(ip, "ipv4_mapped", None) is not None:
        return None
    unsafe = (ip.is_loopback, ip.is_unspecified, ip.is_multicast, ip.is_link_local, ip.is_reserved)
    return str(ip) if ip.is_private and not any(unsafe) else None


def _qname(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return None
    labels = value.split(".")
    if not all(LABEL_RE.fullmatch(label) for label in labels):
        return None
    return value.lower()


def _timeout(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if 0 < value <= MAX_TIMEOUT_S else None


def _parse_target(index: int, raw: object) -> Target:
    if not isinstance(raw, dict):
        raise _bad(index, "entry")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        raise _bad(index, "kind")
    tcp = kind == "tcp_lan"
    if set(raw) - {"timeout_s"} != (TCP_KEYS if tcp else DNS_KEYS) - {"timeout_s"}:
        raise _bad(index, "keys")
    ident = raw["id"]
    if not isinstance(ident, str) or not ID_RE.fullmatch(ident):
        raise _bad(index, "id")
    host = _private_ip(raw["address" if tcp else "resolver"])
    if host is None:
        raise _bad(index, "address")
    timeout = _timeout(raw.get("timeout_s", MAX_TIMEOUT_S))
    if timeout is None:
        raise _bad(index, "timeout")
    if tcp:
        port = raw["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise _bad(index, "port")
        return Target(ident, kind, host, port, None, timeout)
    qname = _qname(raw["qname"])
    if qname is None:
        raise _bad(index, "qname")
    return Target(ident, kind, host, 53, qname, timeout)


def _parse_state_file(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= MAX_PATH
        or "\0" in value
        or not os.path.isabs(value)
    ):
        raise ProbeError("state_file must be an absolute path")
    return value


def parse_config(raw: object) -> ProbeConfig:
    """Strict: unknown keys, wrong types and out-of-range values are rejected with fixed text."""
    if not isinstance(raw, dict) or not set(raw) <= TOP_KEYS:
        raise ProbeError("config must be an object with only known keys")
    enabled = raw.get("enabled", False)
    entries = raw.get("targets", [])
    if not isinstance(enabled, bool):
        raise ProbeError("enabled must be a boolean")
    if not isinstance(entries, list) or len(entries) > MAX_TARGETS:
        raise ProbeError(f"targets must be a list of at most {MAX_TARGETS}")
    targets = tuple(_parse_target(i, entry) for i, entry in enumerate(entries))
    if len({t.id for t in targets}) != len(targets):
        raise ProbeError("target ids must be unique")
    if sum(t.kind == "dns_upstream" for t in targets) > 1:
        raise ProbeError("at most one dns_upstream target is allowed")
    if enabled or "state_file" in raw:
        state_file = _parse_state_file(raw.get("state_file"))
    else:
        state_file = ""
    if enabled and not targets:
        raise ProbeError("an enabled config needs at least one target")
    return ProbeConfig(enabled, state_file, targets)


def load_config(path: str) -> ProbeConfig:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ProbeError("cannot read the probe config") from exc
    if len(data) > MAX_CONFIG_BYTES:
        raise ProbeError("probe config is too large")
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProbeError("probe config is not valid JSON") from exc
    return parse_config(raw)


# ---------------------------------------------------------------- DNS (ported from run_soak.py)
def encode_qname(qname: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in qname.split(".")) + b"\0"


def build_query(query_id: bytes, qname: str) -> bytes:
    header = struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    return query_id + header + encode_qname(qname) + b"\0\1\0\1"


def _dns_name(
    packet: bytes, offset: int, starts: set[int], wire_end: int | None = None
) -> tuple[tuple[bytes, ...], int]:
    """Decode bounded wire labels, preserving boundaries; pointers target prior names only."""
    labels: list[bytes] = []
    seen: set[int] = set()
    end: int | None = None
    expanded = 1
    wire_end = len(packet) if wire_end is None else wire_end
    for _ in range(128):
        # Inline RDATA bytes stay inside RDLENGTH. A pointer may resolve an
        # already-validated earlier name outside that interval.
        bound = len(packet) if end is not None else wire_end
        if not 12 <= offset < bound or offset in seen:
            raise ValueError("invalid DNS name offset")
        seen.add(offset)
        starts.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= bound:
                raise ValueError("short DNS pointer")
            target = ((size & 0x3F) << 8) | packet[offset + 1]
            if not 12 <= target < offset or target not in starts:
                raise ValueError("invalid DNS pointer target")
            if end is None:
                end = offset + 2
            offset = target
        elif size == 0:
            return tuple(labels), end if end is not None else offset + 1
        elif size <= 63:
            if offset + 1 + size > bound:
                raise ValueError("short DNS label")
            expanded += size + 1
            if expanded > 255:
                raise ValueError("DNS name exceeds wire limit")
            labels.append(packet[offset + 1 : offset + 1 + size].lower())
            offset += 1 + size
        else:
            raise ValueError("invalid DNS label")
    raise ValueError("DNS name traversal bound")


def _header_error(
    flags: int, questions: int, answers: int, authority: int, additional: int
) -> str | None:
    if (
        flags & 0x8000
        and not flags & 0x7A0F
        and questions == 1
        and 0 < answers <= 64
        and answers + authority + additional <= 128
    ):
        return None
    if not flags & 0x8000:
        return "malformed"
    if flags & 0xF:
        return "rcode"
    if questions == 1 and answers == 0:
        return "no_answer"
    return "malformed"


def _scan_records(
    reply: bytes, expected: tuple[bytes, ...], counts: tuple[int, int, int]
) -> str | None:
    answers, authority, additional = counts
    starts: set[int] = set()
    question, offset = _dns_name(reply, 12, starts)
    if question != expected or reply[offset : offset + 4] != b"\0\1\0\1":
        return "malformed"
    offset += 4
    found = False
    for index in range(answers + authority + additional):
        owner, offset = _dns_name(reply, offset, starts)
        if offset + 10 > len(reply):
            return "malformed"
        kind, dns_class, _ttl, length = struct.unpack("!HHIH", reply[offset : offset + 10])
        offset += 10
        if offset + length > len(reply):
            return "malformed"
        if kind == 2 and dns_class == 1:
            # Register NS names for subsequent glue compression, without resolving them or
            # treating glue addresses as the probe answer.
            _, ns_end = _dns_name(reply, offset, starts, offset + length)
            if ns_end != offset + length:
                return "malformed"
        found |= (
            index < answers and owner == expected and kind == 1 and dns_class == 1 and length == 4
        )
        offset += length
    if found and offset == len(reply):
        return None
    return "malformed" if found else "no_answer"


def classify_reply(reply: bytes, query_id: bytes, labels: tuple[bytes, ...]) -> str | None:
    """None for a direct IN/A answer owned by the queried name, else an error class."""
    if not 12 <= len(reply) <= MAX_REPLY:
        return "malformed"
    if reply[:2] != query_id:
        return "bad_id"
    flags, questions, answers, authority, additional = struct.unpack("!5H", reply[2:12])
    problem = _header_error(flags, questions, answers, authority, additional)
    if problem is not None:
        return problem
    try:
        return _scan_records(reply, labels, (answers, authority, additional))
    except ValueError:
        return "malformed"


# ---------------------------------------------------------------- one probe
def _exception_class(kind: str, exc: OSError) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if kind != "tcp_lan":
        return "oserror"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "unreachable"
    return "other"


def _attempt(target: Target, dns: DnsFn, connect: ConnectFn) -> str | None:
    if target.kind == "tcp_lan":
        connect(target.host, target.port, target.timeout_s)
        return None
    assert target.qname is not None  # noqa: S101  (validated by parse_config for DNS kinds)
    query_id = secrets.token_bytes(2)
    reply = dns(target.host, build_query(query_id, target.qname), target.timeout_s)
    labels = tuple(x.encode("ascii") for x in target.qname.split("."))
    return classify_reply(reply, query_id, labels)


def _probe(
    target: Target, started: float, now: Callable[[], float], dns: DnsFn, connect: ConnectFn
) -> Result:
    try:
        error = _attempt(target, dns, connect)
    except OSError as exc:
        error = _exception_class(target.kind, exc)
    latency = max(0, min(MAX_LATENCY_MS, round((now() - started) * 1000)))
    return Result(error is None, latency, error)


# ---------------------------------------------------------------- hysteresis
def _day(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d")


def _record(ts: TargetState, result: Result, t: float) -> TargetState:
    entry = (int(t // 60), result.ok, result.latency_ms if result.ok else None, result.error_class)
    day = _day(t)
    if ts.episodes_day != day:
        ts = replace(ts, episodes_day=day, episodes_today=0, flapping=False)
    return replace(
        ts,
        last_attempt=t,
        ring=(*ts.ring, entry)[-RING:],
        last_latency_ms=result.latency_ms if result.ok else ts.last_latency_ms,
    )


def _on_ok(ts: TargetState, t: float) -> TargetState:
    streak = min(ts.consecutive_ok + 1, MAX_COUNT)
    recovered = ts.state != "outage" or streak >= RECOVER_AFTER
    return replace(
        ts,
        consecutive_fail=0,
        consecutive_ok=streak,
        last_ok_at=t,
        state="ok" if recovered else "outage",
    )


def _on_fail(ts: TargetState, error: str | None, t: float) -> TargetState:
    streak = min(ts.consecutive_fail + 1, MAX_COUNT)
    ts = replace(ts, consecutive_ok=0, consecutive_fail=streak, last_error_class=error)
    if ts.state == "outage" or streak < OPEN_AFTER:
        return ts
    capped = ts.episodes_today >= MAX_EPISODES_PER_DAY
    return replace(
        ts,
        state="outage",
        episode_start=int(t),
        flapping=capped,
        episodes_today=ts.episodes_today if capped else ts.episodes_today + 1,
    )


def _apply(ts: TargetState, result: Result, t: float) -> TargetState:
    recorded = _record(ts, result, t)
    return _on_ok(recorded, t) if result.ok else _on_fail(recorded, result.error_class, t)


# ---------------------------------------------------------------- one pass
def _due(ts: TargetState, t: float) -> tuple[bool, str | None]:
    if ts.last_attempt is None:
        return True, None
    gap = t - ts.last_attempt
    if gap < -CLOCK_STEP_S:
        return True, "clock_step"
    return gap >= MIN_INTERVAL_S, None


def _step(
    target: Target,
    ts: TargetState,
    start: float,
    now: Callable[[], float],
    dns: DnsFn,
    connect: ConnectFn,
) -> TargetState:
    t = now()
    due, note = _due(ts, t)
    if not due:
        return ts
    if t - start + target.timeout_s > DEADLINE_S:
        return replace(ts, note="skipped_deadline")
    result = _probe(target, t, now, dns, connect)
    after = _apply(replace(ts, note=note), result, t)
    if not result.ok:
        log.info("probe_failed id=%s error_class=%s", target.id, result.error_class)
    if after.state != ts.state and "outage" in (after.state, ts.state):
        log.warning("probe_state id=%s state=%s", target.id, after.state)
    return after


def run_pass(
    cfg: ProbeConfig,
    state: State,
    *,
    now: Callable[[], float],
    dns: DnsFn,
    connect: ConnectFn,
) -> State:
    """One bounded pass over the allowlisted targets. No-op (state returned as is) when disabled.

    Only ids in `cfg` survive into the result; anything else in `state` is dropped unprobed."""
    if not cfg.enabled:
        return state
    prior = {t.id: t for t in state.targets}
    start = now()
    stepped = tuple(
        _step(t, prior.get(t.id, new_target_state(t.id)), start, now, dns, connect)
        for t in cfg.targets
    )
    return State(written_at=now(), targets=stepped)


# ---------------------------------------------------------------- state document
_TARGET_KEYS = frozenset(TargetState.__dataclass_fields__)


def _target_doc(ts: TargetState) -> dict[str, object]:
    doc: dict[str, object] = {k: getattr(ts, k) for k in _TARGET_KEYS}
    doc["ring"] = [list(entry) for entry in ts.ring]
    return doc


def serialize_state(state: State) -> bytes:
    doc = {
        "v": STATE_VERSION,
        "written_at": state.written_at,
        "targets": [_target_doc(t) for t in state.targets],
    }
    data = json.dumps(doc, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()
    if len(data) > MAX_STATE_BYTES:
        raise ProbeError("state document too large")
    return data


def _num(value: object, high: float, *, integer: bool = False, none_ok: bool = False) -> None:
    if value is None and none_ok:
        return
    kinds = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kinds):
        raise ValueError("bad number")
    if not (0 <= value <= high) or (isinstance(value, float) and not math.isfinite(value)):
        raise ValueError("number out of range")


def _check_ring(ring: object) -> Ring:
    if not isinstance(ring, list) or len(ring) > RING:
        raise ValueError("bad ring")
    out = []
    for entry in ring:
        if not isinstance(entry, list) or len(entry) != 4:
            raise ValueError("bad ring entry")
        minute, ok, latency, error = entry
        _num(minute, MAX_EPOCH, integer=True)
        _num(latency, MAX_LATENCY_MS, integer=True, none_ok=True)
        if type(ok) is not bool or (error is not None and error not in ERROR_CLASSES):
            raise ValueError("bad ring entry")
        out.append((minute, ok, latency, error))
    return tuple(out)


def _target_from_doc(doc: object) -> TargetState:
    if not isinstance(doc, dict) or set(doc) != _TARGET_KEYS:
        raise ValueError("bad target")
    _num(doc["consecutive_fail"], MAX_COUNT, integer=True)
    _num(doc["consecutive_ok"], MAX_COUNT, integer=True)
    _num(doc["episodes_today"], MAX_COUNT, integer=True)
    _num(doc["last_ok_at"], MAX_EPOCH, none_ok=True)
    _num(doc["last_attempt"], MAX_EPOCH, none_ok=True)
    _num(doc["episode_start"], MAX_EPOCH, integer=True, none_ok=True)
    _num(doc["last_latency_ms"], MAX_LATENCY_MS, integer=True, none_ok=True)
    day, error = doc["episodes_day"], doc["last_error_class"]
    valid = (
        isinstance(doc["id"], str)
        and doc["state"] in STATES
        and type(doc["flapping"]) is bool
        and (doc["note"] is None or doc["note"] in NOTES)
        and (error is None or error in ERROR_CLASSES)
        and (day is None or (isinstance(day, str) and DAY_RE.fullmatch(day) is not None))
    )
    if not valid:
        raise ValueError("bad target field")
    return TargetState(**{**doc, "ring": _check_ring(doc["ring"])})


def state_from_bytes(data: bytes, cfg: ProbeConfig) -> State | None:
    """Strictly parse a state document; None when it is not exactly what serialize_state writes.
    Targets that are not in the config allowlist are dropped."""
    if len(data) > MAX_STATE_READ:
        return None
    try:
        doc = json.loads(data.decode("utf-8"))
        if not isinstance(doc, dict) or set(doc) != {"v", "written_at", "targets"}:
            return None
        if doc["v"] != STATE_VERSION or not isinstance(doc["targets"], list):
            return None
        if len(doc["targets"]) > MAX_TARGETS:
            return None
        _num(doc["written_at"], MAX_EPOCH)
        targets = tuple(_target_from_doc(t) for t in doc["targets"])
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    if len({t.id for t in targets}) != len(targets):
        return None
    allowed = {t.id for t in cfg.targets}
    return State(float(doc["written_at"]), tuple(t for t in targets if t.id in allowed))


# ---------------------------------------------------------------- files, lock, one run
def read_state(path: str, cfg: ProbeConfig) -> State:
    """Fresh state when the file is missing or invalid; ProbeError if it cannot be opened safely."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return empty_state()
    except OSError as exc:
        raise ProbeError("cannot open the state file") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProbeError("state file must be a regular file")
        data = stream.read(MAX_STATE_READ + 1)
    state = state_from_bytes(data, cfg)
    if state is None:
        log.warning("probe_state_invalid; starting fresh")
        return empty_state()
    return state


def _fsync_directory(path: str) -> None:
    dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def write_state(path: str, state: State) -> None:
    """Atomic: unique temp file (O_EXCL) + fsync + rename + directory fsync. Mode 0600."""
    payload = serialize_state(state)
    tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                log.debug("temporary state file already gone")
            raise
        _fsync_directory(os.path.dirname(path) or ".")
    except OSError as exc:
        raise ProbeError("cannot write the state file") from exc


def acquire_lock(path: str) -> int | None:
    """Exclusive non-blocking lock; None when another run holds it."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ProbeError("cannot open the lock file") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        os.close(fd)
        raise ProbeError("lock file must be a regular file we own with a single link")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except OSError as exc:
        os.close(fd)
        raise ProbeError("cannot lock the lock file") from exc
    return fd


def run_once(
    cfg: ProbeConfig, *, now: Callable[[], float], dns: DnsFn, connect: ConnectFn
) -> State | None:
    """Lock, load, one pass, atomic write. None (and no I/O at all) when disabled; None when
    another run holds the lock."""
    if not cfg.enabled:
        return None
    lock = acquire_lock(cfg.state_file + ".lock")
    if lock is None:
        return None
    try:
        state = run_pass(cfg, read_state(cfg.state_file, cfg), now=now, dns=dns, connect=connect)
        write_state(cfg.state_file, state)
        return state
    finally:
        os.close(lock)
