"""Read the probe unit's state file as UNTRUSTED input (it is written outside this container).

Strict: size cap before parsing, exact shape, every id/enum/number re-validated. Anything that is
not exactly what deploy/persistent/probe_runner.py writes is `invalid`; the caller treats invalid,
missing, stale and future-dated files alike as "probes unavailable", never as ok or an outage.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 64 * 1024
MAX_TARGETS = 10
RING = 60
MAX_COUNT = 1000
MAX_EPOCH = 1e11
MAX_LATENCY_MS = 5000
# The runner keeps an episode's original episode_start (the dedup token) across a backward clock
# step while writing the corrected written_at, so episode_start may exceed written_at by the size of
# the step. A day covers an NTP or manual correction; anything further out is not a real step.
MAX_CLOCK_STEP_S = 86400
FUTURE_SKEW_S = 10.0  # host and container share one clock: a bigger lead is not a real write time
STATE_VERSION = 1
ID_RE = re.compile(r"[a-z0-9_-]{1,32}")
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
STATES = frozenset({"unknown", "ok", "outage"})
ERROR_CLASSES = frozenset(
    {"malformed", "bad_id", "rcode", "no_answer", "timeout", "oserror", "refused", "unreachable",
     "other"}
)  # fmt: skip
NOTES = frozenset({"skipped_deadline", "clock_step"})
TARGET_KEYS = frozenset(
    {"id", "state", "consecutive_fail", "consecutive_ok", "last_ok_at", "last_error_class",
     "last_latency_ms", "episode_start", "last_attempt", "ring", "episodes_day", "episodes_today",
     "flapping", "suppressed", "note"}
)  # fmt: skip

Ring = tuple[tuple[int, bool, int | None, str | None], ...]


@dataclass(frozen=True)
class ProbeTarget:
    id: str
    state: str
    consecutive_fail: int
    consecutive_ok: int
    last_ok_at: float | None
    last_error_class: str | None
    last_latency_ms: int | None
    episode_start: int | None
    episodes_day: str | None
    flapping: bool
    suppressed: bool
    ring: Ring


@dataclass(frozen=True)
class ProbeDoc:
    written_at: float
    targets: tuple[ProbeTarget, ...]


class ProbeFileInvalid(Exception):
    """Fixed-message: the file is not exactly the documented state document."""


def _member(value: object, allowed: frozenset[str]) -> bool:
    """Membership of an untrusted value: a list or dict must be False, never a TypeError."""
    return isinstance(value, str) and value in allowed


def _num(value: object, high: float, *, integer: bool = False, none_ok: bool = False) -> None:
    if value is None and none_ok:
        return
    kinds = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kinds):
        raise ProbeFileInvalid("bad number")
    if not (0 <= value <= high) or (isinstance(value, float) and not math.isfinite(value)):
        raise ProbeFileInvalid("number out of range")


def _ring(ring: object) -> Ring:
    if not isinstance(ring, list) or len(ring) > RING:
        raise ProbeFileInvalid("bad ring")
    out = []
    for entry in ring:
        if not isinstance(entry, list) or len(entry) != 4:
            raise ProbeFileInvalid("bad ring entry")
        minute, ok, latency, error = entry
        _num(minute, MAX_EPOCH, integer=True)
        _num(latency, MAX_LATENCY_MS, integer=True, none_ok=True)
        if type(ok) is not bool or (error is not None and not _member(error, ERROR_CLASSES)):
            raise ProbeFileInvalid("bad ring entry")
        out.append((minute, ok, latency, error))
    return tuple(out)


def _target(doc: object) -> ProbeTarget:
    if not isinstance(doc, dict) or set(doc) != TARGET_KEYS:
        raise ProbeFileInvalid("bad target")
    for key in ("consecutive_fail", "consecutive_ok", "episodes_today"):
        _num(doc[key], MAX_COUNT, integer=True)
    for key in ("last_ok_at", "last_attempt"):
        _num(doc[key], MAX_EPOCH, none_ok=True)
    _num(doc["episode_start"], MAX_EPOCH, integer=True, none_ok=True)
    _num(doc["last_latency_ms"], MAX_LATENCY_MS, integer=True, none_ok=True)
    ident, error, day = doc["id"], doc["last_error_class"], doc["episodes_day"]
    valid = (
        isinstance(ident, str)
        and ID_RE.fullmatch(ident) is not None
        and _member(doc["state"], STATES)
        and type(doc["flapping"]) is bool
        and type(doc["suppressed"]) is bool
        and (doc["note"] is None or _member(doc["note"], NOTES))
        and (error is None or _member(error, ERROR_CLASSES))
        and (day is None or (isinstance(day, str) and DAY_RE.fullmatch(day) is not None))
    )
    if not valid:
        raise ProbeFileInvalid("bad target field")
    return ProbeTarget(
        id=ident, state=doc["state"], consecutive_fail=doc["consecutive_fail"],
        consecutive_ok=doc["consecutive_ok"], last_ok_at=doc["last_ok_at"],
        last_error_class=error, last_latency_ms=doc["last_latency_ms"],
        episode_start=doc["episode_start"], episodes_day=day, flapping=doc["flapping"],
        suppressed=doc["suppressed"], ring=_ring(doc["ring"]),
    )  # fmt: skip


def parse_probe_doc(data: bytes) -> ProbeDoc:
    """Raise ProbeFileInvalid, and nothing else, unless `data` is exactly a state document
    (size checked first)."""
    try:
        return _parse(data)
    except ProbeFileInvalid:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        raise ProbeFileInvalid("malformed document") from None


def _parse(data: bytes) -> ProbeDoc:
    if len(data) > MAX_FILE_BYTES:
        raise ProbeFileInvalid("file too large")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProbeFileInvalid("not valid JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"v", "written_at", "targets"}:
        raise ProbeFileInvalid("bad document")
    if type(doc["v"]) is not int or doc["v"] != STATE_VERSION:
        raise ProbeFileInvalid("unsupported version")
    if not isinstance(doc["targets"], list) or len(doc["targets"]) > MAX_TARGETS:
        raise ProbeFileInvalid("bad targets")
    _num(doc["written_at"], MAX_EPOCH)
    targets = tuple(_target(t) for t in doc["targets"])
    if len({t.id for t in targets}) != len(targets):
        raise ProbeFileInvalid("duplicate target id")
    limit = doc["written_at"] + MAX_CLOCK_STEP_S
    if any(t.episode_start is not None and t.episode_start > limit for t in targets):
        raise ProbeFileInvalid("episode starts too far after the file was written")
    return ProbeDoc(float(doc["written_at"]), targets)


def read_probe_bytes(path: Path) -> bytes | None:
    """At most MAX_FILE_BYTES+1 bytes of a regular file; None when it does not exist.
    O_NONBLOCK|O_NOFOLLOW: a FIFO or symlink cannot hang or redirect the pipeline."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError:
        raise ProbeFileInvalid("cannot open") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ProbeFileInvalid("not a regular file")
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        try:
            return stream.read(MAX_FILE_BYTES + 1)
        except OSError:
            raise ProbeFileInvalid("cannot read") from None
