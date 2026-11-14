"""Fold the probe unit's state file into pipeline_meta['probe_status'] and `probe_*` events.

Writes ONLY that one pipeline_meta key and events rows of kind probe_outage / probe_recovered /
probe_flapping / probe_stale (device_id NULL, deduplicated by (kind, dedup)). It touches no
measurement, coverage or incident table, so the monitoring detectors and their policy version are
unaffected. Not an incident and never delivered.

The file is untrusted (probe_file.py). A missing, malformed, oversize, future-dated or stale file
means "probes unavailable": status says so, no outage or recovery is ever derived from it.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import replace

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.logs import log
from vigie_pipeline.probe_file import (
    FUTURE_SKEW_S,
    MAX_TARGETS,
    ProbeDoc,
    ProbeFileInvalid,
    ProbeTarget,
    parse_probe_doc,
    read_probe_bytes,
)
from vigie_pipeline.stitch_db import emit_once, event_exists

logger = logging.getLogger("vigie_pipeline")
STATUS_KEY = "probe_status"
STATUS_VERSION = 1
MAX_STATUS_BYTES = 32 * 1024
MAX_GLOBAL_OUTAGES_PER_DAY = 30  # MAX_TARGETS * 3: ids rotating through a writer cannot exceed it
MAX_FLAPPING_PER_DAY = 10
MAX_ORPHANS_PER_PASS = 100
ORPHAN_WINDOW_S = 30 * 86400  # only recent unclosed outages are scanned
# An episode older than this is never reported: the writer picks episode_start, and with it the cap
# bucket, so only the last week's buckets (7 x the per-day caps) can ever be filled.
MAX_CAPPED_IDS_LOGGED = 2 * MAX_TARGETS  # distinct capped ids named per (kind, day)
EMIT_MAX_AGE_S = 7 * 86400
LEDGER_WINDOW_S = EMIT_MAX_AGE_S + 3 * 86400  # every bucket an emittable episode can fall in
MAX_OUTAGES_PER_DAY = 3  # the runner caps episodes at 3 per day; the reader enforces it too
EVENT_KINDS = ("probe_outage", "probe_recovered", "probe_flapping", "probe_stale")

# Log memory (module state): a persistent fault logs once per change, not on every 30 s pass.
_last_invalid: str | None = None
_last_unavailable: str | None = None
# (kind, UTC day) -> ids already named; the first MAX_CAPPED_IDS_LOGGED per key, then one summary.
_capped_logged: dict[tuple[str, str], set[str]] = {}
_capped_suppressed: set[tuple[str, str]] = set()


def _reset_log_memory() -> None:
    global _last_invalid, _last_unavailable
    _last_invalid = _last_unavailable = None
    _capped_logged.clear()
    _capped_suppressed.clear()


def _remember_invalid(reason: str | None) -> None:
    global _last_invalid
    if reason is not None and reason != _last_invalid:
        log(logger, logging.WARNING, "probe_file_invalid", reason=reason)
    _last_invalid = reason


def _remember_unavailable(reason: str | None) -> None:
    global _last_unavailable
    if reason is not None and reason != _last_unavailable:
        log(logger, logging.WARNING, "probe_unavailable", reason=reason)
    _last_unavailable = reason


def _note_capped(kind: str, ident: str, now: float) -> None:
    """Names each capped id once per (kind, day), up to MAX_CAPPED_IDS_LOGGED ids, then logs one
    'suppressed' line: a writer rotating ids cannot make the log or this memory grow."""
    day = iso_utc(now)[:10]
    for old in [k for k in _capped_logged if k[1] != day]:
        del _capped_logged[old]
    for old_key in [k for k in _capped_suppressed if k[1] != day]:
        _capped_suppressed.discard(old_key)
    key = (kind, day)
    named = _capped_logged.setdefault(key, set())
    if ident in named:
        return
    if len(named) < MAX_CAPPED_IDS_LOGGED:
        named.add(ident)
        log(logger, logging.WARNING, "probe_event_capped", kind=kind, id=ident)
    elif key not in _capped_suppressed:
        _capped_suppressed.add(key)
        log(logger, logging.WARNING, "probe_event_capped_suppressed", kind=kind)


def load_probe_doc(settings: ProbeSettings, now: float) -> tuple[ProbeDoc | None, str | None]:
    """(document, None) when fresh and valid, else (None, reason) with reason one of
    missing / invalid / future / stale."""
    assert settings.file is not None  # noqa: S101  (callers gate on settings.enabled)
    try:
        data = read_probe_bytes(settings.file)
        if data is None:
            _remember_invalid(None)
            return None, "missing"
        doc = parse_probe_doc(data)
    except ProbeFileInvalid as exc:
        _remember_invalid(str(exc))
        return None, "invalid"
    _remember_invalid(None)
    if doc.written_at > now + FUTURE_SKEW_S:
        return None, "future"
    if now - doc.written_at > settings.stale_s:
        return None, "stale"
    return doc, None


def _effective(doc: ProbeDoc, stale_s: int) -> ProbeDoc:
    """A target not probed within stale_s of the write (or never) is `unknown`, not its last."""

    def fresh(t: ProbeTarget) -> bool:
        return t.last_attempt is not None and doc.written_at - t.last_attempt <= stale_s

    targets = tuple(t if fresh(t) else replace(t, state="unknown") for t in doc.targets)
    return replace(doc, targets=targets)


def _status_doc(
    doc: ProbeDoc | None, reason: str | None, now: float, stale_s: int
) -> dict[str, object]:
    """valid_until: a reader (S3 /probes) must treat the status as unavailable once now passes it,
    because a stopped pipeline cannot rewrite a status that says ok."""
    return {
        "v": STATUS_VERSION,
        "folded_at": int(now),
        "stale": doc is None,
        "reason": reason,
        "written_at": doc.written_at if doc else None,
        "valid_until": int(doc.written_at + stale_s) if doc else None,
        "targets": [_target_doc(t) for t in doc.targets] if doc else [],
    }


def _target_doc(t: ProbeTarget) -> dict[str, object]:
    return {
        "id": t.id,
        "state": t.state,
        "consecutive_fail": t.consecutive_fail,
        "consecutive_ok": t.consecutive_ok,
        "last_ok_at": t.last_ok_at,
        "last_error_class": t.last_error_class,
        "last_latency_ms": t.last_latency_ms,
        "episode_start": t.episode_start,
        "flapping": t.flapping,
        "suppressed": t.suppressed,
        "ring": [list(entry) for entry in t.ring],
    }


def _token(t: ProbeTarget) -> str:
    return f"{t.id}:{t.episode_start}"


def _emit(inv: sqlite3.Connection, kind: str, severity: str, summary: str, token: str,
          now: float) -> None:  # fmt: skip
    """emit_once, but a lookup first: INSERT OR IGNORE of a duplicate still burns a rowid."""
    if not event_exists(inv, kind, token):
        emit_once(inv, None, kind, severity, summary, token, now)


def _episode_day(start: int) -> str:
    return iso_utc(start)[:10]


def _ledger(inv: sqlite3.Connection, now: float) -> Counter[tuple[str, ...]]:
    """Recent outage and flapping events counted two ways: by the EPISODE's own UTC day (keys
    ('o', id, day), ('O', day), ('f', day)) and by the day the pipeline INSERTED the row (keys
    ('oi', id, day), ('Oi', day), ('fi', day)). The writer picks episode_start, hence the first
    buckets; the insert day is the one it cannot choose, so it is the hard backstop."""
    counts: Counter[tuple[str, ...]] = Counter()
    rows = inv.execute(
        "SELECT kind, dedup, ts FROM events WHERE kind IN ('probe_outage', 'probe_flapping')"
        " AND ts >= ?",
        (iso_utc(now - LEDGER_WINDOW_S),),
    )
    for kind, token, ts in rows:
        ident, _, tail = str(token).rpartition(":")
        inserted = str(ts)[:10]
        if kind == "probe_flapping":
            counts["f", tail] += 1
            counts["fi", inserted] += 1
        elif tail.isdecimal():
            day = _episode_day(int(tail))
            counts["o", ident, day] += 1
            counts["O", day] += 1
            counts["oi", ident, inserted] += 1
            counts["Oi", inserted] += 1
    return counts


def _emit_outage(inv: sqlite3.Connection, t: ProbeTarget, token: str, now: float,
                 ledger: Counter[tuple[str, ...]], late: bool = False) -> None:  # fmt: skip
    if event_exists(inv, "probe_outage", token):
        return
    start = int(t.episode_start or 0)
    day, today = _episode_day(start), iso_utc(now)[:10]
    if (
        start < now - EMIT_MAX_AGE_S
        or ledger["o", t.id, day] >= MAX_OUTAGES_PER_DAY
        or ledger["O", day] >= MAX_GLOBAL_OUTAGES_PER_DAY
        # insert-day backstop: twice the per-day cap, so an episode opened just before midnight
        # and folded just after it (counted on both days) is never refused by a legitimate day
        or ledger["oi", t.id, today] >= 2 * MAX_OUTAGES_PER_DAY
        or ledger["Oi", today] >= 2 * MAX_GLOBAL_OUTAGES_PER_DAY
    ):
        _note_capped("probe_outage", t.id, now)  # the writer's own caps are not trusted
        return
    cls = t.last_error_class or "unknown"
    summary = (
        f"probe {t.id} was failing ({cls}), reported late"
        if late
        else f"probe {t.id} failing ({cls})"
    )
    emit_once(inv, None, "probe_outage", "warn", summary, token, now)
    # only the global counters need updating inside a pass: ids are unique within one document
    ledger["O", day] += 1
    ledger["Oi", today] += 1


def _emit_flapping(inv: sqlite3.Connection, t: ProbeTarget, now: float,
                   ledger: Counter[tuple[str, ...]]) -> None:  # fmt: skip
    token = f"{t.id}:{t.episodes_day}"
    if event_exists(inv, "probe_flapping", token):
        return
    today = iso_utc(now)[:10]
    if (
        ledger["f", str(t.episodes_day)] >= MAX_FLAPPING_PER_DAY
        or ledger["fi", today] >= 2 * MAX_FLAPPING_PER_DAY
    ):
        _note_capped("probe_flapping", t.id, now)
        return
    summary = f"probe {t.id}: repeated outages today, further episodes are not reported"
    emit_once(inv, None, "probe_flapping", "warn", summary, token, now)
    ledger["f", str(t.episodes_day)] += 1
    ledger["fi", today] += 1


def _emit_target_events(inv: sqlite3.Connection, t: ProbeTarget, day: str, now: float,
                        ledger: Counter[tuple[str, ...]]) -> None:  # fmt: skip
    if t.state == "unknown" or t.episodes_day != day:
        return  # not fresh data (relative to written_at): nothing is derived from it
    if t.flapping:
        _emit_flapping(inv, t, now, ledger)
    if t.suppressed or t.episode_start is None:
        return  # a suppressed episode never emits open or recover
    token = _token(t)
    if t.state == "outage":
        _emit_outage(inv, t, token, now, ledger)
    elif t.state == "ok":
        if t.episode_start >= now - EMIT_MAX_AGE_S:  # an episode first seen already recovered
            _emit_outage(inv, t, token, now, ledger, late=True)
        if event_exists(inv, "probe_outage", token):
            _emit(inv, "probe_recovered", "info", f"probe {t.id} recovered", token, now)


def _orphan_reason(target: ProbeTarget | None, start: str) -> str | None:
    """Why an open outage is closed: its target is gone, or the target's current episode is a
    different one (newer, older after a clock step, or none after a fresh runner start)."""
    if target is None:
        return "removed"
    return "superseded" if target.episode_start != int(start) else None


def _close_orphans(inv: sqlite3.Connection, doc: ProbeDoc, now: float) -> None:
    """Close open outages whose episode is no longer the target's current one, so the history ends
    and at most one unclosable row per target (its current episode) can remain."""
    present = {t.id: t for t in doc.targets}
    open_tokens = inv.execute(
        "SELECT o.dedup FROM events o WHERE o.kind='probe_outage' AND o.ts >= ? AND NOT EXISTS"
        " (SELECT 1 FROM events r WHERE r.kind='probe_recovered' AND r.dedup=o.dedup)"
        " ORDER BY o.ts LIMIT ?",
        (iso_utc(now - ORPHAN_WINDOW_S), MAX_ORPHANS_PER_PASS),
    ).fetchall()
    for (token,) in open_tokens:
        ident, _, start = str(token).rpartition(":")
        if not start.isdecimal():
            continue
        reason = _orphan_reason(present.get(ident), start)
        if reason is not None:
            _emit(inv, "probe_recovered", "info", f"probe {ident} recovered ({reason})", token, now)


def _store_status(inv: sqlite3.Connection, status: dict[str, object]) -> None:
    """Upsert, unless only folded_at differs from what is stored (an idle pass writes nothing)."""
    text = json.dumps(status, separators=(",", ":"), sort_keys=True)
    if len(text) > MAX_STATUS_BYTES:
        raise ValueError("probe status exceeds its size bound")
    row = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (STATUS_KEY,)).fetchone()
    if row is not None:
        try:
            old = json.loads(row[0])
        except ValueError:
            old = None
        if isinstance(old, dict) and {**old, "folded_at": 0} == {**status, "folded_at": 0}:
            return
    inv.execute(
        "INSERT INTO pipeline_meta (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (STATUS_KEY, text),
    )


def _fold(inv: sqlite3.Connection, doc: ProbeDoc | None, reason: str | None, now: float,
          stale_s: int) -> None:  # fmt: skip
    with immediate(inv):
        _store_status(inv, _status_doc(doc, reason, now, stale_s))
        if doc is None:  # unavailable: one warning per UTC day (any cause), never an outage
            _emit(inv, "probe_stale", "warn", f"probe data unavailable ({reason})",
                  iso_utc(now)[:10], now)  # fmt: skip
            return
        _close_orphans(inv, doc, now)
        day = iso_utc(doc.written_at)[:10]
        ledger = _ledger(inv, now)
        for target in doc.targets:
            _emit_target_events(inv, target, day, now, ledger)


def fold_probes(
    inv: sqlite3.Connection, settings: ProbeSettings, clock: Callable[[], float]
) -> None:
    """Never raises. A failed fold marks the stored status unavailable ("error") instead of
    leaving the previous one, which may say ok, standing."""
    try:
        now = clock()
        doc, reason = load_probe_doc(settings, now)
        _remember_unavailable(reason)
        if doc is not None:
            doc = _effective(doc, settings.stale_s)
        _fold(inv, doc, reason, now, settings.stale_s)
    except Exception as exc:  # noqa: BLE001 -- the probe stage must never abort run_once
        log(logger, logging.ERROR, "probe_stage_failed", error=type(exc).__name__)
        try:
            _fold(inv, None, "error", clock(), settings.stale_s)
        except Exception as again:  # noqa: BLE001
            log(logger, logging.ERROR, "probe_status_unmarked", error=type(again).__name__)


def retire_status(inv: sqlite3.Connection, clock: Callable[[], float]) -> None:
    """Probes were turned off: a stored status must not keep saying ok. Marks it unavailable
    ("disabled") once; when none was ever stored this is a read only and writes nothing."""
    try:
        if inv.execute("SELECT 1 FROM pipeline_meta WHERE key=?", (STATUS_KEY,)).fetchone() is None:
            return
        with immediate(inv):
            _store_status(inv, _status_doc(None, "disabled", clock(), 0))
    except Exception as exc:  # noqa: BLE001
        log(logger, logging.ERROR, "probe_retire_failed", error=type(exc).__name__)
