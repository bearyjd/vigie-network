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
from collections.abc import Callable

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.logs import log
from vigie_pipeline.probe_file import (
    FUTURE_SKEW_S,
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
MAX_OUTAGES_PER_DAY = 3  # the runner caps episodes at 3 per day; the reader enforces it too
EVENT_KINDS = ("probe_outage", "probe_recovered", "probe_flapping", "probe_stale")


_last_invalid: str | None = None  # the reason last logged, so a persistent fault logs once


def _remember_invalid(reason: str | None) -> None:
    global _last_invalid
    if reason is not None and reason != _last_invalid:
        log(logger, logging.WARNING, "probe_file_invalid", reason=reason)
    _last_invalid = reason


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


def _status_doc(doc: ProbeDoc | None, reason: str | None, now: float) -> dict[str, object]:
    return {
        "v": STATUS_VERSION,
        "folded_at": int(now),
        "stale": doc is None,
        "reason": reason,
        "written_at": doc.written_at if doc else None,
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


def _outages_today(inv: sqlite3.Connection, ident: str, now: float) -> int:
    prefix = f"{ident}:"
    row = inv.execute(
        "SELECT COUNT(*) FROM events WHERE kind='probe_outage' AND substr(dedup, 1, ?)=?"
        " AND substr(ts, 1, 10)=?",
        (len(prefix), prefix, iso_utc(now)[:10]),
    ).fetchone()
    return int(row[0])


def _emit_outage(inv: sqlite3.Connection, t: ProbeTarget, token: str, now: float) -> None:
    if event_exists(inv, "probe_outage", token):
        return
    if _outages_today(inv, t.id, now) >= MAX_OUTAGES_PER_DAY:
        return  # the writer's own cap is not trusted: at most 3 reported per target per day
    summary = f"probe {t.id} failing ({t.last_error_class or 'unknown'})"
    emit_once(inv, None, "probe_outage", "warn", summary, token, now)


def _emit_target_events(inv: sqlite3.Connection, t: ProbeTarget, day: str, now: float) -> None:
    if t.episodes_day != day:
        return  # not today's data (relative to written_at): the writer's day cannot be trusted
    if t.flapping:
        summary = f"probe {t.id}: repeated outages today, further episodes are not reported"
        _emit(inv, "probe_flapping", "warn", summary, f"{t.id}:{t.episodes_day}", now)
    if t.suppressed or t.episode_start is None:
        return  # a suppressed episode never emits open or recover
    token = _token(t)
    if t.state == "outage":
        _emit_outage(inv, t, token, now)
    elif t.state == "ok" and event_exists(inv, "probe_outage", token):
        _emit(inv, "probe_recovered", "info", f"probe {t.id} recovered", token, now)


def _orphan_reason(target: ProbeTarget | None, start: str) -> str | None:
    if target is None:
        return "removed"
    newer = target.episode_start is not None and target.episode_start > int(start)
    return "superseded" if newer else None


def _close_orphans(inv: sqlite3.Connection, doc: ProbeDoc, now: float) -> None:
    """An open probe_outage whose target was removed, or whose episode was replaced by a newer
    one the pipeline never saw recover, is closed so the history always ends."""
    present = {t.id: t for t in doc.targets}
    open_tokens = inv.execute(
        "SELECT o.dedup FROM events o WHERE o.kind='probe_outage' AND NOT EXISTS"
        " (SELECT 1 FROM events r WHERE r.kind='probe_recovered' AND r.dedup=o.dedup)"
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


def _fold(inv: sqlite3.Connection, doc: ProbeDoc | None, reason: str | None, now: float) -> None:
    with immediate(inv):
        _store_status(inv, _status_doc(doc, reason, now))
        if doc is None:  # unavailable: one warning per UTC day (any cause), never an outage
            _emit(inv, "probe_stale", "warn", f"probe data unavailable ({reason})",
                  iso_utc(now)[:10], now)  # fmt: skip
            return
        _close_orphans(inv, doc, now)
        day = iso_utc(doc.written_at)[:10]
        for target in doc.targets:
            _emit_target_events(inv, target, day, now)


def fold_probes(
    inv: sqlite3.Connection, settings: ProbeSettings, clock: Callable[[], float]
) -> None:
    """Never raises: a failure is logged and the pipeline pass carries on."""
    try:
        now = clock()
        doc, reason = load_probe_doc(settings, now)
        _fold(inv, doc, reason, now)
    except Exception as exc:  # noqa: BLE001 -- the probe stage must never abort run_once
        log(logger, logging.ERROR, "probe_stage_failed", error=type(exc).__name__)
