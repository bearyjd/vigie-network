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
EVENT_KINDS = ("probe_outage", "probe_recovered", "probe_flapping", "probe_stale")


def load_probe_doc(settings: ProbeSettings, now: float) -> tuple[ProbeDoc | None, str | None]:
    """(document, None) when fresh and valid, else (None, reason) with reason one of
    missing / invalid / future / stale."""
    assert settings.file is not None  # noqa: S101  (callers gate on settings.enabled)
    try:
        data = read_probe_bytes(settings.file)
        if data is None:
            return None, "missing"
        doc = parse_probe_doc(data)
    except ProbeFileInvalid as exc:
        log(logger, logging.WARNING, "probe_file_invalid", reason=str(exc))
        return None, "invalid"
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


def _emit_target_events(inv: sqlite3.Connection, t: ProbeTarget, now: float) -> None:
    if t.flapping and t.episodes_day is not None:
        emit_once(inv, None, "probe_flapping", "warn",
                  f"probe {t.id}: repeated outages today, further episodes are not reported",
                  f"{t.id}:{t.episodes_day}", now)  # fmt: skip
    if t.suppressed or t.episode_start is None:
        return  # a suppressed episode never emits open or recover
    token = _token(t)
    if t.state == "outage":
        summary = f"probe {t.id} failing ({t.last_error_class or 'unknown'})"
        emit_once(inv, None, "probe_outage", "warn", summary, token, now)
    elif t.state == "ok" and event_exists(inv, "probe_outage", token):
        emit_once(inv, None, "probe_recovered", "info", f"probe {t.id} recovered", token, now)


def _fold(inv: sqlite3.Connection, doc: ProbeDoc | None, reason: str | None, now: float) -> None:
    status = json.dumps(_status_doc(doc, reason, now), separators=(",", ":"), sort_keys=True)
    if len(status) > MAX_STATUS_BYTES:
        raise ValueError("probe status exceeds its size bound")
    with immediate(inv):
        inv.execute(
            "INSERT INTO pipeline_meta (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (STATUS_KEY, status),
        )
        if doc is None:  # unavailable: one warning per UTC day, never an outage
            emit_once(inv, None, "probe_stale", "warn",
                      f"probe data unavailable ({reason})", iso_utc(now)[:10], now)  # fmt: skip
            return
        for target in doc.targets:
            _emit_target_events(inv, target, now)


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
