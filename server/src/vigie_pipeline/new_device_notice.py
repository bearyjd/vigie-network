"""F5: a bounded sweep that opens ONE `new_device` incident per genuinely new, durable device.

DEFAULT OFF (`PipelineConfig.new_device_notice`): with the flag off the processor never calls this
module, so nothing is read or written. Eligibility (docs/monitoring.md): the first MAC is not
randomized; it persisted like a promotion candidate (>= PROMOTE_MIN_HOURS server hours and
`transient_min_dwell_s`, read from the server-anchored `mac_first_received` and the receipt-clamped
`mac_activity`, so collector-supplied stamps cannot fake persistence); it first arrived after the
once-set `f5_enabled_since` watermark; it is not stitched into, and has not absorbed, an older
device; a collector measured it. At most `new_device_max_per_day` notices per UTC day, at most
SWEEP_MAX devices read per run, in (first_seen, id) order.

Once per device life: `pipeline_meta` key `f5_noticed:<device_id>` is written in the SAME
transaction as the incident. The `new_device` event cannot be that guard: it exists for every
device, noticed or not. The incident id is random (sha256 of 16 random bytes): never derived from
the MAC or the device, so the notification link cannot be linked to either.

The incident row is bytes-centric: observed/threshold are 0 and the evidence carries the data. It
holds no MAC, hostname, vendor or IP. The upload engine never touches it. Closing: a decision of
`acknowledged` or `expected` in overrides.db resolves it here (the API never writes inventory.db).
Nothing else closes it; no recover is ever sent (delivery_types.OPEN_ONLY_DETECTORS).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_identity import LineageUnavailable, lineage
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = "new_device"
SWEEP_MAX = 20  # devices handled per run
CLOSE_MAX = 200  # recent owner decisions examined per run
PROMOTE_MIN_HOURS = 2  # keep equal to processor.PROMOTE_MIN_HOURS (asserted by a test)
WATERMARK_KEY = "f5_enabled_since"
NOTICED = "f5_noticed:"  # + device id; value = UTC ISO timestamp of the notice
SKIPPED = "f5_skipped:"  # + device id; merged into/over another device: never a new device
QUIET = ("acknowledged", "expected")  # incident_decisions.status values that close the incident

_CANDIDATES = (
    "SELECT d.id AS id, mf.received AS received, d.first_seen AS first_seen,"
    ' (SELECT MAX("end") FROM mac_activity a WHERE a.mac=o.mac) AS last_end,'
    " (SELECT m.collector_id FROM measurements_hourly m WHERE m.mac=o.mac"
    "  ORDER BY m.hour, m.collector_id LIMIT 1) AS collector"
    " FROM devices d JOIN observations o ON o.device_id=d.id AND o.mac=("
    "  SELECT o2.mac FROM observations o2 WHERE o2.device_id=d.id ORDER BY o2.first_seen, o2.mac"
    "  LIMIT 1)"
    " JOIN mac_first_received mf ON mf.mac=o.mac"
    " WHERE o.is_randomized=0 AND d.status<>'retired' AND d.first_seen>=? AND mf.received>=?"
    " AND NOT EXISTS (SELECT 1 FROM pipeline_meta p WHERE p.key IN (? || d.id, ? || d.id))"
    " AND last_end - mf.received >= ?"
    " AND last_end/3600 - mf.received/3600 + 1 >= ?"
    " AND collector IS NOT NULL"
    " ORDER BY d.first_seen, d.id LIMIT ?"
)


def _watermark(inv: sqlite3.Connection, now: float) -> int:
    """Set once, at the first enabled run, and never moved: existing devices never notify."""
    inv.execute(
        "INSERT OR IGNORE INTO pipeline_meta (key, value) VALUES (?, ?)",
        (WATERMARK_KEY, str(int(now))),
    )
    return int(
        inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (WATERMARK_KEY,)).fetchone()[0]
    )


def _is_new(inv: sqlite3.Connection, identity, device_id: str, since: int) -> bool:
    """Not stitched into an older device and has absorbed none: every MAC of its lineage first
    reached the server after the watermark (an unanchored MAC fails closed)."""
    if identity.device_id != device_id:
        return False
    marks = ",".join("?" * len(identity.macs))
    fresh = inv.execute(
        f"SELECT COUNT(*) FROM mac_first_received WHERE received>=? AND mac IN ({marks})",  # noqa: S608
        (since, *identity.macs),
    ).fetchone()[0]
    return bool(identity.macs) and fresh == len(identity.macs)


def _open_incident(inv: sqlite3.Connection, row, identity, now: float) -> None:
    hour = int(now) // 3600 * 3600
    dwell_hours = (row["last_end"] - row["received"]) // 3600
    evidence = {
        "reason_code": "new_device_first_seen",
        "randomized": False,
        "dwell_hours": dwell_hours,
    }
    inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES (?,?,?,?,?,'open',?,?,?,NULL,0,0,?)",
        (hashlib.sha256(uuid.uuid4().bytes).hexdigest(), row["collector"], identity.device_id,
         identity.key, DETECTOR, hour, hour, iso_utc(now), json.dumps(evidence, sort_keys=True)),
    )  # fmt: skip
    inv.execute(
        "INSERT INTO pipeline_meta (key, value) VALUES (?, ?)",
        (NOTICED + identity.device_id, iso_utc(now)),
    )


def _open_new_incidents(
    inv: sqlite3.Connection, ov: sqlite3.Connection | None, config: PipelineConfig, now: float
) -> int:
    day = iso_utc(now)[:10]
    with immediate(inv):
        since = _watermark(inv, now)
        used = inv.execute(
            "SELECT COUNT(*) FROM pipeline_meta WHERE substr(key,1,?)=? AND substr(value,1,10)=?",
            (len(NOTICED), NOTICED, day),
        ).fetchone()[0]
        room = max(0, config.new_device_max_per_day - used)
        rows = inv.execute(
            _CANDIDATES,
            (iso_utc(since), since, NOTICED, SKIPPED, config.transient_min_dwell_s,
             PROMOTE_MIN_HOURS, SWEEP_MAX + 1),
        ).fetchall()  # fmt: skip
        opened = held = 0
        for row in rows[:SWEEP_MAX]:
            if room <= 0:
                held += 1
                continue
            try:
                identity = lineage(inv, ov, row["id"])
            except LineageUnavailable:
                continue  # retried next run
            if not _is_new(inv, identity, row["id"], since):
                inv.execute("INSERT INTO pipeline_meta (key, value) VALUES (?, ?)",
                            (SKIPPED + row["id"], iso_utc(now)))  # fmt: skip
                continue
            _open_incident(inv, row, identity, now)
            room, opened = room - 1, opened + 1
        held += max(0, len(rows) - SWEEP_MAX)
        if held:
            emit_once(inv, None, "new_device_capped", "warn",
                      f"new-device notice cap {config.new_device_max_per_day}/day reached; "
                      f"{held} held (counted up to {SWEEP_MAX + 1})", day, now)  # fmt: skip
            log(logger, logging.INFO, "new_device_capped", held=held, day=day)
    return opened


def _close_reviewed(inv: sqlite3.Connection, ov: sqlite3.Connection | None) -> int:
    """Owner reviewed it (acknowledged/expected): leave the open state. Snoozed and cleared
    decisions keep it open. Only the most recent CLOSE_MAX decisions are examined per run."""
    if ov is None:
        return 0
    marks = ",".join("?" * len(QUIET))
    try:
        ids = [
            r[0]
            for r in ov.execute(
                "SELECT incident_id FROM incident_decisions WHERE detector=? AND status IN"  # noqa: S608
                f" ({marks}) ORDER BY decided_at DESC, incident_id LIMIT ?",
                (DETECTOR, *QUIET, CLOSE_MAX),
            )
        ]
    except sqlite3.Error:
        return 0  # no decision store yet: nothing was reviewed
    if not ids:
        return 0
    with immediate(inv):
        return inv.execute(
            "UPDATE monitoring_incidents SET state='resolved' WHERE detector=? AND state='open'"  # noqa: S608
            f" AND id IN ({','.join('?' * len(ids))})",
            (DETECTOR, *ids),
        ).rowcount


def sweep_new_devices(
    inv: sqlite3.Connection, ov: sqlite3.Connection | None, config: PipelineConfig, now: float
) -> int:
    """Open at most the daily allowance of new-device incidents and close the reviewed ones.
    Returns the number opened. A database error is logged and contained: it never fails the pass."""
    try:
        opened = _open_new_incidents(inv, ov, config, now)
        _close_reviewed(inv, ov)
    except sqlite3.Error as exc:
        log(logger, logging.ERROR, "new_device_sweep_failed", error=type(exc).__name__)
        return 0
    return opened
