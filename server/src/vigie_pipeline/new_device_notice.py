"""F5: a bounded sweep that opens ONE `new_device` incident per genuinely new, durable device.

DEFAULT OFF (`PipelineConfig.new_device_notice`): with the flag off the processor never calls this
module, so nothing is read or written. Eligibility (docs/monitoring.md): the first MAC is not
randomized; it persisted like a promotion candidate (>= PROMOTE_MIN_HOURS distinct server hours and
`transient_min_dwell_s`, read from the server-anchored `mac_first_received` and the receipt-clamped
`mac_activity`, so collector-supplied stamps cannot fake persistence); it first arrived after the
`f5_enabled_since` watermark; it is not stitched into, and has not absorbed, an older or an
already-noticed device; a collector measured it. At most `new_device_max_per_day` notices per UTC
day, at most SWEEP_MAX devices read per run, in (first_seen, id) order.

Watermark: set at the first enabled run and MOVED to `now` whenever the sweep has not run for
RESUME_GAP_S (flag switched off and on again, or a pipeline outage): devices that arrived while the
sweep was not running never notify (a missed notice beats a spurious one). `f5_last_run` records
the last run.

Once per device life: `pipeline_meta` key `f5_noticed:<device_id>` is written in the SAME
transaction as the incident. The `new_device` event cannot be that guard: it exists for every
device. `f5_skipped:<device_id>` marks a device that is never noticed (merged, stale, or its
lineage keeps failing); it is permanent. The incident id is random (sha256 of 16 random bytes):
never derived from the MAC or the device.

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
from vigie_pipeline.monitoring_identity import Lineage, LineageUnavailable, lineage
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = "new_device"
SWEEP_MAX = 20  # devices handled per run
CLOSE_MAX = 200  # open incidents examined per run for an owner decision (cursor-rotated)
PROMOTE_MIN_HOURS = 2  # keep equal to processor.PROMOTE_MIN_HOURS (asserted by a test)
RESUME_GAP_S = 6 * 3600  # no sweep for longer than this = re-enabled or outage: watermark moves
HOLD_MAX_AGE_S = 72 * 3600  # an eligible device not noticed this long after it could be is dropped
LINEAGE_RETRIES = 3  # consecutive LineageUnavailable results before a device is skipped
WATERMARK_KEY = "f5_enabled_since"
LAST_RUN_KEY = "f5_last_run"
CLOSE_CURSOR_KEY = "f5_close_cursor"
NOTICED = "f5_noticed:"  # + device id; value = UTC ISO timestamp of the notice
SKIPPED = "f5_skipped:"  # + device id; value = "<ISO> <reason>"; permanent
RETRY = "f5_retry:"  # + device id; value = consecutive lineage failures
QUIET = ("acknowledged", "expected")  # incident_decisions.status values that close the incident

_SELECT = (
    "SELECT d.id AS id, o.mac AS mac, mf.received AS received,"
    ' (SELECT MAX("end") FROM mac_activity a WHERE a.mac=o.mac) AS last_end'
)
_FROM = (
    " FROM devices d JOIN observations o ON o.device_id=d.id AND o.mac=("
    "  SELECT o2.mac FROM observations o2 WHERE o2.device_id=d.id ORDER BY o2.first_seen, o2.mac"
    "  LIMIT 1)"
    " JOIN mac_first_received mf ON mf.mac=o.mac"
    " WHERE o.is_randomized=0 AND d.status<>'retired' AND d.first_seen>=?"
    " AND NOT EXISTS (SELECT 1 FROM pipeline_meta p WHERE p.key IN (? || d.id, ? || d.id))"
    " AND last_end - mf.received >= ?"
    " AND last_end/3600 - mf.received/3600 + 1 >= ?"
)
# The collector set is tiny and measurements_hourly's primary key starts with collector_id, so
# both probes are index seeks (a bare `WHERE mac=?` would scan the table once per candidate).
_MEASURED = (
    "EXISTS (SELECT 1 FROM collectors c WHERE EXISTS (SELECT 1 FROM measurements_hourly m"
    " WHERE m.collector_id=c.id AND m.mac=o.mac))"
)
_COLLECTOR = (
    "SELECT c.id FROM collectors c WHERE EXISTS (SELECT 1 FROM measurements_hourly m"
    " WHERE m.collector_id=c.id AND m.mac=?) ORDER BY c.id LIMIT 1"
)
STALE_SQL = _SELECT + _FROM + " AND mf.received<? ORDER BY d.first_seen, d.id LIMIT ?"
FRESH_SQL = (
    _SELECT
    + _FROM
    + " AND mf.received>=? AND "
    + _MEASURED
    + " ORDER BY d.first_seen, d.id LIMIT ?"
)
UNMEASURED_SQL = (
    f"SELECT COUNT(*) FROM ({_SELECT}{_FROM} AND mf.received>=? AND NOT {_MEASURED} LIMIT ?)"  # noqa: S608
)


def _meta(inv: sqlite3.Connection, key: str) -> str | None:
    row = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (key,)).fetchone()
    return None if row is None else row[0]


def _put(inv: sqlite3.Connection, key: str, value: str) -> None:
    inv.execute("INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES (?, ?)", (key, value))


def _watermark(inv: sqlite3.Connection, now: float) -> int:
    """Set at the first run; moved to `now` when the sweep did not run for RESUME_GAP_S, so a
    flag that was off (or an outage) never back-fills. `f5_last_run` only moves forward."""
    since, last = _meta(inv, WATERMARK_KEY), _meta(inv, LAST_RUN_KEY)
    if since is None or last is None or now - int(last) > RESUME_GAP_S:
        since = str(int(now))
        _put(inv, WATERMARK_KEY, since)
    _put(inv, LAST_RUN_KEY, str(max(int(now), int(last)) if last is not None else int(now)))
    return int(since)


def _is_new(inv: sqlite3.Connection, identity: Lineage, device_id: str, since: int) -> bool:
    """Not stitched into another device; every MAC of its lineage first reached the server after
    the watermark (an unanchored MAC fails closed); no member was already noticed (a merge after
    a notice must not produce a second incident)."""
    if identity.device_id != device_id or not identity.macs:
        return False
    marks = ",".join("?" * len(identity.macs))
    fresh = inv.execute(
        f"SELECT COUNT(*) FROM mac_first_received WHERE received>=? AND mac IN ({marks})",  # noqa: S608
        (since, *identity.macs),
    ).fetchone()[0]
    if fresh != len(identity.macs):
        return False
    noticed = inv.execute(
        "SELECT COUNT(*) FROM observations o JOIN pipeline_meta p ON p.key = ? || o.device_id"  # noqa: S608
        f" WHERE o.mac IN ({marks})",
        (NOTICED, *identity.macs),
    ).fetchone()[0]
    return noticed == 0


def _open_incident(
    inv: sqlite3.Connection, row: sqlite3.Row, identity: Lineage, now: float
) -> None:
    collector = inv.execute(_COLLECTOR, (row["mac"],)).fetchone()[0]
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
        (hashlib.sha256(uuid.uuid4().bytes).hexdigest(), collector, identity.device_id,
         identity.key, DETECTOR, hour, hour, iso_utc(now), json.dumps(evidence, sort_keys=True)),
    )  # fmt: skip
    inv.execute(
        "INSERT INTO pipeline_meta (key, value) VALUES (?, ?)",
        (NOTICED + identity.device_id, iso_utc(now)),
    )


def _skip(inv: sqlite3.Connection, device_id: str, now: float, reason: str) -> None:
    _put(inv, SKIPPED + device_id, f"{iso_utc(now)} {reason}")
    inv.execute("DELETE FROM pipeline_meta WHERE key=?", (RETRY + device_id,))


def _lineage_failed(inv: sqlite3.Connection, device_id: str, now: float) -> None:
    count = int(_meta(inv, RETRY + device_id) or 0) + 1
    if count >= LINEAGE_RETRIES:
        _skip(inv, device_id, now, "lineage_unavailable")
    else:
        _put(inv, RETRY + device_id, str(count))


def _systemic(inv: sqlite3.Connection, ov: sqlite3.Connection | None, failed: list[str]) -> bool:
    """A lineage failure that also hits a reference device (or has none to compare) is a store
    problem, not the device's: nobody is blamed, so nothing is skipped for good."""
    marks = ",".join("?" * len(failed))
    ref = inv.execute(
        f"SELECT id FROM devices WHERE id NOT IN ({marks}) ORDER BY id LIMIT 1",  # noqa: S608
        failed,
    ).fetchone()
    if ref is None:
        return True
    try:
        lineage(inv, ov, ref[0])
    except LineageUnavailable:
        return True
    return False


def _params(since: int, config: PipelineConfig, *extra: int) -> tuple:
    return (
        iso_utc(since),
        NOTICED,
        SKIPPED,
        config.transient_min_dwell_s,
        PROMOTE_MIN_HOURS,
        *extra,
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
        cutoff = int(now - HOLD_MAX_AGE_S - config.transient_min_dwell_s)
        stale = inv.execute(STALE_SQL, _params(since, config, cutoff, SWEEP_MAX)).fetchall()
        for row in stale:  # eligible long ago and never noticed: dropped, not announced late
            _skip(inv, row["id"], now, "stale")
        rows = inv.execute(FRESH_SQL, _params(since, config, cutoff, SWEEP_MAX + 1)).fetchall()
        opened, held, failed = 0, len(stale), []
        for row in rows[:SWEEP_MAX]:
            if room <= 0:
                held += 1
                continue
            try:
                identity = lineage(inv, ov, row["id"])
            except LineageUnavailable:
                failed.append(row["id"])
                continue
            if not _is_new(inv, identity, row["id"], since):
                _skip(inv, row["id"], now, "merged")
                continue
            _open_incident(inv, row, identity, now)
            room, opened = room - 1, opened + 1
        if failed and not _systemic(inv, ov, failed):
            for device_id in failed:
                _lineage_failed(inv, device_id, now)
        held += max(0, len(rows) - SWEEP_MAX)
        if held:
            emit_once(
                inv,
                None,
                "new_device_capped",
                "warn",
                f"new-device notice cap {config.new_device_max_per_day}/day reached; "
                f"{held} held or dropped (counted up to {SWEEP_MAX + 1})",
                day,
                now,
            )
            log(logger, logging.INFO, "new_device_capped", held=held, day=day)
        if failed:
            log(logger, logging.WARNING, "new_device_lineage_unavailable", devices=len(failed))
        unmeasured = inv.execute(
            UNMEASURED_SQL, _params(since, config, cutoff, SWEEP_MAX)
        ).fetchone()[0]
        if unmeasured:  # eligible but no collector measured them: they wait, with a trace
            log(logger, logging.INFO, "new_device_unmeasured", devices=unmeasured)
    return opened


def _close_reviewed(inv: sqlite3.Connection, ov: sqlite3.Connection | None) -> int:
    """Owner reviewed it (acknowledged/expected): leave the open state. Snoozed and cleared
    decisions keep it open. A persisted cursor walks the open incidents CLOSE_MAX at a time, so
    neither old unreviewed ones nor old closed decisions can starve a newer review."""
    if ov is None:
        return 0
    with immediate(inv):
        after = int(_meta(inv, CLOSE_CURSOR_KEY) or 0)
        batch = inv.execute(
            "SELECT seq, id FROM monitoring_incidents WHERE detector=? AND state='open'"
            " AND seq>? ORDER BY seq LIMIT ?",
            (DETECTOR, after, CLOSE_MAX),
        ).fetchall()
        _put(inv, CLOSE_CURSOR_KEY, str(batch[-1][0] if len(batch) == CLOSE_MAX else 0))
        if not batch:
            return 0
        ids = [r[1] for r in batch]
        marks = ",".join("?" * len(ids))
        quiet = ",".join("?" * len(QUIET))
        try:
            reviewed = [
                r[0]
                for r in ov.execute(
                    f"SELECT incident_id FROM incident_decisions WHERE status IN ({quiet})"  # noqa: S608
                    f" AND incident_id IN ({marks})",
                    (*QUIET, *ids),
                )
            ]
        except sqlite3.Error as exc:
            log(logger, logging.ERROR, "new_device_close_failed", error=type(exc).__name__)
            return 0
        if not reviewed:
            return 0
        return inv.execute(
            "UPDATE monitoring_incidents SET state='resolved' WHERE detector=? AND state='open'"  # noqa: S608
            f" AND id IN ({','.join('?' * len(reviewed))})",
            (DETECTOR, *reviewed),
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
