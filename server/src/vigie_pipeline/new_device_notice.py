"""F5: a bounded sweep that opens ONE `new_device` incident per genuinely new, durable device.

DEFAULT OFF (`PipelineConfig.new_device_notice`): with the flag off the processor never calls this
module, so nothing is read or written. Eligibility (docs/monitoring.md): the first MAC is not
randomized; it persisted like a promotion candidate (>= PROMOTE_MIN_HOURS distinct server hours and
`transient_min_dwell_s`) measured from the server-anchored `mac_first_received` to the last
`mac_activity` end MINUS ACTIVITY_SKEW_S: a collector stamp may lead its batch's receipt by that
much, so `end - skew` never exceeds the true receipt time and clock skew cannot manufacture dwell or
a second server hour; it first arrived after the `f5_enabled_since` watermark; it is not stitched
into, and has not absorbed, an older or an already-noticed device; a collector measured it. At most
`new_device_max_per_day` notices per UTC day, at most SWEEP_MAX devices read per run, in
(first_seen, id) order.

Watermark: set at the first enabled run and MOVED to `now` whenever the sweep has not run for
RESUME_GAP_S (flag switched off and on again, or a pipeline outage) or the clock stepped back (the
last run lies in the future). Devices that arrived while the sweep was not running
never notify (a missed notice beats a spurious one). `f5_last_run` records the last run.

Hold age: a device that is eligible but not noticed (daily cap) is dropped once it has been held
HOLD_MAX_AGE_S. The age starts at the first pass where the device was NOTICEABLE (eligibility met,
measured, lineage resolved, not merged), persisted as `f5_eligible:<device_id>` (only for the
<= SWEEP_MAX devices of a run's slice; deleted when the device is noticed or skipped, cleared on a
watermark reset). Ageing from first receipt would drop a device that only qualifies late (back
after days, or measured after days) in the very pass where it first becomes eligible.

Once per device life: `pipeline_meta` key `f5_noticed:<device_id>` is written in the SAME
transaction as the incident. The `new_device` event cannot be that guard: it exists for every
device. `f5_skipped:<device_id>` marks a device that is never noticed (merged, or dropped as stale);
it is permanent. A failing lineage is NOT a skip: `f5_retry:<device_id>` = `count|retry_after`
backs it off (1 h doubling to 24 h) and removes it from the batch selection meanwhile. The incident
id is random (sha256 of 16 random bytes): never derived from the MAC or the device.

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
from vigie_pipeline.config import ACTIVITY_SKEW_S, PipelineConfig
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_identity import Lineage, LineageUnavailable, lineage
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = "new_device"
SWEEP_MAX = 20  # devices handled per run
CLOSE_MAX = 200  # open incidents examined per run for an owner decision (cursor-rotated)
PROMOTE_MIN_HOURS = 2  # keep equal to processor.PROMOTE_MIN_HOURS (asserted by a test)
RESUME_GAP_S = 6 * 3600  # no sweep for longer than this = re-enabled or outage: watermark moves
HOLD_MAX_AGE_S = 72 * 3600  # a noticeable device held this long by the cap is dropped
RETRY_BASE_S = 3600  # first lineage backoff; doubles per failure up to RETRY_MAX_S
RETRY_MAX_S = 86400
REFERENCE_PROBES = 8  # devices tried to tell a store problem from a per-device lineage failure
WATERMARK_KEY = "f5_enabled_since"
LAST_RUN_KEY = "f5_last_run"
CLOSE_CURSOR_KEY = "f5_close_cursor"
NOTICED = "f5_noticed:"  # + device id; value = UTC ISO timestamp of the notice
SKIPPED = "f5_skipped:"  # + device id; value = "<ISO> <reason>"; permanent
RETRY = "f5_retry:"  # + device id; value = "<failures>|<retry after, epoch>"
ELIGIBLE = "f5_eligible:"  # + device id; value = epoch of the first noticeable pass
DROPPED = "f5_dropped:"  # + UTC day; value = stale drops that day (older days are cleaned)
QUIET = ("acknowledged", "expected")  # incident_decisions.status values that close the incident

_SELECT = (
    "SELECT d.id AS id, o.mac AS mac, mf.received AS received,"  # noqa: S608
    f' (SELECT MAX("end") FROM mac_activity a WHERE a.mac=o.mac) - {int(ACTIVITY_SKEW_S)}'
    " AS last_end"
)
_FROM = (
    " FROM devices d JOIN observations o ON o.device_id=d.id AND o.mac=("
    "  SELECT o2.mac FROM observations o2 WHERE o2.device_id=d.id ORDER BY o2.first_seen, o2.mac"
    "  LIMIT 1)"
    " JOIN mac_first_received mf ON mf.mac=o.mac"
    " WHERE o.is_randomized=0 AND d.status<>'retired' AND d.first_seen>=?"
    " AND NOT EXISTS (SELECT 1 FROM pipeline_meta p WHERE p.key IN (? || d.id, ? || d.id))"
    " AND NOT EXISTS (SELECT 1 FROM pipeline_meta r WHERE r.key = ? || d.id"
    "  AND CAST(substr(r.value, instr(r.value, '|') + 1) AS INTEGER) > ?)"
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
FRESH_SQL = f"{_SELECT}{_FROM} AND {_MEASURED} ORDER BY d.first_seen, d.id LIMIT ?"  # noqa: S608
UNMEASURED_SQL = f"SELECT COUNT(*) FROM ({_SELECT}{_FROM} AND NOT {_MEASURED} LIMIT ?)"  # noqa: S608


def _meta(inv: sqlite3.Connection, key: str) -> str | None:
    row = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (key,)).fetchone()
    return None if row is None else row[0]


def _put(inv: sqlite3.Connection, key: str, value: str) -> None:
    inv.execute("INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES (?, ?)", (key, value))


def _upper(prefix: str) -> str:
    """Exclusive upper key bound of a prefix range (a primary-key range scan, not a substr scan)."""
    return prefix[:-1] + chr(ord(prefix[-1]) + 1)


def _clear(inv: sqlite3.Connection, prefix: str) -> None:
    inv.execute("DELETE FROM pipeline_meta WHERE key>=? AND key<?", (prefix, _upper(prefix)))


def _watermark(inv: sqlite3.Connection, now: float) -> int:
    """Set at the first run; moved to `now` when the sweep did not run for RESUME_GAP_S or the
    clock stepped back, so a flag that was off, an outage or a clock step never back-fills and
    never pins the watermark in the future. `f5_last_run` is always `now`."""
    since, last = _meta(inv, WATERMARK_KEY), _meta(inv, LAST_RUN_KEY)
    reason = None
    if since is None or last is None:
        reason = "first_run"
    elif int(last) > now:
        reason = "clock_stepped_back"
    elif now - int(last) > RESUME_GAP_S:
        reason = "resumed"
    if reason:
        since = str(int(now))
        _put(inv, WATERMARK_KEY, since)
        _clear(inv, ELIGIBLE)
        _clear(inv, RETRY)
        if reason != "first_run":
            log(logger, logging.WARNING, "new_device_watermark_moved", reason=reason)
    _put(inv, LAST_RUN_KEY, str(int(now)))
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


def _forget(inv: sqlite3.Connection, device_id: str) -> None:
    inv.execute(
        "DELETE FROM pipeline_meta WHERE key IN (? || ?, ? || ?)",
        (ELIGIBLE, device_id, RETRY, device_id),
    )


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
    _forget(inv, row["id"])


def _skip(inv: sqlite3.Connection, device_id: str, now: float, reason: str) -> None:
    _put(inv, SKIPPED + device_id, f"{iso_utc(now)} {reason}")
    _forget(inv, device_id)


def _noticeable_since(inv: sqlite3.Connection, device_id: str, now: float) -> int:
    """Epoch of the first pass where the device was noticeable (see the module docstring)."""
    inv.execute(
        "INSERT OR IGNORE INTO pipeline_meta (key, value) VALUES (?, ?)",
        (ELIGIBLE + device_id, str(int(now))),
    )
    return int(_meta(inv, ELIGIBLE + device_id))


def _lineage_failed(inv: sqlite3.Connection, device_id: str, now: float) -> None:
    """Back the device off (never skip it): 1 h, doubling per failure, at most 24 h."""
    raw = _meta(inv, RETRY + device_id)
    count = int(raw.split("|")[0]) + 1 if raw else 1
    delay = min(RETRY_BASE_S * 2 ** min(count - 1, 10), RETRY_MAX_S)
    _put(inv, RETRY + device_id, f"{count}|{int(now) + delay}")


def _systemic(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection | None,
    failed: list[str],
    resolved_here: bool,
) -> bool:
    """A failure is the store's, not the device's, when some other device resolved in this run or
    on a probe of up to REFERENCE_PROBES devices; with none that resolves (or none to compare)
    nobody is blamed and nobody is backed off."""
    if resolved_here:
        return False
    marks = ",".join("?" * len(failed))
    others = inv.execute(
        f"SELECT id FROM devices WHERE id NOT IN ({marks}) ORDER BY id LIMIT ?",  # noqa: S608
        (*failed, REFERENCE_PROBES),
    ).fetchall()
    for (device_id,) in others:
        try:
            lineage(inv, ov, device_id)
        except LineageUnavailable:
            continue
        return False
    return True


def _record_dropped(inv: sqlite3.Connection, day: str, count: int, now: float) -> None:
    """One `new_device_dropped` event per UTC day whose summary carries the day's running count
    (no MAC); the counter keys of older days are cleaned."""
    key = DROPPED + day
    total = int(_meta(inv, key) or 0) + count
    _put(inv, key, str(total))
    inv.execute(
        "DELETE FROM pipeline_meta WHERE key>=? AND key<? AND key<>?",
        (DROPPED, _upper(DROPPED), key),
    )
    summary = f"new-device notice: {total} held device(s) dropped as stale today"
    emit_once(inv, None, "new_device_dropped", "warn", summary, day, now)
    inv.execute(
        "UPDATE events SET summary=? WHERE kind='new_device_dropped' AND dedup=?", (summary, day)
    )
    log(logger, logging.WARNING, "new_device_dropped", count=count, day=day)


def _params(since: int, config: PipelineConfig, now: float, *extra: int) -> tuple:
    return (
        iso_utc(since),
        NOTICED,
        SKIPPED,
        RETRY,
        int(now),
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
            "SELECT COUNT(*) FROM pipeline_meta WHERE key>=? AND key<? AND substr(value,1,10)=?",
            (NOTICED, _upper(NOTICED), day),
        ).fetchone()[0]
        room = max(0, config.new_device_max_per_day - used)
        rows = inv.execute(FRESH_SQL, _params(since, config, now, SWEEP_MAX + 1)).fetchall()
        opened = held = dropped = 0
        failed: list[str] = []
        for row in rows[:SWEEP_MAX]:
            try:
                identity = lineage(inv, ov, row["id"])
            except LineageUnavailable:
                failed.append(row["id"])
                continue
            if not _is_new(inv, identity, row["id"], since):
                _skip(inv, row["id"], now, "merged")
                continue
            if now - _noticeable_since(inv, row["id"], now) > HOLD_MAX_AGE_S:
                _skip(inv, row["id"], now, "stale")  # held by the cap too long: dropped, not late
                dropped += 1
                continue
            if room <= 0:
                held += 1
                continue
            _open_incident(inv, row, identity, now)
            room, opened = room - 1, opened + 1
        if failed and not _systemic(inv, ov, failed, len(failed) < len(rows[:SWEEP_MAX])):
            for device_id in failed:
                _lineage_failed(inv, device_id, now)
        if room <= 0:
            held += max(0, len(rows) - SWEEP_MAX)
        if dropped:
            _record_dropped(inv, day, dropped, now)
        if held:  # only a reached cap holds a device back
            emit_once(
                inv,
                None,
                "new_device_capped",
                "warn",
                f"new-device notice cap {config.new_device_max_per_day}/day reached; "
                f"{held} held (counted up to {SWEEP_MAX + 1})",
                day,
                now,
            )
            log(logger, logging.INFO, "new_device_capped", held=held, day=day)
        if failed:
            log(logger, logging.WARNING, "new_device_lineage_unavailable", devices=len(failed))
        unmeasured = inv.execute(UNMEASURED_SQL, _params(since, config, now, SWEEP_MAX)).fetchone()[
            0
        ]
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
