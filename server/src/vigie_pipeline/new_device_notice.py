"""F5: a bounded sweep that opens ONE `new_device` incident per genuinely new, durable device.

DEFAULT OFF (`PipelineConfig.new_device_notice`): with the flag off the processor never calls this
module, so nothing is read or written. Eligibility (docs/monitoring.md): the first MAC is not
randomized; it persisted like a promotion candidate (>= PROMOTE_MIN_HOURS distinct server hours and
`transient_min_dwell_s`) measured from the server-anchored `mac_first_received` to the last
`mac_activity` end MINUS ACTIVITY_SKEW_S: a collector stamp may lead its batch's receipt by that
much, so `end - skew` never exceeds the true receipt time and clock skew cannot manufacture dwell or
a second server hour; it was created AFTER the floor (below); it is not stitched into, and has not
absorbed, an older or an already-noticed device; a collector measured it. At most
`new_device_max_per_day` notices per UTC day, at most SWEEP_MAX devices handled per run, in creation
order.

Floor ("new since enable"): `f5_floor` is the highest `events.seq` ever issued when the sweep was
(re-)enabled. Every device gets exactly one `new_device` event at creation (unique per device,
`uq_events_new_device`), and `events.seq` is AUTOINCREMENT: server-assigned, monotonic, never
reused or renumbered. A `devices` rowid is not safe: that table has a TEXT primary key, so VACUUM
may renumber its rowids. A device is "new" iff its `new_device` event has seq > floor. No wall
clock and no collector stamp takes part, so a stale collector timestamp cannot make a new device
look old and a clock step cannot lower the floor; a returning old device keeps its old event and
stays excluded. Processing order, not receipt time, is the definition: a device whose batch is
processed after the floor was set counts as new even if the batch was received earlier (a lagging
pipeline).

The floor moves forward to the newest event when the sweep did not run for more than the gap
(max(RESUME_GAP_S, 4 x the configured pass interval): the flag was switched off and on again, the
pipeline or its overrides store was down, or the clock stepped forward by more than that) or its
stored state is unreadable or above the issued sequence. It is NOT watertight for short gaps: a
toggle or outage shorter than the gap keeps the old floor, so devices that arrived and dwelled in
that window are noticed. The last-run stamp is written in its own small transaction before the
work, so passes that fail (a contained exception streak) still count as runs. When the clock steps
BACK (last run in the future) the pass opens nothing, changes no floor and re-bases `f5_last_run`.
`f5_enabled_since` (epoch of the last floor move) is informational.

Scan cursor: `f5_scan_cursor` is the highest creation-event seq up to which every device is
DECIDED (noticed, skipped, or first MAC randomized, i.e. never eligible). It only advances over a
contiguous run of decided devices (at most SCAN_ADVANCE events per pass) and stops at the first
undecided one (not yet dwelled, unmeasured, backed off, held), so no undecided device is skipped.
The candidate query starts above max(floor, cursor); a floor move resets it to the floor.

Probe rotation: when every device of a run's slice fails its lineage, a store problem is told apart
from per-device failures by probing REFERENCE_PROBES other devices, starting after the persisted
`f5_probe_cursor` and wrapping, so a healthy device is found within ceil(devices / probes) passes.

Hold age: a device that is eligible but not noticed (daily cap) is dropped once it has been held
HOLD_MAX_AGE_S. The age starts at the first pass where the device was among the first FETCH_MAX
candidates (`f5_eligible:<device_id>`, written for those in one bulk statement and deleted when the
device is noticed, skipped, backed off or no longer a candidate: a bounded scan of at most
2 * FETCH_MAX stamps and expired backoffs per run; a floor move leaves no candidate, so it empties
the stamps the same way). A device behind more than FETCH_MAX candidates is stamped when it enters
that window.

Once per device life: `pipeline_meta` key `f5_noticed:<device_id>` is written in the SAME
transaction as the incident. The `new_device` event cannot be that guard: it exists for every
device. `f5_skipped:<device_id>` marks a device that is never noticed (merged, or dropped as stale);
it is permanent. A failing lineage is NOT a skip: `f5_retry:<device_id>` = `count|retry_after`
backs it off (1 h doubling to 24 h) and removes it from the candidate selection meanwhile. The
incident id is random (sha256 of 16 random bytes): never derived from the MAC or the device.

The incident row is bytes-centric: observed/threshold are 0 and the evidence carries the data. It
holds no MAC, hostname, vendor or IP. The upload engine never touches it. Closing: a decision of
`acknowledged` or `expected` in overrides.db resolves it here (the API never writes inventory.db).
Nothing else closes it; no recover is ever sent (delivery_types.OPEN_ONLY_DETECTORS). Per-pass
cost: O(events above the scan cursor), plus at most FETCH_MAX candidates, SCAN_ADVANCE decided
rows examined and SWEEP_MAX lineage lookups, in three small write transactions (floor, open,
close).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import ACTIVITY_SKEW_S, PipelineConfig
from vigie_pipeline.detectors import NEW_DEVICE
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_identity import Lineage, LineageUnavailable, lineage
from vigie_pipeline.overrides import QUIET_STATUSES, decided_incident_ids
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = NEW_DEVICE
SWEEP_MAX = 20  # devices handled per run
FETCH_MAX = 200  # candidates read and hold-stamped per run
CLOSE_MAX = 200  # open incidents examined per run for an owner decision (cursor-rotated)
PROMOTE_MIN_HOURS = 2  # keep equal to processor.PROMOTE_MIN_HOURS (asserted by a test)
RESUME_GAP_S = 900  # least gap: max(this, 4 x the pass interval) without a run = re-enable/outage
HOLD_MAX_AGE_S = 72 * 3600  # a candidate held this long by the cap is dropped
RETRY_BASE_S = 3600  # first lineage backoff; doubles per failure up to RETRY_MAX_S
RETRY_MAX_S = 86400
REFERENCE_PROBES = 8  # devices tried to tell a store problem from a per-device lineage failure
SCAN_ADVANCE = 2000  # events examined per pass when advancing the scan cursor
SINCE_KEY = "f5_enabled_since"  # informational: epoch of the last floor move
FLOOR_KEY = "f5_floor"
LAST_RUN_KEY = "f5_last_run"
CLOSE_CURSOR_KEY = "f5_close_cursor"
SCAN_KEY = "f5_scan_cursor"  # every device with a creation event up to here is decided
PROBE_KEY = "f5_probe_cursor"  # last reference device probed (a device id)
NOTICED = "f5_noticed:"  # + device id; value = UTC ISO timestamp of the notice
SKIPPED = "f5_skipped:"  # + device id; value = "<ISO> <reason>"; permanent
RETRY = "f5_retry:"  # + device id; value = "<failures>|<retry after, epoch>"
ELIGIBLE = "f5_eligible:"  # + device id; value = epoch of the first pass it was a candidate
DROPPED = "f5_dropped:"  # + UTC day; value = stale drops that day (older days are cleaned)

_SELECT = (
    "SELECT d.id AS id, o.mac AS mac, mf.received AS received,"  # noqa: S608
    f' (SELECT MAX("end") FROM mac_activity a WHERE a.mac=o.mac) - {int(ACTIVITY_SKEW_S)}'
    " AS last_end"
)
_FROM = (
    " FROM events e JOIN devices d ON d.id=e.device_id"
    " JOIN observations o ON o.device_id=d.id AND o.mac=("
    "  SELECT o2.mac FROM observations o2 WHERE o2.device_id=d.id ORDER BY o2.first_seen, o2.mac"
    "  LIMIT 1)"
    " JOIN mac_first_received mf ON mf.mac=o.mac"
    " WHERE e.kind='new_device' AND e.seq>?"
    " AND o.is_randomized=0 AND d.status<>'retired'"
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
FRESH_SQL = f"{_SELECT}{_FROM} AND {_MEASURED} ORDER BY e.seq LIMIT ?"  # noqa: S608
UNMEASURED_SQL = f"SELECT COUNT(*) FROM ({_SELECT}{_FROM} AND NOT {_MEASURED} LIMIT ?)"  # noqa: S608


def _meta(inv: sqlite3.Connection, key: str) -> str | None:
    row = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (key,)).fetchone()
    return None if row is None else row[0]


def _meta_int(inv: sqlite3.Connection, key: str) -> int | None:
    """A stored integer, or None when absent or not an integer (never raises on a bad value)."""
    raw = _meta(inv, key)
    try:
        return None if raw is None else int(raw)
    except ValueError:
        return None


def _put(inv: sqlite3.Connection, key: str, value: str) -> None:
    inv.execute("INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES (?, ?)", (key, value))


def _upper(prefix: str) -> str:
    """Exclusive upper key bound of a prefix range (a primary-key range scan, not a substr scan)."""
    return prefix[:-1] + chr(ord(prefix[-1]) + 1)


def _issued_events(inv: sqlite3.Connection) -> int:
    """The highest events.seq ever issued (AUTOINCREMENT keeps it even after deletions)."""
    row = inv.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()
    return 0 if row is None else int(row[0])


def _gap(config: PipelineConfig) -> int:
    """No sweep run for this long = the flag was off, the pipeline was down, or the clock jumped:
    the floor moves. Derived from the configured pass interval, never below RESUME_GAP_S."""
    return max(RESUME_GAP_S, 4 * config.pass_interval_s)


def _created_between(inv: sqlite3.Connection, low: int, high: int) -> int:
    """Devices created in (low, high]: an upper bound of what a floor move drops (to 1000)."""
    return inv.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE kind='new_device' AND seq>? AND seq<=?"
        " LIMIT 1000)",
        (low, high),
    ).fetchone()[0]


def _floor(inv: sqlite3.Connection, now: float, gap: int) -> int | None:
    """The floor to use this pass, or None when the pass must not open anything (clock stepped
    back). Set at the first run; moved to the newest event when the sweep did not run for more than
    `gap`, or its stored state is unreadable or above the issued sequence; never moved by a
    backward clock step. Runs in its own small transaction, so a pass that fails later still
    counts as a run."""
    floor, last = _meta_int(inv, FLOOR_KEY), _meta_int(inv, LAST_RUN_KEY)
    issued = _issued_events(inv)
    reason = None
    if floor is None or last is None:
        reason = "first_run" if _meta(inv, LAST_RUN_KEY) is None else "invalid_state"
    elif last > now:
        _put(inv, LAST_RUN_KEY, str(int(now)))
        log(logger, logging.WARNING, "new_device_watermark_moved", reason="clock_stepped_back")
        return None
    elif floor > issued:
        reason = "invalid_state"
    elif now - last > gap:
        reason = "resumed"
    if reason:
        pending = _created_between(inv, floor or 0, issued) if reason != "first_run" else 0
        floor = issued
        _put(inv, FLOOR_KEY, str(floor))
        _put(inv, SINCE_KEY, str(int(now)))
        _put(inv, SCAN_KEY, str(floor))
        if reason != "first_run":
            log(
                logger,
                logging.WARNING,
                "new_device_watermark_moved",
                reason=reason,
                pending=pending,
            )
    _put(inv, LAST_RUN_KEY, str(int(now)))
    return floor


def _is_new(inv: sqlite3.Connection, identity: Lineage, device_id: str, floor: int) -> bool:
    """Not stitched into another device; every device of its lineage was created after the floor
    (a device without a creation event fails closed); no member was already noticed (a merge after
    a notice must not produce a second incident)."""
    if identity.device_id != device_id or not identity.macs:
        return False
    marks = ",".join("?" * len(identity.macs))
    total, fresh = inv.execute(
        "SELECT COUNT(DISTINCT o.device_id),"  # noqa: S608
        " COUNT(DISTINCT CASE WHEN e.seq>? THEN o.device_id END)"
        " FROM observations o LEFT JOIN events e"
        " ON e.device_id=o.device_id AND e.kind='new_device'"
        f" WHERE o.mac IN ({marks})",
        (floor, *identity.macs),
    ).fetchone()
    if total != fresh:
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


def _stamp(inv: sqlite3.Connection, rows: list[sqlite3.Row], now: float) -> None:
    """Hold age: one bulk write stamping every candidate read this run (at most FETCH_MAX), and a
    bounded cleanup of stamps and expired backoffs of devices that are no longer candidates."""
    inv.executemany(
        "INSERT OR IGNORE INTO pipeline_meta (key, value) VALUES (?, ?)",
        [(ELIGIBLE + r["id"], str(int(now))) for r in rows],
    )
    live = {r["id"] for r in rows}
    stamps = inv.execute(
        "SELECT key FROM pipeline_meta WHERE key>=? AND key<? LIMIT ?",
        (ELIGIBLE, _upper(ELIGIBLE), 2 * FETCH_MAX),
    ).fetchall()
    gone = [(k[0],) for k in stamps if k[0][len(ELIGIBLE) :] not in live]
    retries = inv.execute(
        "SELECT key, CAST(substr(value, instr(value, '|') + 1) AS INTEGER) FROM pipeline_meta"
        " WHERE key>=? AND key<? LIMIT ?",
        (RETRY, _upper(RETRY), 2 * FETCH_MAX),
    ).fetchall()
    gone += [(k,) for k, until in retries if until <= now and k[len(RETRY) :] not in live]
    inv.executemany("DELETE FROM pipeline_meta WHERE key=?", gone)


def _lineage_failed(inv: sqlite3.Connection, device_id: str, now: float) -> None:
    """Back the device off (never skip it): 1 h, doubling per failure, at most 24 h. While backed
    off it is no candidate, so `_stamp` drops its hold stamp: the age restarts when it resolves."""
    raw = _meta(inv, RETRY + device_id) or ""
    try:
        count = int(raw.split("|")[0]) + 1
    except ValueError:
        count = 1
    delay = min(RETRY_BASE_S * 2 ** min(count - 1, 10), RETRY_MAX_S)
    _put(inv, RETRY + device_id, f"{count}|{int(now) + delay}")


def _probe_ids(inv: sqlite3.Connection, failed: list[str]) -> list[str]:
    """Up to REFERENCE_PROBES devices after the persisted probe cursor (wrapping around), so
    successive passes walk through every device instead of re-probing the same lowest ids."""
    marks = ",".join("?" * len(failed))
    base = f"SELECT id FROM devices WHERE id NOT IN ({marks})"  # noqa: S608
    cursor = _meta(inv, PROBE_KEY) or ""
    ids = [
        r[0]
        for r in inv.execute(
            base + " AND id>? ORDER BY id LIMIT ?", (*failed, cursor, REFERENCE_PROBES)
        )
    ]
    if len(ids) < REFERENCE_PROBES:
        more = inv.execute(
            base + " AND id<=? ORDER BY id LIMIT ?", (*failed, cursor, REFERENCE_PROBES - len(ids))
        )
        ids += [r[0] for r in more]
    return ids


def _systemic(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection | None,
    failed: list[str],
    resolved_here: bool,
) -> bool:
    """A failure is the store's, not the device's, when some other device resolved in this run or
    on a probe of REFERENCE_PROBES devices; the probe window rotates a persisted cursor through all
    devices, so a healthy device is found within ceil(devices / REFERENCE_PROBES) passes and the
    failing batch is then backed off. With none that resolves (or none to compare) nobody is
    blamed and nobody is backed off."""
    if resolved_here:
        return False
    ids = _probe_ids(inv, failed)
    if ids:
        _put(inv, PROBE_KEY, ids[-1])
    for device_id in ids:
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
    total = (_meta_int(inv, key) or 0) + count
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


def _params(floor: int, config: PipelineConfig, now: float, *extra: int) -> tuple:
    return (
        floor,
        NOTICED,
        SKIPPED,
        RETRY,
        int(now),
        config.transient_min_dwell_s,
        PROMOTE_MIN_HOURS,
        *extra,
    )


def _classify(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection | None,
    row: sqlite3.Row,
    floor: int,
    now: float,
) -> tuple[str, Lineage | None]:
    """failed (lineage unavailable) | merged | stale (held too long) | ready."""
    try:
        identity = lineage(inv, ov, row["id"])
    except LineageUnavailable:
        return "failed", None
    if not _is_new(inv, identity, row["id"], floor):
        return "merged", None
    stamp = _meta_int(inv, ELIGIBLE + row["id"])
    if stamp is not None and now - stamp > HOLD_MAX_AGE_S:
        return "stale", None
    return "ready", identity


def _report(
    inv: sqlite3.Connection, config: PipelineConfig, now: float, counts: dict[str, int]
) -> None:
    """Events and logs of one pass: the cap (held), stale drops, lineage failures, unmeasured."""
    day = iso_utc(now)[:10]
    if counts["dropped"]:
        _record_dropped(inv, day, counts["dropped"], now)
    if counts["held"]:  # only a reached cap holds a device back
        cap = config.new_device_max_per_day
        emit_once(
            inv,
            None,
            "new_device_capped",
            "warn",
            f"new-device notice cap {cap}/day reached; "
            f"{counts['held']} held (counted up to {FETCH_MAX})",
            day,
            now,
        )
        log(logger, logging.INFO, "new_device_capped", held=counts["held"], day=day)
    if counts["failed"]:
        log(logger, logging.WARNING, "new_device_lineage_unavailable", devices=counts["failed"])
    if counts["unmeasured"]:  # eligible but no collector measured them: they wait, with a trace
        log(logger, logging.INFO, "new_device_unmeasured", devices=counts["unmeasured"])


def _handle(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection | None,
    rows: list[sqlite3.Row],
    floor: int,
    now: float,
    room: int,
) -> tuple[int, dict[str, int]]:
    """Classify the first SWEEP_MAX candidates: open, hold, drop, skip or back off."""
    counts = {"dropped": 0, "held": 0, "failed": 0, "unmeasured": 0}
    failed: list[str] = []
    opened = 0
    for row in rows[:SWEEP_MAX]:
        verdict, identity = _classify(inv, ov, row, floor, now)
        if verdict == "failed":
            failed.append(row["id"])
        elif verdict in ("merged", "stale"):
            _skip(inv, row["id"], now, verdict)
            counts["dropped"] += verdict == "stale"
        elif room <= 0:
            counts["held"] += 1
        else:
            _open_incident(inv, row, identity, now)
            room, opened = room - 1, opened + 1
    if failed and not _systemic(inv, ov, failed, len(failed) < len(rows[:SWEEP_MAX])):
        for device_id in failed:
            _lineage_failed(inv, device_id, now)
    if room <= 0:
        counts["held"] += max(0, len(rows) - SWEEP_MAX)
    counts["failed"] = len(failed)
    return opened, counts


def _advance_cursor(inv: sqlite3.Connection, start: int) -> None:
    """Move the scan cursor past the contiguous run of DECIDED devices after `start`: noticed,
    skipped, whose first MAC is randomized (never eligible), or with no observations at all
    (the candidate query joins observations, so such a device can never match: a pruned or
    stitch-orphaned device would otherwise pin the cursor for good). It stops at the first undecided
    device (not yet dwelled, unmeasured, backed off, held), so nothing undecided is ever skipped;
    at most SCAN_ADVANCE events are examined per pass."""
    rows = inv.execute(
        "SELECT e.seq, EXISTS (SELECT 1 FROM pipeline_meta p"
        " WHERE p.key IN (? || e.device_id, ? || e.device_id))"
        " OR COALESCE((SELECT o.is_randomized FROM observations o WHERE o.device_id=e.device_id"
        " ORDER BY o.first_seen, o.mac LIMIT 1), 1)=1"
        " FROM events e WHERE e.kind='new_device' AND e.seq>? ORDER BY e.seq LIMIT ?",
        (NOTICED, SKIPPED, start, SCAN_ADVANCE),
    ).fetchall()
    cursor = start
    for seq, decided in rows:
        if not decided:
            break
        cursor = seq
    if cursor != start:
        _put(inv, SCAN_KEY, str(cursor))


def _open_new_incidents(
    inv: sqlite3.Connection, ov: sqlite3.Connection | None, config: PipelineConfig, now: float
) -> int:
    with immediate(inv):  # its own small transaction: a failing pass below still counts as a run
        floor = _floor(inv, now, _gap(config))
    if floor is None:
        return 0
    with immediate(inv):
        scan = max(floor, _meta_int(inv, SCAN_KEY) or 0)  # devices at or below it are decided
        used = inv.execute(
            "SELECT COUNT(*) FROM pipeline_meta WHERE key>=? AND key<? AND substr(value,1,10)=?",
            (NOTICED, _upper(NOTICED), iso_utc(now)[:10]),
        ).fetchone()[0]
        rows = inv.execute(FRESH_SQL, _params(scan, config, now, FETCH_MAX)).fetchall()
        _stamp(inv, rows, now)
        room = max(0, config.new_device_max_per_day - used)
        opened, counts = _handle(inv, ov, rows, floor, now, room)
        counts["unmeasured"] = inv.execute(
            UNMEASURED_SQL, _params(scan, config, now, SWEEP_MAX)
        ).fetchone()[0]
        _report(inv, config, now, counts)
        _advance_cursor(inv, scan)
    return opened


def _close_reviewed(inv: sqlite3.Connection, ov: sqlite3.Connection | None) -> int:
    """Owner reviewed it (acknowledged/expected): leave the open state. Snoozed and cleared
    decisions keep it open. A persisted cursor walks the open incidents CLOSE_MAX at a time, so
    neither old unreviewed ones nor old closed decisions can starve a newer review."""
    if ov is None:
        return 0
    with immediate(inv):
        after = _meta_int(inv, CLOSE_CURSOR_KEY) or 0
        batch = inv.execute(
            "SELECT seq, id FROM monitoring_incidents WHERE detector=? AND state='open'"
            " AND seq>? ORDER BY seq LIMIT ?",
            (DETECTOR, after, CLOSE_MAX),
        ).fetchall()
        _put(inv, CLOSE_CURSOR_KEY, str(batch[-1][0] if len(batch) == CLOSE_MAX else 0))
        if not batch:
            return 0
        ids = [r[1] for r in batch]
        try:
            reviewed = decided_incident_ids(ov, ids, QUIET_STATUSES)
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
    Returns the number opened. Any Exception (a database error, a bad stored value, a bug) is
    logged by class name only and contained at this boundary: it never fails the pass, and the
    close step still runs when the open step failed."""
    opened = 0
    for step in ("open", "close"):
        try:
            if step == "open":
                opened = _open_new_incidents(inv, ov, config, now)
            else:
                _close_reviewed(inv, ov)
        except Exception as exc:  # noqa: BLE001 - the sweep must never fail the pipeline pass
            log(
                logger,
                logging.ERROR,
                "new_device_sweep_failed",
                step=step,
                error=type(exc).__name__,
            )
    return opened
