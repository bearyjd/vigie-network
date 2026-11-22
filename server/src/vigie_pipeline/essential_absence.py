"""F6-b: one `essential_absence` incident when a device the OWNER marked essential is not seen for
its own N hours (`essential_devices.absent_after_s`, 3600..604800) while Vigie could see.

DEFAULT OFF (`PipelineConfig.essential_absence`): with the flag off the processor never calls this
module. With the flag on and nothing marked the sweep reads two small things and writes nothing.
It is STATELESS: no `pipeline_meta` key, watermark, cursor or last-run stamp; every verdict is a
pure function of the stored activity, the stored coverage and the stored incidents, so a clock step
or a pipeline gap cannot leave state behind to go wrong.

Rule (docs/monitoring.md "Essential-device absence (F6)"): for each marked device (at most
MAX_MARKS, read-only overrides.db) resolved to its CURRENT canonical device and lineage:
  anchor  = the newest hour (not later than the next hour: a clock running ahead cannot anchor) of
            ACTIVE evidence of any lineage MAC: a `measurements_hourly` row (flows, DNS). A lease
            or neighbour entry is a SNAPSHOT: an agent restart re-emits every unexpired one stamped
            'now', so `last_seen` never takes part. The collector that measured it newest is the
            judging collector (none: abstain);
  Q = the ELIGIBLE `coverage_hourly` hours of that collector strictly after the anchor and before
      the current hour: qualified >= 3420 s, no reasons, AND no batch of that collector that
      overlaps the hour reported dropped identity or DNS rows (`batches.truncated`: a flood makes
      the collector drop leases/neighbours/sightings/DNS, so the device's rows may be missing, not
      the device). A blind hour (no row, unqualified, flooded) is not counted: the clock pauses,
      it never fires;
  fire iff Q * 3600 >= absent_after_s.
Both sides come from the same batch windows (one collector clock, hour keys), so a constant
offset of THAT collector cancels. Across several collectors the newest-activity comparison assumes
their clocks agree within an hour. The server clock is only a clamp. A lineage whose first MAC is
randomized abstains (a rotating address looks absent): only fixed-address devices are suitable.
`run_once` runs this after the batches are processed and skips it when a shard could not be read.

Episode: the anchor hour is the incident's `episode_start`. One incident per (lineage member,
anchor): an absence is announced once, even after review, unmark/re-mark or a merge. Activity in a
later hour moves the anchor past the episode: the open incident resolves (no recover is ever sent,
delivery_types.OPEN_ONLY_DETECTORS) and a later absence is a new episode. Also resolved: the owner
reviewed it (acknowledged/expected), the mark was cleared, the incident's device is no longer
canonical (merged) or has no MAC left. Unmark-closes are paused when the marks read was
incomplete (more than MAX_MARKS); a mark that cannot be resolved or has an invalid value protects
only ITS device. Merged alias marks are judged on the canonical device; several marks of one
lineage use the smallest threshold. At most MAX_PER_DAY incidents open per UTC day (a held device
stays eligible next pass, so the cap can delay a real absence by up to a day). The incident id is
random, evidence is the fixed shape {reason_code, absent_for_hours, threshold_hours}. Devices that
cannot be judged get an `essential_unjudged` event naming the device (never a MAC): once per mark
version for never-measured/randomized/no-MAC, once per day for the rest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.detectors import ESSENTIAL_ABSENCE
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_identity import Lineage, LineageUnavailable, lineage
from vigie_pipeline.overrides import QUIET_STATUSES, decided_incident_ids
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = ESSENTIAL_ABSENCE
REASON = "essential_absent"
HOUR_S = 3600
MIN_S = 3600  # keep equal to vigie_api.essential.MIN_S / MAX_S / MAX_ESSENTIAL (asserted by a test)
MAX_S = 604800
MAX_MARKS = 32
MAX_PER_DAY = 8
MAX_OPEN = 65  # open incidents examined per run (one more than MAX_MARKS x 2: strays are closed)
ELIGIBLE_S = 3420  # an eligible hour: monitoring_engine's qualified-seconds floor
HOURS_READ = 400  # eligible hours read per device (the longest threshold is 168)
FLOOD_ROWS = 500  # flooded batches read per device
# `batches.truncated` keys that mean identity or DNS rows were dropped before they reached us
FLOOD_KEYS = (
    "leases",
    "neigh",
    "sightings",
    "sightings_dropped",
    "dns",
    "dns_out_of_window",
    "truncated_other",  # a merged count of unknown keys: 'something else was lost'
)
SUMMARIES = {
    "never_measured": "no traffic has ever been measured for it",
    "randomized": "its address is randomized (only fixed-address devices can be judged)",
    "no_known_mac": "no address of it is known",
    "identity_unavailable": "its identity data is unavailable (too many addresses or a bad link)",
    "too_many_marks": "too many essential marks (over 32): unmark-closes are paused",
}
PER_VERSION = ("never_measured", "randomized", "no_known_mac")  # one event per mark version


@dataclass(frozen=True)
class Marks:
    valid: tuple[tuple[str, int, int], ...]  # (device id, threshold s, mark version)
    invalid: tuple[str, ...]  # marked ids with an unusable value
    overflow: bool  # more than MAX_MARKS: some marks were not read


@dataclass(frozen=True)
class Entry:
    identity: Lineage
    secs: int
    version: int


@dataclass(frozen=True)
class Plan:
    closes: tuple[tuple[str, str], ...]  # (incident id, reason)
    opens: tuple[tuple[Lineage, str, int, int, int], ...]  # identity, collector, hour, hours, secs
    unjudged: tuple[tuple[str | None, str, int | None], ...]  # (device id, reason, mark version)
    held: int


def _read_marks(ov: sqlite3.Connection) -> Marks:
    """The marked devices, at most MAX_MARKS; a row outside the bounds or of the wrong type is
    reported as invalid (the database is input), an overflow is flagged."""
    rows = ov.execute(
        "SELECT device_id, absent_after_s, version FROM essential_devices"
        " WHERE absent_after_s IS NOT NULL ORDER BY device_id LIMIT ?",
        (MAX_MARKS + 1,),
    ).fetchall()
    valid, invalid = [], []
    for row in rows[:MAX_MARKS]:
        if not isinstance(row[0], str):
            continue
        if type(row[1]) is int and MIN_S <= row[1] <= MAX_S and type(row[2]) is int:
            valid.append((row[0], row[1], row[2]))
        else:
            invalid.append(row[0])
    if invalid:
        log(logger, logging.WARNING, "essential_absence_bad_marks", ignored=len(invalid))
    return Marks(tuple(valid), tuple(invalid), len(rows) > MAX_MARKS)


def _resolve(
    inv: sqlite3.Connection, ov: sqlite3.Connection, marks: Marks
) -> tuple[dict[str, Entry], set[str], list[tuple[str | None, str, int | None]]]:
    """(canonical device -> entry, canonical devices that are marked but cannot be judged,
    unjudged reports). An unresolvable or invalid mark protects only its own device."""
    entries: dict[str, Entry] = {}
    protected: set[str] = set()
    unjudged: list[tuple[str | None, str, int | None]] = []
    for device_id in marks.invalid:
        try:
            protected.add(lineage(inv, ov, device_id).device_id)
        except LineageUnavailable:
            pass  # its device's lineage is unavailable too: nothing of it is closed
    if marks.overflow:
        unjudged.append((None, "too_many_marks", None))
    for device_id, secs, version in marks.valid:
        try:
            identity = lineage(inv, ov, device_id)
        except LineageUnavailable:
            unjudged.append((device_id, "identity_unavailable", None))
            continue
        if not identity.macs:
            protected.add(identity.device_id)
            unjudged.append((device_id, "no_known_mac", version))
            continue
        old = entries.get(identity.device_id)
        if old is None or secs < old.secs:
            entries[identity.device_id] = Entry(identity, secs, version)
    return entries, protected, unjudged


def _members(inv: sqlite3.Connection, identity: Lineage) -> tuple[str, ...]:
    """Lineage member device ids, from the MAC rows (a merged alias is included)."""
    marks = ",".join("?" * len(identity.macs))
    row = inv.execute(
        f"SELECT GROUP_CONCAT(DISTINCT device_id) FROM observations WHERE mac IN ({marks})",  # noqa: S608
        identity.macs,
    ).fetchone()
    return tuple(sorted({identity.device_id, *(row[0] or "").split(",")} - {""}))


def _anchor(inv: sqlite3.Connection, macs: tuple[str, ...], now: float) -> tuple[str, int] | None:
    """(collector, anchor hour): the newest hour of active evidence of any MAC, over collectors
    (a seek per collector and MAC). An hour after the next one cannot anchor."""
    cap = int(now) // HOUR_S * HOUR_S + HOUR_S
    row = inv.execute(
        "SELECT c.id, (SELECT MAX(m.hour) FROM measurements_hourly m WHERE m.collector_id=c.id"  # noqa: S608
        f" AND m.mac IN ({','.join('?' * len(macs))}) AND m.hour<=?) AS h FROM collectors c"
        " ORDER BY h DESC, c.id LIMIT 1",
        (*macs, cap),
    ).fetchone()
    return (row[0], row[1]) if row and row[1] is not None else None


def _flood_windows(inv: sqlite3.Connection, collector: str, anchor: int) -> list[tuple[int, int]]:
    """Batch windows of the collector that reported dropped identity or DNS rows (or whose
    truncation map is unreadable: unknown is not clean)."""
    test = " OR ".join(f"COALESCE(json_extract(truncated,'$.{key}'),0)>0" for key in FLOOD_KEYS)
    rows = inv.execute(
        "SELECT window_start, window_end FROM batches WHERE collector_id=? AND received_at>=?"  # noqa: S608
        " AND window_start IS NOT NULL AND window_end IS NOT NULL AND truncated IS NOT NULL"
        f" AND truncated<>'{{}}' AND CASE WHEN json_valid(truncated) THEN ({test}) ELSE 1 END"
        " LIMIT ?",
        (collector, iso_utc(anchor - 86400), FLOOD_ROWS),
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def _eligible_hours(inv: sqlite3.Connection, collector: str, anchor: int, now: float) -> int:
    """Eligible hours after the anchor and before the current hour that no flooded batch overlaps
    (read up to HOURS_READ)."""
    hours = [
        r[0]
        for r in inv.execute(
            "SELECT hour FROM coverage_hourly WHERE collector_id=? AND hour>? AND hour<?"
            " AND qualified_seconds>=? AND reasons='[]' ORDER BY hour LIMIT ?",
            (collector, anchor, int(now) // HOUR_S * HOUR_S, ELIGIBLE_S, HOURS_READ),
        )
    ]
    flood = _flood_windows(inv, collector, anchor) if hours else []
    return sum(1 for h in hours if not any(s < h + HOUR_S and e > h for s, e in flood))


def _announced(inv: sqlite3.Connection, members: tuple[str, ...], anchor_hour: int) -> bool:
    """This absence (anchor) was already announced for a lineage member, in any incident state."""
    return (
        inv.execute(
            "SELECT 1 FROM monitoring_incidents WHERE detector=? AND episode_start=?"  # noqa: S608
            " AND collector_id IN (SELECT id FROM collectors)"
            f" AND device_id IN ({','.join('?' * len(members))}) LIMIT 1",
            (DETECTOR, anchor_hour, *members),
        ).fetchone()
        is not None
    )


def _open_ids(inv: sqlite3.Connection, device_id: str) -> set[str]:
    """Open incidents of the device, however many incidents are open overall."""
    return {
        r[0]
        for r in inv.execute(
            "SELECT id FROM monitoring_incidents WHERE detector=? AND state='open'"
            " AND device_id=? LIMIT 8",
            (DETECTOR, device_id),
        )
    }


def _open_rows(inv: sqlite3.Connection) -> list[sqlite3.Row]:
    return inv.execute(
        "SELECT id, device_id, episode_start FROM monitoring_incidents"
        " WHERE detector=? AND state='open' ORDER BY seq LIMIT ?",
        (DETECTOR, MAX_OPEN),
    ).fetchall()


def _reviewed(ov: sqlite3.Connection, rows: list[sqlite3.Row]) -> set[str]:
    """Incidents the owner acknowledged or marked expected. A failure only means none closes."""
    if not rows:
        return set()
    try:
        return set(decided_incident_ids(ov, [r["id"] for r in rows], QUIET_STATUSES))
    except sqlite3.Error as exc:
        log(logger, logging.ERROR, "essential_absence_review_failed", error=type(exc).__name__)
        return set()


def _close_reason(
    inv: sqlite3.Connection,
    row: sqlite3.Row,
    identity: Lineage,
    state: tuple[dict[str, Entry], set[str], bool],
    now: float,
) -> str | None:
    entries, protected, complete = state
    if identity.device_id != row["device_id"]:
        return "merged"
    if not identity.macs:
        return "no_macs"
    if identity.device_id in protected:
        return None
    if identity.device_id not in entries:
        return "unmarked" if complete else None
    found = _anchor(inv, identity.macs, now)
    return "returned" if found and found[1] > row["episode_start"] else None


def _closes(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    rows: list[sqlite3.Row],
    state: tuple[dict[str, Entry], set[str], bool],
    now: float,
) -> list[tuple[str, str]]:
    """Open incidents to resolve: reviewed, merged away or MAC-less, unmarked (never while the
    marks read is incomplete or the device's own mark is unusable), or seen again."""
    reviewed = _reviewed(ov, rows)
    closes: list[tuple[str, str]] = []
    for row in rows:
        if row["id"] in reviewed:
            closes.append((row["id"], "reviewed"))
            continue
        try:
            identity = lineage(inv, ov, row["device_id"])
        except LineageUnavailable:
            continue  # unknown is not closed
        reason = _close_reason(inv, row, identity, state, now)
        if reason:
            closes.append((row["id"], reason))
    return closes


def _randomized(inv: sqlite3.Connection, members: tuple[str, ...]) -> bool:
    """The lineage's FIRST MAC is randomized (as F5 reads it): its address rotates."""
    row = inv.execute(
        "SELECT is_randomized FROM observations"  # noqa: S608
        f" WHERE device_id IN ({','.join('?' * len(members))}) ORDER BY first_seen, mac LIMIT 1",
        members,
    ).fetchone()
    return bool(row and row[0])


def _judge(inv: sqlite3.Connection, entry: Entry, now: float) -> tuple[str, str, int, int]:
    """(verdict, collector, anchor hour, eligible hours). The verdict is "fire", "wait" (not absent
    long enough, or already announced) or a reason it cannot be judged."""
    members = _members(inv, entry.identity)
    if _randomized(inv, members):
        return "randomized", "", 0, 0
    found = _anchor(inv, entry.identity.macs, now)
    if found is None:
        return "never_measured", "", 0, 0
    collector, hour = found
    hours = _eligible_hours(inv, collector, hour, now)
    if hours < -(-entry.secs // HOUR_S) or _announced(inv, members, hour):
        return "wait", collector, hour, hours
    return "fire", collector, hour, hours


def _plan(inv: sqlite3.Connection, ov: sqlite3.Connection, now: float) -> Plan:
    marks = _read_marks(ov)
    entries, protected, unjudged = _resolve(inv, ov, marks)
    rows = _open_rows(inv)
    closes = _closes(inv, ov, rows, (entries, protected, not marks.overflow), now)
    closing = {c[0] for c in closes}
    found: list[tuple[Lineage, str, int, int, int]] = []
    for canonical, entry in sorted(entries.items()):
        if _open_ids(inv, canonical) - closing:
            continue  # an incident is open (even beyond the examined window): never a second
        verdict, collector, hour, hours = _judge(inv, entry, now)
        if verdict == "fire":
            found.append((entry.identity, collector, hour, hours, entry.secs))
        elif verdict != "wait":
            unjudged.append((canonical, verdict, entry.version))
    room = max(0, MAX_PER_DAY - _opened_today(inv, now)) if found else 0
    return Plan(tuple(closes), tuple(found[:room]), tuple(unjudged), len(found[room:]))


def _opened_today(inv: sqlite3.Connection, now: float) -> int:
    day = int(now) // 86400 * 86400
    return inv.execute(
        "SELECT COUNT(*) FROM monitoring_incidents WHERE detector=? AND detected_at>=?"
        " AND detected_at<?",
        (DETECTOR, iso_utc(day), iso_utc(day + 86400)),
    ).fetchone()[0]


def _insert(inv: sqlite3.Connection, found: tuple, now: float) -> None:
    identity, collector, hour, hours, secs = found
    evidence = {
        "reason_code": REASON,
        "absent_for_hours": hours,
        "threshold_hours": -(-secs // HOUR_S),
    }
    inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES (?,?,?,?,?,'open',?,?,?,NULL,0,0,?)",
        (hashlib.sha256(uuid.uuid4().bytes).hexdigest(), collector, identity.device_id,
         identity.key, DETECTOR, hour, int(now) // HOUR_S * HOUR_S, iso_utc(now),
         json.dumps(evidence, sort_keys=True)),
    )  # fmt: skip


def _device_exists(inv: sqlite3.Connection, device_id: str) -> bool:
    return inv.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone() is not None


def _emit_unjudged(inv: sqlite3.Connection, item: tuple, day: str, now: float) -> None:
    """One event naming the device (its id, never a MAC; none when the device is unknown)."""
    device_id, reason, version = item
    known = device_id if device_id and _device_exists(inv, device_id) else None
    when = f"v{version}" if reason in PER_VERSION and version is not None else day
    emit_once(inv, known, "essential_unjudged", "warn",
              f"an essential device cannot be judged: {SUMMARIES[reason]}",
              f"{device_id}:{reason}:{when}", now)  # fmt: skip


def _apply(inv: sqlite3.Connection, plan: Plan, now: float) -> int:
    """One transaction: close first (the open-incident index is per lineage), then open, then the
    events. Nothing to do = no transaction at all."""
    if not (plan.closes or plan.opens or plan.unjudged or plan.held):
        return 0
    day = iso_utc(now)[:10]
    with immediate(inv):
        for incident_id, _ in plan.closes:
            inv.execute(
                "UPDATE monitoring_incidents SET state='resolved' WHERE id=? AND state='open'",
                (incident_id,),
            )
        for found in plan.opens:
            _insert(inv, found, now)
        for item in plan.unjudged:
            _emit_unjudged(inv, item, day, now)
        if plan.held:
            emit_once(inv, None, "essential_capped", "warn",
                      f"essential-absence cap {MAX_PER_DAY}/day reached; {plan.held} held",
                      day, now)  # fmt: skip
    for reason in sorted({r for _, r in plan.closes}):
        log(logger, logging.INFO, "essential_absence_closed", reason=reason,
            count=sum(1 for _, r in plan.closes if r == reason))  # fmt: skip
    return len(plan.opens)


def _report_failure(inv: sqlite3.Connection, exc: Exception, now: float) -> None:
    """ERROR once per UTC day and class (an event is the marker); later passes log at DEBUG."""
    name = type(exc).__name__
    fresh = True
    try:
        with immediate(inv):
            fresh = bool(
                emit_once(inv, None, "essential_failed", "warn",
                          f"essential-absence sweep failed: {name}",
                          f"{name}:{iso_utc(now)[:10]}", now)
            )  # fmt: skip
    except Exception:  # noqa: BLE001 - reporting must not raise either
        fresh = True
    log(logger, logging.ERROR if fresh else logging.DEBUG, "essential_absence_failed", error=name)


def sweep_essential_absence(
    inv: sqlite3.Connection, ov: sqlite3.Connection | None, now: float
) -> int:
    """Open and close essential-absence incidents. Returns the number opened. Any Exception (a
    database error, a bad stored value, a bug) is logged by class name only and contained here:
    it never fails the pass."""
    if ov is None:
        return 0
    try:
        return _apply(inv, _plan(inv, ov, now), now)
    except Exception as exc:  # noqa: BLE001 - the sweep must never fail the pipeline pass
        _report_failure(inv, exc, now)
        return 0
