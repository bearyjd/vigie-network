"""F6-b: one `essential_absence` incident when a device the OWNER marked essential is not seen for
its own N hours (`essential_devices.absent_after_s`, 3600..604800) while Vigie could see.

DEFAULT OFF (`PipelineConfig.essential_absence`): with the flag off the processor never calls this
module. With the flag on and nothing marked the sweep reads two small things and writes nothing.
It is STATELESS: no `pipeline_meta` key, watermark, cursor or last-run stamp; every verdict is a
pure function of the stored anchor, the stored coverage and the stored incidents, so a clock step
or a pipeline gap cannot leave state behind to go wrong.

Rule (docs/monitoring.md "Essential-device absence (F6)"): for each marked device (at most
MAX_MARKS, read-only overrides.db) resolved to its CURRENT canonical device and lineage:
  anchor  = the newest last_seen of the lineage (any member MAC or device row counts as seen);
  collector = the one with the newest `measurements_hourly` row of any lineage MAC (none: abstain);
  Q = the ELIGIBLE `coverage_hourly` hours of that collector strictly after the anchor's hour and
      before the current hour (qualified >= 3420 s, no reasons). A blind hour (no row, an
      unqualified row) is not counted: the clock pauses, it never fires.
  fire iff Q * 3600 >= absent_after_s.
Anchor and coverage are stamped by the same collector clock, so a constant offset cancels and
never fires early. The server clock is used only as a clamp: an anchor more than ACTIVITY_SKEW_S
ahead of it cannot be judged (a clock running ahead, or a forged stamp) and is reported by an
event, never silently. `run_once` runs this after the batches are processed and skips it when a
shard could not be read, so a backlog lands before the verdict.

Episode: the anchor hour is the incident's `episode_start`. One incident per (lineage member,
anchor): an absence is announced once, even after review, unmark/re-mark or a merge. The device
being seen again moves the anchor past the episode: the open incident resolves (no recover is
ever sent, delivery_types.OPEN_ONLY_DETECTORS) and a later absence is a new episode and may
notify again. Also resolved: the owner reviewed it (acknowledged/expected), the mark was cleared,
or the incident's device is no longer canonical (merged). A marks table that cannot be read
closes nothing. Merged alias marks are judged on the canonical device; several marks of one
lineage use the smallest threshold. At most MAX_PER_DAY incidents open per UTC day (a held
device stays eligible next pass: nothing is lost, one event per day says so). The incident id is
random, evidence is the fixed shape {reason_code, absent_for_hours, threshold_hours}.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from vigie_ingest.db import immediate, iso_utc
from vigie_pipeline.config import ACTIVITY_SKEW_S
from vigie_pipeline.logs import log
from vigie_pipeline.monitoring_identity import Lineage, LineageUnavailable, lineage
from vigie_pipeline.stitch_db import emit_once

logger = logging.getLogger("vigie_pipeline")
DETECTOR = "essential_absence"
REASON = "essential_absent"
HOUR_S = 3600
MIN_S = 3600  # keep equal to vigie_api.essential.MIN_S / MAX_S / MAX_ESSENTIAL (asserted by a test)
MAX_S = 604800
MAX_MARKS = 32
MAX_PER_DAY = 8
MAX_OPEN = 65  # open incidents examined per run (one more than MAX_MARKS x 2: strays are closed)
ELIGIBLE_S = 3420  # an eligible hour: monitoring_engine's qualified-seconds floor
QUIET = ("acknowledged", "expected")  # incident_decisions.status values that close the incident


@dataclass(frozen=True)
class Plan:
    closes: tuple[tuple[str, str], ...]  # (incident id, reason)
    opens: tuple[
        tuple[Lineage, str, int, int, int], ...
    ]  # identity, collector, anchor, hours, secs
    unjudged: tuple[tuple[str | None, str], ...]  # (device id, reason)
    held: int


def _read_marks(ov: sqlite3.Connection) -> tuple[list[tuple[str, int]], bool]:
    """(the marked devices, all rows usable): at most MAX_MARKS; a row outside the bounds or of
    the wrong type is ignored and logged (the database is input), and so is an overflow."""
    rows = ov.execute(
        "SELECT device_id, absent_after_s FROM essential_devices WHERE absent_after_s IS NOT NULL"
        " ORDER BY device_id LIMIT ?",
        (MAX_MARKS + 1,),
    ).fetchall()
    if len(rows) > MAX_MARKS:
        log(logger, logging.WARNING, "essential_absence_overflow", limit=MAX_MARKS)
    marks = [
        (r[0], r[1])
        for r in rows[:MAX_MARKS]
        if isinstance(r[0], str) and type(r[1]) is int and MIN_S <= r[1] <= MAX_S
    ]
    clean = len(marks) == len(rows[:MAX_MARKS])
    if not clean:
        log(logger, logging.WARNING, "essential_absence_bad_marks", ignored=len(rows) - len(marks))
    return marks, clean


def _resolve(
    inv: sqlite3.Connection, ov: sqlite3.Connection, marks: list[tuple[str, int]]
) -> tuple[dict[str, tuple[Lineage, int]], list[tuple[str | None, str]]]:
    """Marks -> {canonical device id: (lineage, smallest threshold)}; marks that cannot be
    resolved are reported, never dropped silently."""
    entries: dict[str, tuple[Lineage, int]] = {}
    unjudged: list[tuple[str | None, str]] = []
    for device_id, secs in marks:
        try:
            identity = lineage(inv, ov, device_id)
        except LineageUnavailable:
            unjudged.append((None, "identity_unavailable"))
            continue
        if not identity.macs:
            unjudged.append((None, "unknown_device"))
            continue
        old = entries.get(identity.device_id)
        entries[identity.device_id] = (identity, secs if old is None else min(old[1], secs))
    return entries, unjudged


def _parse(text: object) -> int | None:
    try:
        stamp = datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return int(stamp.timestamp())


def _seen(inv: sqlite3.Connection, identity: Lineage) -> tuple[int | None, tuple[str, ...]]:
    """(anchor epoch or None, lineage member device ids): the newest last_seen of any member MAC
    or member device row. Members come from the MAC rows, so a merged alias is included."""
    marks = ",".join("?" * len(identity.macs))
    obs = inv.execute(
        f"SELECT MAX(last_seen), GROUP_CONCAT(DISTINCT device_id) FROM observations"  # noqa: S608
        f" WHERE mac IN ({marks})",
        identity.macs,
    ).fetchone()
    members = tuple(sorted({identity.device_id, *(obs[1] or "").split(",")} - {""}))
    dev = inv.execute(
        f"SELECT MAX(last_seen) FROM devices WHERE id IN ({','.join('?' * len(members))})",  # noqa: S608
        members,
    ).fetchone()
    stamps = [s for s in (obs[0], dev[0]) if s is not None]
    return (_parse(max(stamps)) if stamps else None), members


def _collector(inv: sqlite3.Connection, macs: tuple[str, ...]) -> str | None:
    """The collector that measured the lineage most recently (a seek per collector and MAC)."""
    row = inv.execute(
        "SELECT c.id, (SELECT MAX(m.hour) FROM measurements_hourly m WHERE m.collector_id=c.id"  # noqa: S608
        f" AND m.mac IN ({','.join('?' * len(macs))})) AS h FROM collectors c"
        " ORDER BY h DESC, c.id LIMIT 1",
        macs,
    ).fetchone()
    return row[0] if row and row[1] is not None else None


def _eligible_hours(inv: sqlite3.Connection, collector: str, anchor_hour: int, now: float) -> int:
    """Eligible hours after the anchor's hour and before the current hour (counted up to the
    longest threshold in hours, plus one)."""
    return inv.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM coverage_hourly WHERE collector_id=? AND hour>?"
        " AND hour<? AND qualified_seconds>=? AND reasons='[]' LIMIT ?)",
        (collector, anchor_hour, int(now) // HOUR_S * HOUR_S, ELIGIBLE_S, MAX_S // HOUR_S + 1),
    ).fetchone()[0]


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
        found = ov.execute(
            f"SELECT incident_id FROM incident_decisions WHERE status IN ({','.join('?' * 2)})"  # noqa: S608
            f" AND incident_id IN ({','.join('?' * len(rows))})",
            (*QUIET, *(r["id"] for r in rows)),
        )
        return {r[0] for r in found}
    except sqlite3.Error as exc:
        log(logger, logging.ERROR, "essential_absence_review_failed", error=type(exc).__name__)
        return set()


def _closes(
    inv: sqlite3.Connection,
    ov: sqlite3.Connection,
    rows: list[sqlite3.Row],
    entries: dict[str, tuple[Lineage, int]],
    complete: bool,
) -> list[tuple[str, str]]:
    """Open incidents to resolve: reviewed, merged away, unmarked (only when every mark could be
    resolved), or the device was seen again (its anchor moved past the episode)."""
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
        if identity.device_id != row["device_id"]:
            closes.append((row["id"], "merged"))
        elif identity.device_id not in entries:
            if complete:
                closes.append((row["id"], "unmarked"))
        elif identity.macs:
            anchor = _seen(inv, identity)[0]
            if anchor is not None and anchor // HOUR_S * HOUR_S > row["episode_start"]:
                closes.append((row["id"], "returned"))
    return closes


def _judge(
    inv: sqlite3.Connection, identity: Lineage, secs: int, now: float
) -> tuple[str, str, int, int]:
    """(verdict, collector, anchor hour, eligible hours). The verdict
    is "fire", "wait" (not absent long enough, or already announced) or a reason it cannot be
    judged."""
    anchor, members = _seen(inv, identity)
    if anchor is None:
        return "unreadable_last_seen", "", 0, 0
    if anchor > now + ACTIVITY_SKEW_S:
        return "last_seen_in_the_future", "", 0, 0
    collector = _collector(inv, identity.macs)
    if collector is None:
        return "never_measured", "", 0, 0
    hour = anchor // HOUR_S * HOUR_S
    need = -(-secs // HOUR_S)
    hours = _eligible_hours(inv, collector, hour, now)
    if hours < need or _announced(inv, members, hour):
        return "wait", collector, hour, hours
    return "fire", collector, hour, hours


def _plan(inv: sqlite3.Connection, ov: sqlite3.Connection, now: float) -> Plan:
    marks, clean = _read_marks(ov)
    entries, unjudged = _resolve(inv, ov, marks)
    rows = _open_rows(inv)
    closes = _closes(inv, ov, rows, entries, clean and not unjudged)
    closing = {c[0] for c in closes}
    held_open = {r["device_id"] for r in rows if r["id"] not in closing}
    found: list[tuple[Lineage, str, int, int, int]] = []
    for canonical, (identity, secs) in sorted(entries.items()):
        if canonical in held_open:
            continue
        verdict, collector, hour, hours = _judge(inv, identity, secs, now)
        if verdict == "fire":
            found.append((identity, collector, hour, hours, secs))
        elif verdict != "wait":
            unjudged.append((canonical, verdict))
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


def _apply(inv: sqlite3.Connection, plan: Plan, now: float) -> int:
    """One transaction: close first (the open-incident index is per lineage), then open, then the
    day's events. Nothing to do = no transaction at all."""
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
        for device_id, reason in plan.unjudged:
            emit_once(inv, None, "essential_unjudged", "warn",
                      f"an essential device cannot be judged: {reason}",
                      f"{device_id}:{reason}:{day}", now)  # fmt: skip
        if plan.held:
            emit_once(inv, None, "essential_capped", "warn",
                      f"essential-absence cap {MAX_PER_DAY}/day reached; {plan.held} held",
                      day, now)  # fmt: skip
    for reason in sorted({r for _, r in plan.closes}):
        log(logger, logging.INFO, "essential_absence_closed", reason=reason,
            count=sum(1 for _, r in plan.closes if r == reason))  # fmt: skip
    return len(plan.opens)


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
        log(logger, logging.ERROR, "essential_absence_failed", error=type(exc).__name__)
        return 0
