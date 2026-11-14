"""Chronological replay of a fixture through the real `analyze_monitoring`, one injected-clock pass
per hour, against a throwaway database that is created in a private temp directory and removed.

Nothing here opens or imports configuration, the live data directory or the network. Each device
gets its own synthetic collector so that coverage (which is per collector and hour in the engine)
is per device in the fixture. Data is ingested chronologically: before the pass at `now`, every
sample with hour <= the pass's current hour is inserted, so no pass ever sees a later hour.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.monitoring_engine import analyze_monitoring, samples_for
from vigie_pipeline.monitoring_identity import lineage
from vigie_pipeline.monitoring_strategy import strategy_for
from vigie_pipeline.replay.errors import ReplayInputError
from vigie_pipeline.replay.series import MAX_DEVICES, DeviceSeries
from vigie_pipeline.schema import open_pipeline_inventory

MAX_TICKS = 2160
TICK_OFFSET_S = 1  # a pass runs just after the hour boundary, like a real scheduler
DETECTORS = ("large_upload", "upload_deviation")
ABSTAINED, FIRED, QUIET = "abstained", "fired", "quiet"


@dataclass(frozen=True)
class Outcome:
    device: str
    hour: int
    detector: str
    status: str  # fired | quiet | abstained
    reason: str | None = None  # why abstained
    episode: str | None = None  # incident id of the alert episode when fired


def hourly_clock(first_hour: int, last_hour: int) -> Iterator[int]:
    "Pass times for every hour from first_hour to last_hour inclusive."
    if last_hour < first_hour or (last_hour - first_hour) // 3600 + 1 > MAX_TICKS:
        raise ReplayInputError("replay: clock span is empty or too long")
    for hour in range(first_hour, last_hour + 1, 3600):
        yield hour + 3600 + TICK_OFFSET_S


def _ticks(clock: Iterable[int]) -> tuple[int, ...]:
    ticks = []
    for now in clock:
        if type(now) is not int or now < 3600 or len(ticks) >= MAX_TICKS:
            raise ReplayInputError("replay: invalid clock tick or too many ticks")
        if ticks and now // 3600 <= ticks[-1] // 3600:
            raise ReplayInputError("replay: clock must advance by whole hours")
        ticks.append(now)
    return tuple(ticks)


def _open(root: Path):
    inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
    ov = open_overrides(root / "overrides.db")
    for conn in (inv, ov):  # throwaway files: durability is pointless, fsync dominates the time
        conn.execute("PRAGMA synchronous=OFF")
    return inv, ov


def _seed(inv, devices: tuple[DeviceSeries, ...], epoch: int) -> dict:
    macs = {}
    for i, series in enumerate(devices):
        mac = f"02:00:00:00:{i // 256:02x}:{i % 256:02x}"
        macs[series.device] = (f"c{i}", f"d{i}", mac)
        inv.execute("INSERT INTO collectors(id,key_id) VALUES (?, 'k')", (f"c{i}",))
        inv.execute(
            "INSERT INTO devices(id,first_seen,last_seen) VALUES (?,?,?)",
            (f"d{i}", iso_utc(epoch), iso_utc(epoch)),
        )
        inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,"
            "last_seen) VALUES (?,?,0,'self',?,?)",
            (mac, f"d{i}", iso_utc(epoch), iso_utc(epoch)),
        )
    return macs


def _ingest(inv, ids, row) -> None:
    collector, _device, mac = ids
    inv.execute(
        "INSERT INTO measurements_hourly VALUES (?,?,?,?,0,1,0)",
        (collector, mac, row.hour, row.bytes_up),
    )
    reasons = json.dumps(["degraded"] if row.degraded else [])
    inv.execute(
        "INSERT OR REPLACE INTO coverage_hourly VALUES (?,?,?,?,?)",
        (collector, row.hour, row.qualified_seconds, row.qualified_seconds, reasons),
    )


def _fired(inv, collector: str, device: str, hour: int) -> dict:
    rows = inv.execute(
        "SELECT detector,id FROM monitoring_incidents WHERE collector_id=? AND device_id=? "
        "AND state='open' AND last_hour=?",
        (collector, device, hour),
    ).fetchall()
    return {r[0]: r[1] for r in rows}


def _judge(inv, ov, policy, name, ids, now: int, hour: int) -> tuple[Outcome, ...]:
    "Per-detector outcome for the device's current hour, read back from the engine's own state."
    collector, device, _mac = ids
    identity = lineage(inv, ov, device)
    by_hour = {s.hour: s for s in samples_for(inv, collector, identity, now)}
    current, previous = by_hour.get(hour), by_hour.get(hour - 3600)
    fired = _fired(inv, collector, identity.device_id, hour)
    profile = inv.execute(
        "SELECT state,baseline_id FROM monitoring_profiles WHERE collector_id=? AND device_id=?",
        (collector, identity.device_id),
    ).fetchone()
    reason = _deviation_abstention(inv, policy, current, previous, profile)
    out = []
    for detector in DETECTORS:
        why = _large_abstention(current) if detector == DETECTORS[0] else reason
        out.append(_outcome(name, hour, detector, why, fired))
    return tuple(out)


def _outcome(device, hour, detector, why, fired) -> Outcome:
    if why is not None:
        return Outcome(device, hour, detector, ABSTAINED, why)
    if detector in fired:
        return Outcome(device, hour, detector, FIRED, None, fired[detector])
    return Outcome(device, hour, detector, QUIET)


def _large_abstention(current):
    if current is None:
        return "no_sample"
    return None if current.eligible else "unqualified"


def _deviation_abstention(inv, policy, current, previous, profile):
    if current is None:
        return "no_sample"
    if not current.eligible:
        return "unqualified"
    if profile is None or profile["state"] != "mature" or not profile["baseline_id"]:
        return "learning"
    row = inv.execute(
        "SELECT * FROM monitoring_baselines WHERE id=?", (profile["baseline_id"],)
    ).fetchone()
    strategy = strategy_for(policy)
    reference = strategy.hydrate(dict(row)) if row is not None else None
    if reference is None:
        return "learning"
    if current.hour <= reference["trained_until"]:
        return "in_training"
    if previous is None or not previous.eligible or previous.hour <= reference["trained_until"]:
        return "previous_unavailable"
    if strategy.threshold(current, reference) is None:
        return "cohort_abstain"
    return None


def _unavailable(inv) -> bool:
    return inv.execute("SELECT 1 FROM monitoring_unavailable LIMIT 1").fetchone() is not None


def _universe(devices, ticks, extra_hours) -> dict:
    "device -> sorted hours that get an outcome: ticked, sampled or labelled."
    ticked = {now // 3600 * 3600 - 3600 for now in ticks}
    extra: dict = {}
    for device, hour in extra_hours:
        extra.setdefault(device, set()).add(hour)
    return {
        d.device: sorted(ticked | {s.hour for s in d.samples} | extra.get(d.device, set()))
        for d in devices
    }


def replay(
    series: Iterable[DeviceSeries],
    policy: BaselineConfig | TodConfig,
    clock: Iterable[int] | None = None,
    extra_hours: Iterable[tuple[str, int]] = (),
) -> tuple[Outcome, ...]:
    """Replay `series` and return one Outcome per (device, hour, detector), sorted.

    `clock` yields the pass times (default: every hour from the first to the last sample). An hour
    the clock never ticks is reported as abstained/clock_gap. `extra_hours` adds (device, hour)
    pairs (the labelled hours) to the report so a label can never silently vanish.
    """
    devices = tuple(sorted(series, key=lambda d: d.device))
    if len(devices) > MAX_DEVICES:
        raise ReplayInputError("replay: too many devices")
    hours = [s.hour for d in devices for s in d.samples]
    if clock is None:
        clock = hourly_clock(min(hours), max(hours)) if hours else ()
    ticks = _ticks(clock)
    universe = _universe(devices, ticks, extra_hours)
    done: dict = {}
    with tempfile.TemporaryDirectory(prefix="vigie-replay-") as tmp:
        inv, ov = _open(Path(tmp))
        try:
            ids = _seed(inv, devices, hours[0] if hours else 0)
            done = _run(inv, ov, policy, devices, ids, ticks)
        except sqlite3.Error as exc:
            raise ReplayInputError("replay: engine database error") from exc
        finally:
            inv.close()
            ov.close()
    return _assemble(devices, universe, done)


def _run(inv, ov, policy, devices, ids, ticks) -> dict:
    pending = {d.device: list(d.samples) for d in devices}
    done: dict = {}
    for now in ticks:
        hour = now // 3600 * 3600 - 3600
        for d in devices:
            fresh = [s for s in pending[d.device] if s.hour <= hour]
            pending[d.device] = [s for s in pending[d.device] if s.hour > hour]
            for row in fresh:
                _ingest(inv, ids[d.device], row)
            # every device is queued each pass: a silent hour is then judged, not skipped
            inv.execute(
                "INSERT OR REPLACE INTO monitoring_dirty VALUES (?,?,0)",
                (ids[d.device][0], ids[d.device][2]),
            )
        analyze_monitoring(inv, ov, policy, now)
        if _unavailable(inv):
            raise ReplayInputError("replay: engine could not analyse a device")
        for d in devices:
            for outcome in _judge(inv, ov, policy, d.device, ids[d.device], now, hour):
                done[(d.device, hour, outcome.detector)] = outcome
    return done


def _assemble(devices, universe, done) -> tuple[Outcome, ...]:
    out = []
    for d in devices:
        for hour in universe[d.device]:
            for detector in DETECTORS:
                found = done.get((d.device, hour, detector))
                out.append(found or Outcome(d.device, hour, detector, ABSTAINED, "clock_gap"))
    return tuple(sorted(out, key=lambda o: (o.device, o.hour, o.detector)))
