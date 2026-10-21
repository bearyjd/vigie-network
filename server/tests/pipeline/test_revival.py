from __future__ import annotations

from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

STABLE_LAA = "02:11:22:33:44:55"  # locally administered but a stable address
DAY = 86400


def run(data: Data, now: float, **kw):
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def status(data: Data) -> str:
    return data.q("SELECT status FROM devices")[0]["status"]


def reappeared(data: Data) -> int:
    return data.q("SELECT COUNT(*) c FROM events WHERE kind='device_reappeared'")[0]["c"]


def test_retired_device_seen_again_is_revived_with_event(data):
    data.add_batch(T0, neigh=[STABLE_LAA])
    run(data, T0 + DAY)
    assert status(data) == "retired"
    data.add_batch(T0 + 2 * DAY, neigh=[STABLE_LAA])
    run(data, T0 + 2 * DAY + 10)
    assert status(data) == "transient"
    assert reappeared(data) == 1
    assert len(data.q("SELECT * FROM devices")) == 1  # same device, not a new one
    assert data.q("SELECT since FROM transient_state")[0]["since"] == iso_utc(T0 + 2 * DAY)


def test_revival_event_once_per_revival(data):
    data.add_batch(T0, neigh=[STABLE_LAA])
    run(data, T0 + DAY)
    data.add_batch(T0 + 2 * DAY, neigh=[STABLE_LAA])
    data.add_batch(T0 + 2 * DAY + 60, neigh=[STABLE_LAA])
    run(data, T0 + 2 * DAY + 100)
    run(data, T0 + 2 * DAY + 200)
    assert reappeared(data) == 1
    # retired again, seen again: a second revival, a second event
    run(data, T0 + 4 * DAY)
    assert status(data) == "retired"
    data.add_batch(T0 + 5 * DAY, neigh=[STABLE_LAA])
    run(data, T0 + 5 * DAY + 10)
    assert reappeared(data) == 2


def test_revival_restarts_the_window(data):
    data.add_batch(T0, neigh=[STABLE_LAA])
    run(data, T0 + DAY)
    data.add_batch(T0 + 2 * DAY, neigh=[STABLE_LAA])
    run(data, T0 + 2 * DAY + 10)
    run(data, T0 + 2 * DAY + DAY - 10)  # old first_seen must not retire it again early
    assert status(data) == "transient"
    run(data, T0 + 3 * DAY + 10)
    assert status(data) == "retired"


def test_revived_device_can_be_promoted_again_by_persistence(data):
    data.add_batch(T0, neigh=[STABLE_LAA])
    run(data, T0 + DAY)
    data.add_batch(T0 + 2 * DAY, neigh=[STABLE_LAA])
    data.add_batch(T0 + 2 * DAY + 2 * HOUR + 60, neigh=[STABLE_LAA])
    run(data, T0 + 2 * DAY + 3 * HOUR)
    assert status(data) == "active"


def test_active_device_seen_again_is_not_a_revival(data):
    data.add_batch(T0, neigh=["00:11:22:33:44:55"])
    data.add_batch(T0 + 60, neigh=["00:11:22:33:44:55"])
    run(data, T0 + 100)
    assert status(data) == "active" and reappeared(data) == 0
