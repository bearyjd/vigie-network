from __future__ import annotations

from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

PHONE = "aa:bb:cc:00:00:01"


def run(data: Data, now: float, **kw):
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def statuses(data: Data) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in data.q("SELECT status, COUNT(*) c FROM devices GROUP BY status"):
        out[r["status"]] = r["c"]
    return out


def test_hostname_alone_never_promotes_2000_random_macs(data):
    macs = [f"a2:00:00:00:{i >> 8:02x}:{i & 255:02x}" for i in range(2000)]
    data.add_batch(leases=[(m, "x", None, None) for m in macs])
    run(data, T0 + 10)
    assert statuses(data) == {"transient": 2000}
    stats = run(data, T0 + 86400)
    assert stats.retired == 2000 and stats.promoted == 0
    assert statuses(data) == {"retired": 2000}


def test_two_received_hours_with_dwell_promotes(data):
    data.add_batch(T0, neigh=[PHONE])
    data.add_batch(T0 + 3 * HOUR, neigh=[PHONE])
    run(data, T0 + 3 * HOUR + 10)
    assert statuses(data) == {"active": 1}


def test_two_received_hours_but_short_dwell_does_not_promote(data):
    data.add_batch(T0, neigh=[PHONE])
    data.add_batch(T0 + 1800, neigh=[PHONE], received=T0 + HOUR + 1)
    run(data, T0 + 2 * HOUR)
    assert statuses(data) == {"transient": 1}


def test_forged_record_timestamps_cannot_fake_persistence(data):
    # record ts spans 3 hours, but the server received both batches in the same hour
    data.add_batch(T0, neigh=[PHONE])
    data.add_batch(T0 + 3 * HOUR, neigh=[PHONE], received=T0 + 60)
    run(data, T0 + 4 * HOUR)
    assert statuses(data) == {"transient": 1}


def test_dwell_threshold_is_configurable(data):
    data.add_batch(T0, neigh=[PHONE])
    data.add_batch(T0 + 1800, neigh=[PHONE], received=T0 + HOUR + 1)
    run(data, T0 + 2 * HOUR, transient_min_dwell_s=1800)
    assert statuses(data) == {"active": 1}


def _persistent_devices(data: Data, n: int) -> None:
    macs = [f"a2:00:00:00:00:{i:02x}" for i in range(n)]
    data.add_batch(T0, neigh=macs)
    data.add_batch(T0 + 3 * HOUR, neigh=macs)


def test_promotion_cap_per_hour_trips_and_emits_one_event(data):
    _persistent_devices(data, 25)
    now = T0 + 3 * HOUR + 10
    assert run(data, now).promoted == 20
    assert statuses(data) == {"active": 20, "transient": 5}
    run(data, now + 60)  # same hour: still capped, no second event
    assert statuses(data) == {"active": 20, "transient": 5}
    n = data.q("SELECT COUNT(*) c FROM events WHERE kind='promotion_rate_limited'")[0]["c"]
    assert n == 1
    # next hour the remaining five are promoted
    run(data, now + HOUR)
    assert statuses(data) == {"active": 25}


def test_cap_is_configurable(data):
    _persistent_devices(data, 5)
    run(data, T0 + 3 * HOUR + 10, promotion_cap_per_hour=2)
    assert statuses(data) == {"active": 2, "transient": 3}
