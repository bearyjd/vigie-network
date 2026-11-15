"""F5 S2b final fix round: probe rotation, interval-derived gap, failing passes still count as runs,
the scan cursor, an invalid (too high) floor, close-after-open-failure.
"""

from __future__ import annotations

import pytest
from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from test_f5_new_device_sweep import (
    DWELL,
    MAC,
    PRIVATE,
    REAL_GAP,
    SK,
    arrive,
    decide,
    device_of,
    incidents,
    meas,
    run,
    staggered,
    start,
    ticks,
    wide_gap,  # noqa: F401
)
from test_f5_new_device_sweep_fix1 import meta
from test_f5_new_device_sweep_fix2 import failing

from vigie_pipeline import cli
from vigie_pipeline import new_device_notice as nd
from vigie_pipeline.config import PipelineConfig


# ---- 1: the reference probes rotate, so a failing batch cannot starve the queue ------------------
def test_29_failing_devices_never_starve_one_healthy_device(data, monkeypatch):
    start(data)
    macs_ = staggered(data, 30)
    run(data, T0 + 10, new_device_notice=False)
    ids = [device_of(data, m) for m in macs_]
    healthy = max(ids[20:])  # beyond the first 20, and the highest id of the 10 not in the slice
    failing(monkeypatch, set(ids) - {healthy})  # a fixed lowest-8 probe sample never reaches it
    for step in range(12):
        run(data, T0 + DWELL + 400 + 30 * step)
    assert [r["device_id"] for r in incidents(data)] == [healthy]
    assert meta(data, "f5_skipped:") == {}  # nobody was skipped, only backed off


def test_a_store_wide_outage_blames_nobody_and_recovers(data, monkeypatch):
    start(data)
    macs_ = staggered(data, 3)
    run(data, T0 + 10, new_device_notice=False)
    real = nd.lineage

    def down(*a, **k):
        raise nd.LineageUnavailable("store down")

    monkeypatch.setattr(nd, "lineage", down)
    for step in range(10):
        run(data, T0 + DWELL + 400 + 30 * step)
    assert incidents(data) == [] and meta(data, "f5_skipped:") == {}
    assert meta(data, "f5_retry:") == {}  # nobody was backed off either
    monkeypatch.setattr(nd, "lineage", real)
    run(data, T0 + DWELL + 800)
    assert len(incidents(data)) == len(macs_)


# ---- 2: the gap follows the configured pass interval --------------------------------------------
def test_a_901_second_cadence_still_notices_with_its_interval_configured(data, monkeypatch):
    monkeypatch.setattr(nd, "RESUME_GAP_S", REAL_GAP)
    start(data, pass_interval_s=901)
    arrive(data, MAC, at=T0)
    ticks(data, T0 + 901, T0 + DWELL + SK + 3 * 901, step=901, pass_interval_s=901)
    assert len(incidents(data)) == 1


def test_a_600_second_cadence_notices_with_the_default_interval(data, monkeypatch):
    monkeypatch.setattr(nd, "RESUME_GAP_S", REAL_GAP)
    start(data)
    arrive(data, MAC, at=T0)
    ticks(data, T0 + 540, T0 + DWELL + SK + 1200, step=600)
    assert len(incidents(data)) == 1


def test_an_interval_over_the_maximum_fails_fast_value_free_when_the_flag_is_on():
    top = nd_max()
    PipelineConfig(data_dir=".", new_device_notice=True, pass_interval_s=top)  # the maximum is fine
    with pytest.raises(ValueError, match="VIGIE_NEW_DEVICE_NOTICE") as info:
        PipelineConfig(data_dir=".", new_device_notice=True, pass_interval_s=top + 1)
    assert str(top + 1) not in str(info.value)
    PipelineConfig(data_dir=".", new_device_notice=False, pass_interval_s=top + 1)  # flag off: fine


def test_the_cli_refuses_a_too_long_loop_interval_with_the_flag_on(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VIGIE_NEW_DEVICE_NOTICE", "1")
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    with pytest.raises(SystemExit) as info:
        cli.main(["run", "--loop", str(nd_max() + 1)])
    assert info.value.code == 2
    err = capsys.readouterr().err
    assert "VIGIE_NEW_DEVICE_NOTICE" in err and str(nd_max() + 1) not in err


def nd_max() -> int:
    from vigie_pipeline.config import NEW_DEVICE_MAX_PASS_INTERVAL_S

    return NEW_DEVICE_MAX_PASS_INTERVAL_S


# ---- 3: a failing pass still counts as a run ----------------------------------------------------
def test_an_exception_streak_longer_than_the_gap_does_not_move_the_floor(data, monkeypatch, caplog):
    monkeypatch.setattr(nd, "RESUME_GAP_S", REAL_GAP)
    start(data)
    arrive(data, MAC, at=T0)
    real = nd.lineage

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(nd, "lineage", boom)
    caplog.set_level("INFO", logger="vigie_pipeline")
    ticks(data, T0 + 30, T0 + 30 + 1200, step=30)  # 20 minutes of failing passes
    monkeypatch.setattr(nd, "lineage", real)
    ticks(data, T0 + 1260, T0 + 1260 + 1200, step=600)
    assert len(incidents(data)) == 1
    assert meta(data, "f5_floor") == {"f5_floor": "0"}
    assert "new_device_watermark_moved" not in caplog.text


# ---- 5a: a floor above the issued sequence is invalid -------------------------------------------
def test_a_floor_above_the_issued_sequence_is_reset_and_logged(data, caplog):
    start(data)
    data.inv.execute("UPDATE pipeline_meta SET value='10000' WHERE key='f5_floor'")
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + 30)  # the invalid floor is reset to the issued sequence
    arrive(data, MAC, at=T0 + 60)
    ticks(data, T0 + 540, T0 + DWELL + SK + 600, step=600)
    assert len(incidents(data)) == 1
    assert int(meta(data, "f5_floor")["f5_floor"]) < 10000
    moved = [r for r in caplog.records if r.getMessage() == "new_device_watermark_moved"]
    assert [r.fields["reason"] for r in moved] == ["invalid_state"]


# ---- 5b: the close step runs even when the open step raised -------------------------------------
def test_the_close_step_still_runs_when_the_open_step_raised(data, monkeypatch):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + SK + 10)
    (row,) = incidents(data)
    decide(data, row, "expected")

    def boom(*a, **k):
        raise ValueError("open failed")

    monkeypatch.setattr(nd, "_floor", boom)
    run(data, T0 + DWELL + SK + 40)  # must not raise
    assert incidents(data)[0]["state"] == "resolved"


# ---- 5c: the floor-move log carries an upper bound of the dropped backlog -----------------------
def test_a_floor_move_logs_how_many_devices_it_may_have_dropped(data, caplog):
    start(data)
    arrive(data, MAC, at=T0, measured=False)
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + 7 * HOUR)  # the resume gap passed: the unmeasured waiting device is dropped
    moved = [r for r in caplog.records if r.getMessage() == "new_device_watermark_moved"]
    assert moved and moved[0].fields["reason"] == "resumed" and moved[0].fields["pending"] == 1


# ---- 4: the scan cursor -------------------------------------------------------------------------
def top_event_seq(data: Data) -> int:
    return data.q("SELECT MAX(seq) FROM events WHERE kind='new_device'")[0][0]


def cursor(data: Data) -> int:
    return int(meta(data, "f5_scan_cursor")["f5_scan_cursor"])


def test_the_cursor_advances_past_noticed_skipped_and_randomized_devices(data):
    start(data, new_device_max_per_day=20)
    arrive(data, [MAC, "00:1a:2b:00:00:02"])
    arrive(data, PRIVATE, at=T0 + 20)
    run(data, T0 + DWELL + SK + 60, new_device_max_per_day=20)
    assert len(incidents(data)) == 2
    assert cursor(data) == top_event_seq(data)


def test_the_cursor_never_skips_a_device_that_is_not_yet_eligible(data):
    start(data, new_device_max_per_day=20)
    waiting, later = "00:1a:2b:00:00:0a", "00:1a:2b:00:00:0b"
    arrive(data, waiting, at=T0, measured=False)  # first in the queue, nobody measured it
    arrive(data, later, at=T0 + 10)
    run(data, T0 + DWELL + SK + 60, new_device_max_per_day=20)
    first_seq = data.q("SELECT seq FROM events WHERE device_id=?", device_of(data, waiting))[0][0]
    assert [r["device_id"] for r in incidents(data)] == [device_of(data, later)]
    assert cursor(data) < first_seq  # it stays behind the waiting device
    meas(data, waiting)  # measured later: it becomes eligible
    run(data, T0 + DWELL + SK + 90, new_device_max_per_day=20)
    assert device_of(data, waiting) in {r["device_id"] for r in incidents(data)}
    assert cursor(data) == top_event_seq(data)


def test_the_cursor_never_skips_a_device_whose_lineage_resolves_later(data, monkeypatch):
    start(data, new_device_max_per_day=20)
    first, second = "00:1a:2b:00:00:0c", "00:1a:2b:00:00:0d"
    arrive(data, first, at=T0)
    arrive(data, second, at=T0 + 10)
    run(data, T0 + 10, new_device_notice=False, new_device_max_per_day=20)
    bad = device_of(data, first)
    real, _ = failing(monkeypatch, {bad})
    now = T0 + DWELL + SK + 60
    run(data, now, new_device_max_per_day=20)
    assert [r["device_id"] for r in incidents(data)] == [device_of(data, second)]
    monkeypatch.setattr(nd, "lineage", real)
    run(data, now + 3700, new_device_max_per_day=20)  # the backoff expired and lineage resolves
    assert bad in {r["device_id"] for r in incidents(data)}
    assert cursor(data) == top_event_seq(data)


def test_a_raised_floor_hides_waiting_devices_without_skipping_them_for_good(data):
    start(data)
    arrive(data, MAC, measured=False)
    run(data, T0 + DWELL + SK + 30)  # created, waiting for a measurement: undecided
    seq = data.q("SELECT seq FROM sqlite_sequence WHERE name='events'")[0][0]
    data.inv.execute("UPDATE pipeline_meta SET value=? WHERE key='f5_floor'", (str(seq),))
    meas(data, MAC)
    run(data, T0 + DWELL + SK + 60)
    assert incidents(data) == [] and meta(data, "f5_skipped:") == {}  # below the floor: ignored


def test_the_cursor_follows_the_floor_when_it_moves(data):
    start(data)
    arrive(data, MAC, at=T0)
    run(data, T0 + DWELL + SK + 60)
    run(data, T0 + 20 * HOUR)  # a long gap: the floor moves
    assert cursor(data) == int(meta(data, "f5_floor")["f5_floor"])


def test_a_pass_is_cheap_once_every_device_is_decided(data):
    start(data)
    for i in range(3000):  # randomized devices: never eligible, so decided
        did = f"dev-{i}"
        data.inv.execute(
            "INSERT INTO devices(id,first_seen,last_seen) VALUES (?,'2026-10-14T00:00:00Z',"
            "'2026-10-14T00:00:00Z')",
            (did,),
        )
        data.inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen)"
            " VALUES (?,?,1,'self','x','x')",
            (f"aa:00:00:00:{i >> 8:02x}:{i & 255:02x}", did),
        )
        data.inv.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
            " VALUES (?,?,'x','new_device','info','x')",
            (f"ev-{i}", did),
        )
    config = PipelineConfig(data_dir=data.root, new_device_notice=True)
    for step in range(3):  # the cursor catches up SCAN_ADVANCE rows per pass
        nd.sweep_new_devices(data.inv, None, config, T0 + 30 * (step + 1))
    steps = []
    data.inv.set_progress_handler(lambda: steps.append(1) or 0, 1000)
    nd.sweep_new_devices(data.inv, None, config, T0 + 200)
    data.inv.set_progress_handler(None, 0)
    assert len(steps) < 60  # under 60k VM steps (a rescan of 3000 events costs far more)
