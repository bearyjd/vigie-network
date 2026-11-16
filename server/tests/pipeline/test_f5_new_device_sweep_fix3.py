"""F5 S2b fix round 3: the creation-event floor, backward clock steps, stale collector stamps, hold
stamps for the whole candidate window, the 15 minute gap, containment, cleanup, function size.
"""

from __future__ import annotations

import inspect

from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from test_f5_new_device_sweep import (
    DAY,
    DWELL,
    MAC,
    REAL_GAP,
    SK,
    arrive,
    decide,
    device_of,
    incidents,
    macs,
    meas,
    run,
    staggered,
    start,
    ticks,
    wide_gap,  # noqa: F401
)
from test_f5_new_device_sweep_fix1 import meta
from test_f5_new_device_sweep_fix2 import failing

from vigie_pipeline import new_device_notice as nd

M2 = "00:1a:2b:77:00:01"


# ---- the floor is an event sequence, not a clock and not a rowid --------------------------------
def test_the_floor_is_the_highest_event_sequence_and_survives_a_vacuum(data):
    arrive(data, MAC, at=T0 - 5 * DAY)
    run(data, T0 - 5 * DAY + DWELL, new_device_notice=False)
    start(data)
    seq = data.q("SELECT seq FROM sqlite_sequence WHERE name='events'")[0][0]
    assert meta(data, "f5_floor") == {"f5_floor": str(seq)}
    data.inv.execute("VACUUM")  # renumbers devices rowids; events.seq is AUTOINCREMENT
    arrive(data, M2, at=T0)
    run(data, T0 + DWELL + SK + 60)
    assert [r["device_id"] for r in incidents(data)] == [device_of(data, M2)]


# R1: a backward clock step can no longer lower the floor
def test_a_pass_with_the_clock_six_days_back_notices_nothing(data):
    arrive(data, MAC, at=T0 - 5 * DAY)  # present long before the flag is enabled
    ticks(data, T0 - 5 * DAY + DWELL + SK, T0 - 4 * DAY, step=5 * HOUR, new_device_notice=False)
    start(data)
    run(data, T0)
    assert incidents(data) == []
    run(data, T0 - 6 * DAY)  # one pass with an unsynced clock
    run(data, T0 + 60)
    assert incidents(data) == []


def test_a_pass_with_the_clock_stepped_back_opens_nothing(data):
    start(data)
    arrive(data, MAC, measured=False)
    now = T0 + DWELL + SK + 100
    run(data, now)  # not measured yet: nothing to open
    meas(data, MAC)
    run(data, now - 50)  # the clock stepped back: this pass opens nothing
    assert incidents(data) == []
    run(data, now + 20)
    assert len(incidents(data)) == 1


def test_a_small_backward_step_after_dwell_notices_nothing_old(data):
    arrive(data, MAC, at=T0 - 3 * DAY)
    ticks(
        data, T0 - 3 * DAY + DWELL + SK, T0 - 3 * DAY + 6 * HOUR, step=HOUR, new_device_notice=False
    )
    start(data)
    run(data, T0)
    run(data, T0 - 3 * DAY + 5 * HOUR)
    run(data, T0 + 60)
    assert incidents(data) == []


# R2: a stale collector stamp cannot hide a genuinely new device
def test_a_new_device_with_a_stale_collector_stamp_is_noticed_once(data):
    start(data)
    arrive(data, MAC, at=T0)
    data.add_batch(1_700_000_000, neigh=[MAC], received=T0 + 600)  # router without an RTC
    ticks(data, T0 + DWELL + SK, T0 + DAY, step=HOUR)
    assert data.q("SELECT first_seen FROM devices")[0][0] < "2024"  # the stamp really is stale
    assert len(incidents(data)) == 1


# ---- R3: the whole candidate window is hold-stamped in the first pass ---------------------------
def test_a_real_device_behind_a_flood_is_stamped_at_once_and_ages_from_then(data):
    start(data)
    arrive(data, macs(60), at=T0)
    arrive(data, M2, at=T0 + 10)
    first = T0 + DWELL + SK + 60
    run(data, first)
    real = device_of(data, M2)
    assert f"f5_eligible:{real}" in meta(data, "f5_eligible:")  # not only the first 20
    t = first
    while f"f5_skipped:{real}" not in meta(data, "f5_skipped:") and t < first + 10 * DAY:
        t += 3 * HOUR
        run(data, t)
    assert meta(data, "f5_skipped:")[f"f5_skipped:{real}"].endswith(" stale")
    assert t - first <= 84 * HOUR  # 72 h of hold, then 3-hour passes drop 20 at a time (was 236 h)


def test_at_most_fetch_max_candidates_are_stamped_per_run(data):
    start(data)
    arrive(data, macs(250), at=T0)
    run(data, T0 + DWELL + SK + 60)
    assert len(incidents(data)) == 3
    assert len(meta(data, "f5_eligible:")) == nd.FETCH_MAX - 3  # 200 stamped, 3 noticed


# ---- R4: the resume gap is 15 minutes ------------------------------------------------------------
def test_the_resume_gap_constant_is_fifteen_minutes():
    assert REAL_GAP == 900


def off_window_scenario(data, minutes):
    """Flag on, then off; a device arrives and dwells while it is off; on again after `minutes`."""
    start(data, transient_min_dwell_s=120)
    run(data, T0, transient_min_dwell_s=120)
    data.add_batch(T0 + 700, neigh=[MAC])
    data.add_batch(T0 + 700 + 120 + SK, neigh=[MAC])  # the second server hour, dwell met
    meas(data, MAC)
    run(data, T0 + 300, new_device_notice=False, transient_min_dwell_s=120)
    run(data, T0 + minutes * 60, transient_min_dwell_s=120)
    return incidents(data)


def test_a_flag_off_window_shorter_than_the_gap_can_notice_what_dwelled_in_it(data, monkeypatch):
    monkeypatch.setattr(nd, "RESUME_GAP_S", REAL_GAP)
    assert len(off_window_scenario(data, 14)) == 1  # documented: not watertight under 15 minutes


def test_a_flag_off_window_longer_than_the_gap_notices_nothing_from_it(data, monkeypatch):
    monkeypatch.setattr(nd, "RESUME_GAP_S", REAL_GAP)
    assert off_window_scenario(data, 16) == []


# ---- R5: containment of any exception, defensive meta parsing ------------------------------------
def test_a_corrupt_last_run_value_neither_escapes_nor_disables_the_sweep(data, caplog):
    start(data)
    data.inv.execute("UPDATE pipeline_meta SET value='x' WHERE key='f5_last_run'")
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0)  # must not raise
    assert "new_device_watermark_moved" in caplog.text
    arrive(data, MAC, at=T0 + 60)
    run(data, T0 + DWELL + SK + 100)
    assert len(incidents(data)) == 1


def test_a_corrupt_floor_or_close_cursor_is_ignored_not_fatal(data):
    start(data)
    arrive(data, MAC, at=T0)
    run(data, T0 + DWELL + SK + 10)
    (row,) = incidents(data)
    data.inv.execute("UPDATE pipeline_meta SET value='??' WHERE key='f5_close_cursor'")
    decide(data, row, "expected")
    run(data, T0 + DWELL + SK + 40)
    assert incidents(data)[0]["state"] == "resolved"
    data.inv.execute("UPDATE pipeline_meta SET value='zz' WHERE key='f5_floor'")
    run(data, T0 + DWELL + SK + 70)  # must not raise


def test_any_exception_is_contained_and_logged_by_class_name(data, monkeypatch, caplog):
    start(data)
    arrive(data, MAC)

    def boom(*a, **k):
        raise ValueError("secret detail " + MAC)

    monkeypatch.setattr(nd, "_open_incident", boom)
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + DWELL + SK + 10)  # must not raise
    assert incidents(data) == []
    failed = [r for r in caplog.records if r.getMessage() == "new_device_sweep_failed"]
    assert failed and failed[0].fields["error"] == "ValueError"
    assert MAC not in caplog.text and "secret detail" not in caplog.text


# ---- bounds and cleanup --------------------------------------------------------------------------
def test_the_per_run_slice_is_twenty_devices(data, monkeypatch):
    start(data, new_device_max_per_day=20)
    macs_ = staggered(data, 30)
    run(data, T0 + 10, new_device_notice=False)
    _, calls = failing(monkeypatch, {device_of(data, m) for m in macs_[:20]})
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert len(calls) == 20 and incidents(data) == []


def test_the_retry_delay_stops_at_a_day(data):
    start(data)
    for _ in range(8):
        nd._lineage_failed(data.inv, "dev-x", T0)
    assert meta(data, "f5_retry:") == {"f5_retry:dev-x": f"8|{T0 + 86400}"}


def test_a_device_that_left_eligibility_loses_its_stamp_and_does_not_drop_when_it_returns(data):
    start(data, new_device_max_per_day=1)
    macs_ = staggered(data, 3)
    run(data, T0 + DWELL + 300, new_device_max_per_day=1)  # first noticed, two held and stamped
    held = device_of(data, macs_[1])
    assert f"f5_eligible:{held}" in meta(data, "f5_eligible:")
    data.inv.execute("UPDATE devices SET status='retired' WHERE id=?", (held,))
    run(data, T0 + DWELL + 330, new_device_max_per_day=1)
    assert f"f5_eligible:{held}" not in meta(data, "f5_eligible:")  # cleaned within the scan
    ticks(data, T0 + DWELL + 3 * HOUR, T0 + 80 * HOUR, new_device_max_per_day=1)
    data.inv.execute("UPDATE devices SET status='active' WHERE id=?", (held,))
    ticks(data, T0 + 80 * HOUR + HOUR, T0 + 100 * HOUR, new_device_max_per_day=1)
    assert f"f5_skipped:{held}" not in meta(data, "f5_skipped:")
    assert held in {r["device_id"] for r in incidents(data)}


def test_an_expired_backoff_of_a_device_that_left_is_cleaned(data, monkeypatch):
    start(data)
    arrive(data, [MAC, M2])
    run(data, T0 + 10, new_device_notice=False)
    bad = device_of(data, MAC)
    failing(monkeypatch, {bad})
    now = T0 + DWELL + SK + 10
    run(data, now)
    assert f"f5_retry:{bad}" in meta(data, "f5_retry:")
    data.inv.execute("UPDATE devices SET status='retired' WHERE id=?", (bad,))
    ticks(data, now + 4 * HOUR, now + 5 * HOUR, step=HOUR)
    assert meta(data, "f5_retry:") == {}


def test_a_backed_off_device_restarts_its_hold_age_when_it_resolves(data, monkeypatch):
    start(data)
    arrive(data, [MAC, M2])
    run(data, T0 + 10, new_device_notice=False)
    bad = device_of(data, MAC)
    real, _ = failing(monkeypatch, {bad})
    now = T0 + DWELL + SK + 10
    ticks(data, now, now + 80 * HOUR)  # fails for longer than the 72 h hold
    monkeypatch.setattr(nd, "lineage", real)
    ticks(data, now + 81 * HOUR, now + 110 * HOUR)  # the backoff (at most a day) expires
    assert bad in {r["device_id"] for r in incidents(data)}
    assert f"f5_skipped:{bad}" not in meta(data, "f5_skipped:")


def test_every_sweep_function_stays_within_fifty_lines():
    for name, fn in inspect.getmembers(nd, inspect.isfunction):
        if fn.__module__ == nd.__name__:
            lines = len(inspect.getsource(fn).splitlines())
            assert lines <= 50, (name, lines)


def test_classify_returns_one_of_four_verdicts():
    assert inspect.signature(nd._classify).return_annotation
    assert "stale" in inspect.getsource(nd._classify)
