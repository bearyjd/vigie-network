"""Repro: whole-second clock skew between consecutive collector windows disqualifies the hour.

The collector derives window_start from (wall - (mono - last_flush_mono)) with wall and monotonic
truncated independently, so start_n can be 1 s before end_{n-1}. See collector/agent/src/window.rs.
"""

import json

from vigie_pipeline.measurements import Measurements, apply_measurements
from vigie_pipeline.schema import open_pipeline_inventory

HOUR = 1_791_997_200
MAC = "aa:bb:cc:00:00:01"


def _window(inv, n: int, start: int, end: int) -> None:
    apply_measurements(
        inv,
        Measurements("c1", f"b{n}", start, end, "2026-10-24T00:00:00Z", (), {MAC: (10, 0, 1, 0)}),
    )


def _coverage(inv):
    observed, qualified, reasons = inv.execute(
        "SELECT observed_seconds,qualified_seconds,reasons FROM coverage_hourly"
    ).fetchone()
    return observed, qualified, json.loads(reasons)


def test_touching_60s_windows_stay_qualified(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    for n in range(5):
        _window(inv, n, HOUR + 60 * n, HOUR + 60 * (n + 1))
    assert _coverage(inv) == (300, 300, [])
    inv.close()


def test_one_second_start_skew_does_not_disqualify_the_hour(tmp_path):
    """Intended: 1 s of whole-second clock skew is not a real overlap. Currently FAILS."""
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    _window(inv, 0, HOUR, HOUR + 60)
    _window(inv, 1, HOUR + 60, HOUR + 120)
    _window(inv, 2, HOUR + 119, HOUR + 180)  # start_n = end_{n-1} - 1
    _window(inv, 3, HOUR + 180, HOUR + 240)
    observed, qualified, reasons = _coverage(inv)
    assert "overlapping_window" not in reasons
    assert qualified > 0
    inv.close()


def _hour_coverage(tmp_path, windows):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    for n, (start, end) in enumerate(windows):
        _window(inv, n, start, end)
    result = _coverage(inv)
    inv.close()
    return result


def test_overlap_of_exactly_tolerance_qualifies(tmp_path):
    observed, qualified, reasons = _hour_coverage(
        tmp_path, [(HOUR, HOUR + 60), (HOUR + 58, HOUR + 120)]
    )
    assert "overlapping_window" not in reasons
    assert (observed, qualified) == (122, 122)


def test_overlap_beyond_tolerance_disqualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(tmp_path, [(HOUR, HOUR + 60), (HOUR + 57, HOUR + 120)])
    assert "overlapping_window" in reasons
    assert qualified == 0


def test_one_second_skew_on_both_neighbours_qualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(
        tmp_path, [(HOUR, HOUR + 60), (HOUR + 59, HOUR + 120), (HOUR + 119, HOUR + 180)]
    )
    assert reasons == []
    assert qualified > 0


def test_identical_window_with_new_batch_id_still_disqualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(tmp_path, [(HOUR, HOUR + 60), (HOUR, HOUR + 60)])
    assert "overlapping_window" in reasons
    assert qualified == 0


def test_full_hour_of_skewed_windows_qualifies(tmp_path):
    windows = [(HOUR + 60 * n - (1 if n else 0), HOUR + 60 * (n + 1)) for n in range(60)]
    observed, qualified, reasons = _hour_coverage(tmp_path, windows)
    assert reasons == []
    assert qualified == observed >= 3420
