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
    assert (observed, qualified) == (120, 120)  # union, not the 122 s sum


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
    assert qualified == observed == 3600  # union credit: the skewed seconds are counted once


def _abs(windows):
    return [(HOUR + s, HOUR + e) for s, e in windows]


def test_nested_short_window_still_disqualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(tmp_path, _abs([(0, 60), (10, 12)]))
    assert "overlapping_window" in reasons
    assert qualified == 0


def test_nested_window_arriving_first_still_disqualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(tmp_path, _abs([(10, 12), (0, 60)]))
    assert "overlapping_window" in reasons
    assert qualified == 0


def test_duplicate_two_second_window_with_new_batch_id_disqualifies(tmp_path):
    _, qualified, reasons = _hour_coverage(tmp_path, _abs([(0, 2), (0, 2)]))
    assert "overlapping_window" in reasons
    assert qualified == 0


def test_short_windows_get_no_tolerance(tmp_path):
    # both windows are below MIN_TOLERANT_WINDOW_S (4 s): 3 s windows shifted by 1 s
    _, _, reasons = _hour_coverage(tmp_path, _abs([(0, 3), (1, 4)]))
    assert "overlapping_window" in reasons


def test_short_new_window_on_the_edge_of_a_long_one_is_not_tolerated(tmp_path):
    _, _, reasons = _hour_coverage(tmp_path, _abs([(0, 60), (58, 61)]))
    assert "overlapping_window" in reasons


def test_short_prior_window_on_the_edge_of_a_long_new_one_is_not_tolerated(tmp_path):
    _, _, reasons = _hour_coverage(tmp_path, _abs([(58, 61), (0, 60)]))
    assert "overlapping_window" in reasons


def test_more_than_two_intersecting_neighbours_adds_no_coverage(tmp_path):
    observed, qualified, reasons = _hour_coverage(
        tmp_path, _abs([(0, 100), (50, 100), (40, 100), (98, 200)])
    )
    assert "overlapping_window" in reasons
    assert (observed, qualified) == (100, 0)


def test_observed_and_qualified_are_clamped_to_one_hour(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    _window(inv, 0, HOUR, HOUR + 3500)
    inv.execute("UPDATE coverage_hourly SET observed_seconds=3590,qualified_seconds=3590")
    _window(inv, 1, HOUR + 3500, HOUR + 3600)  # contiguous; sum would be 3690
    observed, qualified, _ = _coverage(inv)
    inv.close()
    assert (observed, qualified) == (3600, 3600)


def test_four_second_windows_edge_overlap_is_tolerated(tmp_path):
    observed, _, reasons = _hour_coverage(tmp_path, _abs([(0, 4), (2, 6)]))
    assert "overlapping_window" not in reasons
    assert observed == 6


def test_three_chained_windows_credit_the_union_not_the_sum(tmp_path):
    observed, qualified, reasons = _hour_coverage(
        tmp_path, _abs([(0, 1200), (1198, 2400), (2398, 3600)])
    )
    assert reasons == []
    assert observed == qualified == 3600


def test_chain_with_union_below_threshold_does_not_qualify_as_3420(tmp_path):
    # 57 windows of 60 s, each overlapping the previous by 2 s: union is 57*58+2 = 3308 s
    windows = [(58 * n, 58 * n + 60) for n in range(57)]
    observed, qualified, reasons = _hour_coverage(tmp_path, _abs(windows))
    assert reasons == []
    assert observed == qualified == 58 * 57 + 2
    assert observed < 3420


def test_reverse_arrival_order_credits_the_union(tmp_path):
    observed, qualified, reasons = _hour_coverage(
        tmp_path, _abs([(2398, 3600), (1198, 2400), (0, 1200)])
    )
    assert reasons == []
    assert observed == qualified == 3600


def test_overlap_with_two_prior_neighbours_subtracts_both(tmp_path):
    # arrival order: left, right, then the middle one overlapping each by 2 s
    observed, qualified, reasons = _hour_coverage(tmp_path, _abs([(0, 100), (198, 300), (98, 200)]))
    assert reasons == []
    assert observed == qualified == 300


def test_four_second_middle_window_overlapped_on_both_sides(tmp_path):
    observed, qualified, reasons = _hour_coverage(tmp_path, _abs([(0, 100), (98, 102), (100, 200)]))
    assert reasons == []
    assert observed == qualified == 200
