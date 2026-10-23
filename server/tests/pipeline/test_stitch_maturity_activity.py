"""Activity intervals (fold, widen, clip, per-MAC cap), the server-anchored maturity, and the
single merged evidence-gap list."""

from __future__ import annotations

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    NOW,
    NOW_ABS,
    OLD,
    appear,
    candidates,
    inv,  # noqa: F401
    kinds,
    mac,
    run,
    run_at,
    seeded,
    seeded_d,
    source_of,
    suggestions,
)

from vigie_pipeline import activity
from vigie_pipeline.activity import (
    Gaps,
    coalesce_to,
    load_activity,
    purge_activity,
    record_activity,
)
from vigie_pipeline.config import ACTIVITY_MAX_REPORT_LAG_S, ACTIVITY_SKEW_S, INTERVALS_PER_MAC
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.snapshot import EMPTY
from vigie_pipeline.sources import MacActivity


def intervals(data: Data, mac_addr: str) -> list[tuple[int, int]]:
    return [tuple(r) for r in data.q('SELECT start, "end" FROM mac_activity WHERE mac=?', mac_addr)]


# ---- folding ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gap", "expected"),
    [(300, [(0, 120), (1000, 1060)]), (2000, [(0, 1060)]), (879, [(0, 120), (1000, 1060)]),
     (880, [(0, 1060)])],  # a gap of exactly the threshold does not split
)  # fmt: skip
def test_activity_splits_on_gap_and_is_configurable(data, gap, expected):
    m = appear(data, 1, 0, 120, step=60)
    data.add_batch(T0 + 1000, dns=[(m, T0 + 1000), (m, T0 + 1060)])
    run(data, activity_gap_s=gap)
    assert intervals(data, m) == [(T0 + s, T0 + e) for s, e in expected]


def test_activity_idempotent_out_of_order_and_retention(data):
    m = appear(data, 1, 600, 720)
    run(data)
    before = intervals(data, m)
    data.add_batch(T0, dns=[(m, T0), (m, T0 + 60)])  # older batch arrives later
    run(data)
    assert intervals(data, m) == [(T0, T0 + 60), *before]
    data.add_batch(T0 + 300, dns=[(m, T0 + 300)])  # bridges the gap (<=5 min each side)
    run(data)
    assert intervals(data, m) == [(T0, T0 + 720)]
    run(data)
    assert intervals(data, m) == [(T0, T0 + 720)]
    run_at(data, T0 + 720 + 7 * 86400 + 1)  # retention: 7 days after the interval end
    assert intervals(data, m) == []


def _fold(inv_db, stamps: set[int], received: int, retention: int = 7 * 86400, m: str = mac(77)):
    act = MacActivity(first_ts=min(stamps), last_ts=max(stamps), stamps=set(stamps))
    record_activity(inv_db, {m: act}, 300, received, retention)
    return sorted(r[0] for r in inv_db.execute("SELECT start FROM mac_activity WHERE mac=?", (m,)))


def test_activity_window_boundaries(tmp_path):
    pinv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec, week = T0, 7 * 86400
    assert ACTIVITY_SKEW_S == 300 and ACTIVITY_MAX_REPORT_LAG_S == 3600
    assert _fold(pinv, {rec + 300}, rec) == [rec + 300]  # small clock skew accepted
    pinv.execute("DELETE FROM mac_activity")
    assert _fold(pinv, {rec + 301}, rec) == []
    assert _fold(pinv, {rec - week}, rec) == []  # the lower bound is the report lag, not retention
    assert _fold(pinv, {rec - 3600}, rec) == [rec - 3600]  # exactly the lag
    assert _fold(pinv, {rec - 3601}, rec) == [rec - 3600]


def test_stamps_older_than_the_report_lag_are_ignored_for_new_and_known_macs_alike(tmp_path):
    pinv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec, lag = T0, ACTIVITY_MAX_REPORT_LAG_S
    m = "ae:00:00:00:09:09"
    assert _fold(pinv, {rec - lag - 1}, rec, m=m) == []  # first sighting: too old
    assert _fold(pinv, {rec - lag}, rec, m=m) == [rec - lag]  # exactly the lag: kept
    # the MAC is known now, but a later batch cannot back-fill further than its own lag either
    assert _fold(pinv, {rec - 3 * lag}, rec, m=m) == [rec - lag]
    assert _fold(pinv, {rec - 3 * lag}, rec + 2 * lag, m=m) == [rec - lag]
    assert _fold(pinv, {rec + lag}, rec + 2 * lag, m=m) == [rec - lag, rec + lag]


def test_the_report_lag_never_exceeds_a_shorter_retention(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = T0
    stamps = {rec - 2000, rec - 900, rec - 500}
    act = MacActivity(first_ts=min(stamps), last_ts=max(stamps), stamps=stamps)
    record_activity(conn, {"m": act}, 300, rec, 1000)  # retention 1000 s < the 3600 s lag
    assert sorted(r[0] for r in conn.execute("SELECT start FROM mac_activity")) == [
        rec - 900,
        rec - 500,
    ]


def test_epoch_zero_and_far_future_stamps_do_not_mature_a_mac(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 400, 400)
    data.add_batch(T0 + 401, dns=[(b, 5)])  # a router without an RTC
    data.add_batch(T0 + 402, dns=[(b, T0 + 10**7)])
    run(data)
    assert source_of(data, b) == "self"
    assert data.q("SELECT MIN(start), MAX(\"end\") FROM mac_activity WHERE mac=?", b)[0][:] == (
        T0 + 400, T0 + 400,
    )  # fmt: skip
    ov.close()


def test_a_mac_with_only_ignored_or_no_stamps_is_still_recorded_as_received(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    record_activity(conn, {"m": MacActivity(1, 1, stamps={1})}, 300, 10**9, 7 * 86400)
    record_activity(conn, {"n": MacActivity(1, 1)}, 300, 10**9, 7 * 86400)
    rows = conn.execute("SELECT mac, received FROM mac_first_received ORDER BY mac").fetchall()
    assert [tuple(r) for r in rows] == [("m", 10**9), ("n", 10**9)]
    assert conn.execute("SELECT COUNT(*) FROM mac_activity").fetchone()[0] == 0


# ---- the per-MAC cap holds at write time ---------------------------------------------------------


def test_coalesce_to_bridges_the_smallest_silences_first():
    ivs = [(0, 10), (20, 30), (100, 110), (111, 120), (500, 510)]
    assert coalesce_to(ivs, 5) == ivs
    assert coalesce_to(ivs, 4) == [(0, 10), (20, 30), (100, 120), (500, 510)]
    assert coalesce_to(ivs, 3) == [(0, 30), (100, 120), (500, 510)]
    assert coalesce_to(ivs, 2) == [(0, 120), (500, 510)]
    assert coalesce_to(ivs, 1) == [(0, 510)]


def test_a_mac_never_holds_more_than_the_interval_cap_however_many_bursts_it_sends(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = 10**9
    for k in range(72):  # one lone stamp every 400 s (more than a gap apart): 72 raw intervals
        act = MacActivity(rec + 400 * k, rec + 400 * k, stamps={rec + 400 * k})
        record_activity(conn, {"m": act}, 300, rec + 400 * k, 7 * 86400)
        count = conn.execute("SELECT COUNT(*) FROM mac_activity WHERE mac='m'").fetchone()[0]
        assert count <= INTERVALS_PER_MAC
    rows = conn.execute(
        'SELECT start, "end" FROM mac_activity WHERE mac=? ORDER BY start', ("m",)
    ).fetchall()
    assert len(rows) == INTERVALS_PER_MAC
    assert all(a[1] < b[0] for a, b in zip(rows, rows[1:], strict=False))  # still disjoint
    assert (rows[0][0], rows[-1][1]) == (rec, rec + 400 * 71)  # the span is unchanged


def test_coalescing_only_adds_presence_so_a_present_copy_stays_vetoed(inv, monkeypatch):
    monkeypatch.setattr(activity, "INTERVALS_PER_MAC", 4)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    inv.commit()
    m = "ae:ff:00:00:00:01"
    inv.db.execute(
        "INSERT INTO devices (id, first_seen, last_seen) VALUES ('A', '2026-01-02T00:00:00Z', 't')"
    )
    inv.db.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint, vendor_class,"
        " hostname, mdns_name, link_source, first_seen, last_seen)"
        " VALUES (?,'A',1,'1,2,3','x','victim',NULL,'self','2026-01-02T00:00:00Z','t')", (m,),
    )  # fmt: skip
    stamps = {NOW_ABS - 3000 + i * 400 for i in range(8)}  # eight bursts beside the victim
    record_activity(
        inv.db, {m: MacActivity(min(stamps), max(stamps), stamps=stamps)}, 300, NOW_ABS, 7 * 86400
    )
    inv.db.execute("UPDATE mac_first_received SET received=? WHERE mac=?", (NOW_ABS - 5000, m))
    assert inv.db.execute("SELECT COUNT(*) FROM mac_activity WHERE mac=?", (m,)).fetchone()[0] == 4
    inv.stitch(EMPTY)
    assert inv.state("A") == [("D", "vetoed")]


# ---- loading: widen, clip, retention -------------------------------------------------------------


@pytest.mark.parametrize(("raw", "expect"), [
    ((1000, 1000), (850, 1150)),
    ((1000, 1100), (900, 1200)),
    ((0, 99), (-100, 200)),  # odd shortfall: the extra second goes to the end
    ((0, 300), (0, 300)),
    ((0, 400), (0, 400)),
])  # fmt: skip
def test_load_activity_widens_to_the_minimum_width(tmp_path, raw, expect):
    pinv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    pinv.execute("INSERT INTO mac_activity VALUES ('m', ?, ?)", raw)
    assert load_activity(pinv, ["m"], min_width_s=300, min_end=0, first_received={}) == {
        "m": [expect]
    }


@pytest.mark.parametrize(
    ("raw", "kept"),
    [
        ((6300, 6399), None),  # wholly before the horizon (10000 - 3600 = 6400)
        ((6300, 6400), (6400, 6400)),  # touches the horizon: kept, clipped
        ((6000, 7000), (6400, 7000)),
        ((6400, 6500), (6400, 6500)),
        ((9000, 9100), (9000, 9100)),
    ],
)
def test_activity_before_the_report_lag_horizon_is_clipped(tmp_path, raw, kept):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", *raw))
    got = load_activity(conn, ["m"], min_width_s=0, min_end=0, first_received={"m": 10_000})
    assert got == ({"m": [kept]} if kept else {})
    assert load_activity(conn, ["m"], min_width_s=0, min_end=0, first_received={}) == {"m": [raw]}


def test_clipping_applies_after_widening_and_the_retention_cutoff_applies(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 6500, 6500))
    conn.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 100, 110))
    got = load_activity(conn, ["m"], min_width_s=300, min_end=500, first_received={"m": 10_000})
    assert got == {"m": [(6400, 6650)]}  # widened to [6350, 6650], then clipped at 6400
    got = load_activity(conn, ["m"], min_width_s=0, min_end=0, first_received={"m": 0})
    assert got == {"m": [(100, 110), (6500, 6500)]}


def test_purge_forgets_first_received_of_a_mac_without_activity_only(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.executemany("INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,?)",
                     [("gone", 100), ("kept", 100), ("fresh", 10_000)])  # fmt: skip
    conn.execute(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("kept", 9_000, 9_500)
    )
    conn.executemany('INSERT INTO evidence_gaps (start, "end") VALUES (?,?)', [(1, 100), (1, 9000)])
    purge_activity(conn, 10_000, 1_000)  # cutoff 9_000
    assert {r[0] for r in conn.execute("SELECT mac FROM mac_first_received")} == {"kept", "fresh"}
    assert [r[0] for r in conn.execute('SELECT "end" FROM evidence_gaps')] == [9000]


# ---- maturity is server-observed ------------------------------------------------------------


def test_first_received_is_the_server_clock_of_the_first_batch_and_never_moves(data):
    b = appear(data, 2, 0, 100)
    appear(data, 2, 200, 300)
    run_at(data, T0 + 400)
    assert data.q("SELECT received FROM mac_first_received WHERE mac=?", b)[0][0] == T0 + 100


def backdated(data: Data, n: int, received: int) -> str:
    """A new MAC whose first batch carries stamps 8000..7300 s old plus one fresh stamp."""
    m = mac(n)
    stamps = [*range(received - 8000, received - 7299, 100), received]
    data.add_batch(
        T0 + received - 8000, received=T0 + received,
        leases=[(m, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")],
        sightings=[(m, "mdns", "Daves Phone")], dns=[(m, T0 + t) for t in stamps],
    )  # fmt: skip
    return m


def test_backdated_first_batch_cannot_mature_a_mac_beside_the_present_device(data):
    n = 20000
    ov, _ = seeded_d(data, n)
    data.add_batch(
        T0 + n, received=T0 + n, dns=[(mac(1), T0 + t) for t in range(n - 3600, n + 1, 60)]
    )
    b = backdated(data, 2, n)
    run_at(data, T0 + n + 5)
    assert source_of(data, b) == "self"
    data.add_batch(T0 + n + 3600, received=T0 + n + 3600,
                   dns=[(mac(1), T0 + t) for t in range(n, n + 3601, 60)])  # fmt: skip
    run_at(data, T0 + n + 3700)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []  # one trusted stamp
    ov.close()


def test_a_later_batch_backfill_cannot_mature_a_copy_beside_the_present_device(data):
    n = 3000
    ov, _ = seeded_d(data, n)
    data.add_batch(T0 + n, received=T0 + n, dns=[(mac(1), T0 + t) for t in range(0, n + 1, 60)])
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + n, received=T0 + n, leases=lease, sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + n)])  # fmt: skip
    data.add_batch(T0 + n + 700, received=T0 + n + 700,
                   dns=[(b, T0 + t) for t in range(n - 5000, n - 4300, 100)])  # fmt: skip
    run_at(data, T0 + n + 1000)
    assert data.q("SELECT COUNT(*) FROM mac_activity WHERE mac=?", b)[0][0] == 1
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    ov.close()


def test_server_clock_anchors_maturity_even_for_honest_stamps(data):
    ov, _ = seeded_d(data, 300)
    b = appear(data, 2, 4000, 4700)  # 700 s of stamps, received at 4700
    run_at(data, T0 + 4700 + 600)  # first received exactly one grace ago: not yet
    assert source_of(data, b) == "self"
    run_at(data, T0 + 4700 + 601)
    assert source_of(data, b) == "rule"
    ov.close()


def test_sparse_two_stamp_copy_is_deferred_while_victim_is_present(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 400, 400)
    run(data)
    appear(data, 2, 1100, 1100)  # span 1000 s but only 600 s covered: not mature
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    appear(data, 2, 1800, 1800)  # covered 900 s, all of it beside the victim: vetoed
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


@pytest.mark.parametrize("end", [1000, 1000])
def test_covered_time_exactly_at_grace_is_deferred(data, end):
    ov, _ = seeded(data)
    b = appear(data, 2, 400, end)  # one interval of exactly 600 s
    run(data)
    assert source_of(data, b) == "self"
    ov.close()


@pytest.mark.parametrize(("first_ago", "covered", "expect"), [
    (601, 601, "ok"), (600, 601, "young"), (601, 600, "young"), (None, 601, "young"),
])  # fmt: skip
def test_mature_needs_both_server_age_and_covered_time_over_the_grace(
    inv, first_ago, covered, expect
):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW_ABS - 1000, NOW_ABS - 1000 + covered)])
    if first_ago is not None:
        inv.db.execute(
            "INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,?)",
            (m, NOW_ABS - first_ago),
        )
    else:  # no anchor at all: unknown age is not mature
        inv.db.execute("DELETE FROM mac_first_received WHERE mac=?", (m,))
    cp, hood, _ = inv.hood(m)
    assert cp.maturity(hood, m) == expect


def test_immature_candidate_wholly_inside_another_device_is_only_provisional(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 150, 150)  # one stamp, widened to [0, 300]: overlap == covered time
    run(data)
    assert suggestions(data) == []
    assert [c["state"] for c in candidates(data)] == ["open"]  # never a permanent veto
    assert kinds(data, "identity_overlap_veto") == []


def test_first_stamp_of_a_legitimate_handover_is_not_a_permanent_veto(data):
    ov, dev = seeded_d(data, 3600)
    appear(data, 2, 3600, 3600)  # L's first stamp, inside the old MAC's presence tail
    run_at(data, T0 + 3700)
    assert source_of(data, mac(2)) == "self"
    assert [c["state"] for c in candidates(data)] == ["open"]
    assert kinds(data, "identity_overlap_veto") == []
    appear(data, 2, 3700, 7200)  # L carries on alone
    run_at(data, T0 + 7300)
    assert source_of(data, mac(2)) == "rule"
    ov.close()


def test_a_provisional_overlap_never_downgrades_an_existing_candidate_row(inv):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 400, NOW_ABS - 400)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',1.0,'{}','suggested','t')"
    )
    st = inv.stitch()
    assert inv.state("A") == [("D", "suggested")] and st.vetoed == 0
    inv.db.execute("DELETE FROM identity_candidates")
    st = inv.stitch()
    assert inv.state("A") == [("D", "open")] and st.vetoed == 0
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0


# ---- evidence gaps: one merged list for every collector ------------------------------------------


def fold_gap(conn, stamps, received, retention=7 * 86400):
    act = MacActivity(min(stamps), max(stamps), stamps=set(stamps))
    record_activity(conn, {"m": act}, 300, received, retention)
    return [tuple(r) for r in conn.execute('SELECT start, "end" FROM evidence_gaps ORDER BY start')]


def test_stamps_dropped_for_the_report_lag_become_a_gap(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = T0
    assert fold_gap(conn, {rec - 3600, rec - 10}, rec) == []  # exactly the lag: kept, no gap
    gaps = fold_gap(conn, {rec - 5000, rec - 4000, rec - 100}, rec)
    assert gaps == [(rec - 5000, rec - 3600)]
    assert fold_gap(conn, {rec - 10**6}, rec) == gaps  # older than retention: epoch junk, not a gap


def test_gaps_within_one_activity_gap_merge_whatever_the_collector(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = 10**9
    assert fold_gap(conn, {rec - 9000}, rec) == [(rec - 9000, rec - 3600)]
    assert fold_gap(conn, {rec - 6000}, rec + 100) == [(rec - 9000, rec - 3500)]  # overlapping
    assert fold_gap(conn, {rec - 20000}, rec + 200) == [(rec - 20000, rec - 3400)]  # extends back
    assert fold_gap(conn, {rec - 3100 - 3600}, rec + 500) == [
        (rec - 20000, rec - 3100)
    ]  # within a gap
    assert len(fold_gap(conn, {rec + 450000}, rec + 500000)) == 2  # disjoint: a second row


def test_the_gap_table_is_bounded_by_retention_over_the_activity_gap(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = 10**9
    for k in range(300):  # a collector dripping a late stamp every 2 s for 600 s
        fold_gap(conn, {rec - 3700 + 2 * k}, rec + 2 * k)
    assert conn.execute("SELECT COUNT(*) FROM evidence_gaps").fetchone()[0] == 1


GAP_CASES = [
    (lambda lo, hi: (hi + 300, hi + 400), True),  # starts within one activity gap of the window
    (lambda lo, hi: (hi + 301, hi + 400), False),
    (lambda lo, hi: (lo - 400, lo - 300), True),  # ends within one activity gap of the window
    (lambda lo, hi: (lo - 400, lo - 301), False),
    (lambda lo, hi: (lo - 2000, lo - 1000), False),
    (lambda lo, hi: (lo + 20, lo + 30), True),
]


@pytest.mark.parametrize(("make", "blocked"), GAP_CASES)
def test_a_mac_whose_window_overlaps_a_gap_is_not_mature(inv, make, blocked):
    m = inv.mac(
        "D",
        "h",
        None,
        "self",
        OLD,
        [(NOW_ABS - 2000, NOW_ABS - 1900), (NOW_ABS - 1700, NOW_ABS - 1000)],
    )
    cp, hood, _ = inv.hood(m)
    assert cp.maturity(hood, m) == "ok"
    lo, hi = hood.act[m][0][0], hood.act[m][-1][1]
    inv.db.execute('INSERT INTO evidence_gaps (start, "end") VALUES (?,?)', make(lo, hi))
    cp, hood, _ = inv.hood(m)
    assert cp.maturity(hood, m) == ("gap" if blocked else "ok")


def test_every_gap_is_loaded_so_the_oldest_relevant_one_still_blocks(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW_ABS - 2000, NOW_ABS - 1000)])
    inv.commit()
    lo = NOW_ABS - 2000 - 5 * 86400
    inv.db.executemany(  # 3000 disjoint gaps (more than any old per-collector cap), oldest relevant
        'INSERT INTO evidence_gaps (start, "end") VALUES (?,?)',
        [(lo + 400 * k, lo + 400 * k + 5) for k in range(1000)],
    )
    inv.db.execute(
        'INSERT INTO evidence_gaps (start, "end") VALUES (?,?)', (NOW_ABS - 2100, NOW_ABS - 2050)
    )
    gaps = Gaps(inv.db, 0)
    assert len(gaps.spans) == 1001 and gaps.overlaps(NOW_ABS - 2300, NOW_ABS - 700)
    assert not gaps.overlaps(NOW_ABS - 100, NOW_ABS)
    cp, hood, _ = inv.hood(m)
    assert cp.maturity(hood, m) == "gap"


def test_the_copy_beside_a_late_collectors_victim_becomes_a_human_decision(data):
    ov, dev = seeded_d(data, 300)
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + 2000, collector="rtr-2", received=T0 + 2000, leases=lease,
                   sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + t) for t in range(1000, 2001, 60)])  # fmt: skip
    # the victim's collector was cut off 90 minutes; its backlog arrives late and part is dropped
    data.add_batch(T0 + 5400, collector="rtr-1", received=T0 + 5400,
                   dns=[(mac(1), T0 + t) for t in range(300, 5401, 60)])  # fmt: skip
    run_at(data, T0 + 6000)
    run_at(data, T0 + 6100)
    assert data.q("SELECT COUNT(*) FROM evidence_gaps")[0][0] == 1
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    (s,) = suggestions(data)
    assert (s["reason_code"], s["reason_text"]) == ("rule_hit_needs_confirm", "evidence_gap")
    events = kinds(data, "stitch_deferred")
    assert len(events) == 1 and "evidence_gap" in events[0]["summary"]
    run_at(data, T0 + 6000 + 86400)
    assert len(kinds(data, "stitch_deferred")) == 2  # once per UTC day
    ov.close()


def test_without_dropped_stamps_the_same_copy_attaches(data):
    ov, dev = seeded_d(data, 300)
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + 2000, collector="rtr-2", received=T0 + 2000, leases=lease,
                   sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + t) for t in range(1000, 2001, 60)])  # fmt: skip
    data.add_batch(T0 + 5400, collector="rtr-1", received=T0 + 5400,
                   dns=[(mac(1), T0 + t) for t in range(1800, 5401, 60)])  # fmt: skip
    run_at(data, T0 + 6000)
    assert data.q("SELECT COUNT(*) FROM evidence_gaps")[0][0] == 0
    assert source_of(data, b) == "rule" and kinds(data, "stitch_deferred") == []
    ov.close()


def test_a_gap_keeps_a_sustained_overlap_provisional(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    inv.db.execute(
        'INSERT INTO evidence_gaps (start, "end") VALUES (?,?)', (NOW_ABS - 8000, NOW_ABS - 3000)
    )
    st = inv.stitch(RULE_SNAP_LOCAL)
    assert inv.state("A") == [("D", "open")] and st.vetoed == 0 and st.attached == 0
    assert (
        inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0
    )  # overlap: no nudge
    inv.db.execute("DELETE FROM evidence_gaps")
    inv.db.execute("DELETE FROM identity_candidates")
    assert inv.stitch(RULE_SNAP_LOCAL).vetoed == 1 and inv.state("A") == [("D", "vetoed")]


from stitch_helpers import RULE_SNAP as RULE_SNAP_LOCAL  # noqa: E402


def test_a_mac_with_no_stamps_in_the_subject_query_is_not_examined(inv):
    inv.mac("D", "victim", None, "self", OLD, [], rand=1)
    assert inv.stitch(EMPTY).examined == 0 and NOW > 0


def test_a_hostname_change_after_the_first_sighting_refreshes_the_stored_fold(data):
    """Opus M2 (mutant): the lookup must follow the NEW name of a known MAC."""
    from vigie_pipeline.stitch_types import fold

    m = appear(data, 1, 0, 300, host="Old-Name", mdns=None)
    run(data)
    assert data.q("SELECT hostname_fold FROM observations WHERE mac=?", m)[0][0] == fold("Old-Name")
    appear(data, 1, 400, 700, host="Ｓtraße-PC", mdns=None)  # renamed, newest batch wins
    appear(data, 2, 800, 1100, host="strasse-pc", mdns=None)  # a later roll under the new name
    run(data)
    assert data.q("SELECT hostname_fold FROM observations WHERE mac=?", m)[0][0] == fold(
        "Ｓtraße-PC"
    )
    assert [c["state"] for c in candidates(data)] == ["suggested"]
