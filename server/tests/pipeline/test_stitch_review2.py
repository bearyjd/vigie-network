"""Fix-round 2 tests for the second stitching review (H1-H4, M1, M2, L1, mutants)."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    HOST,
    MDNS,
    NOW,
    OPT55,
    OPT60,
    Overrides,
    appear,
    candidates,
    device_of,
    kinds,
    mac,
    run,
    sig,
    suggestions,
)
from test_stitch_review import flood_mac, seeded, source_of

from vigie_pipeline import schema, snapshot
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.activity import Interval, load_activity, record_activity
from vigie_pipeline.config import ACTIVITY_SKEW_S, PipelineConfig
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import apply_pipeline_migrations, open_pipeline_inventory
from vigie_pipeline.sources import MacActivity


@pytest.fixture
def pinv(data: Data) -> sqlite3.Connection:
    apply_pipeline_migrations(data.inv)
    return data.inv


def iot(data: Data, **kw):
    return seeded(data, group="iot", **kw)


# ---- H1: maturity counts covered time, not the first-to-last span -------------------------------


def test_sparse_two_stamp_copy_is_deferred_while_victim_is_present(data):
    ov, _ = iot(data, a_end=3100)
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


def test_covered_time_exactly_at_grace_is_deferred(data):
    ov, _ = iot(data)
    b = appear(data, 2, 400, 1000)  # one interval of exactly 600 s
    run(data)
    assert source_of(data, b) == "self"
    ov.close()


def test_immature_candidate_wholly_inside_another_device_is_only_provisional(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 150, 150)  # one stamp, widened to [0, 300]: overlap == covered time
    run(data)
    assert suggestions(data) == []
    # 300 s covered is not mature: the overlap is provisional (round 5), never a permanent veto
    assert [c["state"] for c in candidates(data)] == ["open"]
    assert kinds(data, "identity_overlap_veto") == []


def test_mature_candidate_wholly_inside_another_device_is_vetoed(data):
    appear(data, 1, 0, 3000)
    appear(data, 2, 1000, 2000)  # 1000 s covered (mature), wholly inside the peer
    run(data)
    assert suggestions(data) == []
    assert [c["state"] for c in candidates(data)] == ["vetoed"]


def test_candidate_almost_inside_another_device_is_not_vetoed(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 160, 160)  # widened to [10, 310]: overlap 290 < covered 300
    run(data)
    assert [c["state"] for c in candidates(data)] == ["suggested"]


def test_zero_overlap_is_never_vetoed_even_with_zero_covered_time(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 400)
    run(data, activity_gap_s=0)  # no widening: the stamp covers 0 s and overlaps 0 s
    assert [c["state"] for c in candidates(data)] == ["suggested"]


# ---- H2: out-of-range collector timestamps -------------------------------------------------------


def test_epoch_zero_stamp_does_not_mature_a_mac(data):
    ov, _ = iot(data, a_end=3100)
    b = appear(data, 2, 400, 400)
    data.add_batch(T0 + 401, dns=[(b, 5)])  # a router without an RTC
    run(data)
    assert source_of(data, b) == "self"
    assert data.q("SELECT MIN(start) FROM mac_activity WHERE mac=?", b)[0][0] == T0 + 400
    ov.close()


def test_far_future_stamp_does_not_mature_a_mac(data):
    ov, _ = iot(data, a_end=3100)
    b = appear(data, 2, 400, 400)
    data.add_batch(T0 + 401, dns=[(b, T0 + 10**7)])
    run(data)
    assert source_of(data, b) == "self"
    assert data.q('SELECT MAX("end") FROM mac_activity WHERE mac=?', b)[0][0] == T0 + 400
    ov.close()


def _fold(inv: sqlite3.Connection, stamps: set[int], received: int, retention: int = 7 * 86400):
    m = mac(77)
    act = MacActivity(first_ts=min(stamps), last_ts=max(stamps), stamps=set(stamps))
    record_activity(inv, {m: act}, 300, received, retention)
    return sorted(r[0] for r in inv.execute("SELECT start FROM mac_activity WHERE mac=?", (m,)))


def test_activity_window_boundaries(pinv):
    rec, week = T0, 7 * 86400
    assert ACTIVITY_SKEW_S == 300
    assert _fold(pinv, {rec + 300}, rec) == [rec + 300]  # small clock skew accepted
    pinv.execute("DELETE FROM mac_activity")
    assert _fold(pinv, {rec + 301}, rec) == []
    # the lower bound is the report lag (1 h) of the batch, not the retention window
    # (test_stitch_review3.test_stamps_older_than_the_report_lag_...)
    assert _fold(pinv, {rec - week}, rec) == []
    assert _fold(pinv, {rec - 3600}, rec) == [rec - 3600]  # exactly the lag
    assert _fold(pinv, {rec - 3601}, rec) == [rec - 3600]


# ---- H3: the victim's own partial-signature MAC is a veto peer ----------------------------------


def test_victims_partial_match_mac_is_a_veto_peer(data):
    ov, _ = seeded(data, group="iot", rule_sig=sig(mdns_name=MDNS))
    v2 = appear(data, 3, 400, 3000, mdns=None)  # victim's new MAC, mDNS not seen yet
    b = appear(data, 2, 400, 3000)  # a full-signature copy beside it
    run(data)  # a single pass must already veto
    assert source_of(data, b) == "self" and source_of(data, v2) == "self"
    assert kinds(data, "mac_attached") == []
    vetoed = {e["device_id"] for e in kinds(data, "identity_overlap_veto")}
    assert device_of(data, b) in vetoed
    ov.close()


# ---- H4: flood accounting --------------------------------------------------------------------


def _same_name_macs(data: Data, n: int, base: int = 10) -> list[str]:
    macs = [flood_mac(i + base) for i in range(n)]
    data.add_batch(
        T0 + 700,
        leases=[(m, HOST, OPT55, OPT60) for m in macs],
        dns=[(m, T0 + 700 + t) for m in macs for t in (0, 60)],
    )
    return macs


def test_flood_boundary_64_is_not_flooded_65_is(data):
    _same_name_macs(data, 64)
    run(data)
    assert kinds(data, "signature_flood") == []
    _same_name_macs(data, 1, base=500)
    run(data)
    assert len(kinds(data, "signature_flood")) == 1


def test_attached_macs_do_not_count_toward_the_flood_cap(data):
    ov, dev = iot(data)
    for i in range(70):  # one legitimate roll per pass for much longer than the cap
        start = 1000 + i * 800
        b = appear(data, 2 + i, start, start + 700)
        run(data, now=T0 + start + 700 + 3600)  # the server clock is after each receipt
        assert source_of(data, b) == "rule", f"roll {i} not attached"
    assert kinds(data, "signature_flood") == []
    assert len(kinds(data, "mac_attached")) == 70
    ov.close()


def test_junk_hostname_macs_do_not_block_the_legit_device(data):
    ov, dev = iot(data)
    macs = [flood_mac(i + 10) for i in range(65)]
    data.add_batch(T0 + 10, leases=[(m, f"x{i}", OPT55, OPT60) for i, m in enumerate(macs)],
                   dns=[(m, T0 + 10) for m in macs])  # fmt: skip
    run(data)
    b = appear(data, 2, 4000, 5000)
    run(data)
    assert source_of(data, b) == "rule"
    assert kinds(data, "signature_flood") == []
    ov.close()


def test_flooded_name_attaches_nothing_and_says_so_once_per_day(data):
    ov, dev = iot(data)
    macs = _same_name_macs(data, 65)
    b = appear(data, 2, 4000, 5000)
    for _ in range(3):
        run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert len(kinds(data, "signature_flood")) == 1  # M1: dedup per signature per UTC day
    assert all(source_of(data, m) == "self" for m in macs)
    ov.close()


def test_flood_event_repeats_on_a_new_day(data):
    _same_name_macs(data, 65)
    run(data)
    run_once(PipelineConfig(data_dir=data.root), now=NOW + 86400)
    assert len(kinds(data, "signature_flood")) == 2


# ---- mutants: caps ---------------------------------------------------------------------------


def test_row_cap_is_exact_and_counts_suggestion_rows(data, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_ROWS_PER_PASS", 4)
    for i in range(6):
        appear(data, 2 * i, 0, 60, opt55=f"[{i}]")
        appear(data, 2 * i + 1, 400, 460, opt55=f"[{i}]")
    run(data)
    assert len(candidates(data)) == 2 and len(suggestions(data)) == 2  # 2 rows each = 4
    for _ in range(6):
        run(data)
    assert len(suggestions(data)) == 6


# ---- M1/M2 ---------------------------------------------------------------------------------


def test_unassigned_target_needs_confirmation_not_attach(data):
    ov, dev = seeded(data, group=None)  # no device_overrides row at all
    b = appear(data, 2, 400, 1200)
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm"
    ov.close()


def test_target_with_null_group_needs_confirmation(data):
    ov, dev = seeded(data, group=None)
    ov.override(dev, None, version=2)
    b = appear(data, 2, 400, 1200)
    run(data)
    assert source_of(data, b) == "self"
    assert [s["reason_code"] for s in suggestions(data)] == ["rule_hit_needs_confirm"]
    ov.close()


def test_explicit_auto_inherit_group_still_attaches(data):
    ov, dev = iot(data)
    b = appear(data, 2, 400, 1200)
    run(data)
    assert device_of(data, b) == dev and source_of(data, b) == "rule"
    ov.close()


# ---- L1: v4 -> v5 --------------------------------------------------------------------------


def test_populated_v4_database_migrates_to_v5(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:4])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    ins = (
        "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES (?, 'd', 't', 'identity_candidate', 'info', 's')"
    )
    conn.execute(ins, ("e1",))
    conn.execute(ins, ("e2",))
    conn.execute("INSERT INTO mac_activity VALUES ('m', 1, 2)")
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 4
    conn.close()
    monkeypatch.undo()
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 7
    rows = conn.execute("SELECT id, dedup FROM events ORDER BY seq").fetchall()
    assert [tuple(r) for r in rows] == [("e1", None), ("e2", None)]  # NULL dedup stays NULL
    assert conn.execute("SELECT COUNT(*) FROM mac_activity").fetchone()[0] == 1
    assert apply_pipeline_migrations(conn) == 7  # re-apply is a no-op
    assert conn.execute("SELECT COUNT(*) FROM pipeline_schema").fetchone()[0] == 7
    conn.execute(ins, ("e3",))  # NULLs never collide on the partial unique index


# ---- mutants: activity widening, snapshot exceptions ---------------------------------------------


@pytest.mark.parametrize(("raw", "expect"), [
    ((1000, 1000), (850, 1150)),
    ((1000, 1100), (900, 1200)),
    ((0, 99), (-100, 200)),  # odd shortfall: the extra second goes to the end
    ((0, 300), (0, 300)),
    ((0, 400), (0, 400)),
])  # fmt: skip
def test_load_activity_widens_to_the_minimum_width(pinv, raw: Interval, expect: Interval):
    pinv.execute("INSERT INTO mac_activity VALUES ('m', ?, ?)", raw)
    assert load_activity(pinv, 300) == {"m": [expect]}


@pytest.mark.parametrize("exc", [TypeError("x"), KeyError("x"), IndexError("x")])
def test_unexpected_read_errors_fail_closed(tmp_path, monkeypatch, exc):
    ov = Overrides(tmp_path)
    ov.close()
    conn = snapshot.sqlite3.connect(tmp_path / "overrides.db")
    conn.row_factory = sqlite3.Row

    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr(snapshot, "_read", boom)
    with pytest.raises(snapshot.OverridesUnreadable):
        snapshot.load_snapshot(conn, NOW)
    assert not conn.in_transaction


def test_flood_log_is_a_warning(data, caplog):
    _same_name_macs(data, 65)
    with caplog.at_level(logging.WARNING):
        run(data)
    assert "signature_flood" in caplog.text
