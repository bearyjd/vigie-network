"""Fix-round 5 tests: rule-derived peers, server-observed maturity, provisional overlap, expiry
clock, write cap, suggestion look-up bounds, retired MACs, odd gaps, legacy dedup, malformed
overrides, re-check cursor."""

from __future__ import annotations

import logging
import sqlite3
import time

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import Overrides, appear, candidates, device_of, kinds, mac, sig
from test_stitch_review import RULE, source_of
from test_stitch_review4 import NOW, RULE_SNAP, Inv, inv  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_pipeline import processor, schema
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.activity import load_activity, purge_activity, record_activity
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import canonical_device
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.snapshot import Rule, Snapshot
from vigie_pipeline.sources import MacActivity
from vigie_pipeline.stitch import stitch
from vigie_pipeline.stitch_db import emit_once

OLD = "2026-01-01T00:00:00Z"


def run_at(data: Data, now: float, **kw):
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def link_of(inv: Inv, m: str) -> tuple:
    row = inv.db.execute("SELECT device_id, link_source FROM observations WHERE mac=?", (m,))
    return tuple(row.fetchone())


# ---- 1: peers come from the rule and the target identity, not from the applicant's extras ----


def extra_name_world(inv: Inv):
    """Hostname-only rule for D. D's old MAC: victim/Dave. V (the real device's current MAC):
    no hostname, mDNS Dave. A (the applicant): victim, and an extra mDNS 'Other' the rule never
    asked for."""
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 10000, NOW - 5000)], rand=0)
    inv.mac("V", None, "Dave", "self", "2026-01-02T00:00:00Z", [(NOW - 4000, NOW)])
    return inv.mac("A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])


def test_an_extra_applicant_name_cannot_exclude_the_real_device_from_the_veto(inv):
    a = extra_name_world(inv)
    st = inv.stitch(RULE_SNAP)
    assert link_of(inv, a) == ("A", "self") and st.attached == 0
    assert ("D", "vetoed") in inv.state("A")
    assert inv.count("identity_overlap_veto") == 1


def test_an_extra_applicant_name_cannot_hide_a_suspect_from_the_recheck(inv):
    a = extra_name_world(inv)
    inv.db.execute(
        "UPDATE observations SET device_id='D', link_source='rule', link_rule_id='r1' WHERE mac=?",
        (a,),
    )
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


def test_recheck_without_its_rule_still_uses_the_names_shared_with_the_target(inv):
    a = extra_name_world(inv)
    inv.db.execute(
        "UPDATE observations SET device_id='D', link_source='rule', link_rule_id='gone'"
        " WHERE mac=?",
        (a,),
    )
    st = inv.stitch(Snapshot({}, (), {}, {}, {}))  # the rule was revoked: not in the snapshot
    assert st.suspect == 1


def test_a_legitimate_roll_with_the_rule_names_only_still_attaches(inv):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(RULE_SNAP).attached == 1
    assert link_of(inv, a) == ("D", "rule")


# ---- 2: maturity is server-observed ----


def seeded_d(data: Data, end: int, *, step: int = 60):
    """The original device O (mac 1, rule target, iot) active over [0, end]."""
    o = appear(data, 1, 0, end, step=step)
    run_at(data, T0 + end + 1)
    ov = Overrides(data.root)
    dev = device_of(data, o)
    ov.rule(RULE, dev, sig())
    ov.override(dev, "iot", version=3)
    return ov, dev


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
    assert source_of(data, b) == "self"  # still only one trusted stamp
    assert kinds(data, "mac_attached") == []
    ov.close()


def test_server_clock_anchors_maturity_even_for_honest_stamps(data):
    ov, _ = seeded_d(data, 300)
    b = appear(data, 2, 4000, 4700)  # 700 s of stamps, received at 4700
    run_at(data, T0 + 4700 + 600)  # first received exactly one grace ago: not yet
    assert source_of(data, b) == "self"
    run_at(data, T0 + 4700 + 601)
    assert source_of(data, b) == "rule"
    ov.close()


def test_first_received_is_the_server_clock_of_the_first_batch_and_never_moves(data):
    b = appear(data, 2, 0, 100)
    appear(data, 2, 200, 300)
    run_at(data, T0 + 400)
    assert data.q("SELECT received FROM mac_first_received WHERE mac=?", b)[0][0] == T0 + 100


def test_a_mac_with_only_ignored_stamps_is_still_recorded_as_received(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    record_activity(inv, {"m": MacActivity(1, 1, stamps={1})}, 300, 10**9, 7 * 86400)
    assert inv.execute("SELECT mac, received FROM mac_first_received").fetchall()[0][:] == (
        "m",
        10**9,
    )
    assert inv.execute("SELECT COUNT(*) FROM mac_activity").fetchone()[0] == 0


def test_purge_forgets_first_received_of_a_mac_without_activity_only(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    inv.executemany("INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,?)",
                    [("gone", 100), ("kept", 100), ("fresh", 10_000)])  # fmt: skip
    inv.execute(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("kept", 9_000, 9_500)
    )
    purge_activity(inv, 10_000, 1_000)  # cutoff 9_000
    assert {r[0] for r in inv.execute("SELECT mac FROM mac_first_received")} == {"kept", "fresh"}


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
    got = load_activity(conn, 0, first_received={"m": 10_000}, max_lag_s=3600)
    assert got == ({"m": [kept]} if kept else {})
    assert load_activity(conn, 0) == {"m": [raw]}  # no anchor, no clip


def test_clipping_applies_after_widening(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 6500, 6500))
    got = load_activity(conn, 300, first_received={"m": 10_000}, max_lag_s=3600)
    assert got == {"m": [(6400, 6650)]}  # widened to [6350, 6650], then clipped at 6400


def test_loading_is_bounded_to_the_newest_intervals_of_each_active_mac(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(i * 1000, i * 1000) for i in range(200)])
    inv.mac("E", "h", None, "self", OLD, [(5, 5)])
    inv.act("elsewhere", [(1, 1)])  # active MACs are driven by mac_activity, not observations
    full = load_activity(inv.db, 300)[m]
    capped = load_activity(inv.db, 300, per_mac_limit=64)
    assert capped[m] == full[-64:] and len(capped[m]) == 64
    assert set(capped) == {
        m,
        "elsewhere",
        next(k for k in full_keys(inv) if k not in (m, "elsewhere")),
    }
    old_only = load_activity(inv.db, 300, per_mac_limit=64, min_end=150_000)
    assert set(old_only) == {m} and old_only[m][-1] == full[-1]  # the retention cutoff applies


def full_keys(inv):
    return [r[0] for r in inv.db.execute("SELECT DISTINCT mac FROM mac_activity")]


@pytest.mark.parametrize(("first_ago", "covered", "expect"), [
    (601, 601, True), (600, 601, False), (601, 600, False), (None, 601, False),
])  # fmt: skip
def test_mature_needs_both_server_age_and_covered_time_over_the_grace(
    inv, first_ago, covered, expect
):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 1000, NOW - 1000 + covered)])
    if first_ago is not None:
        inv.db.execute(
            "INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,?)",
            (m, NOW - first_ago),
        )
    else:  # no anchor at all: unknown age is not mature
        inv.db.execute("DELETE FROM mac_first_received WHERE mac=?", (m,))
    assert inv.stitcher().mature(m) is expect


# ---- 3: an immature overlap is provisional, a mature one is permanent ----


def handover(data: Data):
    ov, dev = seeded_d(data, 3600)
    appear(data, 2, 3600, 3600)  # L's first stamp, inside the old MAC's presence tail
    return ov, dev


def test_first_stamp_of_a_legitimate_handover_is_not_a_permanent_veto(data):
    ov, dev = handover(data)
    l_mac = mac(2)
    run_at(data, T0 + 3700)
    assert source_of(data, l_mac) == "self"
    assert [c["state"] for c in candidates(data)] == ["open"]
    assert kinds(data, "identity_overlap_veto") == []
    appear(data, 2, 3700, 7200)  # L carries on alone
    run_at(data, T0 + 7300)
    assert source_of(data, l_mac) == "rule"
    assert [e["kind"] for e in data.q("SELECT kind FROM events WHERE kind='mac_attached'")]
    ov.close()


def test_a_provisional_overlap_keeps_an_existing_suggestion_row_untouched(inv):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW - 20000, NOW)], rand=0)
    a = inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 400, NOW - 400)])
    st = inv.stitch()
    assert inv.state("A") == [("D", "open")] and st.vetoed == 0
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0, a


def test_a_mature_overlap_is_a_permanent_veto_that_only_a_human_dismissal_clears(data):
    ov, dev = seeded_d(data, 3000)
    b = appear(data, 2, 1000, 2000)  # 1000 s covered, wholly inside the device's presence
    run_at(data, T0 + 4000)
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    assert source_of(data, b) == "self"
    # the interval cap / fresh stamps never launder it ...
    run_at(data, T0 + 4100)
    assert [c["state"] for c in candidates(data)] == ["vetoed"]
    # ... a human dismissal (what the API round exposes) is honoured and never rewritten
    data.inv.execute("UPDATE identity_candidates SET state='dismissed'")
    run_at(data, T0 + 4200)
    assert [c["state"] for c in candidates(data)] == ["dismissed"]
    assert source_of(data, b) == "self"  # the overlap is real: dismissal does not invent a clear
    ov.close()


def test_a_stale_veto_dismissed_by_a_human_lets_the_next_pass_attach(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.execute("COMMIT") if inv.db.in_transaction else None
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',0.8,'{}','vetoed','t')"
    )
    inv.db.commit()
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, a) == ("A", "self")
    inv.db.execute("UPDATE identity_candidates SET state='dismissed' WHERE id='c1'")
    inv.db.commit()
    assert inv.stitch(RULE_SNAP).attached == 1 and link_of(inv, a) == ("D", "rule")


def test_a_provisional_overlap_never_downgrades_an_existing_candidate_row(inv):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW - 20000, NOW)], rand=0)
    inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 400, NOW - 400)])
    inv.db.commit()
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',1.0,'{}','suggested','t')"
    )
    inv.db.commit()
    inv.stitch()
    assert inv.state("A") == [("D", "suggested")] and inv.count("identity_overlap_veto") == 0


# ---- 4: the rule expiry clock ----


def expiring_world(data: Data, expires: int):
    a = appear(data, 1, 0, 300)
    run_at(data, T0 + 301)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule(RULE, dev, sig(), expires_at=iso_utc(T0 + expires))
    ov.override(dev, "iot", version=3)
    ov.conn.commit()
    return ov


def slow_clock(monkeypatch, start: float, elapsed: float):
    state = {"t": start}
    monkeypatch.setattr(
        processor, "time", type("T", (), {"time": staticmethod(lambda: state["t"])})
    )
    real = processor._process_batches

    def slow(*a, **kw):
        out = real(*a, **kw)
        state["t"] += elapsed  # the batch backlog took this long
        return out

    monkeypatch.setattr(processor, "_process_batches", slow)


@pytest.mark.parametrize(("elapsed", "expect"), [(0, "rule"), (120, "self")])
def test_rule_expiry_is_judged_at_stitch_time_not_at_run_start(data, monkeypatch, elapsed, expect):
    n = 20000
    ov = expiring_world(data, n + 700)
    b = appear(data, 2, n - 1000, n)
    slow_clock(monkeypatch, T0 + n + 610, elapsed)
    run_once(PipelineConfig(data_dir=data.root))  # a live clock
    assert source_of(data, b) == expect
    ov.close()


def test_injected_now_pins_the_clock(data):
    n = 20000
    ov = expiring_world(data, n + 700)
    b = appear(data, 2, n - 1000, n)
    run_at(data, T0 + n + 610)
    assert source_of(data, b) == "rule"
    ov.close()


def expiring_inv(inv: Inv, expires: float):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    b = inv.mac("B", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    rule = Rule("r1", "D", "1,2,3", "x", "victim", None, expires)
    snap = Snapshot({}, (rule,), {"iot": 1}, {"D": (1, "iot")}, {})
    return b, snap


def test_expiry_is_rechecked_with_the_clock_read_after_the_lock_is_held(inv):
    b, snap = expiring_inv(inv, NOW + 10)
    inv.db.commit()
    seen = []

    def clock():
        seen.append(inv.db.in_transaction)
        return NOW + 20  # by the time the lock is ours the rule has expired

    st = stitch(inv.db, snap, inv.cfg, NOW, clock)
    assert seen[0] is True and st.attached == 0 and link_of(inv, b) == ("B", "self")


def test_expiry_boundary_is_exclusive(inv):
    b, snap = expiring_inv(inv, NOW + 10)
    inv.db.commit()
    assert stitch(inv.db, snap, inv.cfg, NOW, lambda: NOW + 10).attached == 0  # == expiry: expired
    assert stitch(inv.db, snap, inv.cfg, NOW, lambda: NOW + 9).attached == 1, b


def test_expiry_is_checked_again_at_attach_time(inv):
    b, snap = expiring_inv(inv, NOW + 10)
    inv.db.commit()
    reads = iter([NOW, NOW])  # stitch() now, then the rule match filter: both still live

    def clock():
        return next(reads, NOW + 20)  # every later read: expired

    st = stitch(inv.db, snap, inv.cfg, NOW, clock)
    assert st.attached == 0 and link_of(inv, b) == ("B", "self")


# ---- 5: the row cap is exact ----


def pair_world(inv: Inv, shapes: list[str]):
    """One (older, younger) pair per shape: 'both' (host+mDNS, scores 1.0) or 'host' (0.8)."""
    for i, shape in enumerate(shapes):
        mdns = f"m{i}" if shape == "both" else None
        inv.mac(
            f"O{i}",
            f"h{i}",
            mdns,
            "self",
            "2026-01-01T00:00:00Z",
            [(NOW - 90000 + i, NOW - 90000 + i)],
        )
        inv.mac(f"Y{i}", f"h{i}", mdns, "self", f"2026-02-01T00:{i // 60:02d}:{i % 60:02d}Z",
                [(NOW - 5000 + i, NOW - 5000 + i)])  # fmt: skip


def totals(inv: Inv) -> tuple[int, int]:
    q = "SELECT COUNT(*) FROM "
    return (inv.db.execute(q + "identity_candidates").fetchone()[0],
            inv.db.execute(q + "suggestions").fetchone()[0])  # fmt: skip


def test_mixed_sequence_never_overshoots_the_cap(inv):
    pair_world(inv, ["both"] * 99 + ["host"] + ["both"])
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, suggest_threshold=0.9)
    st = inv.stitch()
    cands, sugg = totals(inv)
    assert (cands, sugg) == (100, 99) and cands + sugg == 199 <= 200
    assert st.capped >= 1 and st.candidates == 100 and st.suggestions == 99
    inv.stitch()  # the next pass finishes the last pair (both rows)
    assert totals(inv) == (101, 100)


def test_the_cap_is_exactly_reached_not_exceeded(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_ROWS_PER_PASS", 6)
    pair_world(inv, ["both"] * 5)
    inv.stitch()
    assert totals(inv) == (3, 3)  # three whole decisions of two rows each


def test_stale_evidence_updates_are_charged_and_identical_ones_are_free(inv):
    n = 250
    pair_world(inv, ["host"] * n)
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, suggest_threshold=0.9)
    inv.db.execute("COMMIT") if inv.db.in_transaction else None
    for i in range(n):
        inv.db.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,0.8,'{}','open','t')", (f"c{i}", f"Y{i}", f"O{i}"),
        )  # fmt: skip
    inv.db.commit()
    stale = "SELECT COUNT(*) FROM identity_candidates WHERE evidence='{}'"
    st = inv.stitch()
    assert st.candidates == 200 and inv.db.execute(stale).fetchone()[0] == 50 and st.capped >= 1
    assert inv.stitch().candidates == 50
    before = inv.db.total_changes
    st = inv.stitch()
    assert st.candidates == 0 and st.capped == 0 and inv.db.total_changes == before


def test_a_dismissed_or_vetoed_row_is_never_rewritten_or_charged(inv):
    pair_world(inv, ["host"] * 3)
    inv.db.execute("COMMIT") if inv.db.in_transaction else None
    for i, state in enumerate(["dismissed", "vetoed", "dismissed"]):
        inv.db.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,0.8,'{}',?,'t')", (f"c{i}", f"Y{i}", f"O{i}", state),
        )  # fmt: skip
    inv.db.commit()
    st = inv.stitch()
    assert st.candidates == 0 and inv.stitcher().writes == 0
    rows = inv.db.execute("SELECT state, evidence FROM identity_candidates ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("dismissed", "{}"), ("vetoed", "{}"), ("dismissed", "{}")]


# ---- 6: suggestion look-ups are indexed, bounded and time-boxed ----


def test_suggestion_lookups_use_the_pair_index(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    for sql in (
        "SELECT id, expires_at FROM suggestions WHERE action='merge_identity' AND device_ids=?",
        "SELECT id FROM suggestions WHERE action='merge_identity' AND device_ids=?"
        " AND expires_at>=?",
    ):
        plan = " ".join(
            r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, ("[]", "x")[: sql.count("?")])
        )
        assert "idx_suggestions_pair" in plan and "SCAN" not in plan, plan


def test_a_pass_over_200_suggested_pairs_beside_500k_expired_suggestions_is_fast(inv):
    pair_world(inv, ["both"] * 200)
    inv.stitch()
    inv.stitch()  # 100 whole decisions fit one pass
    assert totals(inv) == (200, 200)
    expired = iso_utc(NOW - 10**6)
    inv.db.execute("BEGIN")
    inv.db.executemany(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES (?,'merge_identity',?,'{}','x','{}',?,?)",
        ((f"x{i}", f'["u{i}","w{i}"]', expired, expired) for i in range(500_000)),
    )
    inv.db.execute("COMMIT")
    inv.db.execute(
        "UPDATE suggestions SET expires_at=? WHERE id NOT LIKE 'x%'", (iso_utc(NOW - 5),)
    )
    inv.db.commit()  # the 200 real suggestions expired: each pair is looked up again
    start = time.perf_counter()
    inv.stitch()
    assert time.perf_counter() - start < 2.0


def test_the_stitch_transaction_is_time_boxed_at_a_safe_point(inv, monkeypatch):
    pair_world(inv, ["both"] * 5)
    monkeypatch.setattr(stitch_mod, "STITCH_MAX_TXN_SECONDS", -1)
    st = inv.stitch(RULE_SNAP)
    assert totals(inv) == (0, 0) and st.candidates == 0
    assert inv.count("stitch_budget_exhausted") == 1  # once, however many phases stopped
    monkeypatch.setattr(stitch_mod, "STITCH_MAX_TXN_SECONDS", 3)
    inv.stitch()
    assert totals(inv) == (5, 5)


def test_suggestion_lookups_are_charged_to_the_work_budget(inv, monkeypatch):
    pair_world(inv, ["both"] * 5)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 12)
    inv.stitch()
    assert 0 < totals(inv)[1] < 5 and inv.count("stitch_budget_exhausted") == 1


# ---- 7: retired MACs do not flood ----


def retired_world(inv: Inv, n: int = 65):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    for i in range(n):
        inv.mac(f"R{i}", "victim", None, "self", "2026-01-02T00:00:00Z",
                [(NOW - 172800, NOW - 172700)])  # fmt: skip
    inv.db.execute("UPDATE devices SET status='retired' WHERE id LIKE 'R%'")


def test_retired_macs_do_not_make_a_live_flood(inv):
    retired_world(inv)
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    st = inv.stitch(RULE_SNAP)
    assert st.flooded == 0 and inv.count("signature_flood") == 0
    assert st.attached == 1 and link_of(inv, b) == ("D", "rule")


def test_a_group_of_live_macs_still_floods(inv):
    retired_world(inv)
    inv.db.execute("UPDATE devices SET status='active' WHERE id LIKE 'R%'")
    inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.count("signature_flood") >= 1


def test_the_compatible_pool_flood_ignores_retired_macs_too(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    for i in range(65):  # mDNS-only: not in the hostname group, but compatible peers
        inv.mac(f"R{i}", None, f"n{i}", "self", "2026-01-02T00:00:00Z", [(NOW - 172800,) * 2])
    inv.db.execute("UPDATE devices SET status='retired' WHERE id LIKE 'R%'")
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(RULE_SNAP).attached == 1 and link_of(inv, b) == ("D", "rule")


def test_a_retired_peers_intervals_still_veto_by_name_and_by_pool(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    inv.mac("RN", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW - 100)])
    inv.mac("RP", None, "other", "self", "2026-02-01T00:00:30Z", [(NOW - 3000, NOW - 100)])
    inv.db.execute("UPDATE devices SET status='retired' WHERE id IN ('RN', 'RP')")
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, b) == ("B", "self")
    st = inv.stitcher()
    obs = {o.device_id: o for o in st.obs}
    assert {obs["RN"].mac, obs["RP"].mac} <= st.compatible_peers(obs["B"]) | {
        p.mac for p in st.name_peers(obs["B"])
    }


# ---- 8: odd gaps ----


@pytest.mark.parametrize(
    ("gap", "lead", "expect"),
    [(301, 150, True), (300, 150, False), (302, 150, True), (299, 150, False),
     (300, 149, True), (300, 100, True), (300, 151, False)],
)  # fmt: skip
def test_half_gap_lead_boundary_is_exact(inv, gap, lead, expect):
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, activity_gap_s=gap)
    cand = inv.mac("C", "h", None, "self", OLD, [(NOW, NOW + 601)])
    peer = inv.mac("P", "h", None, "self", OLD, [(NOW - 100, NOW + 601 - lead)])
    st = inv.stitcher()  # covered 601 > grace 600, own lead as given
    assert st.sustained(cand, [peer]) is expect


# ---- review 5 opus findings: compatible peers need a reason to be peers ----


@pytest.mark.parametrize(
    ("offset", "expect"), [(300, True), (301, False), (-300, True), (-301, False)]
)
def test_a_nameless_mac_is_a_peer_only_within_a_gap_of_the_candidate(inv, offset, expect):
    c = inv.mac("C", "victim", None, "self", "2026-01-03T00:10:00Z", [(NOW - 500, NOW)])
    t = 600 + offset
    z = inv.mac(
        "Z", None, None, "self", f"2026-01-03T00:{t // 60:02d}:{t % 60:02d}Z", [(NOW - 500, NOW)]
    )
    st = inv.stitcher()
    assert (z in st.compatible_peers(next(o for o in st.obs if o.mac == c))) is expect


@pytest.mark.parametrize(("offset", "expect"), [(300, True), (301, False)])
def test_a_junk_named_mac_is_a_peer_only_within_a_gap_too(inv, offset, expect):
    c = inv.mac("C", "victim", None, "self", "2026-01-03T00:10:00Z", [(NOW - 500, NOW)])
    t = 600 + offset
    z = inv.mac(
        "Z", None, "junk", "self", f"2026-01-03T00:{t // 60:02d}:{t % 60:02d}Z", [(NOW - 500, NOW)]
    )
    st = inv.stitcher()
    assert (z in st.compatible_peers(next(o for o in st.obs if o.mac == c))) is expect


def test_a_mac_with_a_name_the_target_already_used_is_a_peer_at_any_time(inv):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    c = inv.mac("C", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW - 500, NOW)])
    v = inv.mac("V", None, "dave", "self", "2026-09-01T00:00:00Z", [(NOW - 500, NOW)])
    j = inv.mac("J", None, "junk", "self", "2026-09-01T00:00:00Z", [(NOW - 500, NOW)])
    st = inv.stitcher()
    got = st._compat_raw(next(o for o in st.obs if o.mac == c), st._names_of("D"))
    assert v in got and j not in got


def test_a_mac_sharing_the_candidates_own_name_is_a_peer_at_any_time(inv):
    c = inv.mac("C", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW - 500, NOW)])
    v = inv.mac("V", "Victim", "x", "self", "2026-09-01T00:00:00Z", [(NOW - 500, NOW)])
    st = inv.stitcher()
    assert v in st.compatible_peers(next(o for o in st.obs if o.mac == c))


def test_a_big_filtered_out_pool_does_not_starve_the_recheck(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    for k in range(20):
        inv.mac("D", "victim", None, "rule", f"2026-01-02T00:00:{k:02d}Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id='r1' WHERE link_source='rule'")
    for k in range(3000):  # nameless, far in time: never peers, so never charged
        inv.mac(f"Z{k}", None, None, "self", "2026-06-01T00:00:00Z", [(NOW - 100000,) * 2])
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 200)
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 20 and inv.count("stitch_budget_exhausted") == 0


def test_an_already_flagged_mac_costs_the_recheck_nothing(inv):
    attached_world(inv, "r1")
    inv.stitch(RULE_SNAP)
    assert inv.count("rule_attach_suspect") == 1
    st = inv.stitcher()
    st.ops = 0
    st._recheck_rule_attached()
    assert st.ops == 0


def test_the_budget_event_names_the_phase_that_ran_out(inv, monkeypatch):
    attached_world(inv, "r1")
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 0)
    inv.stitch(RULE_SNAP)
    row = inv.db.execute("SELECT summary FROM events WHERE kind='stitch_budget_exhausted'")
    assert "recheck_rule_attached" in row.fetchone()[0]


def test_a_flood_is_one_event_per_group_per_day_across_passes(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 3)
    for k in range(5):
        inv.mac(f"F{k}", "swarm", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    inv.stitch(RULE_SNAP)
    inv.stitch(RULE_SNAP, NOW + 60)
    assert inv.count("signature_flood") == 1
    inv.stitch(RULE_SNAP, NOW + 86400)
    assert inv.count("signature_flood") == 2


# ---- 9: legacy dedup tokens ----

LEGACY = [
    ("identity_overlap_veto", "d1", "identity overlap veto d1~d2", "d1~d2"),
    ("identity_candidate_ambiguous", "d1", "identity candidate ambiguous: 2 devices match d1",
     "d1"),
    ("identity_candidate", "d1", "identity candidate d1 -> d2 score 0.90", "d1 -> d2"),
    ("rule_attach_suspect", "d1", "rule attach suspect abcd1234: sustained overlap with peers",
     "abcd1234~d1"),
    ("signature_flood", None, "signature flood abcd1234: 70 MACs skipped", "abcd1234:2026-10-14"),
    ("stitch_budget_exhausted", None, "stitching overlap budget exhausted", "2026-10-14"),
    ("signature_flood_summary", None, "3 further signature floods", "summary:2026-10-14"),
]  # fmt: skip


def v5_database(path, monkeypatch):
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:5])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d1','t','t')")
    for i, (kind, dev, summary, _) in enumerate(LEGACY):
        conn.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES (?,?,?,?,?,?)",
            (f"e{i}", dev, "2026-10-14T01:02:03Z", kind, "warn", summary),
        )
    conn.commit()
    conn.close()
    monkeypatch.undo()


def test_migration_6_backfills_legacy_tokens_so_events_stay_once_only(tmp_path, monkeypatch):
    v5_database(tmp_path / "inventory.db", monkeypatch)
    conn = open_pipeline_inventory(tmp_path / "inventory.db")
    got = {r["kind"]: r["dedup"] for r in conn.execute("SELECT kind, dedup FROM events")}
    assert got == {kind: token for kind, _, _, token in LEGACY}
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    for kind, dev, _, token in LEGACY:
        assert emit_once(conn, dev, kind, "warn", "again", token, NOW) is False, kind
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
    assert emit_once(conn, "d1", "identity_overlap_veto", "warn", "new", "d1~d9", NOW) is True


def test_migration_6_survives_legacy_duplicates_and_keeps_them(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    v5_database(path, monkeypatch)
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:5])
    conn = open_pipeline_inventory(path)
    conn.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES"
        " ('dup','d1','2026-10-14T05:00:00Z','identity_overlap_veto','warn',"
        "'identity overlap veto d1~d2')"
    )
    conn.commit()
    conn.close()
    monkeypatch.undo()
    conn = open_pipeline_inventory(path)
    rows = conn.execute(
        "SELECT id, dedup FROM events WHERE kind='identity_overlap_veto'"
    ).fetchall()
    assert sorted(r["dedup"] is None for r in rows) == [False, True]  # one token, one left alone
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(LEGACY) + 1


def test_migration_6_leaves_unrecognised_summaries_alone(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:5])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d1','t','t')")
    conn.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES"
        " ('a','d1','t','identity_candidate','info','something else'),"
        " ('b',NULL,'t','identity_candidate_ambiguous','warn','x'),"
        " ('c',NULL,'t','mac_attached','info','identity overlap veto z')"
    )
    conn.commit()
    conn.close()
    monkeypatch.undo()
    conn = open_pipeline_inventory(path)
    assert [r[0] for r in conn.execute("SELECT dedup FROM events")] == [None, None, None]


# ---- 10: malformed overrides.db ----


def broken_overrides(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("CREATE TABLE identity_links (from_device TEXT PRIMARY KEY)")  # no into_device
    conn.commit()
    conn.close()


def test_malformed_overrides_skips_stitching_but_keeps_cursor_progress(data, caplog):
    broken_overrides(data.root)
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    with caplog.at_level(logging.ERROR):
        stats = run_at(data, T0 + 7000)
    assert stats.batches == 2 and stats.suggestions == 0 and stats.attached == 0
    assert data.q("SELECT COUNT(*) FROM observations")[0][0] == 2
    assert data.q("SELECT COUNT(*) FROM pipeline_cursor")[0][0] == 1
    assert candidates(data) == [] and "stitching_skipped" in caplog.text
    assert caplog.text.count("stitching_skipped") == 1
    assert run_at(data, T0 + 7100).batches == 0  # nothing reprocessed


def test_canonical_lookup_with_a_malformed_table_returns_the_device(tmp_path, caplog):
    broken_overrides(tmp_path)
    conn = sqlite3.connect(tmp_path / "overrides.db")
    conn.row_factory = sqlite3.Row
    with caplog.at_level(logging.ERROR):
        assert canonical_device(conn, "dev") == "dev"
    assert "overrides_unreadable" in caplog.text


def test_canonical_lookup_with_a_missing_table_is_silent(tmp_path, caplog):
    conn = sqlite3.connect(tmp_path / "empty.db")
    conn.row_factory = sqlite3.Row
    with caplog.at_level(logging.ERROR):
        assert canonical_device(conn, "dev") == "dev"
    assert caplog.text == ""


# ---- residuals: re-check cursor, copy-before-victim ----


def test_recheck_budget_stops_rotate_so_every_attached_mac_is_eventually_checked(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    for k in range(3):  # three rule-attached MACs that overlap each other for hours
        inv.mac("D", "victim", None, "rule", f"2026-01-0{k + 2}T00:00:00Z", [(NOW - 10000, NOW)],
                newdev=False)  # fmt: skip
    for row in inv.db.execute("SELECT mac FROM observations WHERE link_source='rule'").fetchall():
        inv.db.execute("UPDATE observations SET link_rule_id='r1' WHERE mac=?", (row[0],))
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 4)  # one MAC (3 units) per pass
    seen = []
    for i in range(3):
        inv.stitch(RULE_SNAP, NOW + i)
        seen.append(inv.count("rule_attach_suspect"))
    assert seen == [1, 2, 3]
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 20000)
    inv.stitch(RULE_SNAP, NOW + 9)
    assert inv.db.execute("SELECT COUNT(*) FROM stitch_state").fetchone()[0] == 0  # cursor cleared


def test_a_copy_attached_before_the_victim_is_flagged_when_the_victim_arrives(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 200000, NOW - 190000)], rand=0)
    copy = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z",
                   [(NOW - 100000 + i * 400,) * 2 for i in range(70)])  # fmt: skip
    st = inv.stitch(RULE_SNAP, NOW - 60000)
    assert st.attached == 1 and link_of(inv, copy) == ("D", "rule")
    inv.act(copy, [(NOW - 5000 + i * 400,) * 2 for i in range(13)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 5000, NOW)])
    st = inv.stitch(RULE_SNAP, NOW)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


# ---- sole-contributor tests for each peer source and each charge ----


def peer_world(inv: Inv, v_host, v_mdns, v_src="self", v_first="2026-01-03T00:01:00Z"):
    """Hostname-only rule for D (old MAC victim/Dave); V overlaps the applicant A (victim/Other)."""
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    inv.mac("V", v_host, v_mdns, v_src, v_first, [(NOW - 3000, NOW)])
    return inv.mac("A", "victim", "Other", "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])


def test_rule_view_alone_keeps_a_peer_whose_mdns_differs_from_the_applicants_extra_name(inv):
    a = peer_world(inv, None, "Elsewhere")  # only the hostname-only view does not contradict V
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, a) == ("A", "self")


def test_target_signature_alone_keeps_a_peer_with_another_hostname(inv):
    a = peer_world(inv, "renamed", "Dave")  # shares only D's mDNS name
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, a) == ("A", "self")


def test_view_name_peers_include_macs_the_compatible_pool_excludes(inv):
    a = peer_world(inv, "victim", None, v_src="rule")  # not self-linked: not in the pool
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, a) == ("A", "self")


def attached_world(inv: Inv, rule_id: str):
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", "Dave", "rule", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id=? WHERE mac=?", (rule_id, a))
    inv.db.execute(  # the evidence recorded when A attached under the hostname-only rule
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, attached_at)"
        " VALUES (?,?,'D','victim',NULL,'t')",
        (a, rule_id),
    )
    inv.mac("V", None, "Elsewhere", "self", "2026-01-03T00:01:00Z", [(NOW - 3000, NOW)])


def test_recheck_with_its_rule_uses_the_rule_names_only(inv):
    attached_world(inv, "r1")  # hostname-only rule: V (mDNS only, other name) is a peer
    assert inv.stitch(RULE_SNAP).suspect == 1


def test_recheck_without_a_rule_and_no_shared_names_uses_all_of_the_macs_names(inv):
    inv.mac("D", "victim", None, "rule", OLD, [(NOW - 3000, NOW)], rand=0)  # D's only MAC
    inv.mac("E", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.execute("UPDATE observations SET link_rule_id='gone'")
    st = inv.stitch(Snapshot({}, (), {}, {}, {}))  # shares no name with another MAC of its device
    assert st.suspect == 2


def test_withdraw_and_suggest_lookups_each_charge_the_work_budget(inv):
    pair_world(inv, ["both"])
    st = inv.stitcher()
    y = next(o for o in st.obs if o.device_id == "Y0")
    st.ops = 0
    st._withdraw(y, ["a", "b", "c"])
    assert st.ops == 3
    st.ops = 0
    st._suggest(y, "O0", 1.0, {}, "fingerprint_match", ["opt55"])
    assert st.ops == 1


def test_stitcher_reads_bounded_clipped_activity(inv, monkeypatch):
    seen = {}
    real = stitch_mod.load_activity

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(stitch_mod, "load_activity", spy)
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 20000, NOW - 20000), (NOW - 100, NOW)])
    inv.db.execute(
        "INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?,?)", (m, NOW - 50)
    )
    st = inv.stitcher()
    assert seen["per_mac_limit"] == 64 and seen["max_lag_s"] == 3600
    assert st.act[m] == [(NOW - 200, NOW + 100)]  # the 20000 s old stamp is clipped away


def test_a_mac_whose_batch_had_no_stamps_is_still_recorded(tmp_path):
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    record_activity(inv, {"m": MacActivity(1, 1)}, 300, 10**9, 7 * 86400)
    assert inv.execute("SELECT received FROM mac_first_received").fetchone()[0] == 10**9


def test_view_name_peers_catch_a_peer_when_the_target_no_longer_has_the_rule_name(inv):
    inv.mac("D", "oldname", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    inv.mac("P", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])  # not pooled
    a = inv.mac("A", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, a) == ("A", "self")


def test_compatible_set_counts_macs_sharing_the_views_name_even_if_the_target_lacks_it(inv):
    inv.mac("D", "oldname", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    p = inv.mac("P", "victim", "x", "self", "2026-09-01T00:00:00Z", [(NOW - 3000, NOW)])
    a = inv.mac("A", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW - 3000, NOW)])
    st = inv.stitcher()
    assert p in st._compat_raw(next(o for o in st.obs if o.mac == a), set())


def test_macs_carrying_a_name_the_target_used_count_toward_the_compatible_flood(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 3)
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    for k in range(4):  # the target's own mDNS name, far in time from the applicant
        inv.mac(f"K{k}", None, "dave", "self", "2026-09-01T00:00:00Z", [(NOW - 100000,) * 2])
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 3000, NOW)])
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 0 and link_of(inv, b) == ("B", "self") and inv.count("signature_flood")


def test_malformed_groups_make_the_batches_run_without_identity_links(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700, host="other", mdns="Other")
    run_at(data, T0 + 800)
    dev_a, dev_b = device_of(data, a), device_of(data, b)
    ov = Overrides(data.root)
    ov.link(dev_a, dev_b)
    ov.conn.commit()
    ov.close()
    conn = sqlite3.connect(data.root / "overrides.db")
    conn.execute("DROP TABLE groups")
    conn.execute("CREATE TABLE groups (id TEXT PRIMARY KEY)")  # no auto_inherit column
    conn.commit()
    conn.close()
    appear(data, 1, 900, 1000)
    run_at(data, T0 + 1100)
    last = data.q("SELECT last_seen FROM devices WHERE id=?", dev_b)[0][0]
    assert last < iso_utc(T0 + 900)  # the canonical device was not touched through the link
