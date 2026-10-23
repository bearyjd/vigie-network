"""Bounds that hold by construction (docs/stitching-design.md section 3): floods, the row and
attach caps, the suggestion cap, the round-robins and compute budget, bounded neighbourhoods
(truncation degrades, never attaches), oversize components, the short APPLY lock, query plans."""

from __future__ import annotations

import logging
import time

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401
from stitch_helpers import (
    HOST,
    MDNS,
    NOW,
    NOW_ABS,
    OLD,
    OPT55,
    OPT60,
    RULE_SNAP,
    Inv,
    appear,
    candidates,
    flood_mac,
    inv,  # noqa: F401
    kinds,
    run,
    run_at,
    seeded,
    source_of,
    suggestions,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import stitch_apply as apply_mod
from vigie_pipeline import stitch_compute as compute_mod
from vigie_pipeline import stitch_hood as hood_mod
from vigie_pipeline.config import MAX_ROWS_PER_PASS, PipelineConfig
from vigie_pipeline.snapshot import EMPTY, Rule, Snapshot
from vigie_pipeline.stitch_apply import apply_plan
from vigie_pipeline.stitch_compute import RECHECK_CURSOR, SELF_CURSOR, compute_plan
from vigie_pipeline.stitch_types import Veto

# ---- floods ------------------------------------------------------------------------------------


def _same_name_macs(data: Data, n: int, base: int = 10) -> list[str]:
    macs = [flood_mac(i + base) for i in range(n)]
    data.add_batch(
        T0 + 700,
        leases=[(m, HOST, OPT55, OPT60) for m in macs],
        dns=[(m, T0 + 700 + t) for m in macs for t in (0, 60)],
    )
    return macs


def test_flood_of_one_signature_is_bounded_fast_and_reported_once_a_day(data, caplog):
    macs = [flood_mac(i) for i in range(301)]
    data.add_batch(
        T0,
        leases=[(m, HOST, OPT55, OPT60) for m in macs],
        sightings=[(m, "mdns", MDNS) for m in macs],
        dns=[(m, T0 + i) for i, m in enumerate(macs)],
    )
    start = time.perf_counter()
    with caplog.at_level(logging.WARNING):
        run(data)
    assert time.perf_counter() - start < 3.0
    assert candidates(data) == [] and suggestions(data) == []
    assert len(kinds(data, "signature_flood")) == 1 and "signature_flood" in caplog.text
    run(data)  # one event per signature per UTC day, not per pass
    assert len(kinds(data, "signature_flood")) == 1
    run_at(data, NOW + 86400)
    assert len(kinds(data, "signature_flood")) == 2


def test_flood_boundary_64_is_not_flooded_65_is(data):
    _same_name_macs(data, 64)
    run(data)
    assert kinds(data, "signature_flood") == []
    _same_name_macs(data, 1, base=500)
    run(data)
    assert len(kinds(data, "signature_flood")) == 1


def test_flooded_name_attaches_nothing(data):
    ov, dev = seeded(data)
    macs = _same_name_macs(data, 65)
    b = appear(data, 2, 4000, 5000)
    for _ in range(3):
        run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert len(kinds(data, "signature_flood")) == 1
    assert all(source_of(data, m) == "self" for m in macs)
    ov.close()


def test_junk_hostname_macs_do_not_block_the_legit_device(data):
    ov, dev = seeded(data)
    macs = [flood_mac(i + 10) for i in range(65)]
    data.add_batch(T0 + 10, leases=[(m, f"x{i}", OPT55, OPT60) for i, m in enumerate(macs)],
                   dns=[(m, T0 + 10) for m in macs])  # fmt: skip
    run(data)
    b = appear(data, 2, 4000, 5000)
    run(data)
    assert source_of(data, b) == "rule" and kinds(data, "signature_flood") == []
    ov.close()


@pytest.mark.timeout(180)  # 70 full pipeline runs: slow on a loaded disk, not timing-sensitive
def test_attached_macs_do_not_count_toward_the_flood_cap(data):
    ov, dev = seeded(data)
    for i in range(70):  # one legitimate roll per pass for much longer than the cap
        start = 1000 + i * 800
        b = appear(data, 2 + i, start, start + 700)
        run(data, now=T0 + start + 700 + 3600)  # the server clock is after each receipt
        assert source_of(data, b) == "rule", f"roll {i} not attached"
    assert kinds(data, "signature_flood") == [] and len(kinds(data, "mac_attached")) == 70
    ov.close()


def retired_world(inv: Inv, n: int = 65) -> None:
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for i in range(n):
        inv.mac(f"R{i}", "victim", None, "self", "2026-01-02T00:00:00Z",
                [(NOW_ABS - 172800, NOW_ABS - 172700)])  # fmt: skip
    inv.db.execute("UPDATE devices SET status='retired' WHERE id LIKE 'R%'")


def test_retired_macs_do_not_make_a_live_flood(inv):
    retired_world(inv)
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    st = inv.stitch(RULE_SNAP)
    assert st.flooded == 0 and inv.count("signature_flood") == 0
    assert st.attached == 1 and inv.link_of(b) == ("D", "rule")


def test_a_group_of_live_macs_still_floods(inv):
    retired_world(inv)
    inv.db.execute("UPDATE devices SET status='active' WHERE id LIKE 'R%'")
    inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.count("signature_flood") >= 1


def test_silent_macs_older_than_retention_do_not_count_toward_a_flood(inv):
    old = NOW_ABS - inv.cfg.activity_retention_s - 86400
    for i in range(66):
        inv.mac(f"S{i}", "hostX", None, "self", OLD, [(old + i * 1000, old + i * 1000)])
    for i in range(4):
        inv.mac(f"L{i}", "hostX", None, "self", f"2026-02-0{i + 1}T00:00:00Z",
                [(NOW_ABS - 86400 + i * 2000,) * 2])  # fmt: skip
    stats = inv.stitch()
    assert stats.flooded == 0 and inv.count("signature_flood") == 0
    assert stats.candidates > 0  # 70 eligible MACs share the name, only 4 are live: not a flood


def test_the_compatible_pool_flood_ignores_retired_macs_too(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for i in range(65):  # mDNS-only: not in the hostname group, but compatible peers
        inv.mac(f"R{i}", None, f"n{i}", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 172800,) * 2])
    inv.db.execute("UPDATE devices SET status='retired' WHERE id LIKE 'R%'")
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(b) == ("D", "rule")


def test_junk_named_macs_first_seen_long_before_or_after_are_not_a_flood(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_SIGNATURE_BUCKET", 3)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(5):  # a name nobody else uses and no closeness in time: not a compatible peer
        inv.mac(
            f"P{k}",
            None,
            f"p{k}",
            "self",
            "2026-03-01T00:00:00Z",
            [(NOW_ABS - 3600 * (k + 1),) * 2],
        )
    inv.mac(
        "B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 70000, NOW_ABS - 69000)]
    )
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 1 and inv.count("signature_flood") == 0


def test_compatible_set_of_exactly_the_bucket_size_is_not_a_flood(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_SIGNATURE_BUCKET", 6)  # D + five mDNS-only peers
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(5):
        inv.mac(
            f"P{k}",
            None,
            f"p{k}",
            "self",
            "2026-02-01T00:00:00Z",
            [(NOW_ABS - 3600 * (k + 1),) * 2],
        )
    inv.mac(
        "B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 70000, NOW_ABS - 69000)]
    )
    st = inv.stitch(RULE_SNAP)
    assert inv.count("signature_flood") == 0 and st.attached == 1


def test_macs_carrying_a_name_the_target_used_count_toward_the_compatible_flood(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_SIGNATURE_BUCKET", 3)
    inv.mac("D", "victim", "Dave", "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(4):  # the target's own mDNS name, far in time from the applicant
        inv.mac(f"K{k}", None, "dave", "self", "2026-09-01T00:00:00Z", [(NOW_ABS - 100000,) * 2])
    b = inv.mac("B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 0 and inv.link_of(b) == ("B", "self") and inv.count("signature_flood")


def test_a_flood_is_one_event_per_group_per_day_across_passes(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_SIGNATURE_BUCKET", 3)
    for k in range(5):
        inv.mac(f"F{k}", "swarm", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.stitch(RULE_SNAP)
    inv.stitch(RULE_SNAP, NOW_ABS + 60)
    assert inv.count("signature_flood") == 1
    inv.stitch(RULE_SNAP, NOW_ABS + 86400)
    assert inv.count("signature_flood") == 2


# ---- the row cap is exact ----------------------------------------------------------------------


def pair_world(inv: Inv, shapes: list[str]) -> None:
    """One (older, younger) pair per shape: 'both' (host+mDNS, scores 1.0) or 'host' (0.8)."""
    for i, shape in enumerate(shapes):
        mdns = f"m{i}" if shape == "both" else None
        inv.mac(
            f"O{i}", f"h{i}", mdns, "self", "2026-01-01T00:00:00Z", [(NOW_ABS - 90000 + i,) * 2]
        )
        inv.mac(f"Y{i}", f"h{i}", mdns, "self", f"2026-02-01T00:{i // 60:02d}:{i % 60:02d}Z",
                [(NOW_ABS - 5000 + i, NOW_ABS - 5000 + i)])  # fmt: skip


def test_rows_written_per_pass_are_capped_and_later_passes_catch_up(data, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 5)
    for i in range(20):  # twenty distinct signatures, each an old and a new MAC
        appear(data, 2 * i, 0, 60, opt55=f"[{i}]")
        appear(data, 2 * i + 1, 400, 460, opt55=f"[{i}]")
    run(data)
    assert len(candidates(data)) <= 5 and len(suggestions(data)) <= 5
    for _ in range(14):
        run(data)
    assert len(suggestions(data)) == 20


def test_row_cap_is_exact_and_counts_suggestion_rows(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 6)
    pair_world(inv, ["both"] * 5)
    st = inv.stitch()
    assert inv.totals() == (3, 3) and st.capped >= 1  # three whole decisions of two rows each
    inv.stitch()
    assert inv.totals() == (5, 5)


def test_mixed_sequence_never_overshoots_the_cap(inv):
    pair_world(inv, ["both"] * 99 + ["host"] + ["both"])
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, suggest_threshold=0.9)
    st = inv.stitch()
    cands, sugg = inv.totals()
    assert (cands, sugg) == (100, 99) and cands + sugg == 199 <= MAX_ROWS_PER_PASS
    assert st.capped >= 1 and st.candidates == 100 and st.suggestions == 99
    inv.stitch()  # the next pass finishes the last pair (both rows)
    assert inv.totals() == (101, 100)


def test_stale_evidence_updates_are_charged_and_identical_ones_are_free(inv, monkeypatch):
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 100)
    n = 120  # 240 MACs: one robin's worth
    pair_world(inv, ["host"] * n)
    inv.cfg = PipelineConfig(data_dir=inv.cfg.data_dir, suggest_threshold=0.9)
    for i in range(n):
        inv.db.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,0.8,'{}','open','t')", (f"c{i}", f"Y{i}", f"O{i}"),
        )  # fmt: skip
    stale = "SELECT COUNT(*) FROM identity_candidates WHERE evidence='{}'"
    st = inv.stitch()
    assert st.candidates == 100 and inv.db.execute(stale).fetchone()[0] == 20 and st.capped >= 1
    assert inv.stitch().candidates == 20
    before = inv.db.total_changes
    st = inv.stitch()
    assert st.candidates == 0 and st.capped == 0
    assert inv.db.total_changes - before <= 2  # only the robin cursors, never a row


def test_a_dismissed_or_vetoed_row_is_never_rewritten(inv):
    pair_world(inv, ["host"] * 3)
    for i, state in enumerate(["dismissed", "vetoed", "dismissed"]):
        inv.db.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,?,?,0.8,'{}',?,'t')", (f"c{i}", f"Y{i}", f"O{i}", state),
        )  # fmt: skip
    assert inv.stitch().candidates == 0
    rows = inv.db.execute("SELECT state, evidence FROM identity_candidates ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("dismissed", "{}"), ("vetoed", "{}"), ("dismissed", "{}")]


def test_a_veto_that_does_not_fit_the_cap_withdraws_nothing(inv, monkeypatch):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    c = inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES ('s1','merge_identity','[\"A\", \"D\"]','{}','x','{}','t',?)",
        (iso_utc(NOW_ABS + 10**6),),
    )
    inv.commit()
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 0)
    st = inv.stitch(EMPTY)
    assert inv.db.execute("SELECT expires_at FROM suggestions").fetchone()[0] == iso_utc(
        NOW_ABS + 10**6
    )
    assert inv.state("A") == [] and st.capped == 1
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 1)
    inv.stitch(EMPTY)
    assert inv.state("A") == [("D", "vetoed")] and c
    assert inv.db.execute("SELECT expires_at FROM suggestions").fetchone()[0] < iso_utc(NOW_ABS)


def test_an_ambiguous_decision_is_written_whole_or_not_at_all(inv, monkeypatch):
    inv.mac("D", "twin", None, "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    inv.mac("E", "twin", None, "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    inv.mac("A", "twin", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    monkeypatch.setattr(
        apply_mod, "MAX_ROWS_PER_PASS", 1
    )  # room for one row, the decision needs two
    st = inv.stitch(EMPTY)
    assert inv.state("A") == [] and st.capped == 1
    monkeypatch.setattr(apply_mod, "MAX_ROWS_PER_PASS", 2)
    inv.stitch(EMPTY)
    assert sorted(inv.state("A")) == [("D", "ambiguous"), ("E", "ambiguous")]


# ---- the per-target suggestion cap bounds the orphan cleanup -------------------------------------


def test_open_suggestions_into_one_device_are_capped_and_the_cap_is_reported(inv):
    inv.mac("D", "swarm", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(70):  # seventy later MACs that never overlap: all would suggest into D
        inv.mac(f"Y{k}", "swarm", None, "self", f"2026-02-01T00:{k // 60:02d}:{k % 60:02d}Z",
                [(NOW_ABS - 70000 + k * 1000,) * 2])  # fmt: skip
    inv.db.execute("UPDATE devices SET status='retired' WHERE id LIKE 'Y%'")  # not a live flood
    inv.stitch()
    st = inv.stitch()
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 64
    assert st.deferred == 6 and inv.count("stitch_deferred") == 1
    row = inv.db.execute("SELECT summary FROM events WHERE kind='stitch_deferred'").fetchone()
    assert "suggestion_cap" in row[0]
    states = [r[0] for r in inv.db.execute("SELECT state FROM identity_candidates")]
    assert states.count("suggested") == 64 and states.count("open") == 6


# ---- round-robins and the compute budget ---------------------------------------------------------


def test_every_mac_gets_its_turn_across_passes_and_the_cursor_wraps(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MACS_PER_PASS", 10)
    pair_world(inv, ["both"] * 25)
    seen = []
    for _ in range(6):
        inv.stitch()
        seen.append(
            inv.db.execute("SELECT value FROM stitch_state WHERE key=?", (SELF_CURSOR,)).fetchone()
        )
    assert inv.totals() == (25, 25)
    assert seen[-1] is None and all(s is not None for s in seen[:5])  # wrapped on the 6th


def test_a_spray_of_self_macs_does_not_delay_the_recheck(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "D",
        "victim",
        None,
        "rule",
        "2026-01-02T00:00:00Z",
        [(NOW_ABS - 10000, NOW_ABS)],
        newdev=False,
    )
    inv.attachment(a, "r1", "D", "victim", None, [[True, False]])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 10000, NOW_ABS)])
    for i in range(600):  # far more self subjects than one pass examines
        inv.mac(
            f"S{i}", f"junk{i}", None, "self", "2026-06-01T00:00:00Z", [(NOW_ABS - 5000 + i,) * 2]
        )
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1
    assert inv.db.execute("SELECT value FROM stitch_state WHERE key=?", (SELF_CURSOR,)).fetchone()
    assert (
        inv.db.execute("SELECT value FROM stitch_state WHERE key=?", (RECHECK_CURSOR,)).fetchone()
        is None
    )


class Ticking:
    def __init__(self, step: float) -> None:
        self.t, self.step = 1000.0, step

    def monotonic(self) -> float:
        self.t += self.step
        return self.t


def test_compute_budget_stops_between_subjects_and_the_cursor_persists(inv, monkeypatch):
    pair_world(inv, ["both"] * 6)
    inv.commit()
    monkeypatch.setattr(compute_mod, "time", Ticking(3.0))  # 5 s budget: one subject per pass
    st = inv.stitch()
    assert st.examined == 1 and st.deferred >= 1 and inv.count("stitch_deferred") == 1
    cursor = inv.db.execute("SELECT value FROM stitch_state WHERE key=?", (SELF_CURSOR,)).fetchone()
    assert cursor is not None
    inv.stitch(EMPTY, NOW_ABS + 60)
    assert inv.count("stitch_deferred") == 1  # once per UTC day
    monkeypatch.setattr(compute_mod, "time", Ticking(0.0))
    inv.stitch(EMPTY, NOW_ABS + 120)
    assert inv.totals() == (6, 6)


def test_the_recheck_robin_runs_first_so_a_spent_budget_never_switches_it_off(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac(
        "D",
        "victim",
        None,
        "rule",
        "2026-01-02T00:00:00Z",
        [(NOW_ABS - 10000, NOW_ABS)],
        newdev=False,
    )
    inv.attachment(a, "r1", "D", "victim", None, [[True, False]])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 10000, NOW_ABS)])
    pair_world(inv, ["both"] * 3)
    inv.commit()
    monkeypatch.setattr(compute_mod, "time", Ticking(1.0))  # a budget of a handful of checks
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1  # the re-check ran first, within its own share of the budget


# ---- bounded neighbourhoods: incomplete evidence degrades, never attaches ------------------------


def spray(inv: Inv, n: int, name: str = "victim") -> None:
    for i in range(n):  # newer last_seen than anyone legitimate: they fill the bounded lookup
        inv.mac(
            f"S{i}",
            name,
            None,
            "self",
            "2026-06-01T00:00:00Z",
            [],
            last_seen="2026-09-01T00:00:00Z",
        )


def test_a_spray_beyond_the_bucket_bound_degrades_to_a_suggestion_never_attaches(inv, monkeypatch):
    monkeypatch.setattr(hood_mod, "BUCKET_ROWS", 10)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac(
        "V",
        "victim",
        None,
        "self",
        "2026-01-03T00:00:00Z",
        [(NOW_ABS - 5000, NOW_ABS)],
        last_seen="2026-01-03T00:00:00Z",
    )  # the victim, present the whole time
    a = inv.mac(
        "A",
        "victim",
        None,
        "self",
        "2026-01-04T00:00:00Z",
        [(NOW_ABS - 5000, NOW_ABS)],
        last_seen="2026-01-04T00:00:00Z",
    )  # the copy beside it
    spray(inv, 12)
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 0 and inv.link_of(a) == ("A", "self")
    row = inv.db.execute("SELECT reason_code, reason_text FROM suggestions").fetchone()
    assert tuple(row) == ("rule_hit_needs_confirm", "truncated")
    assert inv.count("stitch_deferred") == 1
    summary = inv.db.execute("SELECT summary FROM events WHERE kind='stitch_deferred'").fetchone()[
        0
    ]
    assert "truncated" in summary


def test_without_the_spray_the_same_copy_is_vetoed(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    a = inv.mac("A", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    assert inv.stitch(RULE_SNAP).attached == 0 and inv.state("A") == [("D", "vetoed")]
    assert inv.link_of(a) == ("A", "self")


def test_a_truncated_candidate_neighbourhood_writes_nothing_but_a_daily_event(inv, monkeypatch):
    monkeypatch.setattr(hood_mod, "BUCKET_ROWS", 10)
    inv.mac("O", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("Y", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)],
            last_seen="2026-01-04T00:00:00Z")  # fmt: skip
    spray(inv, 12)
    st = inv.stitch()
    assert inv.totals() == (0, 0) and st.deferred >= 1 and inv.count("stitch_deferred") == 1


def test_a_complete_lookup_at_exactly_the_bound_is_not_truncated(inv, monkeypatch):
    monkeypatch.setattr(hood_mod, "BUCKET_ROWS", 10)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    spray(inv, 8)  # D + A + 8 = 10 rows: complete
    assert inv.stitch(RULE_SNAP).attached == 1 and inv.link_of(a) == ("D", "rule")


def test_a_target_with_too_many_known_signatures_is_incomplete_evidence(inv, monkeypatch):
    monkeypatch.setattr(hood_mod, "TARGET_KEYS", 3)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(4):
        inv.mac("D", f"name{k}", f"mdns{k}", "rule", OLD, [], newdev=False)
    a = inv.mac("A", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 0 and inv.link_of(a) == ("A", "self")
    assert inv.db.execute("SELECT reason_text FROM suggestions").fetchone()[0] == "target_keys"


# ---- oversize merge components ------------------------------------------------------------------


def test_an_oversize_component_is_deferred_not_recorded_as_a_veto(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_ALIAS_IDS", 5)
    monkeypatch.setattr(hood_mod, "MAX_ALIAS_IDS", 5)
    links = {f"d{i}": f"d{i + 1}" for i in range(10)} | {f"a{i}": f"a{i + 1}" for i in range(8)}
    links["A"] = "a0"
    inv.mac("A", "victim", None, "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    cp = inv.compute(Snapshot(links, (), {}, {}, {}))
    hood = cp._hood()
    assert cp._veto_state(hood, "A", "d0") == "oversize"  # both sides over the cap: a human decides
    assert cp._veto_state(hood, "A", "unrelated") is None  # a small side is still decided normally
    assert any(getattr(d, "kind", None) == "stitch_deferred" for d in cp.decisions)
    assert inv.db.execute("SELECT COUNT(*) FROM identity_candidates").fetchone()[0] == 0


def test_the_oversize_boundary_is_exact(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_ALIAS_IDS", 3)
    links = {"a1": "A", "a2": "A", "b1": "T", "b2": "T", "b3": "T"}  # |A side|=3, |T side|=4
    inv.mac("A", "victim", None, "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    cp = inv.compute(Snapshot(links, (), {}, {}, {}))
    hood = cp._hood()
    assert len(hood.alias_ids("A")) == 3 and len(hood.alias_ids("T")) == 4
    assert cp._veto_state(hood, "A", "T") is None  # the smaller side is exactly at the limit
    monkeypatch.setattr(compute_mod, "MAX_ALIAS_IDS", 2)
    assert cp._veto_state(hood, "A", "T") == "oversize"


def test_an_oversize_target_component_makes_the_rule_hit_a_provisional_row(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_ALIAS_IDS", 2)
    monkeypatch.setattr(hood_mod, "MAX_ALIAS_IDS", 2)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    links = {"x1": "D", "x2": "D", "y1": "A", "y2": "A"}
    snap = Snapshot(links, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {})
    st = inv.stitch(snap)
    assert (
        st.attached == 0 and inv.link_of(a) == ("A", "self") and inv.state("A") == [("D", "open")]
    )
    assert inv.db.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 0
    assert inv.count("stitch_deferred") == 1


# ---- merged device ranges are widened under the row cap ------------------------------------------


def test_widening_is_count_bounded_per_pass_and_writes_only_where_narrow(inv):
    links = {}
    for i in range(500):
        inv.mac(f"S{i}", f"s{i}", None, "self", "2026-01-01T00:00:00Z", [], rand=0)
        inv.mac(f"T{i}", f"t{i}", None, "self", "2026-02-01T00:00:00Z", [], rand=0)
        links[f"S{i}"] = f"T{i}"
    inv.db.execute("UPDATE devices SET last_seen='2026-06-01T00:00:00Z' WHERE id LIKE 'S%'")
    snap = Snapshot(links, (), {}, {}, {})
    narrow = (
        "SELECT COUNT(*) FROM devices WHERE id LIKE 'T%' AND first_seen > '2026-01-01T00:00:00Z'"
    )
    inv.stitch(snap)
    assert inv.db.execute(narrow).fetchone()[0] == 300  # 200 widened, no more
    inv.stitch(snap)
    inv.stitch(snap)
    assert inv.db.execute(narrow).fetchone()[0] == 0
    row = inv.db.execute("SELECT first_seen, last_seen FROM devices WHERE id='T7'").fetchone()
    assert tuple(row) == ("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")
    before = inv.db.total_changes
    inv.stitch(snap)
    assert inv.db.total_changes == before  # nothing narrow left: not a single row write


# ---- the APPLY lock is short and the reads are indexed -------------------------------------------


def test_apply_holds_the_lock_under_a_second_with_a_full_action_list(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(25):  # 25 attaches asked for, 20 allowed (mature, never concurrent)
        inv.mac(f"A{k}", "victim", None, "self", f"2026-01-{k + 2:02d}T00:00:00Z",
                [(NOW_ABS - 70000 + k * 2000, NOW_ABS - 69000 + k * 2000)])  # fmt: skip
    pair_world(inv, ["both"] * 150)  # 300 rows asked for, 200 allowed
    inv.commit()
    inv.db.execute("BEGIN")
    inv.db.executemany(  # a big inventory to make every scan visible
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES (?,'merge_identity',?,'{}','x','{}',?,?)",
        ((f"x{i}", f'["u{i}","w{i}"]', iso_utc(NOW_ABS - 10**6), iso_utc(NOW_ABS - 10**6))
         for i in range(200_000)),
    )  # fmt: skip
    inv.db.execute("COMMIT")
    plan = compute_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS)
    start = time.perf_counter()
    st = apply_plan(inv.db, RULE_SNAP, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert time.perf_counter() - start < 1.0
    assert st.attached == 20 and inv.totals()[0] + inv.totals()[1] - 200_000 <= 400
    assert (
        inv.db.execute("SELECT COUNT(*) FROM suggestions WHERE id NOT LIKE 'x%'").fetchone()[0]
        <= 100
    )


def test_a_pass_over_200_suggested_pairs_beside_500k_expired_suggestions_is_fast(inv):
    pair_world(inv, ["both"] * 200)
    for _ in range(3):  # 100 whole decisions fit one pass; one robin covers 128 pairs
        inv.stitch()
    assert inv.totals() == (200, 200)
    expired = iso_utc(NOW_ABS - 10**6)
    inv.db.execute("BEGIN")
    inv.db.executemany(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES (?,'merge_identity',?,'{}','x','{}',?,?)",
        ((f"x{i}", f'["u{i}","w{i}"]', expired, expired) for i in range(500_000)),
    )
    inv.db.execute("COMMIT")
    inv.db.execute(
        "UPDATE suggestions SET expires_at=? WHERE id NOT LIKE 'x%'", (iso_utc(NOW_ABS - 5),)
    )
    inv.commit()  # the 200 real suggestions expired: each pair is looked up again
    start = time.perf_counter()
    inv.stitch()
    assert time.perf_counter() - start < 2.0


def bulk_inventory(inv: Inv, total: int, active: int) -> None:
    """`total` observations (one device each); the first `active` also have recent activity."""
    inv.commit()
    inv.db.execute("BEGIN")
    inv.db.executemany(
        "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)",
        ((f"b{i}", OLD, OLD) for i in range(total)),
    )
    inv.db.executemany(
        "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint, vendor_class,"
        " hostname, mdns_name, link_source, first_seen, last_seen)"
        " VALUES (?,?,1,'9,9','z',?,NULL,'self',?,?)",
        ((f"be:{i >> 16:02x}:{i >> 8 & 255:02x}:{i & 255:02x}:00:01", f"b{i}", f"n{i}", OLD, OLD)
         for i in range(total)),
    )  # fmt: skip
    inv.db.executemany(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
        ((f"be:{i >> 16:02x}:{i >> 8 & 255:02x}:{i & 255:02x}:00:01", NOW_ABS - 500, NOW_ABS - 400)
         for i in range(active)),
    )  # fmt: skip
    inv.db.executemany(
        "INSERT OR IGNORE INTO mac_first_received (mac, received) VALUES (?,?)",
        ((f"be:{i >> 16:02x}:{i >> 8 & 255:02x}:{i & 255:02x}:00:01", NOW_ABS - 10**6)
         for i in range(active)),
    )  # fmt: skip
    inv.db.execute("COMMIT")


def test_600k_observations_with_1k_active_macs_stitch_fast(inv):
    bulk_inventory(inv, 600_000, 1_000)
    start = time.perf_counter()
    st = inv.stitch(RULE_SNAP)
    assert time.perf_counter() - start < 3.0
    assert st.examined == 256  # one robin's worth; the rest follow on later passes


def test_the_neighbourhood_queries_use_indexes(inv):
    inv.mac("D", "h", None, "self", OLD, [(NOW_ABS - 100, NOW_ABS)])
    inv.commit()
    plans = {
        "self": (compute_mod.SELF_SUBJECTS, ("", 0, 5)),
        "rule": (compute_mod.RULE_SUBJECTS, ("", 5)),
        "name": (f"SELECT {hood_mod.OBS_COLUMNS} {hood_mod.OBS_FROM} WHERE o.dhcp_fingerprint=?"  # noqa: S608
                 " AND o.vendor_class=? AND o.hostname = ? COLLATE NOCASE ORDER BY o.last_seen DESC"
                 " LIMIT ?", ("a", "b", "c", 5)),
        "mdns": (f"SELECT {hood_mod.OBS_COLUMNS} {hood_mod.OBS_FROM} WHERE o.dhcp_fingerprint=?"  # noqa: S608
                 " AND o.vendor_class=? AND o.mdns_name = ? COLLATE NOCASE ORDER BY o.last_seen"
                 " DESC LIMIT ?", ("a", "b", "c", 5)),
        "close": (f"SELECT {hood_mod.OBS_COLUMNS} {hood_mod.OBS_FROM} WHERE o.dhcp_fingerprint=?"  # noqa: S608
                  " AND o.vendor_class=? AND o.first_seen BETWEEN ? AND ? ORDER BY o.first_seen"
                  " LIMIT ?", ("a", "b", "c", "d", 5)),
        "devices": (f"SELECT {hood_mod.OBS_COLUMNS} {hood_mod.OBS_FROM} WHERE o.device_id IN (?,?)"  # noqa: S608
                    " LIMIT ?", ("a", "b", 5)),
        "pair": ("SELECT id, expires_at FROM suggestions WHERE action='merge_identity'"
                 " AND device_ids=?", ("[]",)),
        "into": ("SELECT COUNT(*) FROM suggestions WHERE action='merge_identity'"
                 " AND json_extract(device_ids, '$[1]')=? AND expires_at>?", ("d", "t")),
        "event": ("SELECT 1 FROM events WHERE kind=? AND dedup=?", ("k", "t")),
    }  # fmt: skip
    for name, (sql, args) in plans.items():
        plan = " ".join(r[3] for r in inv.db.execute("EXPLAIN QUERY PLAN " + sql, args))
        assert "SCAN observations" not in plan and "SCAN suggestions" not in plan, (name, plan)
        assert "SCAN events" not in plan and "TEMP B-TREE" not in plan, (name, plan)


def test_no_summary_table_or_trigger_is_left(inv):
    names = {r[0] for r in inv.db.execute("SELECT name FROM sqlite_master")}
    assert not names & {"mac_last_seen", "mac_collectors", "collector_gaps", "trg_mac_last_seen"}
    assert inv.db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
                          " AND tbl_name='mac_activity'").fetchone()[0] == 0  # fmt: skip


def test_the_apply_phase_rejects_a_stale_veto_decision_cheaply(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 20000, NOW_ABS)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    plan = compute_plan(inv.db, EMPTY, inv.cfg, NOW_ABS)
    assert any(isinstance(d, Veto) for d in plan.decisions)
    inv.db.execute("UPDATE observations SET link_source='human', device_id='D' WHERE mac=?", (a,))
    st = apply_plan(inv.db, EMPTY, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert st.vetoed == 0 and inv.state("A") == []


def test_a_rule_target_without_a_group_is_reported_through_stats(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    snap = Snapshot({}, (Rule("r1", "D", "1,2,3", "x", "victim", None),), {}, {}, {})
    st = inv.stitch(snap)
    assert st.suggestions == 1 and st.attached == 0 and st.examined == 1


# ---- fix round 1 -------------------------------------------------------------------------------


def test_a_dismissal_between_compute_and_apply_cancels_the_suggestion(inv):
    inv.mac("O", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("Y", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','Y','O',0.8,'{}','open','t')"
    )
    inv.commit()
    plan = compute_plan(inv.db, EMPTY, inv.cfg, NOW_ABS)
    inv.db.execute("UPDATE identity_candidates SET state='dismissed' WHERE id='c1'")  # a human
    st = apply_plan(inv.db, EMPTY, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert st.suggestions == 0 and st.stale == 1
    assert inv.totals() == (1, 0) and inv.state("Y") == [("O", "dismissed")]


def test_a_flooded_compatible_pool_turns_the_rule_hit_into_a_confirm_suggestion(inv, monkeypatch):
    monkeypatch.setattr(compute_mod, "MAX_SIGNATURE_BUCKET", 3)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(5):  # five live MACs with their own names, first seen within a gap of B
        inv.mac(f"P{k}", None, f"p{k}", "self", f"2026-02-01T00:00:{k + 1:02d}Z",
                [(NOW_ABS - 3600 * (k + 1),) * 2])  # fmt: skip
    b = inv.mac(
        "B", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW_ABS - 70000, NOW_ABS - 69000)]
    )
    st = inv.stitch(RULE_SNAP)
    assert inv.link_of(b) == ("B", "self") and st.attached == 0 and st.suggestions == 1
    row = inv.db.execute("SELECT reason_code, reason_text FROM suggestions").fetchone()
    assert tuple(row) == ("rule_hit_needs_confirm", "compatible_flood")
    assert inv.count("signature_flood") == 1 and inv.count("stitch_deferred") == 1


def test_a_candidate_whose_matching_device_has_too_many_macs_is_incomplete_evidence(
    inv, monkeypatch
):
    monkeypatch.setattr(hood_mod, "BUCKET_ROWS", 5)
    inv.mac("O", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(6):  # the matching device also owns six MACs with other names
        inv.mac("O", f"other{k}", None, "rule", OLD, [], newdev=False)
    inv.mac("Y", "victim", None, "self", "2026-01-04T00:00:00Z", [(NOW_ABS - 5000, NOW_ABS)])
    st = inv.stitch()
    assert inv.totals() == (0, 0) and st.deferred == 1 and inv.count("stitch_deferred") == 1


def test_the_self_robin_keeps_a_share_of_the_budget_whatever_the_recheck_costs(inv, monkeypatch):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    for k in range(40):  # forty quiet rule-attached MACs: more than the recheck can do in its share
        ivs = [(NOW_ABS - 80000 + k * 1000, NOW_ABS - 79500 + k * 1000)]
        m = inv.mac("D", "victim", None, "rule", f"2026-01-{k % 28 + 1:02d}T00:{k:02d}:00Z", ivs,
                    newdev=False)  # fmt: skip
        inv.attachment(m, "r1", "D", "victim", None, [[True, False]])
    pair_world(inv, ["both"] * 6)
    inv.commit()
    monkeypatch.setattr(compute_mod, "time", Ticking(0.5))  # ten budget checks a pass
    st = inv.stitch(RULE_SNAP)
    assert 0 < st.candidates and st.examined > st.candidates  # both robins made progress
