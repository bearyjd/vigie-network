"""Fix-round 6 tests: per-phase time-box, aliased vetoes, immutable attach evidence, per-batch
report lag, malformed rules, exact cleanup cap, reserved decisions, unreadable-overrides event,
attach-time re-read, fail-closed anchors."""

from __future__ import annotations

import json
import sqlite3
import time

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from stitch_helpers import Overrides, appear, device_of, kinds, mac, sig
from test_stitch_review import source_of
from test_stitch_review4 import NOW, RULE_SNAP, Inv, inv  # noqa: F401
from test_stitch_review5 import (
    OLD,
    attached_world,
    link_of,
    pair_world,
    run_at,
    seeded_d,
    totals,
)

from vigie_ingest.db import iso_utc
from vigie_pipeline import schema
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.snapshot import (
    EMPTY,
    OverridesUnreadable,
    Rule,
    Snapshot,
    load_snapshot,
)
from vigie_pipeline.stitch import BudgetExhaustedError, Stitcher, stitch

# ---- H1: the time-box starts after setup and is split per phase ----------------------------------


class FakeTime:
    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t


def slow_setup(monkeypatch, seconds: float, cap: float = 10**6) -> FakeTime:
    """A stitching setup that takes `seconds` of (fake) monotonic time."""
    clock = FakeTime()
    monkeypatch.setattr(stitch_mod, "time", clock)
    monkeypatch.setattr(stitch_mod, "STITCH_SETUP_MAX_SECONDS", cap)
    real = stitch_mod.load_first_received

    def slow(conn):
        clock.t += seconds
        return real(conn)

    monkeypatch.setattr(stitch_mod, "load_first_received", slow)
    return clock


def test_a_slow_setup_does_not_exhaust_the_time_box_of_every_phase(inv, monkeypatch):
    attached_world(inv, "r1")
    pair_world(inv, ["both"])
    slow_setup(monkeypatch, 100.0)  # setup alone outlasts STITCH_MAX_TXN_SECONDS
    st = inv.stitch(RULE_SNAP)
    assert st.suspect == 1 and st.suggestions == 1
    assert inv.count("stitch_budget_exhausted") == 0


def test_every_phase_gets_an_equal_slice_of_the_time_box_after_setup(inv, monkeypatch):
    clock = slow_setup(monkeypatch, 5.0)
    seen = []
    for name in ("_recheck_rule_attached", "apply_rules", "stitch_candidates"):
        real = getattr(Stitcher, name)

        def spy(self, real=real):
            seen.append(self.deadline - clock.t)
            return real(self)

        spy.__name__ = name
        monkeypatch.setattr(Stitcher, name, spy)
    inv.stitch(RULE_SNAP)
    assert seen == [1.0, 1.0, 1.0]  # STITCH_MAX_TXN_SECONDS (3) / 3


def test_a_setup_over_its_cap_releases_the_lock_and_says_so_once(inv, monkeypatch):
    pair_world(inv, ["both"])
    slow_setup(monkeypatch, 100.0, cap=2)
    st = inv.stitch(RULE_SNAP)
    assert st.candidates == 0 and totals(inv) == (0, 0)
    assert not inv.db.in_transaction  # the write lock is gone
    inv.stitch(RULE_SNAP, NOW + 60)
    assert inv.count("stitch_budget_exhausted") == 1
    summary = inv.db.execute("SELECT summary FROM events WHERE kind='stitch_budget_exhausted'")
    assert "setup" in summary.fetchone()[0]


def test_the_setup_check_runs_inside_the_observation_loading(inv, monkeypatch):
    for i in range(10):
        inv.mac(f"M{i}", f"h{i}", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    ticks = []
    real = stitch_mod._load_obs

    def spy(conn, snap, tick):
        ticks.append(tick)
        return real(conn, snap, tick)

    monkeypatch.setattr(stitch_mod, "_load_obs", spy)
    inv.stitcher()
    assert ticks and callable(ticks[0])
    monkeypatch.setattr(stitch_mod, "STITCH_SETUP_MAX_SECONDS", -1)
    with pytest.raises(BudgetExhaustedError):
        Stitcher(inv.db, EMPTY, inv.cfg, NOW)


def three_attached(inv: Inv) -> list[str]:
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    macs = [
        inv.mac(
            "D",
            "victim",
            None,
            "rule",
            f"2026-01-0{k + 2}T00:00:00Z",
            [(NOW - 10000, NOW)],
            newdev=False,
        )  # fmt: skip
        for k in range(3)
    ]
    inv.db.execute("UPDATE observations SET link_rule_id='r1' WHERE link_source='rule'")
    return sorted(macs)


def test_a_recheck_that_finishes_no_mac_moves_its_cursor_past_the_head(inv, monkeypatch):
    macs = three_attached(inv)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", -1)  # nothing ever fits
    seen = []
    for i in range(4):
        inv.stitch(RULE_SNAP, NOW + i)
        seen.append(inv.db.execute("SELECT value FROM stitch_state").fetchone()[0])
    assert seen == [macs[0], macs[1], macs[2], macs[0]]


def test_many_observations_do_not_stop_the_recheck_within_a_few_passes(inv, monkeypatch):
    three_attached(inv)
    inv.db.commit()
    inv.db.execute("BEGIN")
    inv.db.executemany(
        "INSERT INTO devices (id, first_seen, last_seen) VALUES (?,?,?)",
        ((f"f{i}", OLD, OLD) for i in range(200_000)),
    )
    inv.db.executemany(
        "INSERT INTO observations (mac, device_id, is_randomized, dhcp_fingerprint, vendor_class,"
        " hostname, mdns_name, link_source, first_seen, last_seen)"
        " VALUES (?,?,1,'9,9','z',?,NULL,'self',?,?)",
        ((f"fe:{i >> 16:02x}:{i >> 8 & 255:02x}:{i & 255:02x}:00:01", f"f{i}", f"n{i}", OLD, OLD)
         for i in range(200_000)),
    )  # fmt: skip
    inv.db.execute("COMMIT")
    monkeypatch.setattr(stitch_mod, "STITCH_MAX_TXN_SECONDS", 1)
    monkeypatch.setattr(stitch_mod, "STITCH_SETUP_MAX_SECONDS", 600)
    for i in range(8):
        start = time.perf_counter()
        inv.stitch(RULE_SNAP, NOW + i)
        assert time.perf_counter() - start < 12
        if inv.count("rule_attach_suspect") == 3:
            break
    assert inv.count("rule_attach_suspect") == 3


# ---- L-A: a veto follows its target through merges ---------------------------------------------


def merged_veto_world(inv: Inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 100000, NOW - 80000)], rand=0)
    inv.mac("E", "elsewhere", None, "self", OLD, [(NOW - 100000, NOW - 99000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 50000, NOW - 40000)])
    inv.db.execute(  # the historical veto (A, D): its overlap has since left the interval window
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','A','D',0.8,'{}','vetoed','t')"
    )
    return a


def merged_snap(links: dict[str, str]) -> Snapshot:
    rule = Rule("r1", "E", "1,2,3", "x", "victim", None)
    return Snapshot(links, (rule,), {"iot": 1}, {"E": (1, "iot")}, {})


def test_a_permanent_veto_survives_its_target_being_merged(inv):
    a = merged_veto_world(inv)
    st = inv.stitch(merged_snap({"D": "E"}))
    assert st.attached == 0 and link_of(inv, a) == ("A", "self")


def test_without_the_merge_the_other_target_is_not_blocked_by_the_veto(inv):
    a = merged_veto_world(inv)
    assert inv.stitch(merged_snap({})).attached == 1 and link_of(inv, a) == ("E", "rule")


def test_a_veto_on_a_merged_candidate_device_also_blocks(inv):
    a = merged_veto_world(inv)
    inv.db.execute("UPDATE identity_candidates SET device_a='Aold'")
    inv.db.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('Aold','t','t')")
    inv.db.execute("UPDATE devices SET status='retired' WHERE id='Aold'")
    assert inv.stitch(merged_snap({"D": "E", "Aold": "A"})).attached == 0, a


def test_alias_ids_cover_the_canonical_device_and_every_merged_one(inv):
    inv.mac("X", "h", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    st = Stitcher(inv.db, merged_snap({"D": "E", "F": "D"}), inv.cfg, NOW)
    assert st.alias_ids("D") == {"D", "E", "F"}
    assert st.alias_ids("E") == {"D", "E", "F"}
    assert st.alias_ids("Z") == {"Z"}


# ---- L-B: the attach evidence is immutable -----------------------------------------------------


def attach_then_rename(inv: Inv, rename: str | None):
    inv.mac("D", "previous-name", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 60000, NOW - 4000)])
    assert inv.stitch(RULE_SNAP, NOW - 3000).attached == 1
    if rename:
        inv.db.execute("UPDATE observations SET hostname=? WHERE mac=?", (rename, a))
    inv.act(a, [(NOW - 3999, NOW)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 4000, NOW)])
    return a


@pytest.mark.parametrize("rename", [None, "renamed-copy"])
def test_renaming_an_attached_copy_cannot_hide_a_later_overlap(inv, rename):
    attach_then_rename(inv, rename)
    st = inv.stitch(RULE_SNAP, NOW)
    assert st.suspect == 1 and inv.count("rule_attach_suspect") == 1


def test_the_attach_records_the_rule_fields_and_values_of_that_moment(inv):
    inv.mac("D", "previous-name", "mx", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", "Extra", "self", "2026-01-02T00:00:00Z", [(NOW - 60000, NOW)])
    inv.stitch(RULE_SNAP)
    row = inv.db.execute("SELECT rule_id, target, hostname, mdns_name FROM rule_attachments")
    assert [tuple(r) for r in row] == [("r1", "D", "victim", None)]  # the rule names the hostname
    assert link_of(inv, a) == ("D", "rule")


def test_the_evidence_survives_the_rule_being_revoked(inv):
    attach_then_rename(inv, "renamed-copy")
    revoked = Snapshot({}, (), {"iot": 1}, {"D": (1, "iot")}, {})
    assert inv.stitch(revoked, NOW).suspect == 1


# ---- M1: the report lag applies to every batch ------------------------------------------------


def test_a_later_batch_backfill_cannot_mature_a_copy_beside_the_present_device(data):
    n = 3000
    ov, _ = seeded_d(data, n)
    data.add_batch(T0 + n, received=T0 + n, dns=[(mac(1), T0 + t) for t in range(0, n + 1, 60)])
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + n, received=T0 + n, leases=lease, sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + n)])  # fmt: skip
    # a week-old-style back-fill: stamps 1 h+ before THIS batch's receipt, over the victim's absence
    data.add_batch(T0 + n + 700, received=T0 + n + 700,
                   dns=[(b, T0 + t) for t in range(n - 5000, n - 4300, 100)])  # fmt: skip
    run_at(data, T0 + n + 1000)
    assert data.q("SELECT COUNT(*) FROM mac_activity WHERE mac=?", b)[0][0] == 1
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    ov.close()


# ---- M2: malformed rule rows never escape ----


def ro(path) -> sqlite3.Connection:
    conn = open_overrides_ro(path)
    assert conn is not None
    return conn


def test_a_deeply_nested_signature_is_skipped_not_fatal(tmp_path, caplog):
    ov = Overrides(tmp_path)
    ov.rule("good", "D", sig())
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('deep','D',?,'t','owner')", ("[" * 200_000 + "]" * 200_000,),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert [r.id for r in snap.rules] == ["good"] and snap.malformed_rules == 1


@pytest.mark.parametrize("device_id", [b"\x00\x01", "", "   "])
def test_a_rule_with_a_non_string_or_blank_device_id_is_skipped(tmp_path, device_id):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('bad',?,?,'t','owner')", (device_id, json.dumps(sig())),
    )  # fmt: skip
    ov.rule("good", "D", sig())
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert [r.id for r in snap.rules] == ["good"] and snap.malformed_rules == 1


def test_a_rule_with_a_blob_id_is_skipped(tmp_path):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES (?, 'D', ?, 't', 'owner')", (b"\xff", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    snap = load_snapshot(ro(tmp_path / "overrides.db"), NOW)
    assert snap.rules == () and snap.malformed_rules == 1


def test_a_link_with_a_blob_endpoint_fails_the_whole_snapshot_closed(tmp_path):
    ov = Overrides(tmp_path)
    ov.conn.execute("PRAGMA ignore_check_constraints=ON")
    ov.conn.execute(
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
        " VALUES (?, 'E', 'm', 't', 'owner')", (b"\x01",),
    )  # fmt: skip
    ov.conn.commit()
    with pytest.raises(OverridesUnreadable):
        load_snapshot(ro(tmp_path / "overrides.db"), NOW)


def test_load_snapshot_maps_any_unexpected_exception_to_unreadable(tmp_path, monkeypatch):
    Overrides(tmp_path).close()
    monkeypatch.setattr("vigie_pipeline.snapshot._read", lambda *a: 1 / 0)
    with pytest.raises(OverridesUnreadable):
        load_snapshot(ro(tmp_path / "overrides.db"), NOW)


def test_two_matching_rules_one_with_a_blob_device_do_not_abort_the_run(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('blob',?,?,'t','owner')", (b"\x00", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700)
    run_at(data, T0 + 6000)  # must not raise
    assert source_of(data, b) == "rule" and device_of(data, b) == dev
    assert len(kinds(data, "rule_malformed")) == 1
    run_at(data, T0 + 6100)
    assert len(kinds(data, "rule_malformed")) == 1  # once per day
    ov.close()


# ---- L-D: the attach cleanup is under the row cap ---------------------------------------------


def test_attach_cleanup_of_201_open_candidates_respects_the_cap_and_finishes_later(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    inv.db.executemany(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, 'A', ?, 0.8, '{}', 'open', 't')",
        ((f"c{i}", f"X{i}") for i in range(201)),
    )
    inv.db.commit()
    open_q = "SELECT COUNT(*) FROM identity_candidates WHERE state='open'"
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 1 and link_of(inv, a) == ("D", "rule")
    assert inv.db.execute(open_q).fetchone()[0] == 1  # 200 dismissed, never more than the cap
    assert inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[
        0
    ]
    inv.stitch(RULE_SNAP, NOW + 1)
    assert inv.db.execute(open_q).fetchone()[0] == 0
    assert (
        inv.db.execute("SELECT COUNT(*) FROM stitch_state WHERE key LIKE 'settle:%'").fetchone()[0]
        == 0
    )


def test_cleanup_rows_count_against_rows_written_this_pass(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    inv.db.executemany(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, 'A', ?, 0.8, '{}', 'suggested', 't')",
        ((f"c{i}", f"X{i}") for i in range(5)),
    )
    inv.db.commit()
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    assert st._dismiss_open_candidates("A", 3) == 3
    assert st._dismiss_open_candidates("A", 0) == 0
    assert st._dismiss_open_candidates("A", -4) == 0
    assert st._dismiss_open_candidates("A", 99) == 2


# ---- L1: whole decisions are reserved ---------------------------------------------------------


def suggested_pair(inv: Inv):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW - 20000, NOW)], rand=0)
    inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    inv.stitch(EMPTY, NOW - 10000)  # a first pass: A is no peer yet -> nothing vetoed
    return inv.db.execute("SELECT id, expires_at FROM suggestions").fetchall()


def test_a_veto_that_does_not_fit_the_cap_withdraws_nothing(inv, monkeypatch):
    inv.mac("D", "victim", "m", "self", OLD, [(NOW - 20000, NOW)], rand=0)
    c = inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.mac("Q", "q", None, "self", OLD, [(NOW - 5, NOW)])
    inv.db.commit()
    inv.db.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES ('s1','merge_identity','[\"A\", \"D\"]','{}','x','{}','t',?)",
        (iso_utc(NOW + 10**6),),
    )
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY, inv.cfg, NOW)
    obs = next(o for o in st.obs if o.mac == c)
    st.writes = 200
    st._veto(obs, "D", 0.8, {})
    assert inv.db.execute("SELECT expires_at FROM suggestions").fetchone()[0] == iso_utc(
        NOW + 10**6
    )
    assert inv.state("A") == [] and st.stats.capped == 1
    st.writes = 199
    st._veto(obs, "D", 0.8, {})
    assert inv.state("A") == [("D", "vetoed")]
    assert inv.db.execute("SELECT expires_at FROM suggestions").fetchone()[0] < iso_utc(NOW)


def test_an_ambiguous_decision_is_written_whole_or_not_at_all(inv):
    c = inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY, inv.cfg, NOW)
    obs = next(o for o in st.obs if o.mac == c)
    st.writes = 199  # room for one row, the decision needs two
    st._ambiguous(obs, ["X", "Y"], 0.8, {})
    assert inv.state("A") == [] and st.stats.capped == 1
    st.writes = 198
    st._ambiguous(obs, ["X", "Y"], 0.8, {})
    assert sorted(inv.state("A")) == [("X", "ambiguous"), ("Y", "ambiguous")]


def test_withdrawals_are_charged_before_the_first_update(inv, monkeypatch):
    c = inv.mac("A", "victim", "m", "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    for i, canon in enumerate(["X", "Y", "Z"]):
        inv.db.execute(
            "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis,"
            " created_at, expires_at) VALUES (?,'merge_identity',?,'{}','x','{}','t',?)",
            (f"s{i}", json.dumps(["A", canon]), iso_utc(NOW + 10**6)),
        )
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY, inv.cfg, NOW)
    obs = next(o for o in st.obs if o.mac == c)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 2)
    st.ops = 0
    with pytest.raises(BudgetExhaustedError):
        st._withdraw(obs, ["X", "Y", "Z"])
    still = inv.db.execute("SELECT COUNT(*) FROM suggestions WHERE expires_at > ?", (iso_utc(NOW),))
    assert still.fetchone()[0] == 3  # nothing was half-withdrawn
    st.ops = 0
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 3)
    st._withdraw(obs, ["X", "Y", "Z"])
    assert st.ops == 3
    assert (
        still.connection.execute(
            "SELECT COUNT(*) FROM suggestions WHERE expires_at > ?", (iso_utc(NOW),)
        ).fetchone()[0]
        == 0
    )


# ---- L2: an unreadable overrides.db is an event, and merged ranges catch up ----


def break_groups(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit TO auto_inherit_x")
    conn.commit()
    conn.close()


def fix_groups(root) -> None:
    conn = sqlite3.connect(root / "overrides.db")
    conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit_x TO auto_inherit")
    conn.commit()
    conn.close()


def test_unreadable_overrides_writes_one_event_per_day_naming_the_error_class(data):
    appear(data, 1, 0, 300)
    Overrides(data.root).close()
    break_groups(data.root)
    run_at(data, T0 + 400)
    run_at(data, T0 + 500)
    (event,) = kinds(data, "stitching_skipped")
    assert "OperationalError" in event["summary"] and event["severity"] == "warn"
    run_at(data, T0 + 400 + 86400)
    assert len(kinds(data, "stitching_skipped")) == 2


def test_a_readable_overrides_db_writes_no_skip_event(data):
    appear(data, 1, 0, 300)
    Overrides(data.root).close()
    run_at(data, T0 + 400)
    assert kinds(data, "stitching_skipped") == []


def test_merged_device_ranges_catch_up_after_an_unreadable_period(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700, host="other", mdns="Other")
    run_at(data, T0 + 800)
    dev_a, dev_b = device_of(data, a), device_of(data, b)
    ov = Overrides(data.root)
    ov.link(dev_a, dev_b)
    ov.conn.commit()
    ov.close()
    break_groups(data.root)
    appear(data, 1, 900, 1000)
    run_at(data, T0 + 1100)
    last = "SELECT last_seen FROM devices WHERE id=?"
    assert data.q(last, dev_b)[0][0] < data.q(last, dev_a)[0][0]  # not widened while unreadable
    fix_groups(data.root)
    run_at(data, T0 + 1200)
    assert data.q(last, dev_b)[0][0] == data.q(last, dev_a)[0][0]


# ---- L3: revocation and regrouping are seen at attach time --------------------------------------


def authorised_world(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700)
    run_at(data, T0 + 4800)  # B is recorded but not yet mature
    return ov, dev, b


def late_stitch(data, ov_conn, snap):
    cfg = PipelineConfig(data_dir=data.root)
    return stitch(data.inv, snap, cfg, T0 + 6000, None, ov_conn)


@pytest.mark.parametrize(
    ("change", "attached"),
    [
        (None, 1),
        ("UPDATE identity_rules SET revoked_at='2026-10-02T00:00:00Z'", 0),
        ("UPDATE groups SET auto_inherit=0 WHERE id='iot'", 0),
        ("UPDATE device_overrides SET group_id=NULL", 0),
        ("UPDATE device_overrides SET group_id='guest'", 0),
    ],
)
def test_the_attach_rereads_the_rule_and_group_under_the_lock(data, change, attached):
    ov, dev, b = authorised_world(data)
    conn = ro(data.root / "overrides.db")
    snap = load_snapshot(conn, T0 + 6000)
    assert len(snap.rules) == 1 and snap.group_auto_inherit["iot"] == 1
    if change:
        ov.conn.execute(change)
        ov.conn.commit()
    assert late_stitch(data, conn, snap).attached == attached
    assert source_of(data, b) == ("rule" if attached else "self")
    ov.close()


def test_an_unreadable_overrides_db_at_attach_time_aborts_the_attach(data):
    ov, dev, b = authorised_world(data)
    conn = ro(data.root / "overrides.db")
    snap = load_snapshot(conn, T0 + 6000)
    ov.conn.execute("ALTER TABLE groups RENAME COLUMN auto_inherit TO auto_inherit_x")
    ov.conn.commit()
    assert late_stitch(data, conn, snap).attached == 0
    ov.close()


# ---- L4: fail-closed anchors and the migration anchor -------------------------------------------


def test_legacy_macs_are_anchored_at_migration_time_not_at_a_collector_stamp(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:5])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO mac_activity VALUES ('m', 1, 2)")  # a stamp from 1970
    conn.commit()
    conn.close()
    monkeypatch.undo()
    before = int(time.time())
    conn = open_pipeline_inventory(path)
    (anchor,) = conn.execute("SELECT received FROM mac_first_received").fetchone()
    assert before <= anchor <= int(time.time())


def test_rule_attachments_table_exists_after_migration(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(rule_attachments)")]
    assert cols == ["mac", "rule_id", "target", "hostname", "mdns_name", "attached_at"]


# ---- survivors of the round-6 mutation check ----


def test_rule_malformed_is_one_event_per_utc_day(data):
    ov, _ = seeded_d(data, 300)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('blob',?,?,'t','owner')", (b"\x00", json.dumps(sig())),
    )  # fmt: skip
    ov.conn.commit()
    run_at(data, T0 + 6000)
    run_at(data, T0 + 6100)
    assert len(kinds(data, "rule_malformed")) == 1
    run_at(data, T0 + 6000 + 86400)
    assert len(kinds(data, "rule_malformed")) == 2
    ov.close()


def test_the_report_lag_never_exceeds_a_shorter_retention(tmp_path):
    from vigie_pipeline.activity import record_activity
    from vigie_pipeline.sources import MacActivity

    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = T0
    stamps = {rec - 2000, rec - 900, rec - 500}
    act = MacActivity(first_ts=min(stamps), last_ts=max(stamps), stamps=stamps)
    record_activity(conn, {"m": act}, 300, rec, 1000)  # retention 1000 s < the 3600 s lag
    got = sorted(r[0] for r in conn.execute("SELECT start FROM mac_activity"))
    assert got == [rec - 900, rec - 500]


def test_widening_linked_devices_writes_only_where_a_range_is_too_narrow(inv):
    inv.mac("S", "s", None, "self", OLD, [(NOW - 100, NOW)])
    inv.mac("T", "t", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    wide = "UPDATE devices SET first_seen=?, last_seen=? WHERE id=?"
    inv.db.execute(wide, ("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", "S"))
    inv.db.execute(wide, ("2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z", "T"))
    inv.db.commit()
    snap = Snapshot({"S": "T"}, (), {}, {}, {})
    stitch(inv.db, snap, inv.cfg, NOW)
    row = inv.db.execute("SELECT first_seen, last_seen FROM devices WHERE id='T'").fetchone()
    assert tuple(row) == ("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")
    before = inv.db.total_changes
    stitch(inv.db, snap, inv.cfg, NOW)
    assert inv.db.total_changes == before  # nothing narrow left: not a single row write


def test_run_once_hands_its_overrides_connection_to_the_attach_recheck(data, monkeypatch):
    ov, dev, b = authorised_world(data)
    from vigie_pipeline import processor

    real = processor.stitch

    def revoke_then_stitch(*args, **kwargs):
        ov.conn.execute("UPDATE identity_rules SET revoked_at='2026-10-02T00:00:00Z'")
        ov.conn.commit()  # revoked after the snapshot was read, before the attach
        return real(*args, **kwargs)

    monkeypatch.setattr(processor, "stitch", revoke_then_stitch)
    stats = run_at(data, T0 + 6000)
    assert stats.attached == 0 and source_of(data, b) == "self"
    ov.close()


# ---- addendum: rotation, revoked-rule re-check, fail-closed anchor ----


def quiet_attached(inv: Inv) -> list[str]:
    """Three rule-attached MACs of D that never overlap anything, so none can ever be flagged."""
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    macs = [
        inv.mac(
            "D",
            "victim",
            None,
            "rule",
            f"2026-01-0{k + 2}T00:00:00Z",
            [(NOW - 70000 + k * 20000, NOW - 60000 + k * 20000)],
            newdev=False,
        )  # fmt: skip
        for k in range(3)
    ]
    inv.db.execute("UPDATE observations SET link_rule_id='r1' WHERE link_source='rule'")
    return sorted(macs)


def test_recheck_rotates_through_every_attached_mac_across_budget_stops(inv, monkeypatch):
    macs = quiet_attached(inv)
    monkeypatch.setattr(stitch_mod, "MAX_OVERLAP_OPS_PER_PASS", 4)  # one MAC (3 units) per pass
    checked: list[str] = []
    real = Stitcher._recheck

    def spy(self, o):
        real(self, o)
        checked.append(o.mac)

    monkeypatch.setattr(Stitcher, "_recheck", spy)
    cursors = []
    for i in range(3):
        inv.stitch(RULE_SNAP, NOW + i)
        row = inv.db.execute("SELECT value FROM stitch_state WHERE key='recheck_after_mac'")
        cursors.append(row.fetchone()[0])
    assert checked == macs  # one new MAC per pass, in order, none twice
    assert cursors == macs  # the cursor is the last MAC checked


def test_a_revoked_rules_attach_is_rechecked_against_the_persisted_evidence(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "UPDATE observations SET link_rule_id='gone', hostname='renamed' WHERE mac=?", (a,)
    )
    inv.db.execute(
        "INSERT INTO rule_attachments VALUES (?, 'gone', 'D', 'victim', NULL, 't')", (a,)
    )
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(Snapshot({}, (), {}, {}, {})).suspect == 1  # found via the stored hostname


def test_without_stored_evidence_a_name_shared_with_the_target_still_finds_the_suspect(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id='gone' WHERE mac=?", (a,))
    inv.mac("V", "victim", None, "rule", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])  # not pooled
    assert inv.stitch(Snapshot({}, (), {}, {}, {})).suspect >= 1
    assert inv.count("rule_attach_suspect") >= 1


def test_a_mac_without_an_anchor_is_never_attached_by_a_rule(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    b = inv.mac("B", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.execute("DELETE FROM mac_first_received WHERE mac=?", (b,))
    assert inv.stitch(RULE_SNAP).attached == 0 and link_of(inv, b) == ("B", "self")
    inv.db.execute("INSERT INTO mac_first_received VALUES (?, ?)", (b, NOW - 10**6))
    assert inv.stitch(RULE_SNAP).attached == 1


def test_legacy_recheck_uses_the_names_shared_with_the_target_to_exclude_contradicting_macs(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id='gone' WHERE mac=?", (a,))
    # a different hostname contradicts the shared 'victim': not a peer, however close in time
    inv.mac("V", "other", None, "self", "2026-01-02T00:01:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(Snapshot({}, (), {}, {}, {})).suspect == 0
