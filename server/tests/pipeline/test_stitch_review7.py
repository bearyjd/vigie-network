"""Fix-round 7 tests: bounded setup, strict rule signatures, evidence gaps, frozen attach evidence,
settle limits, migration 9 re-anchoring, post-attach map updates, orphan suggestions, merge
components."""

from __future__ import annotations

import json
import sqlite3
import time

import pytest
from pipeline_helpers import T0, data  # noqa: F401
from stitch_helpers import Overrides, appear, kinds, mac, sig
from test_stitch_review import source_of
from test_stitch_review4 import NOW, RULE_SNAP, Inv, inv  # noqa: F401
from test_stitch_review5 import OLD, link_of, run_at, seeded_d

from vigie_ingest.db import iso_utc
from vigie_pipeline import schema
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.activity import (
    active_macs,
    load_activity,
    load_first_received,
    load_gaps,
    record_activity,
)
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.schema import open_pipeline_inventory
from vigie_pipeline.snapshot import Rule, Snapshot, load_snapshot
from vigie_pipeline.sources import MacActivity
from vigie_pipeline.stitch import BudgetExhaustedError, Stitcher, _components
from vigie_pipeline.stitch_db import vetoed_between, withdraw_orphan_suggestions

# ---- H1: setup work follows the ACTIVE macs, not every observation ever seen ----


def bulk_inventory(inv: Inv, total: int, active: int) -> None:
    """`total` observations (one device each); the first `active` also have recent activity."""
    inv.db.commit()
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
        ((f"be:{i >> 16:02x}:{i >> 8 & 255:02x}:{i & 255:02x}:00:01", NOW - 500, NOW - 400)
         for i in range(active)),
    )  # fmt: skip
    inv.db.execute("COMMIT")


def test_600k_observations_with_1k_active_macs_stitch_fast_and_hold_the_lock_briefly(inv):
    bulk_inventory(inv, 600_000, 1_000)
    start = time.perf_counter()
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    setup = time.perf_counter() - start
    # the REAL setup cap, not a looser number: setup finished inside it, uncut
    assert not st.partial and setup < stitch_mod.STITCH_SETUP_MAX_SECONDS
    assert len(st.act) == 1_000
    assert len(st.obs) == 1_000  # not the 600k: only devices that can matter are loaded
    inv.db.execute("ROLLBACK") if inv.db.in_transaction else None
    start = time.perf_counter()
    inv.stitch(RULE_SNAP)
    assert time.perf_counter() - start < 2.0


def test_the_load_queries_use_indexes(inv):
    inv.mac("D", "h", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    plans = {
        "skip": 'SELECT mac FROM mac_activity WHERE mac > ? AND "end" >= ? ORDER BY mac LIMIT 1',
        "obs": "SELECT * FROM observations o JOIN devices d ON d.id = o.device_id"
        " WHERE o.device_id IN (?,?)",
        "dev": "SELECT DISTINCT device_id FROM observations WHERE mac IN (?,?)",
    }
    for name, sql in plans.items():
        args = ("", 0) if name == "skip" else ("a", "b")
        plan = " ".join(r[3] for r in inv.db.execute("EXPLAIN QUERY PLAN " + sql, args))
        assert "SEARCH" in plan and "SCAN observations" not in plan, (name, plan)
        assert "SCAN mac_activity" not in plan, (name, plan)


def test_devices_that_can_matter_are_loaded_and_unrelated_inactive_ones_are_not(inv):
    inv.mac("T", "victim", "Dave", "self", OLD, [], rand=0)  # rule target, no activity at all
    inv.mac("T", "victim", "Dave", "rule", OLD, [], newdev=False)
    inv.mac("A", "a", None, "self", OLD, [(NOW - 100, NOW)])  # active
    inv.mac("A", "a2", None, "self", OLD, [], newdev=False)  # inactive MAC of an active device
    inv.mac("Z", "z", None, "self", OLD, [])  # unrelated and inactive
    inv.db.commit()
    snap = Snapshot({"M": "T"}, (Rule("r", "T", "1,2,3", "x", "victim", None),), {}, {}, {})
    inv.db.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('M', 't', 't')")
    inv.mac("M", "merged", None, "self", OLD, [], newdev=False)  # merged into the target
    inv.db.commit()
    st = Stitcher(inv.db, snap, inv.cfg, NOW)
    loaded = {o.device_id for o in st.obs}
    assert loaded == {"T", "A", "M"} and len(st.obs) == 5


def test_activity_older_than_the_retention_cutoff_is_not_loaded(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 10**7, NOW - 10**7 + 10)])
    inv.db.execute("INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?, 0)", (m,))
    inv.db.commit()
    assert Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW).act.get(m) is None


EMPTY_SNAP = Snapshot({}, (), {}, {}, {})


def test_the_activity_scan_checks_the_time_between_pages_and_between_macs(inv, monkeypatch):
    for i in range(5):
        inv.mac(f"M{i}", f"h{i}", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    ticks = []
    monkeypatch.setattr("vigie_pipeline.activity.PAGE", 2)
    found, capped = active_macs(inv.db, NOW - 1000, lambda: ticks.append(1))
    assert (
        len(found) == 5 and not capped and len(ticks) == 4
    )  # pages of 2, 2, 1 and the final empty one
    ticks.clear()
    load_activity(inv.db, 300, per_mac_limit=64, tick=lambda: ticks.append(1))
    assert len(ticks) == 4 + 5  # the 4 pages again, then one per MAC


def test_the_enumeration_never_touches_stale_rows(inv):
    inv.db.commit()
    inv.db.execute("BEGIN")
    inv.db.executemany(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
        ((f"st:{i:06x}", 1000, 2000) for i in range(100_000)),
    )  # stale: ended long before the cutoff
    inv.db.executemany(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
        ((f"ac:{i:06x}", NOW - 100, NOW) for i in range(3)),
    )
    inv.db.execute("COMMIT")
    steps = []
    inv.db.set_progress_handler(lambda: steps.append(1) or 0, 1000)  # one call per 1000 VM steps
    found, _ = active_macs(inv.db, NOW - 10_000, lambda: None)
    inv.db.set_progress_handler(None, 0)
    assert sorted(found) == [f"ac:{i:06x}" for i in range(3)]
    assert len(steps) < 5  # a scan of the 100k stale rows would take hundreds of thousands of steps
    plan = " ".join(
        r[3] for r in inv.db.execute(
            "EXPLAIN QUERY PLAN SELECT mac, last_end FROM mac_last_seen WHERE last_end >= ?"
            " AND (last_end > ? OR mac > ?) ORDER BY last_end, mac LIMIT ?", (0, 0, "", 5)
        )
    )  # fmt: skip
    assert "idx_mac_last_seen_end" in plan and "SCAN mac_last_seen" not in plan


def test_the_summary_follows_inserts_and_purges(inv):
    from vigie_pipeline.activity import purge_activity

    inv.db.commit()
    inv.db.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 1, 10))
    inv.db.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 20, 30))
    inv.db.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 5, 7))
    q = "SELECT last_end FROM mac_last_seen WHERE mac='m'"
    assert inv.db.execute(q).fetchone()[0] == 30  # the maximum, whatever the insert order
    purge_activity(inv.db, 10_000, 1_000)
    assert inv.db.execute(q).fetchone() is None


def test_first_receipts_are_loaded_for_the_requested_macs_only(inv):
    for i in range(3):
        inv.mac(f"M{i}", f"h{i}", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    macs = [r[0] for r in inv.db.execute("SELECT mac FROM observations ORDER BY mac")]
    got = load_first_received(inv.db, macs[:2])
    assert set(got) == set(macs[:2])
    assert load_first_received(inv.db, []) == {}


def test_the_compatible_pool_scan_is_charged_and_first_seen_is_parsed_once(inv):
    for i in range(2100):
        inv.mac(f"N{i}", None, None, "self", "2026-06-01T00:00:00Z", [(NOW - 100000,) * 2])
    c = inv.mac("C", "victim", None, "self", "2026-01-01T00:00:00Z", [(NOW - 100, NOW)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    me = next(o for o in st.obs if o.mac == c)
    assert me.first_ts == 1767225600.0  # 2026-01-01T00:00:00Z
    st.ops = 0
    st._compat_raw(me)
    assert st.ops == 1 + 2 + 0  # one for the set, two for 2101 scanned pool MACs, none peers


# ---- H2: every supplied signature field is validated ----


def snapshot_with(tmp_path, signature) -> Snapshot:
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('r','D',?,'t','owner')", (json.dumps(signature),),
    )  # fmt: skip
    ov.conn.commit()
    conn = open_overrides_ro(tmp_path / "overrides.db")
    assert conn is not None
    return load_snapshot(conn, NOW)


BASE = {"opt55": "1,121,3", "opt60": "android", "hostname": "victim"}


@pytest.mark.parametrize(
    "extra",
    [
        {"mdns_name": {"required": "Different Name"}},
        {"mdns_name": 5}, {"mdns_name": []}, {"mdns_name": True}, {"mdns_name": "   "},
        {"mdns_name": ""}, {"hostname": 5}, {"hostname": ["a"]}, {"hostname": " "},
        {"opt60": 7}, {"opt60": {}}, {"opt60": ""}, {"opt55": "abc"}, {"opt55": "1,,2"},
        {"opt55": "1, 2"}, {"opt55": [1, "x"]}, {"opt55": [True]}, {"opt55": {}}, {"opt55": []},
        {"opt55": 5}, {"opt55": ""},
    ],
)  # fmt: skip
def test_a_supplied_field_of_the_wrong_type_rejects_the_whole_rule(tmp_path, extra):
    snap = snapshot_with(tmp_path, {**BASE, **extra})
    assert snap.rules == () and snap.malformed_rules == 1


@pytest.mark.parametrize(
    "sigdict",
    [
        BASE,
        {**BASE, "mdns_name": None},
        {"opt55": [1, 121, 3], "opt60": "android", "mdns_name": "Dave"},
        {**BASE, "extra_ignored": {"any": "thing"}},
    ],
)
def test_absent_or_null_fields_and_valid_values_are_fine(tmp_path, sigdict):
    snap = snapshot_with(tmp_path, sigdict)
    assert len(snap.rules) == 1 and snap.malformed_rules == 0


def test_an_incomplete_signature_is_ignored_not_malformed(tmp_path):
    snap = snapshot_with(tmp_path, {"opt55": "1,2", "opt60": "x"})  # no name at all
    assert snap.rules == () and snap.malformed_rules == 0


def test_a_weakened_rule_cannot_attach_a_different_mdns_name(data):
    ov, dev = seeded_d(data, 300)
    ov.conn.execute("DELETE FROM identity_rules")
    ov.rule("weak", dev, {**sig(), "mdns_name": {"required": "Different Name"}})
    ov.conn.commit()
    b = appear(data, 2, 4000, 4700, mdns="Another Name")
    run_at(data, T0 + 6000)
    assert source_of(data, b) == "self" and len(kinds(data, "rule_malformed")) == 1
    ov.close()


# ---- M1: dropped stamps are recorded as missing evidence and block maturity ----


def fold(conn, stamps, received, collector="c1", retention=7 * 86400):
    act = MacActivity(min(stamps), max(stamps), stamps=set(stamps))
    record_activity(conn, {"m": act}, 300, received, retention, collector)
    return [
        tuple(r)
        for r in conn.execute('SELECT collector_id, start, "end", recorded FROM collector_gaps')
    ]


def test_stamps_dropped_for_the_report_lag_become_a_gap(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = T0
    assert fold(conn, {rec - 3600, rec - 10}, rec) == []  # exactly the lag: kept, no gap
    gaps = fold(conn, {rec - 5000, rec - 4000, rec - 100}, rec)
    assert gaps == [("c1", rec - 5000, rec - 3600, rec)]
    assert fold(conn, {rec - 10**6}, rec) == gaps  # older than retention: epoch junk, not a gap
    assert fold(conn, {rec - 9000}, rec, collector=None) == gaps  # no collector named


def test_gap_rows_are_purged_with_the_activity(tmp_path):
    from vigie_pipeline.activity import purge_activity

    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.executemany(
        "INSERT INTO collector_gaps VALUES (?,?,?,?)", [("c", 1, 100, 1), ("c", 1, 9000, 1)]
    )
    purge_activity(conn, 10_000, 1_000)  # cutoff 9_000: the first gap ends before it
    assert [r[0] for r in conn.execute('SELECT "end" FROM collector_gaps')] == [9000]


GAP_CASES = [
    (lambda lo, hi: (hi + 300, hi + 400), True),  # starts within one activity gap of the window
    (lambda lo, hi: (hi + 301, hi + 400), False),
    (lambda lo, hi: (lo - 400, lo - 300), True),  # ends within one activity gap of the window
    (lambda lo, hi: (lo - 400, lo - 301), False),
    (lambda lo, hi: (lo - 2000, lo - 1000), False),
    (lambda lo, hi: (lo + 20, lo + 30), True),
]


@pytest.mark.parametrize(("make", "blocked"), GAP_CASES)
def test_a_mac_whose_window_overlaps_a_gap_of_its_collector_is_not_mature(inv, make, blocked):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 2000, NOW - 1900), (NOW - 1700, NOW - 1000)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    assert st.mature(m) is True
    lo, hi = st.act[m][0][0], st.act[m][-1][1]
    start, end = make(lo, hi)
    st._gap_index = {"c1": ([start], [end])}
    st.mac_collectors = {m: frozenset({"c1"})}
    assert st.mature(m) is (not blocked)
    st.mac_collectors = {m: frozenset({"other"})}  # a gap of a collector that never saw the MAC
    assert st.mature(m) is True
    st.mac_collectors = {}  # no collector recorded for the MAC: every collector counts
    assert st.mature(m) is (not blocked)
    st.mac_collectors = {m: frozenset({"other"})}
    assert st.mature(m, "T") is True  # the joining identity is unknown to `by_canon`
    st.by_canon["T"] = [next(iter(st.obs))]
    st.mac_collectors = {m: frozenset({"other"}), next(iter(st.obs)).mac: frozenset({"c1"})}
    assert st.mature(m, "T") is (not blocked)  # the victim's collector counts too


def test_the_copy_beside_a_late_collectors_victim_does_not_attach(data):
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
    assert data.q("SELECT COUNT(*) FROM collector_gaps")[0][0] == 1
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
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
    assert data.q("SELECT COUNT(*) FROM collector_gaps")[0][0] == 0
    assert source_of(data, b) == "rule"
    ov.close()


# ---- M2: attach evidence freezes the fingerprints and the union of the matched rules ----


def two_rule_snap() -> Snapshot:
    rules = (
        Rule("r1", "D", "1,2,3", "x", "victim", None),
        Rule("r2", "D", "1,2,3", "x", None, "Dave"),
    )
    return Snapshot({}, rules, {"iot": 1}, {"D": (1, "iot")}, {})


def attach_with_two_rules(inv: Inv) -> str:
    inv.mac("D", "previous", "old", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", "Dave", "self", "2026-01-02T00:00:00Z", [(NOW - 60000, NOW - 4000)])
    assert inv.stitch(two_rule_snap(), NOW - 3000).attached == 1
    return a


def test_the_attach_stores_the_union_of_all_matched_rules_fields_and_the_fingerprints(inv):
    a = attach_with_two_rules(inv)
    row = inv.db.execute(
        "SELECT rule_id, hostname, mdns_name, opt55, opt60 FROM rule_attachments WHERE mac=?", (a,)
    ).fetchone()
    assert tuple(row) == ("r1", "victim", "Dave", "1,2,3", "x")


def test_the_recheck_uses_both_rules_fields_after_a_rename(inv):
    a = attach_with_two_rules(inv)
    inv.db.execute("UPDATE observations SET hostname='x1', mdns_name='x2' WHERE mac=?", (a,))
    inv.act(a, [(NOW - 3999, NOW)])
    inv.mac("V", None, "Dave", "self", "2026-01-03T00:00:00Z", [(NOW - 4000, NOW)])  # mdns only
    assert inv.stitch(two_rule_snap(), NOW).suspect == 1


def test_the_recheck_searches_the_attach_time_fingerprint_bucket(inv):
    a = attach_with_two_rules(inv)
    inv.db.execute("UPDATE observations SET dhcp_fingerprint='9,9' WHERE mac=?", (a,))
    inv.act(a, [(NOW - 3999, NOW)])
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 4000, NOW)])
    assert inv.stitch(two_rule_snap(), NOW).suspect == 1


def test_attachments_without_stored_fingerprints_fall_back_to_the_current_ones(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, attached_at)"
        " VALUES (?, 'gone', 'D', 'victim', NULL, 't')", (a,),
    )  # fmt: skip
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(EMPTY_SNAP).suspect == 1


# legacy attaches (made before rule_attachments existed) are re-checked against the names they
# share with the target's other MACs, not against whatever the MAC calls itself now
def test_legacy_recheck_ignores_the_macs_current_extra_names(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", "Extra", "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id='gone' WHERE mac=?", (a,))
    # V's mDNS name contradicts A's extra name, but only the shared hostname counts: V is a peer
    inv.mac("V", None, "Elsewhere", "self", "2026-01-02T00:01:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(EMPTY_SNAP).suspect == 1


# ---- M3 / L2 / L3: settle limits, post-attach maps, orphan suggestions ----


def put_settle(inv: Inv, names: list[str]) -> None:
    inv.db.commit()
    for n in names:
        inv.db.execute("INSERT INTO stitch_state (key, value) VALUES (?, '1')", (f"settle:{n}",))
    inv.db.commit()


def test_settle_stops_when_the_allowance_is_spent_and_checks_the_deadline(inv, monkeypatch):
    put_settle(inv, [f"X{i}" for i in range(30)])
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    calls = []
    monkeypatch.setattr(st, "_settle_device", lambda d: calls.append(d))
    st.writes = 200
    st._settle_attached()
    assert calls == []
    st.writes = 0
    st.deadline = 0.0  # the time-box is spent
    with pytest.raises(BudgetExhaustedError):
        st._settle_attached()
    assert calls == []
    st.deadline = time.monotonic() + 100

    def spend(device):
        calls.append(device)
        st.writes += 100

    monkeypatch.setattr(st, "_settle_device", spend)
    st._settle_attached()
    assert len(calls) == 2  # 100 + 100: stopped at once when nothing was left


def attach_unit(inv: Inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.db.commit()
    return a


def test_a_committed_attach_updates_the_maps_even_when_the_time_box_is_spent(inv):
    a = attach_unit(inv)
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    me = st.by_mac[a]
    st.deadline = 0.0  # spent: any check_time/charge would raise
    st._attach(me, "D", RULE_SNAP.rules[0], 1.0, [RULE_SNAP.rules[0]])
    new = st.by_mac[a]
    assert (new.device_id, new.canon, new.source, new.rule_id) == ("D", "D", "rule", "r1")
    assert new in st.by_canon["D"] and me not in st.by_canon["A"]
    assert new in st.obs and me not in st.obs
    assert all(a not in [o.mac for o in v] or new in v for v in st.groups.values())
    assert st._live_sizes is None and st._by_fp is None  # caches rebuilt lazily


def suggestion(inv: Inv, sid: str, pair: list[str], expires: int):
    inv.db.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES (?,'merge_identity',?,'{}','x','{}','t',?)",
        (sid, json.dumps(pair), iso_utc(expires)),
    )


def test_the_attach_expires_the_orphans_open_suggestions_at_once(inv):
    a = attach_unit(inv)
    suggestion(inv, "s1", ["A", "D"], NOW + 10**6)
    suggestion(inv, "s2", ["A", "Q"], NOW + 10**6)
    suggestion(inv, "s3", ["B", "A"], NOW + 10**6)  # not from the orphan: untouched
    suggestion(inv, "s4", ["A", "R"], NOW - 10)  # already expired
    inv.db.commit()
    assert inv.stitch(RULE_SNAP).attached == 1 and link_of(inv, a) == ("D", "rule")
    rows = dict(inv.db.execute("SELECT id, expires_at FROM suggestions").fetchall())
    assert rows["s1"] < iso_utc(NOW) and rows["s2"] < iso_utc(NOW)
    assert rows["s3"] == iso_utc(NOW + 10**6) and rows["s4"] == iso_utc(NOW - 10)


def test_every_orphan_suggestion_is_expired_whatever_the_row_allowance(inv):
    a = attach_unit(inv)
    for i in range(5):
        suggestion(inv, f"s{i}", ["A", f"X{i}"], NOW + 10**6)
    inv.db.commit()
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    st.writes = 200  # the row allowance is spent
    st._attach(st.by_mac[a], "D", RULE_SNAP.rules[0], 1.0, [RULE_SNAP.rules[0]])
    open_q = "SELECT COUNT(*) FROM suggestions WHERE expires_at >= ?"
    assert inv.db.execute(open_q, (iso_utc(NOW),)).fetchone()[0] == 0
    assert st.writes == 200  # and nothing was charged


def test_a_decided_suggestion_is_never_withdrawn(inv):
    attach_unit(inv)
    suggestion(inv, "s1", ["A", "X"], NOW + 10**6)
    inv.db.commit()
    snap = Snapshot({}, (), {}, {}, {"s1": "accepted"})
    assert withdraw_orphan_suggestions(inv.db, snap, "A", NOW) == 0


def test_settle_marker_stays_until_the_candidate_rows_are_done(inv):
    attach_unit(inv)
    inv.db.executemany(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?, 'A', ?, 0.8, '{}', 'open', 't')",
        ((f"c{i}", f"X{i}") for i in range(3)),
    )
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    st.writes = 199  # room for one row
    st._settle_device("A")
    marker = "SELECT value FROM stitch_state WHERE key='settle:A'"
    assert inv.db.execute(marker).fetchone() is not None
    st.writes = 0
    st._settle_device("A")
    assert inv.db.execute(marker).fetchone() is None


# ---- L1: migration 9 re-anchors collector-stamp anchors ----


FULL = schema.PIPELINE_MIGRATIONS


def v6_database(path, monkeypatch, rows):
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", FULL[:5])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.executemany('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', rows)
    conn.commit()
    conn.close()
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", FULL[:6])
    open_pipeline_inventory(path).close()  # now at the pre-edit version 6
    monkeypatch.undo()


def test_upgrading_a_version_6_database_resets_every_existing_anchor_conservatively(
    tmp_path, monkeypatch
):
    path = tmp_path / "inventory.db"
    # "purged": its earliest interval is gone; "equal": an honest-looking receipt equal to the
    # earliest stamp; "plain": an anchor unlike its stamps. Provenance cannot be told apart, so ALL
    # existing anchors move to the migration time and are marked legacy.
    v6_database(
        path,
        monkeypatch,
        [("equal", 5, 9), ("plain", 7, 9), ("purged", 1, 2), ("multi", 1, 2), ("multi", 5, 9)],
    )
    raw = sqlite3.connect(path)
    raw.execute("UPDATE mac_first_received SET received = 4000 WHERE mac='plain'")
    raw.execute("UPDATE mac_first_received SET received = 3 WHERE mac='purged'")
    raw.commit()
    raw.close()
    assert (
        sqlite3.connect(path).execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 6
    )
    before = int(time.time())
    conn = open_pipeline_inventory(path)
    rows = {
        r["mac"]: (r["received"], r["legacy"])
        for r in conn.execute("SELECT * FROM mac_first_received")
    }
    assert all(legacy == 1 and before <= got <= int(time.time()) for got, legacy in rows.values())
    assert set(rows) == {"equal", "plain", "purged", "multi"}
    summary = dict(conn.execute("SELECT mac, last_end FROM mac_last_seen").fetchall())
    assert summary == {
        "equal": 9,
        "plain": 9,
        "purged": 2,
        "multi": 9,
    }  # backfilled from the activity
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 11
    record_activity(conn, {"fresh": MacActivity(1, 1)}, 300, 10**9, 7 * 86400)
    assert conn.execute(
        "SELECT received, legacy FROM mac_first_received WHERE mac='fresh'"
    ).fetchone()[:] == (10**9, 0)
    open_pipeline_inventory(path).close()  # re-opening never resets the rows written afterwards
    assert (
        open_pipeline_inventory(path)
        .execute("SELECT received FROM mac_first_received WHERE mac='fresh'")
        .fetchone()[0]
        == 10**9
    )


def test_migration_6_is_the_form_that_was_applied_before(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", FULL[:5])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute('INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)', ("m", 17, 20))
    conn.commit()
    conn.close()
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", FULL[:6])
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT received FROM mac_first_received").fetchone()[0] == 17  # MIN(start)


def test_a_fresh_install_has_no_legacy_rows_and_the_columns(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    assert conn.execute("SELECT COUNT(*) FROM mac_first_received").fetchone()[0] == 0
    cols = [r[1] for r in conn.execute("PRAGMA table_info(mac_first_received)")]
    assert cols == ["mac", "received", "legacy"]
    record_activity(conn, {"m": MacActivity(1, 1)}, 300, 10**9, 7 * 86400)
    assert conn.execute("SELECT legacy FROM mac_first_received").fetchone()[0] == 0


# ---- L4: merge components ----


def test_components_follow_chains_of_any_length_and_cycles():
    links = {f"d{i}": f"d{i + 1}" for i in range(100)} | {"x": "y", "y": "x", "q": "d0"}
    comp = _components(links)
    assert comp["d100"] == comp["d0"] == comp["q"] and len(comp["d0"]) == 102
    assert comp["x"] == frozenset({"x", "y"})
    assert "free" not in comp


def vetoed_row(inv: Inv, a: str, b: str) -> None:
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES (?,?,?,0.8,'{}','vetoed','t')", (f"{a}{b}", a, b),
    )  # fmt: skip


def test_a_veto_survives_a_merge_chain_longer_than_the_link_depth(inv):
    inv.mac("A", "victim", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    vetoed_row(inv, "A", "d0")
    inv.db.commit()
    links = {f"d{i}": f"d{i + 1}" for i in range(60)}
    st = Stitcher(inv.db, Snapshot(links, (), {}, {}, {}), inv.cfg, NOW)
    me = next(o for o in st.obs if o.device_id == "A")
    assert st._vetoed(me, "d60") is True
    assert st._vetoed(me, "unrelated") is False


def test_vetoed_between_is_chunked_beyond_the_variable_limit(inv):
    inv.db.commit()
    vetoed_row(inv, "a-39999", "b-39999")
    inv.db.commit()
    a = {f"a-{i}" for i in range(40_000)}
    b = {f"b-{i}" for i in range(40_000)}
    assert vetoed_between(inv.db, a, b) is True
    assert vetoed_between(inv.db, a - {"a-39999"}, b) is False
    assert vetoed_between(inv.db, set(), b) is False


def test_an_oversize_component_is_deferred_not_recorded_as_a_veto(inv, monkeypatch):
    inv.mac("A", "victim", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 5)
    links = {f"d{i}": f"d{i + 1}" for i in range(10)} | {f"a{i}": f"a{i + 1}" for i in range(8)}
    links["A"] = "a0"
    st = Stitcher(inv.db, Snapshot(links, (), {}, {}, {}), inv.cfg, NOW)
    me = next(o for o in st.obs if o.device_id == "A")
    assert st._vetoed(me, "d0") is True  # both sides over the cap: deferred to a human
    assert st._vetoed(me, "d0") is True
    rows = inv.db.execute(
        "SELECT summary, device_id FROM events WHERE kind='alias_component_oversize'"
    ).fetchall()
    assert len(rows) == 1 and "d10" in rows[0][0] and "limit 5" in rows[0][0] and rows[0][1] is None
    assert inv.db.execute("SELECT COUNT(*) FROM identity_candidates").fetchone()[0] == 0
    assert st._vetoed(me, "unrelated") is False  # a small side is still decided normally
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 5000)
    assert st._vetoed(me, "d0") is False  # no veto exists: nothing is blocked once it fits


def test_a_veto_is_found_across_a_huge_component_through_the_smaller_sides_index(inv):
    inv.db.commit()
    vetoed_row(inv, "A", "d29999")
    vetoed_row(inv, "e29999", "B")
    inv.db.commit()
    big = frozenset(f"d{i}" for i in range(30_000))
    small = frozenset({"A"})
    assert vetoed_between(inv.db, small, big) is True  # keyed by the small side's device_a
    assert vetoed_between(inv.db, big, frozenset({"B"})) is False  # e29999 is not in `big`
    assert vetoed_between(inv.db, frozenset({"e29999"}), frozenset({"B"})) is True
    assert vetoed_between(inv.db, big | {"e29999"}, frozenset({"B"})) is True  # via device_b index
    plan = " ".join(
        r[3] for r in inv.db.execute(
            "EXPLAIN QUERY PLAN SELECT device_a FROM identity_candidates"
            " WHERE state='vetoed' AND device_b IN (?, ?)", ("x", "y"),
        )
    )  # fmt: skip
    assert "idx_candidates_vetoed_b" in plan and "SCAN" not in plan


def test_the_observation_loader_checks_the_time_between_chunks(inv):
    inv.mac("D", "h", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    calls = []

    def boom():
        calls.append(1)
        raise BudgetExhaustedError

    with pytest.raises(BudgetExhaustedError):
        stitch_mod._load_obs(inv.db, EMPTY_SNAP, boom, ["D"])
    assert calls == [1]
    assert stitch_mod._load_obs(inv.db, EMPTY_SNAP, boom, []) == []  # nothing to load: no check


def test_the_attach_stores_the_hostname_of_a_matching_rule_that_is_not_the_lowest_id(inv):
    rules = (
        Rule("r1", "D", "1,2,3", "x", None, "Dave"),
        Rule("r2", "D", "1,2,3", "x", "victim", None),
    )
    snap = Snapshot({}, rules, {"iot": 1}, {"D": (1, "iot")}, {})
    inv.mac("D", "previous", "old", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", "Dave", "self", "2026-01-02T00:00:00Z", [(NOW - 60000, NOW - 4000)])
    assert inv.stitch(snap, NOW - 3000).attached == 1
    row = inv.db.execute(
        "SELECT rule_id, hostname, mdns_name FROM rule_attachments WHERE mac=?", (a,)
    )
    assert tuple(row.fetchone()) == ("r1", "victim", "Dave")


def test_an_attach_to_a_retired_target_marks_the_moved_observation_retired(inv):
    a = attach_unit(inv)
    inv.db.execute("UPDATE devices SET status='retired' WHERE id='D'")
    inv.db.commit()
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    st._attach(st.by_mac[a], "D", RULE_SNAP.rules[0], 1.0, [RULE_SNAP.rules[0]])
    assert st.by_mac[a].retired is True


# ================= round 8 =================


def chain(n: int, prefix: str = "d") -> dict[str, str]:
    return {f"{prefix}{i}": f"{prefix}{i + 1}" for i in range(n)}


def test_canonical_follows_the_complete_chain_of_any_length_and_survives_cycles():
    snap = Snapshot(chain(200) | {"x": "y", "y": "z", "z": "x", "w": "x"}, (), {}, {}, {})
    assert snap.canonical("d0") == snap.canonical("d150") == "d200"
    assert snap.canonical("d200") == "d200" and snap.canonical("free") == "free"
    assert (
        snap.canonical("x") == snap.canonical("y") == snap.canonical("z")
    )  # one cycle: one answer
    assert snap.canonical("w") == snap.canonical("x")
    two = Snapshot({"a": "b", "b": "c", "q": "b"}, (), {}, {}, {})
    assert (two.canonical("a"), two.canonical("q"), two.canonical("b")) == ("c", "c", "c")


def test_a_rule_on_the_start_of_a_41_link_chain_still_vetoes_an_overlap_with_its_far_end(inv):
    links = chain(41)
    inv.mac("d0", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    inv.mac("d40", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.mac("d41", "other", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    rule = Rule("r", "d0", "1,2,3", "x", "victim", None)
    snap = Snapshot(links, (rule,), {"iot": 1}, {"d41": (1, "iot")}, {})
    st = inv.stitch(snap)
    assert st.attached == 0 and link_of(inv, a) == ("A", "self")
    assert ("d41", "vetoed") in inv.state("A")  # decided against the COMPLETE chain's end


def test_components_share_one_set_and_tick():
    ticks = []
    comp = _components(chain(1000), lambda: ticks.append(1))
    assert comp["d0"] is comp["d1000"] is comp["d500"] and len(comp["d0"]) == 1001
    assert ticks  # interruptible
    start = time.perf_counter()
    big = _components(chain(60_000))
    assert time.perf_counter() - start < 3 and len(big["d0"]) == 60_001


def test_component_construction_stops_on_the_deadline():
    def boom():
        raise BudgetExhaustedError

    with pytest.raises(BudgetExhaustedError):
        _components(chain(10), boom)


def two_rule_attach(inv: Inv):
    inv.mac("D", "previous", "old", "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", "Dave", "self", "2026-01-02T00:00:00Z", [(NOW - 60000, NOW - 4000)])
    assert inv.stitch(two_rule_snap(), NOW - 3000).attached == 1
    return a


def test_each_matched_rules_view_is_stored_and_checked_separately(inv):
    a = two_rule_attach(inv)
    views = inv.db.execute("SELECT views FROM rule_attachments WHERE mac=?", (a,)).fetchone()[0]
    assert json.loads(views) == [[False, True], [True, False]]
    inv.act(a, [(NOW - 3999, NOW)])
    # no hostname, an mDNS name that contradicts the UNION but not the hostname-only view,
    # first seen within a gap of the attached MAC
    inv.mac("V", None, "Elsewhere", "self", "2026-01-02T00:01:00Z", [(NOW - 4000, NOW)])
    assert inv.stitch(two_rule_snap(), NOW).suspect == 1


def test_an_attachment_without_stored_views_uses_its_one_combined_view(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, attached_at)"
        " VALUES (?, 'gone', 'D', 'victim', NULL, 't')", (a,),
    )  # fmt: skip
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 3000, NOW)])
    assert inv.stitch(EMPTY_SNAP).suspect == 1


def test_an_older_device_with_no_retained_activity_still_gets_a_fingerprint_suggestion(inv):
    inv.mac("O", "victim", "Dave", "self", OLD, [], rand=0)  # activity long purged
    inv.mac("Z", "unrelated", None, "self", OLD, [])  # inactive and unrelated: not loaded
    y = inv.mac("Y", "victim", "Dave", "self", "2026-02-01T00:00:00Z", [(NOW - 500, NOW)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    assert {o.device_id for o in st.obs} == {"O", "Y"}
    stats = inv.stitch()
    assert stats.suggestions == 1 and inv.state("Y") == [("O", "suggested")], y


def test_a_case_different_name_still_finds_the_historical_identity(inv):
    inv.mac("O", "VICTIM", None, "self", OLD, [], rand=0)
    inv.mac("Y", "victim", None, "self", "2026-02-01T00:00:00Z", [(NOW - 500, NOW)])
    inv.db.commit()
    assert {o.device_id for o in Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW).obs} == {"O", "Y"}


def test_historical_matches_are_limited_oldest_first(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "HISTORIC_MATCH_LIMIT", 3)
    for i in range(6):
        inv.mac(f"O{i}", "victim", None, "self", f"2026-01-0{i + 1}T00:00:00Z", [], rand=0)
    inv.mac("Y", "victim", None, "self", "2026-03-01T00:00:00Z", [(NOW - 500, NOW)])
    inv.db.commit()
    loaded = {o.device_id for o in Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW).obs}
    assert loaded == {"Y", "O0", "O1", "O2"}


def test_the_historical_lookups_use_the_fingerprint_name_indexes(inv):
    inv.db.commit()
    for column, index in (("hostname", "idx_obs_fp_host"), ("mdns_name", "idx_obs_fp_mdns")):
        plan = " ".join(
            r[3] for r in inv.db.execute(
                "EXPLAIN QUERY PLAN SELECT device_id FROM observations WHERE dhcp_fingerprint=?"  # noqa: S608
                f" AND vendor_class=? AND {column} = ? COLLATE NOCASE ORDER BY first_seen LIMIT ?",
                ("a", "b", "c", 3),
            )
        )  # fmt: skip
        assert index in plan and "SCAN" not in plan and "TEMP B-TREE" not in plan, plan


def test_first_receipts_beyond_one_chunk_are_all_returned(inv):
    inv.db.commit()
    macs = [f"m{i:04d}" for i in range(1000)]
    inv.db.executemany(
        "INSERT INTO mac_first_received (mac, received) VALUES (?, ?)", [(m, 7) for m in macs]
    )
    inv.db.commit()
    assert load_first_received(inv.db, macs) == dict.fromkeys(macs, 7)


def test_canonical_resolution_is_linear_in_the_chain_length():
    snap = Snapshot(chain(30_000), (), {}, {}, {})
    start = time.perf_counter()
    assert snap.canonical("d0") == "d30000" and snap.canonical("d12345") == "d30000"
    assert time.perf_counter() - start < 2.0


def test_component_construction_ticks_in_every_loop():
    ticks = []
    _components(chain(10_000), lambda: ticks.append(1))
    # 3 ticks in the link loop (steps 0, 4096, 8192), 3 in the group loop, 1 after the one group
    assert len(ticks) == 7


def test_a_component_over_the_cap_is_not_expanded_for_loading(inv, monkeypatch):
    inv.mac("d0", "h", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 5)
    st = Stitcher(inv.db, Snapshot(chain(10), (), {}, {}, {}), inv.cfg, NOW)
    assert st._expand(["d0"]) == {"d0"}
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 50)
    assert st._expand(["d0"]) == {f"d{i}" for i in range(11)}


def test_inactive_loaded_devices_do_not_trigger_historical_lookups(inv):
    inv.mac("T", "tname", None, "self", OLD, [], rand=0)  # a rule target without activity
    inv.mac("H", "tname", None, "self", "2026-01-02T00:00:00Z", [], rand=0)  # unrelated, inactive
    inv.mac("Y", "other", None, "self", "2026-02-01T00:00:00Z", [(NOW - 500, NOW)])
    inv.db.commit()
    rule = Rule("r", "T", "1,2,3", "x", "tname", None)
    st = Stitcher(inv.db, Snapshot({}, (rule,), {}, {}, {}), inv.cfg, NOW)
    assert {o.device_id for o in st.obs} == {"T", "Y"}  # T is inactive: no lookup for its name


def test_vetoes_are_looked_up_from_the_smaller_side(inv):
    inv.db.commit()
    seen: list[str] = []
    inv.db.set_trace_callback(seen.append)
    small, big = frozenset({"A"}), frozenset(f"d{i}" for i in range(50))
    vetoed_between(inv.db, small, big)
    vetoed_between(inv.db, big, small)
    inv.db.set_trace_callback(None)
    assert "device_a IN" in seen[0] and "device_b IN" in seen[1]


def test_canonical_resolution_reuses_the_resolved_tail_of_shared_chains():
    links = chain(8_000) | {f"l{i}": "d0" for i in range(8_000)}
    snap = Snapshot(links, (), {}, {}, {})
    start = time.perf_counter()
    assert snap.canonical("l7999") == snap.canonical("l0") == "d8000"
    assert time.perf_counter() - start < 2.0  # 8000 leaves x 8000-link tail, if not memoised


# ================= round 8 addendum =================


class Ticking:
    """A fake monotonic clock that advances every time the stitcher checks the time."""

    def __init__(self, step: float) -> None:
        self.t, self.step = 1000.0, step

    def monotonic(self) -> float:
        return self.t


def tick_clock(monkeypatch, step: float) -> Ticking:
    clock = Ticking(step)
    monkeypatch.setattr(stitch_mod, "time", clock)
    real = Stitcher._check_time

    def advance(self):
        clock.t += clock.step
        real(self)

    monkeypatch.setattr(Stitcher, "_check_time", advance)
    return clock


def attached_with_peer(inv: Inv) -> str:
    """A rule-attached MAC (with stored attach evidence) and a peer overlapping it for hours."""
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 10000, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute("UPDATE observations SET link_rule_id='r1' WHERE mac=?", (a,))
    inv.db.execute(
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, attached_at,"
        " opt55, opt60, views)"
        " VALUES (?, 'r1', 'D', 'victim', NULL, 't', '1,2,3', 'x', '[[true,false]]')",
        (a,),
    )  # fmt: skip
    inv.mac("V", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 10000, NOW)])
    return a


def spray(inv: Inv, count: int, intervals: int = 3) -> None:
    for i in range(count):
        inv.mac(f"S{i}", f"junk{i}", None, "self", "2026-06-01T00:00:00Z",
                [(NOW - 5000 + k * 400,) * 2 for k in range(intervals)])  # fmt: skip


def test_a_spray_cuts_the_bulk_setup_short_but_the_recheck_still_runs(inv, monkeypatch):
    attached_with_peer(inv)
    spray(inv, 400)
    inv.db.commit()
    clock = tick_clock(monkeypatch, 0.05)  # 2 s of cap = 40 time checks: far fewer than the work
    start = clock.t
    st = inv.stitch(RULE_SNAP)
    assert inv.count("rule_attach_suspect") == 1 and st.suspect == 1
    summary = inv.db.execute("SELECT summary FROM events WHERE kind='stitch_budget_exhausted'")
    rows = [r[0] for r in summary]
    assert len(rows) == 1 and "only the re-check" in rows[0]
    # the lock was held for at most the setup cap plus the time-box (in the fake clock's time)
    assert (
        clock.t - start
        <= stitch_mod.STITCH_SETUP_MAX_SECONDS + stitch_mod.STITCH_MAX_TXN_SECONDS + 1
    )


def test_a_cut_setup_skips_the_rules_and_candidate_phases(inv, monkeypatch):
    attached_with_peer(inv)
    pair_world_for_spray(inv)
    spray(inv, 400)
    inv.db.commit()
    tick_clock(monkeypatch, 0.05)
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    assert st.partial is True and len(st.obs) < 800
    ran = []
    for name in ("_recheck_rule_attached", "apply_rules", "stitch_candidates"):
        real = getattr(Stitcher, name)
        monkeypatch.setattr(
            Stitcher, name, lambda self, real=real, name=name: (ran.append(name), real(self))[1]
        )
    st.run()
    assert ran == ["_recheck_rule_attached"]


def pair_world_for_spray(inv: Inv) -> None:
    inv.mac("O9", "pair", None, "self", OLD, [(NOW - 90000, NOW - 89000)])
    inv.mac("Y9", "pair", None, "self", "2026-02-01T00:00:00Z", [(NOW - 500, NOW)])


def test_an_uncut_setup_runs_every_phase(inv):
    attached_with_peer(inv)
    pair_world_for_spray(inv)
    inv.db.commit()
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    assert st.partial is False
    assert inv.stitch(RULE_SNAP).suggestions == 1  # the candidate phase ran


def test_the_interval_fetch_of_every_mac_checks_the_time(inv, monkeypatch):
    for i in range(30):
        inv.mac(f"M{i}", f"h{i}", None, "self", OLD, [(NOW - 100 * k,) * 2 for k in range(1, 65)])
    inv.db.commit()
    seen = []
    real = Stitcher._check_time
    monkeypatch.setattr(Stitcher, "_check_time", lambda self: (seen.append(1), real(self))[1])
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    assert len(seen) > 30 and len(st.act) == 30  # at least one check per MAC's interval fetch


def test_the_active_set_is_capped_newest_first_and_reported_once_a_day(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_ACTIVE_MACS", 10)
    macs = [inv.mac(f"M{i:02d}", f"h{i}", None, "self", OLD, [(NOW - 1000 + i, NOW - 1000 + i)])
            for i in range(30)]  # fmt: skip
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    assert st.active_capped is True
    assert set(st.act) == set(macs[-10:])  # the 10 newest
    inv.stitch(EMPTY_SNAP)
    inv.stitch(EMPTY_SNAP, NOW + 60)
    assert inv.count("stitch_active_set_capped") == 1


def test_the_active_set_cap_boundary_is_exact(inv):
    for i in range(10):
        inv.mac(f"M{i:02d}", f"h{i}", None, "self", OLD, [(NOW - 100 + i, NOW - 100 + i)])
    inv.db.commit()
    assert active_macs(inv.db, NOW - 1000, lambda: None, 10)[1] is False  # exactly the limit
    got, capped = active_macs(inv.db, NOW - 1000, lambda: None, 9)
    assert capped is True and len(got) == 9
    assert active_macs(inv.db, NOW - 1000, lambda: None, 11)[1] is False


def test_active_macs_come_newest_first_across_pages(inv, monkeypatch):
    monkeypatch.setattr("vigie_pipeline.activity.PAGE", 3)
    for i in range(8):
        inv.mac(f"M{i}", f"h{i}", None, "self", OLD, [(NOW - 100 * (8 - i),) * 2])
    inv.db.commit()
    got, capped = active_macs(inv.db, NOW - 10_000, lambda: None)
    ends = [
        inv.db.execute("SELECT last_end FROM mac_last_seen WHERE mac=?", (m,)).fetchone()[0]
        for m in got
    ]
    assert ends == sorted(ends, reverse=True) and len(got) == 8 and not capped
    got5, capped5 = active_macs(inv.db, NOW - 10_000, lambda: None, 5)
    assert got5 == got[:5] and capped5 is True


# ---- evidence gaps are scoped to the collectors involved, merged, charged and reported ----


def test_record_activity_remembers_which_collector_saw_a_mac(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    record_activity(conn, {"m": MacActivity(1, 1)}, 300, 10**9, 7 * 86400, "c1")
    record_activity(conn, {"m": MacActivity(1, 1)}, 300, 10**9, 7 * 86400, "c2")
    record_activity(conn, {"m": MacActivity(1, 1)}, 300, 10**9, 7 * 86400, "c1")
    got = conn.execute(
        "SELECT collector_id FROM mac_collectors WHERE mac='m' ORDER BY 1"
    ).fetchall()
    assert [r[0] for r in got] == ["c1", "c2"]


def test_overlapping_gaps_of_a_collector_are_merged_into_one_row(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    rec = 10**9

    def late(collector, stamps, received):
        act = MacActivity(min(stamps), max(stamps), stamps=set(stamps))
        record_activity(conn, {"m": act}, 300, received, 7 * 86400, collector)

    late("c1", {rec - 9000}, rec)  # gap [rec-9000, rec-3600]
    late("c1", {rec - 6000}, rec + 100)  # inside/overlapping: merges
    only = conn.execute(
        "SELECT start, \"end\" FROM collector_gaps WHERE collector_id='c1'"
    ).fetchall()
    assert [tuple(r) for r in only] == [(rec - 9000, rec - 3500)]  # both extents kept
    late("c1", {rec - 20000}, rec + 200)  # extends it backwards
    late("c2", {rec - 6000}, rec)  # another collector: its own row
    rows = conn.execute(
        'SELECT collector_id, start, "end" FROM collector_gaps ORDER BY 1, 2'
    ).fetchall()
    assert [tuple(r) for r in rows] == [
        ("c1", rec - 20000, rec + 200 - 3600),
        ("c2", rec - 6000, rec - 3600),
    ]
    late("c1", {rec + 450000}, rec + 500000)  # disjoint from the merged one: a second row
    assert (
        conn.execute("SELECT COUNT(*) FROM collector_gaps WHERE collector_id='c1'").fetchone()[0]
        == 2
    )


def test_load_gaps_merges_and_caps_per_collector(tmp_path, monkeypatch):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.executemany(
        'INSERT INTO collector_gaps (collector_id, start, "end", recorded) VALUES (?,?,?,0)',
        [("c", 10, 20), ("c", 15, 30), ("c", 100, 110), ("c", 200, 210), ("d", 1, 2)],
    )
    assert load_gaps(conn, 0) == {"c": [(10, 30), (100, 110), (200, 210)], "d": [(1, 2)]}
    assert load_gaps(conn, 105) == {"c": [(100, 110), (200, 210)]}
    monkeypatch.setattr("vigie_pipeline.activity.MAX_GAPS_PER_COLLECTOR", 2)
    assert load_gaps(conn, 0)["c"] == [(100, 110), (200, 210)]  # the newest two
    ticks = []
    load_gaps(conn, 0, lambda: ticks.append(1))
    assert ticks == [1]


def late_victim_world(data, gap_collector: str):
    ov, dev = seeded_d(data, 300)
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + 2000, collector="rtr-2", received=T0 + 2000, leases=lease,
                   sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + t) for t in range(1000, 2001, 60)])  # fmt: skip
    data.add_batch(T0 + 5400, collector=gap_collector, received=T0 + 5400,
                   dns=[(mac(1), T0 + t) for t in range(300, 5401, 60)])  # fmt: skip
    return ov, b


def test_a_deferred_attach_names_the_collector_once_a_day(data):
    ov, b = late_victim_world(data, "rtr-1")
    run_at(data, T0 + 6000)
    run_at(data, T0 + 6100)
    events = kinds(data, "evidence_gap")
    assert len(events) == 1 and "rtr-1" in events[0]["summary"]
    assert source_of(data, b) == "self"
    run_at(data, T0 + 6000 + 86400)
    assert len(kinds(data, "evidence_gap")) == 2
    ov.close()


def test_a_gap_of_a_collector_that_saw_neither_side_does_not_block(data):
    ov, dev = seeded_d(data, 300)
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + 2000, collector="rtr-2", received=T0 + 2000, leases=lease,
                   sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + t) for t in range(1000, 2001, 60)])  # fmt: skip
    data.add_batch(T0 + 5400, collector="rtr-1", received=T0 + 5400,
                   dns=[(mac(1), T0 + t) for t in range(1800, 5401, 60)])  # fmt: skip
    data.inv.execute(
        'INSERT INTO collector_gaps (collector_id, start, "end", recorded) VALUES (?,?,?,0)',
        ("rtr-9", T0, T0 + 6000),
    )
    run_at(data, T0 + 6000)
    assert source_of(data, b) == "rule" and kinds(data, "evidence_gap") == []
    ov.close()


def test_the_gap_lookup_binary_searches_the_merged_gaps(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 2000, NOW - 1000)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    lo, hi = st.act[m][0][0], st.act[m][-1][1]
    starts = [lo - 5000 + 10 * i for i in range(400)]
    st._gap_index = {"c": (starts, [x + 5 for x in starts])}  # 2000 disjoint gaps before the window
    st.mac_collectors = {m: frozenset({"c"})}
    assert st._gap_collectors(m) == []
    st._gap_index = {"c": (starts + [hi - 1], [x + 5 for x in starts] + [hi + 5])}
    assert st._gap_collectors(m) == ["c"]


# ---- legacy anchors keep their activity as evidence ----


def legacy_world(inv: Inv, legacy_victim: bool):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 170000, NOW - 7200)], rand=0)
    inv.db.execute(
        "INSERT OR REPLACE INTO mac_first_received (mac, received, legacy) VALUES"
        " ((SELECT mac FROM observations WHERE device_id='D'), ?, ?)",
        (NOW - 50, int(legacy_victim)),
    )
    a = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW - 90000, NOW - 80000)])
    inv.db.execute("UPDATE mac_first_received SET received=? WHERE mac=?", (NOW - 95000, a))
    return a


def test_a_legacy_victims_old_activity_still_vetoes_a_twin(inv):
    a = legacy_world(inv, legacy_victim=True)
    st = inv.stitch(RULE_SNAP)
    assert st.attached == 0 and link_of(inv, a) == ("A", "self")
    assert ("D", "vetoed") in inv.state("A")


def test_without_the_legacy_mark_the_clipped_activity_lets_the_twin_attach(inv):
    a = legacy_world(inv, legacy_victim=False)
    assert inv.stitch(RULE_SNAP).attached == 1 and link_of(inv, a) == ("D", "rule")


def test_a_legacy_macs_own_covered_time_counts_only_after_its_anchor(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(NOW - 170000, NOW - 7200), (NOW - 400, NOW)])
    inv.db.execute("UPDATE mac_first_received SET legacy=1, received=? WHERE mac=?", (NOW - 100, m))
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    assert len(st.act[m]) == 2 and m in st.legacy
    horizon = NOW - 100 - 3600
    assert horizon < NOW - 400
    assert st.covered(m) == 400  # only the recent interval counts; the 2-day-old one is evidence
    assert st.mature(m) is False


# ---- a malformed rule makes its target a human decision ----


def test_a_malformed_rule_on_a_target_turns_a_valid_attach_into_a_suggestion(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"D"}))
    st = inv.stitch(snap)
    assert st.attached == 0 and link_of(inv, a) == ("A", "self") and st.suggestions == 1
    reason = inv.db.execute("SELECT reason_code FROM suggestions").fetchone()[0]
    assert reason == "rule_hit_needs_confirm"


def test_a_malformed_rule_on_another_device_changes_nothing(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    snap = Snapshot({}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"Z"}))
    assert inv.stitch(snap).attached == 1 and link_of(inv, a) == ("D", "rule")


def test_a_malformed_target_is_matched_through_merges(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 3000, NOW)])
    inv.mac("E", "elsewhere", None, "self", OLD, [], rand=0)
    snap = Snapshot(
        {"E": "D"}, RULE_SNAP.rules, {"iot": 1}, {"D": (1, "iot")}, {}, 1, frozenset({"E"})
    )  # the malformed rule sits on E, which is merged into D
    assert inv.stitch(snap).attached == 0 and link_of(inv, a) == ("A", "self")


@pytest.mark.parametrize("raw", ["not json", '"a string"', "[1, 2]", "42", "null", ""])
def test_a_signature_that_is_not_a_json_object_is_malformed_and_names_its_target(tmp_path, raw):
    ov = Overrides(tmp_path)
    ov.conn.execute(
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('r','D',?,'t','owner')", (raw,),
    )  # fmt: skip
    ov.conn.commit()
    conn = open_overrides_ro(tmp_path / "overrides.db")
    snap = load_snapshot(conn, NOW)
    assert snap.rules == () and snap.malformed_rules == 1 and snap.malformed_devices == {"D"}


def test_a_wrong_typed_field_also_names_its_target(tmp_path):
    snap = snapshot_with(tmp_path, {**BASE, "mdns_name": {"x": 1}})
    assert snap.malformed_rules == 1 and snap.malformed_devices == {"D"}


# ---- orphan suggestions in both directions ----


def test_suggestions_pointing_into_the_orphan_are_expired_too(inv):
    a = attach_unit(inv)
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','X','A',0.9,'{}','suggested','t')"
    )
    suggestion(inv, "into", ["X", "A"], NOW + 10**6)
    suggestion(inv, "from", ["A", "Y"], NOW + 10**6)
    suggestion(inv, "other", ["X", "Q"], NOW + 10**6)
    inv.db.commit()
    assert inv.stitch(RULE_SNAP).attached == 1, a
    rows = dict(inv.db.execute("SELECT id, expires_at FROM suggestions").fetchall())
    assert rows["into"] < iso_utc(NOW) and rows["from"] < iso_utc(NOW)
    assert rows["other"] == iso_utc(NOW + 10**6)


def test_a_decided_suggestion_into_the_orphan_is_kept(inv):
    attach_unit(inv)
    inv.db.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','X','A',0.9,'{}','suggested','t')"
    )
    suggestion(inv, "into", ["X", "A"], NOW + 10**6)
    inv.db.commit()
    snap = Snapshot({}, (), {}, {}, {"into": "rejected"})
    assert withdraw_orphan_suggestions(inv.db, snap, "A", NOW) == 0


# ---- survivors: time check, cache reset, retention filter, component boundary ----


def test_the_device_lookup_of_active_macs_checks_the_time(inv):
    inv.mac("D", "h", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    st = Stitcher(inv.db, EMPTY_SNAP, inv.cfg, NOW)
    st.deadline = 0.0
    with pytest.raises(BudgetExhaustedError):
        st._device_ids_of(["x"])
    assert st._device_ids_of([]) == set()  # nothing to look up: no check


def test_an_attach_resets_the_cached_interval_union_of_its_target(inv):
    a = attach_unit(inv)
    st = Stitcher(inv.db, RULE_SNAP, inv.cfg, NOW)
    before = list(st._canon_union("D"))
    assert all(iv[1] < NOW - 1000 for iv in before)  # D alone: old activity only
    st._attach(st.by_mac[a], "D", RULE_SNAP.rules[0], 1.0, [RULE_SNAP.rules[0]])
    after = st._canon_union("D")
    assert (
        after != before and after[-1][1] >= NOW
    )  # now includes the attached MAC's recent activity


def test_the_per_mac_query_drops_intervals_before_the_retention_cutoff(inv):
    m = inv.mac("D", "h", None, "self", OLD, [(100, 110), (1000, 1010)])
    inv.db.execute("INSERT OR REPLACE INTO mac_first_received (mac, received) VALUES (?, 0)", (m,))
    inv.db.commit()
    got = load_activity(inv.db, 0, per_mac_limit=64, min_end=500, macs=[m])
    assert got == {m: [(1000, 1010)]}
    assert load_activity(inv.db, 0, per_mac_limit=64, min_end=0, macs=[m])[m] == [
        (100, 110),
        (1000, 1010),
    ]


def test_the_oversize_boundary_is_exact(inv, monkeypatch):
    inv.mac("A", "victim", None, "self", OLD, [(NOW - 100, NOW)])
    inv.db.commit()
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 3)
    links = {"a1": "A", "a2": "A", "b1": "T", "b2": "T", "b3": "T"}  # |A side|=3, |T side|=4
    st = Stitcher(inv.db, Snapshot(links, (), {}, {}, {}), inv.cfg, NOW)
    me = next(o for o in st.obs if o.device_id == "A")
    assert len(st.alias_ids("A")) == 3 and len(st.alias_ids("T")) == 4
    assert st._vetoed(me, "T") is False  # the smaller side is exactly at the limit: decided
    monkeypatch.setattr(stitch_mod, "MAX_ALIAS_IDS", 2)
    assert st._vetoed(me, "T") is True  # one over: deferred


def test_a_gap_on_the_candidates_own_collector_is_reported_as_well(data):
    ov, dev = seeded_d(data, 300)
    b = mac(2)
    lease = [(b, "Daves-Phone", "[1,121,3,6,15,119,252]", "android-dhcp-14")]
    data.add_batch(T0 + 5400, collector="rtr-2", received=T0 + 5400, leases=lease,
                   sightings=[(b, "mdns", "Daves Phone")],
                   dns=[(b, T0 + t) for t in range(1000, 5401, 60)])  # fmt: skip
    run_at(data, T0 + 6500)
    assert source_of(data, b) == "self" and len(kinds(data, "evidence_gap")) == 1
    assert "rtr-2" in kinds(data, "evidence_gap")[0]["summary"]
    ov.close()


def test_a_victims_collector_gap_keeps_a_sustained_overlap_provisional(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 20000, NOW)], rand=0)
    a = inv.mac("A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW - 5000, NOW)])
    inv.db.execute("INSERT INTO mac_collectors (mac, collector_id) VALUES (?, 'c2')", (a,))
    d_mac = inv.db.execute("SELECT mac FROM observations WHERE device_id='D'").fetchone()[0]
    inv.db.execute("INSERT INTO mac_collectors (mac, collector_id) VALUES (?, 'c1')", (d_mac,))
    inv.db.execute(
        'INSERT INTO collector_gaps (collector_id, start, "end", recorded) VALUES (?,?,?,0)',
        ("c1", NOW - 8000, NOW - 3000),
    )
    st = inv.stitch(EMPTY_SNAP)
    assert inv.state("A") == [("D", "open")] and st.vetoed == 0  # the victim's evidence is missing
    inv.db.execute("DELETE FROM collector_gaps")
    inv.db.execute("DELETE FROM identity_candidates")
    assert inv.stitch(EMPTY_SNAP).vetoed == 1 and inv.state("A") == [("D", "vetoed")]


def test_the_core_loads_the_newest_peers_of_an_attachments_name(inv, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_SIGNATURE_BUCKET", 2)  # the limit is 3 devices
    inv.mac("D", "victim", None, "self", OLD, [(NOW - 90000, NOW - 80000)], rand=0)
    a = inv.mac("D", "victim", None, "rule", "2026-01-02T00:00:00Z", [(NOW - 100, NOW)],
                newdev=False)  # fmt: skip
    inv.db.execute(
        "INSERT INTO rule_attachments (mac, rule_id, target, hostname, mdns_name, attached_at,"
        " opt55, opt60) VALUES (?, 'r', 'D', 'victim', NULL, 't', '1,2,3', 'x')", (a,)
    )  # fmt: skip
    for i in range(6):
        inv.mac(f"P{i}", "victim", None, "self", f"2026-02-0{i + 1}T00:00:00Z", [])
    inv.db.commit()
    tick_clock_none = Stitcher.__new__(Stitcher)
    tick_clock_none.inv = inv.db
    assert tick_clock_none._newest_devices("1,2,3", "x", "hostname", "victim") == {"P3", "P4", "P5"}
