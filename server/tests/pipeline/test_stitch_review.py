"""Fix-round tests for the independent stitching review (H1-H3, M1-M4, L2-L3, T2, mutants)."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from datetime import UTC, datetime

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

from vigie_ingest.db import iso_utc
from vigie_pipeline import stitch as stitch_mod
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.snapshot import EMPTY, Rule, load_snapshot
from vigie_pipeline.stitch import Obs, Stitcher

RULE = "11111111-rule"


def seeded(
    data: Data, *, a_end: int = 300, group: str | None = "iot", rule_sig: dict | None = None
):
    a = appear(data, 1, 0, a_end)
    run(data)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule(RULE, dev, rule_sig or sig())
    if group is not None:
        ov.override(dev, group, version=3)
    return ov, dev


def source_of(data: Data, mac_addr: str) -> str:
    return data.q("SELECT link_source FROM observations WHERE mac=?", mac_addr)[0][0]


# ---- H1: overlap veto cannot be dodged by timing -----------------------------------------------


def test_loop_mode_passes_30s_apart_never_attach_a_fingerprint_copy(data):
    ov, _ = seeded(data, a_end=2400)
    for end in range(30, 1800, 30):  # the pipeline runs every 30 s while the copy stays online
        b = appear(data, 2, end - 30, end, step=10)
        run(data)
        assert source_of(data, b) == "self", f"attached at pass ending {end}"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_sparse_attacker_at_301s_is_vetoed_not_attached(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 0, 3010, step=301)  # one stamp per interval: zero-length intervals
    run(data)
    assert source_of(data, b) == "self"
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "identity_overlap_veto")) == 1
    ov.close()


def test_short_pulses_cannot_hide_below_the_gap(data):
    ov, _ = seeded(data, a_end=3100)
    b = appear(data, 2, 0, 10, step=5)
    for start in (301, 602, 903):
        b = appear(data, 2, start, start + 10, step=5)
    run(data)
    assert source_of(data, b) == "self"
    ov.close()


def test_young_mac_is_deferred_without_events_then_attaches(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 400)  # a single stamp: observed span below the grace window
    run(data)
    run(data)
    assert source_of(data, b) == "self"
    assert kinds(data, "identity_overlap_veto") == []
    assert kinds(data, "identity_candidate_ambiguous") == []
    assert kinds(data, "mac_attached") == []
    appear(data, 2, 400, 1200)  # now observed for longer than the grace window, no overlap
    run(data)
    assert device_of(data, b) == dev and source_of(data, b) == "rule"
    ov.close()


def test_span_exactly_at_grace_is_still_deferred(data):
    ov, _ = seeded(data)
    b = appear(data, 2, 400, 1000)  # span == 600 == grace
    run(data)
    assert source_of(data, b) == "self"
    ov.close()


# ---- H2: flood DoS -----------------------------------------------------------------------------


def flood_mac(n: int) -> str:
    return f"ae:00:00:00:{n >> 8:02x}:{n & 255:02x}"


def test_flood_of_one_signature_is_bounded_and_fast(data):
    n = 301
    macs = [flood_mac(i) for i in range(n)]
    data.add_batch(
        T0,
        leases=[(m, HOST, OPT55, OPT60) for m in macs],
        sightings=[(m, "mdns", MDNS) for m in macs],
        dns=[(m, T0 + i) for i, m in enumerate(macs)],
    )
    start = time.perf_counter()
    run(data)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, elapsed
    assert len(candidates(data)) == 0 and len(suggestions(data)) == 0
    assert len(kinds(data, "signature_flood")) == 1
    run(data)  # one event per signature per UTC day, not per pass
    assert len(kinds(data, "signature_flood")) == 1


def test_flooded_signature_never_rule_attaches(data):
    ov, _ = seeded(data)
    macs = [flood_mac(i + 10) for i in range(80)]
    data.add_batch(
        T0 + 400,
        leases=[(m, HOST, OPT55, OPT60) for m in macs],
        dns=[(m, T0 + 400 + t) for m in macs for t in (0, 700)],
    )
    run(data)
    assert kinds(data, "mac_attached") == []
    assert len(kinds(data, "signature_flood")) == 1
    ov.close()


def test_rows_written_per_pass_are_capped(data, monkeypatch):
    monkeypatch.setattr(stitch_mod, "MAX_ROWS_PER_PASS", 5)
    for i in range(20):  # twenty distinct signatures, each an old and a new MAC
        appear(data, 2 * i, 0, 60, opt55=f"[{i}]")
        appear(data, 2 * i + 1, 400, 460, opt55=f"[{i}]")
    run(data)
    assert len(candidates(data)) <= 5 and len(suggestions(data)) <= 5
    for _ in range(14):  # later passes keep making progress until everything is recorded
        run(data)
    assert len(suggestions(data)) == 20


def test_events_dedup_uses_an_indexed_column(data):
    appear(data, 1, 0, 300)
    run(data)
    cols = [r[1] for r in data.inv.execute("PRAGMA table_info(events)")]
    assert "dedup" in cols
    plan = " ".join(
        str(tuple(r))
        for r in data.inv.execute(
            "EXPLAIN QUERY PLAN SELECT 1 FROM events WHERE kind=? AND dedup=?", ("k", "t")
        )
    )
    assert "USING" in plan and "INDEX" in plan.upper()


# ---- H3 / G6: a named field that differs blocks the rule ---------------------------------------


def test_opt_match_but_hostname_differs_does_not_attach(data):
    ov, _ = seeded(data)
    b = appear(data, 2, 400, 1200, host="Someone-Elses-Phone")
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    ov.close()


def test_opt_match_but_mdns_name_differs_does_not_attach(data):
    ov, _ = seeded(data, rule_sig=sig(hostname=None, mdns_name=MDNS))
    b = appear(data, 2, 400, 1200, mdns="Other Name")
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    c = appear(data, 3, 1500, 2300)  # control (not beside b): a matching mDNS name does attach
    run(data)
    assert source_of(data, c) == "rule"
    ov.close()


# ---- M1: identity_state != ok never rule-attaches ----------------------------------------------


@pytest.mark.parametrize("state", ["conflict", "pending_confirm"])
def test_target_identity_state_not_ok_needs_confirmation(data, state):
    ov, dev = seeded(data)
    data.inv.execute("UPDATE devices SET identity_state=? WHERE id=?", (state, dev))
    b = appear(data, 2, 400, 1200)
    run(data)
    assert source_of(data, b) == "self"
    (s,) = suggestions(data)
    assert s["reason_code"] == "rule_hit_needs_confirm"
    ov.close()


def test_candidate_identity_state_conflict_needs_confirmation(data):
    appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 1200)
    run(data)  # no rule yet: a fingerprint suggestion only
    data.inv.execute(
        "UPDATE devices SET identity_state='conflict' WHERE id=?", (device_of(data, b),)
    )
    ov = Overrides(data.root)
    ov.rule(RULE, device_of(data, mac(1)), sig())
    run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    ov.close()


# ---- M2: a pair that becomes vetoed withdraws its open suggestion ------------------------------


def test_vetoed_pair_withdraws_the_open_suggestion(data):
    a = appear(data, 1, 0, 300)
    b = appear(data, 2, 400, 700)
    run(data)
    (s,) = suggestions(data)
    assert s["expires_at"] > iso_utc(NOW)
    appear(data, 1, 300, 1700)  # now they are provably concurrent for 1300 s
    appear(data, 2, 700, 1700)
    run(data)
    (s,) = suggestions(data)
    assert s["expires_at"] < iso_utc(NOW)
    assert candidates(data)[0]["state"] == "vetoed"
    assert (a, b) and len(suggestions(data)) == 1  # nothing new was created
    run(data)
    assert len(suggestions(data)) == 1


def test_decided_suggestion_is_not_withdrawn(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    (s,) = suggestions(data)
    ov = Overrides(data.root)
    ov.decide(s["id"], "accepted")
    appear(data, 1, 300, 1700)
    appear(data, 2, 700, 1700)
    run(data)
    assert suggestions(data)[0]["expires_at"] == s["expires_at"]
    ov.close()


def test_ambiguous_pair_withdraws_the_open_suggestion(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    run(data)
    assert len(suggestions(data)) == 1
    appear(data, 3, 0, 300)  # a second old device with the same signature, concurrent with 1
    appear(data, 1, 300, 1700)
    appear(data, 3, 300, 1700)
    run(data)
    assert all(s["expires_at"] < iso_utc(NOW) for s in suggestions(data))
    assert len(kinds(data, "identity_candidate_ambiguous")) >= 1


# ---- M3 / L3: snapshot hardening ---------------------------------------------------------------


def seeded_snapshot(tmp_path, **rule_kw):
    ov = Overrides(tmp_path)
    ov.rule("r1", "dev-1", sig(), **{k: v for k, v in rule_kw.items() if k != "created_by"})
    if "created_by" in rule_kw:
        ov.conn.execute("UPDATE identity_rules SET created_by=?", (rule_kw["created_by"],))
    ov.close()
    conn = open_overrides_ro(tmp_path / "overrides.db")
    assert conn is not None
    return conn


@pytest.mark.parametrize("who", ["", "   "])
def test_rule_without_a_creator_is_ignored(tmp_path, who):
    conn = seeded_snapshot(tmp_path, created_by=who)
    assert load_snapshot(conn, NOW).rules == ()


def test_rule_with_a_creator_is_active(tmp_path):
    conn = seeded_snapshot(tmp_path)
    assert len(load_snapshot(conn, NOW).rules) == 1


@pytest.mark.parametrize("revoked", ["", " ", "2026-10-02T00:00:00Z", "garbage"])
def test_any_non_null_revoked_at_is_revoked(tmp_path, revoked):
    conn = seeded_snapshot(tmp_path, revoked_at=revoked)
    assert load_snapshot(conn, NOW).rules == ()


@pytest.mark.parametrize("expires", ["", "   "])
def test_blank_expires_at_ignores_the_rule(tmp_path, expires):
    conn = seeded_snapshot(tmp_path, expires_at=expires)
    assert load_snapshot(conn, NOW).rules == ()


def test_expiry_boundary_is_exclusive(tmp_path):
    at = datetime(2026, 12, 1, tzinfo=UTC)
    conn = seeded_snapshot(tmp_path, expires_at=at.isoformat())
    assert len(load_snapshot(conn, at.timestamp() - 1).rules) == 1
    assert load_snapshot(conn, at.timestamp()).rules == ()


def raw_overrides(tmp_path, ddl: str, *inserts: str | tuple[str, str]):
    path = tmp_path / "overrides.db"
    conn = sqlite3.connect(path)
    conn.executescript(ddl)
    for stmt in inserts:
        conn.execute(*((stmt,) if isinstance(stmt, str) else (stmt[0], (stmt[1],))))
    conn.commit()
    conn.close()
    return open_overrides_ro(path)


RULES_DDL = (
    "CREATE TABLE identity_rules (id TEXT, device_id TEXT, signature TEXT, created_at TEXT,"
    " created_by TEXT, expires_at TEXT, revoked_at TEXT);"
)


def test_non_integer_auto_inherit_fails_closed(tmp_path):
    from vigie_pipeline.snapshot import OverridesUnreadable

    conn = raw_overrides(
        tmp_path,
        "CREATE TABLE groups (id, auto_inherit);",
        "INSERT INTO groups VALUES ('iot', 'yes')",
    )
    with pytest.raises(OverridesUnreadable):
        load_snapshot(conn, NOW)


def test_missing_columns_fail_closed(tmp_path):
    from vigie_pipeline.snapshot import OverridesUnreadable

    conn = raw_overrides(tmp_path, "CREATE TABLE identity_rules (id TEXT, device_id TEXT);")
    with pytest.raises(OverridesUnreadable):
        load_snapshot(conn, NOW)


def test_rules_without_device_overrides_table_fail_closed(tmp_path):
    from vigie_pipeline.snapshot import OverridesUnreadable

    row = (
        "INSERT INTO identity_rules VALUES ('r', 'd', ?, 't', 'o', NULL, NULL)",
        json.dumps(sig()),
    )
    conn = raw_overrides(tmp_path, RULES_DDL, row)
    with pytest.raises(OverridesUnreadable):
        load_snapshot(conn, NOW)


def test_missing_device_overrides_in_a_live_run_skips_stitching(data, caplog):
    ov, _ = seeded(data)
    ov.conn.execute("DROP TABLE device_overrides")
    b = appear(data, 2, 400, 1200)
    with caplog.at_level(logging.ERROR):
        run(data)
    assert source_of(data, b) == "self"
    assert "stitching_skipped" in caplog.text
    ov.close()


def test_snapshot_error_does_not_fall_back_to_empty(data):
    appear(data, 1, 0, 300)
    appear(data, 2, 400, 700)
    ov = Overrides(data.root)
    ov.conn.execute("DROP TABLE identity_rules")
    ov.conn.execute(
        "CREATE TABLE identity_rules (id TEXT PRIMARY KEY, device_id TEXT)"  # columns missing
    )
    run(data)
    assert suggestions(data) == [] and candidates(data) == []  # EMPTY would have suggested
    ov.close()


# ---- M4: one read transaction ------------------------------------------------------------------


def test_snapshot_reads_run_inside_one_transaction(tmp_path):
    conn = seeded_snapshot(tmp_path)
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    load_snapshot(conn, NOW)
    conn.set_trace_callback(None)
    assert seen[0].upper().startswith("BEGIN") and seen[-1].upper() == "COMMIT"
    assert sum(s.upper().startswith("SELECT") for s in seen) >= 5
    assert not conn.in_transaction


def test_failed_snapshot_leaves_no_open_transaction(tmp_path):
    from vigie_pipeline.snapshot import OverridesUnreadable

    conn = raw_overrides(tmp_path, "CREATE TABLE identity_rules (id TEXT);")
    with pytest.raises(OverridesUnreadable):
        load_snapshot(conn, NOW)
    assert not conn.in_transaction


# ---- L2: veto peers are the union over every matched rule --------------------------------------


def test_veto_peers_cover_every_matched_rule(data):
    a = appear(data, 1, 0, 300)
    run(data)
    ov = Overrides(data.root)
    dev = device_of(data, a)
    ov.rule("a-rule", dev, sig())  # hostname rule
    ov.rule("b-rule", dev, sig(hostname=None, mdns_name=MDNS))  # mDNS rule
    d = appear(data, 3, 0, 1500, host="Other-Host")  # matches only b-rule, long-lived
    b = appear(data, 2, 100, 1500)  # matches both; overlaps d for 1400 s
    run(data)
    assert source_of(data, b) == "self" and source_of(data, d) == "self"
    assert kinds(data, "mac_attached") == []
    ov.close()


# ---- T2: overrides.db is never modified --------------------------------------------------------


def test_overrides_db_bytes_unchanged_across_an_attaching_run(data):
    ov, dev = seeded(data)
    ov.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    path = ov.path
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    b = appear(data, 2, 400, 1200)
    run(data)
    assert device_of(data, b) == dev
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    ov.close()


# ---- mutants: each attach layer alone, missing target ------------------------------------------


def stitcher(data: Data) -> Stitcher:
    run(data)
    cfg = PipelineConfig(data_dir=data.root)
    return Stitcher(data.inv, EMPTY, cfg, NOW)


def obs(**kw) -> Obs:
    base = {
        "mac": mac(9),
        "device_id": "d1",
        "canon": "d1",
        "randomized": True,
        "source": "self",
        "opt55": "1",
        "opt60": "x",
        "hostname": "h",
        "mdns": None,
        "first_seen": "t",
    }
    return Obs(**{**base, **kw})


@pytest.mark.parametrize(
    "change",
    [{"source": "rule"}, {"source": "human"}, {"canon": "other"}, {"randomized": False},
     {"opt55": None}, {"opt60": None}, {"hostname": None, "mdns": None}],
)  # fmt: skip
def test_each_eligibility_layer_alone_blocks(data, change):
    appear(data, 9, 0, 300)
    st = stitcher(data)
    st.act[mac(9)] = [(0, 300)]
    assert st.eligible(obs()) is True
    assert st.eligible(obs(**change)) is False


def test_eligibility_requires_activity(data):
    appear(data, 9, 0, 300)
    st = stitcher(data)
    assert st.eligible(obs(mac=mac(40))) is False


def test_attach_never_moves_a_mac_that_is_not_a_self_link(data):
    ov, dev = seeded(data)
    b = appear(data, 2, 400, 1200)
    run(data)  # b is attached by the rule
    assert source_of(data, b) == "rule"
    st = stitcher(data)
    other = appear(data, 5, 0, 300, opt55="[7]")
    run(data)
    before = data.q("SELECT * FROM observations WHERE mac=?", b)[0]
    o = obs(mac=b, device_id=before["device_id"], canon=before["device_id"], source="rule")
    rule = Rule("r", device_of(data, other), OPT55, OPT60, HOST, None)
    st._attach(o, device_of(data, other), rule, 1.0, [rule])
    assert tuple(data.q("SELECT * FROM observations WHERE mac=?", b)[0]) == tuple(before)
    assert len(kinds(data, "mac_attached")) == 1
    ov.close()


def test_rule_pointing_at_a_missing_device_attaches_nothing(data, caplog):
    appear(data, 1, 0, 300)
    run(data)
    ov = Overrides(data.root)
    ov.rule(RULE, "no-such-device", sig())
    b = appear(data, 2, 400, 1200)
    with caplog.at_level(logging.WARNING):
        run(data)
    assert source_of(data, b) == "self" and kinds(data, "mac_attached") == []
    assert "rule_device_missing" in caplog.text
    ov.close()
