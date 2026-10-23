"""Human clear decisions are read-only inputs, consumed once by the inventory owner."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest
from stitch_helpers import NOW_ABS, OLD, RULE_SNAP, inv  # noqa: F401

from vigie_pipeline.config import MAX_ROWS_PER_PASS
from vigie_pipeline.overrides import canonical_device
from vigie_pipeline.snapshot import EMPTY, CandidateDecision, load_snapshot


def decision_snapshot(*, candidate="c1", a="A", b="D", decision="decision-1"):
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE candidate_decisions (candidate_id TEXT PRIMARY KEY, device_a TEXT,"
        " device_b TEXT, action TEXT, decided_by TEXT, decided_at TEXT, id TEXT UNIQUE)"
    )
    conn.execute(
        "INSERT INTO candidate_decisions VALUES (?,?,?,'clear_veto','owner','t',?)",
        (candidate, a, b, decision),
    )
    before = conn.total_changes
    conn.execute("PRAGMA query_only=ON")
    snapshot = load_snapshot(conn, NOW_ABS)
    assert conn.total_changes == before
    assert conn.execute("SELECT action FROM candidate_decisions").fetchone()[0] == "clear_veto"
    conn.close()
    return snapshot


def veto(inv):
    inv.db.execute(
        "INSERT INTO identity_candidates (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('c1','A','D',0.8,'{}','vetoed','t')"
    )


def state(inv):
    return inv.db.execute("SELECT state FROM identity_candidates WHERE id='c1'").fetchone()[0]


def test_clear_consumes_read_only_decision_without_attaching(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    subject = inv.mac(
        "A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)]
    )
    veto(inv)
    snap = decision_snapshot()
    stats = inv.stitch(snap)
    assert state(inv) == "dismissed"
    assert stats.attached == 0
    assert inv.link_of(subject) == ("A", "self")


@pytest.mark.parametrize("fields", [{"candidate": "other"}, {"a": "D", "b": "A"}])
def test_clear_requires_exact_candidate_and_ordered_pair(inv, fields):
    veto(inv)
    inv.stitch(decision_snapshot(**fields))
    assert state(inv) == "vetoed"


def test_consumed_clear_cannot_remove_a_later_veto(inv):
    veto(inv)
    snap = decision_snapshot()
    inv.stitch(snap)
    assert state(inv) == "dismissed"
    inv.db.execute("UPDATE identity_candidates SET state='vetoed'")
    inv.stitch(snap)
    assert state(inv) == "vetoed"
    inv.stitch(decision_snapshot(decision="decision-2"))
    assert state(inv) == "dismissed"


def test_mismatched_decision_cannot_clear_a_future_matching_veto(inv):
    veto(inv)
    snap = decision_snapshot(a="other")
    inv.stitch(snap)
    inv.db.execute("UPDATE identity_candidates SET device_a='other'")
    inv.stitch(snap)
    assert state(inv) == "vetoed"


def test_clear_work_is_bounded_and_remaining_decisions_progress_next_pass(inv):
    limit = MAX_ROWS_PER_PASS // 2
    decisions = []
    for number in range(limit + 1):
        candidate = f"candidate-{number}"
        a = f"A-{number}"
        inv.db.execute(
            "INSERT INTO identity_candidates (id,device_a,device_b,score,evidence,state,created_at)"
            " VALUES (?,?,'D',0.8,'{}','vetoed','t')",
            (candidate, a),
        )
        decisions.append(CandidateDecision(f"clear-{number}", candidate, a, "D"))
    snap = replace(EMPTY, candidate_decisions=tuple(decisions))
    inv.stitch(snap)
    assert (
        inv.db.execute(
            "SELECT COUNT(*) FROM identity_candidates WHERE state='dismissed'"
        ).fetchone()[0]
        == limit
    )
    inv.stitch(snap)
    assert (
        inv.db.execute("SELECT COUNT(*) FROM identity_candidates WHERE state='vetoed'").fetchone()[
            0
        ]
        == 0
    )


def test_clear_recomputes_evidence_before_rule_attach(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    subject = inv.mac(
        "A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)]
    )
    veto(inv)
    cleared = decision_snapshot()
    snap = replace(RULE_SNAP, candidate_decisions=cleared.candidate_decisions)
    assert inv.stitch(snap).attached == 1
    assert inv.link_of(subject) == ("D", "rule")


def test_clear_does_not_bypass_real_overlap(inv):
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 6000, NOW_ABS)], rand=0)
    subject = inv.mac(
        "A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)]
    )
    veto(inv)
    cleared = decision_snapshot()
    snap = replace(RULE_SNAP, candidate_decisions=cleared.candidate_decisions)
    assert inv.stitch(snap).attached == 0
    assert inv.link_of(subject) == ("A", "self")


@pytest.mark.parametrize("legacy", [False, True])
def test_identity_link_readers_ignore_revoked_links_and_support_legacy_schema(legacy):
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE identity_links (from_device TEXT, into_device TEXT)")
    conn.execute("INSERT INTO identity_links VALUES ('A','D')")
    if not legacy:
        conn.execute("ALTER TABLE identity_links ADD COLUMN revoked_at TEXT")
    assert canonical_device(conn, "A") == "D"
    assert load_snapshot(conn, NOW_ABS).canonical("A") == "D"
    if not legacy:
        conn.execute("UPDATE identity_links SET revoked_at='t'")
        assert canonical_device(conn, "A") == "A"
        assert load_snapshot(conn, NOW_ABS).canonical("A") == "A"
    conn.close()
