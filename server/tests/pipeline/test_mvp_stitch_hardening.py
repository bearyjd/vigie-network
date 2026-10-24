"""Regressions for post-merge identity hardening, at real SQLite seams."""

import json
import sqlite3
from dataclasses import replace

import pytest
from stitch_helpers import NOW_ABS, OLD, RULE_SNAP, Inv

from vigie_pipeline import activity, stitch_types
from vigie_pipeline.activity import purge_activity, record_activity
from vigie_pipeline.schema import apply_pipeline_migrations, open_pipeline_inventory
from vigie_pipeline.snapshot import EMPTY
from vigie_pipeline.sources import MacActivity
from vigie_pipeline.stitch_apply import apply_plan
from vigie_pipeline.stitch_compute import compute_plan
from vigie_pipeline.stitch_db import veto_generation
from vigie_pipeline.stitch_types import Attach, Suggest, Veto, fold, short_hash


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("expired_rows_pending", [False, True])
def test_returning_mac_anchor_is_validated_before_fresh_activity(
    tmp_path, monkeypatch, retained, expired_rows_pending
):
    db = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    monkeypatch.setattr(activity, "PRUNE_BATCH_ROWS", 1)
    now, retention = NOW_ABS, 86400
    db.executemany(
        "INSERT INTO mac_first_received VALUES (?,?)",
        [("a", now - 3 * retention), ("z", now - 2 * retention)],
    )
    db.execute(
        "INSERT INTO mac_activity VALUES (?,?,?)",
        (
            "z",
            now - retention if retained else now - 2 * retention,
            now - retention if retained else now - 2 * retention,
        ),
    )
    if expired_rows_pending:
        db.execute(
            "INSERT INTO mac_activity VALUES (?,?,?)",
            ("a", now - 3 * retention, now - 3 * retention),
        )
    purge_activity(db, now, retention)
    assert db.execute("SELECT received FROM mac_first_received WHERE mac='z'").fetchone()
    record_activity(
        db, {"z": MacActivity(now - 600, now, stamps={now - 600, now})}, 300, now, retention
    )
    anchor = db.execute("SELECT received FROM mac_first_received WHERE mac='z'").fetchone()[0]
    assert anchor == (now - 2 * retention if retained else now)
    db.close()


def test_merged_alias_veto_inserted_after_compute_blocks_attach(tmp_path):
    inv = Inv(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    m = inv.mac(
        "A", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 4000)]
    )
    snap = replace(RULE_SNAP, links={"alias": "D"})
    inv.commit()
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    assert any(isinstance(d, Attach) and d.mac == m for d in plan.decisions)
    with sqlite3.connect(tmp_path / "inventory.db") as writer:
        writer.execute(
            "INSERT INTO identity_candidates"
            " (id,device_a,device_b,score,evidence,state,created_at)"
            " VALUES ('race','A','alias',1,'{}','vetoed','t')"
        )
    stats = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert stats.attached == 0
    assert inv.link_of(m) == ("A", "self")
    inv.db.close()


@pytest.mark.parametrize("name_field", ["hostname", "mdns_name"])
def test_suggestion_hashes_use_equivalent_name_fold(tmp_path, name_field):
    inv = Inv(tmp_path)
    old_names = ("Straße", None) if name_field == "hostname" else (None, "Straße")
    new_names = ("ＳＴＲＡＳＳＥ", None) if name_field == "hostname" else (None, "ＳＴＲＡＳＳＥ")
    inv.mac("D", *old_names, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("A", *new_names, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 4000)])
    assert inv.stitch(EMPTY).suggestions == 1
    row = inv.db.execute("SELECT payload FROM suggestions").fetchone()
    summary = json.loads(row[0])["evidence_summary"]
    assert summary["hashes"][name_field] == short_hash("strasse")
    assert summary["hashes"]["opt55"] == short_hash("1,2,3")
    inv.db.close()


def test_fold_exhaustion_cannot_persist_unchecked_key(tmp_path, monkeypatch):
    inv = Inv(tmp_path)
    monkeypatch.setattr(stitch_types.unicodedata, "normalize", lambda _form, value: value + "x")
    with pytest.raises(ValueError, match="converg"):
        inv.db.execute("INSERT INTO pipeline_meta VALUES ('bad-fold',?)", (fold("name"),))
    assert inv.db.execute("SELECT value FROM pipeline_meta WHERE key='bad-fold'").fetchone() is None
    inv.db.close()


def test_veto_stamp_tracks_all_mutations_but_not_unrelated_candidates(tmp_path):
    inv = Inv(tmp_path)
    inv.commit()
    assert veto_generation(inv.db) == 0
    inv.db.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('c','A','B',1,'{}','open','t')"
    )
    assert veto_generation(inv.db) == 0
    inv.db.execute("UPDATE identity_candidates SET state='vetoed' WHERE id='c'")
    assert veto_generation(inv.db) == 1
    inv.db.execute("BEGIN")
    inv.db.execute("UPDATE identity_candidates SET device_b='C' WHERE id='c'")
    assert veto_generation(inv.db) == 2
    inv.db.execute("ROLLBACK")
    assert veto_generation(inv.db) == 1
    apply_pipeline_migrations(inv.db)
    assert veto_generation(inv.db) == 1
    inv.db.execute("UPDATE identity_candidates SET device_b='C' WHERE id='c'")
    assert veto_generation(inv.db) == 2
    inv.db.execute("DELETE FROM identity_candidates WHERE id='c'")
    assert veto_generation(inv.db) == 3
    inv.db.close()


def test_recent_server_receipt_survives_until_usable_activity_arrives(tmp_path):
    db = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    first, now = NOW_ABS - 1200, NOW_ABS
    # A MAC can first reach the server in a batch whose row stamps are not usable.
    record_activity(
        db,
        {"recent": MacActivity(first - 7200, first - 7200, stamps={first - 7200})},
        300,
        first,
        86400,
    )
    assert db.execute("SELECT 1 FROM mac_activity WHERE mac='recent'").fetchone() is None
    record_activity(
        db, {"recent": MacActivity(now - 600, now, stamps={now - 600, now})}, 300, now, 86400
    )
    assert (
        db.execute("SELECT received FROM mac_first_received WHERE mac='recent'").fetchone()[0]
        == first
    )
    db.close()


@pytest.mark.parametrize("rule", [False, True])
def test_planned_veto_does_not_cancel_unrelated_safe_decision(tmp_path, rule):
    inv = Inv(tmp_path)
    inv.mac("D", "victim", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    inv.mac("X", "other", None, "self", OLD, [(NOW_ABS - 10000, NOW_ABS)], rand=0)
    inv.mac("B", "other", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 6000, NOW_ABS)])
    returning = inv.mac(
        "A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 60000, NOW_ABS - 4000)]
    )
    snap = RULE_SNAP if rule else EMPTY
    inv.commit()
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    actions = [d for d in plan.decisions if isinstance(d, (Veto, Attach, Suggest))]
    assert isinstance(actions[0], Veto)
    assert any(isinstance(d, Attach if rule else Suggest) and d.mac == returning for d in actions)
    stats = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert stats.vetoed == 1
    assert (stats.attached if rule else stats.suggestions) == 1
    assert inv.link_of(returning) == (("D", "rule") if rule else ("A", "self"))
    inv.db.close()


@pytest.mark.parametrize("reverse_order", [False, True])
@pytest.mark.parametrize("auto_inherit", [False, True])
def test_computed_reverse_pair_veto_blocks_same_plan_attach_or_suggestion(
    tmp_path, reverse_order, auto_inherit
):
    inv = Inv(tmp_path)
    inv.mac(
        "B", "victim", None, "self", "2026-01-02T00:00:00Z", [(NOW_ABS - 10000, NOW_ABS - 9399)]
    )
    a = inv.mac("A", "victim", None, "self", OLD, [(NOW_ABS - 9899, NOW_ABS - 7899)])
    snap = replace(
        RULE_SNAP,
        rules=(replace(RULE_SNAP.rules[0], device_id="B"),),
        overrides={"B": (1, "iot")},
        group_auto_inherit={"iot": int(auto_inherit)},
    )
    inv.commit()
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    assert any(
        isinstance(d, Veto) and (d.from_device, d.into) == ("B", "A") for d in plan.decisions
    )
    assert any(
        isinstance(d, Attach if auto_inherit else Suggest) and d.mac == a for d in plan.decisions
    )
    if reverse_order:
        plan = replace(plan, decisions=tuple(reversed(plan.decisions)))
    stats = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, None, plan)
    assert stats.vetoed == 1
    assert stats.attached == stats.suggestions == 0
    assert inv.link_of(a) == ("A", "self")
    assert (
        inv.db.execute(
            "SELECT state FROM identity_candidates WHERE device_a='B' AND device_b='A'"
        ).fetchone()[0]
        == "vetoed"
    )
    again = inv.stitch(snap)
    assert again.attached == again.suggestions == 0
    assert inv.link_of(a) == ("A", "self")
    inv.db.close()
