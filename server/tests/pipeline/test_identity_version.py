"""Identity-only invalidation and the SQL write-path coverage contract."""

from __future__ import annotations

import ast
import re
import sqlite3
from pathlib import Path

import pytest
from stitch_helpers import NOW_ABS, OLD, Overrides, inv  # noqa: F401

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.snapshot import OverridesUnreadable, load_snapshot
from vigie_pipeline.stitch_apply import apply_plan
from vigie_pipeline.stitch_compute import compute_plan


def world(tmp_path):
    ov = Overrides(tmp_path)
    ov.rule("r1", "D", {"opt55": "1,2,3", "opt60": "x", "hostname": "victim"})
    ov.override("D", "iot")
    ov.link("X", "Y")
    ov.decide("s", "accepted")
    ov.conn.execute(
        "INSERT INTO candidate_decisions VALUES ('c','A','D','clear_veto','u','t','c1')"
    )
    return ov, open_overrides_ro(ov.path)


def version(conn):
    return conn.execute("SELECT version FROM identity_version WHERE singleton=1").fetchone()[0]


RELEVANT = [
    "INSERT INTO identity_rules VALUES ('r2','Z','{}','t','u',NULL,NULL)",
    "UPDATE identity_rules SET revoked_at='t' WHERE id='r1'",
    "UPDATE identity_rules SET expires_at='t' WHERE id='r1'",
    "UPDATE identity_rules SET signature='{}' WHERE id='r1'",
    "DELETE FROM identity_rules WHERE id='r1'",
    "INSERT INTO identity_links VALUES ('Z','D','m','t','u',NULL)",
    "UPDATE identity_links SET into_device='D' WHERE from_device='X'",
    "UPDATE identity_links SET revoked_at='t' WHERE from_device='X'",
    "DELETE FROM identity_links WHERE from_device='X'",
    "INSERT INTO suggestion_decisions VALUES ('s2','rejected','u','t',NULL)",
    "UPDATE suggestion_decisions SET state='rejected' WHERE suggestion_id='s'",
    "DELETE FROM suggestion_decisions WHERE suggestion_id='s'",
    "INSERT INTO candidate_decisions VALUES ('c2','B','D','clear_veto','u','t','c2')",
    "UPDATE candidate_decisions SET id='c3' WHERE candidate_id='c'",
    "DELETE FROM candidate_decisions WHERE candidate_id='c'",
    "INSERT INTO device_overrides (device_id,group_id,updated_at,updated_by)"
    " VALUES ('Z','guest','t','u')",
    "UPDATE device_overrides SET group_id='guest' WHERE device_id='D'",
    "UPDATE groups SET auto_inherit=0 WHERE id='iot'",
    "INSERT INTO groups VALUES ('new','New',NULL,1)",
    "DELETE FROM groups WHERE id='kids'",
]
IRRELEVANT = [
    "INSERT INTO audit_log (id,ts,principal,action) VALUES ('a','t','u','test')",
    "INSERT INTO api_tokens VALUES ('t','hash','admin',0)",
    "UPDATE groups SET name='renamed',enforcement_ref='x' WHERE id='iot'",
    "UPDATE device_overrides SET name='label',owner='u',type='phone',version=version+1,"
    " updated_at='new' WHERE device_id='D'",
    "INSERT INTO device_overrides (device_id,name,updated_at,updated_by)"
    " VALUES ('Z','label','t','u')",
    "UPDATE device_overrides SET group_id=group_id WHERE device_id='D'",
    "UPDATE identity_rules SET created_at='new' WHERE id='r1'",
    "UPDATE identity_links SET merge_id='new',created_at='new',created_by='other'",
    "UPDATE suggestion_decisions SET decided_by='other',decided_at='new',applied='{}'",
    "INSERT INTO api_write_receipts VALUES ('q','f','{}')",
]


@pytest.mark.parametrize("change", RELEVANT + IRRELEVANT)
def test_concurrent_write_invalidates_exactly_identity_inputs(inv, tmp_path, change):
    ov, ro = world(tmp_path)
    inv.mac("D", "old", None, "self", OLD, [(NOW_ABS - 90000, NOW_ABS - 80000)], rand=0)
    mac = inv.mac("A", "victim", None, "self", "2026-01-03T00:00:00Z", [(NOW_ABS - 3000, NOW_ABS)])
    inv.commit()
    snap = load_snapshot(ro, NOW_ABS)
    plan = compute_plan(inv.db, snap, inv.cfg, NOW_ABS)
    ov.conn.execute(change)
    stats = apply_plan(inv.db, snap, inv.cfg, NOW_ABS, lambda: NOW_ABS, ro, plan)
    relevant = change in RELEVANT
    assert stats.attached == (0 if relevant else 1)
    assert stats.stale == (1 if relevant else 0)
    assert inv.link_of(mac) == (("A", "self") if relevant else ("D", "rule"))
    assert version(ov.conn) == snap.identity_version + (1 if relevant else 0)
    ro.close()
    ov.close()


def test_version_bump_is_transactional(tmp_path):
    ov, ro = world(tmp_path)
    before = version(ov.conn)
    ov.conn.execute("BEGIN IMMEDIATE")
    ov.conn.execute("UPDATE identity_rules SET revoked_at='t'")
    assert version(ov.conn) == before + 1
    assert load_snapshot(ro, NOW_ABS).identity_version == before
    ov.conn.execute("ROLLBACK")
    assert version(ov.conn) == before
    ro.close()
    ov.close()


@pytest.mark.parametrize("upgrade", [False, True])
def test_identity_version_migration_is_idempotent(tmp_path, upgrade):
    path = tmp_path / "overrides.db"
    if upgrade:
        conn = sqlite3.connect(path)
        for migration in OVERRIDES_MIGRATIONS[:4]:
            for sql in migration:
                conn.execute(sql)
        conn.execute("PRAGMA user_version=4")
        conn.commit()
        conn.close()
    conn = open_overrides(path)
    assert [tuple(row) for row in conn.execute("SELECT * FROM identity_version")] == [(1, 0)]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO identity_version VALUES (2,0)")
    conn.close()
    conn = open_overrides(path)
    assert version(conn) == 0
    assert conn.execute("SELECT COUNT(*) FROM identity_version").fetchone()[0] == 1
    conn.close()


def test_snapshot_stamp_uses_the_same_read_transaction(tmp_path):
    ov, ro = world(tmp_path)
    start = version(ov.conn)
    wrote = False

    def concurrent(sql):
        nonlocal wrote
        if "FROM identity_rules" in sql and not wrote:
            wrote = True
            ov.conn.execute("UPDATE groups SET auto_inherit=0 WHERE id='iot'")

    ro.set_trace_callback(concurrent)
    snap = load_snapshot(ro, NOW_ABS)
    assert wrote and snap.group_auto_inherit["iot"] == 1
    assert snap.identity_version == start
    assert load_snapshot(ro, NOW_ABS).identity_version == start + 1
    ro.close()
    ov.close()


def test_malformed_version_table_never_falls_back(tmp_path):
    ov, ro = world(tmp_path)
    ov.conn.execute("DROP TABLE identity_version")
    ov.conn.execute("CREATE TABLE identity_version (singleton, version)")
    ov.conn.execute("INSERT INTO identity_version VALUES (1,'bad')")
    with pytest.raises(OverridesUnreadable):
        load_snapshot(ro, NOW_ABS)
    ro.close()
    ov.close()


def test_legacy_missing_table_uses_coarse_fallback(tmp_path):
    ov, ro = world(tmp_path)
    ov.conn.execute("DROP TABLE identity_version")
    snap = load_snapshot(ro, NOW_ABS)
    assert snap.identity_version is None and isinstance(snap.data_version, int)
    ov.conn.execute("INSERT INTO audit_log (id,ts,principal,action) VALUES ('a','t','u','test')")
    assert load_snapshot(ro, NOW_ABS).data_version != snap.data_version
    ro.close()
    ov.close()


# New SQL paths require an explicit review, even if their table was already classified.
WRITE_PATHS = {
    "writes.py": [
        ("_apply", "INSERT", "device_overrides"),
        ("_apply", "UPDATE", "device_overrides"),
        ("_audit", "INSERT", "audit_log"),
    ],
    "evidence_writes.py": [("record_export", "INSERT", "audit_log")],
    "dataset_writes.py": [
        ("stage", "INSERT", "dataset_imports"),
        ("stage", "INSERT", "dataset_entries_staging"),
        ("stage", "INSERT", "audit_log"),
        ("_decide", "INSERT", "audit_log"),
        ("accept.apply", "UPDATE", "dataset_imports"),
        ("accept.apply", "UPDATE", "dataset_imports"),
        ("reject.apply", "UPDATE", "dataset_imports"),
    ],
    "identity_writes.py": [
        ("atomic", "INSERT", "audit_log"),
        ("atomic", "INSERT", "api_write_receipts"),
        ("decide.operation", "UPDATE", "identity_links"),
        ("decide.operation", "INSERT", "identity_links"),
        ("decide.operation", "INSERT", "identity_merges"),
        ("decide.operation", "INSERT", "identity_rules"),
        ("decide.operation", "UPDATE", "identity_merges"),
        ("decide.operation", "INSERT", "suggestion_decisions"),
        ("undo.operation", "UPDATE", "identity_rules"),
        ("undo.operation", "UPDATE", "identity_links"),
        ("undo.operation", "UPDATE", "identity_links"),
        ("undo.operation", "UPDATE", "identity_merges"),
        ("create_rule.operation", "INSERT", "identity_rules"),
        ("revoke_rule.operation", "UPDATE", "identity_rules"),
        ("clear_veto.operation", "INSERT", "candidate_decisions"),
    ],
}
IRRELEVANT_WRITE_TABLES = {
    "audit_log": "audit history never changes attach authorization",
    "api_write_receipts": "idempotency receipt only",
    "identity_merges": "undo history; live identity is in links/rules/decisions",
    "dataset_imports": "staged threat data; nothing reads it for attach authorization",
    "dataset_entries_staging": "staged threat data; nothing reads it for attach authorization",
}
TRIGGERED_WRITE_TABLES = {
    "device_overrides",
    "identity_links",
    "identity_rules",
    "suggestion_decisions",
    "candidate_decisions",
}


def sql_paths(tree, scope=""):
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            yield from sql_paths(node, f"{scope}.{node.name}".lstrip("."))
            continue
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany", "executescript"}
            and node.args
        ):
            sql = node.args[0]
            if isinstance(sql, ast.Constant) and isinstance(sql.value, str):
                text = sql.value
            elif isinstance(sql, ast.JoinedStr):
                text = "".join(part.value for part in sql.values if isinstance(part, ast.Constant))
            else:
                pytest.fail(f"unclassified dynamic SQL in {scope}:{node.lineno}")
            match = re.match(
                r"\s*(INSERT(?: OR \w+)? INTO|UPDATE|DELETE FROM|REPLACE INTO)\s+(\w+)",
                text,
                re.I,
            )
            if match:
                yield scope, match[1].split()[0], match[2]
        yield from sql_paths(node, scope)


def test_every_writes_module_dml_path_has_version_policy(tmp_path):
    source = Path(__file__).parents[2] / "src" / "vigie_api"
    found = {}
    for path in source.glob("*writes*.py"):
        paths = list(sql_paths(ast.parse(path.read_text())))
        assert paths == WRITE_PATHS.get(path.name), path.name
        found[path.name] = paths
        for _, _, table in paths:
            assert table in TRIGGERED_WRITE_TABLES | IRRELEVANT_WRITE_TABLES.keys()
    assert found.keys() == WRITE_PATHS.keys()
    conn = open_overrides(tmp_path / "policy.db")
    triggered = {
        row[0]
        for row in conn.execute(
            "SELECT tbl_name FROM sqlite_master WHERE type='trigger'"
            " AND sql LIKE '%identity_version%'"
        )
    }
    assert TRIGGERED_WRITE_TABLES <= triggered
    conn.close()
