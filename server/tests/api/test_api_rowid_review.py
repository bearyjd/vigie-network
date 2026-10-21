"""Event paging cursors are rowids: rowids must never be reused, even after deleting the newest."""

from __future__ import annotations

from api_helpers import Env, env, ts  # noqa: F401


def test_audit_rowids_are_not_reused_after_deleting_the_newest_row(env: Env) -> None:
    def add(i: str) -> None:
        env.ov.execute(
            "INSERT INTO audit_log (id, ts, principal, action, target) VALUES (?,?,?,?,?)",
            (i, ts(), "app:test", "device.patch", "d1"),
        )

    add("a1")
    add("a2")
    cursor = env.get("/events").json()["page"]["next_cursor"]  # resume point = rowid 2
    env.ov.execute("DELETE FROM audit_log WHERE id='a2'")
    add("a3")  # must not be handed rowid 2 again, or the cursor would skip it
    assert [e["id"] for e in env.get("/events", since=cursor).json()["data"]] == ["a3"]


def test_inventory_events_have_a_monotonic_sequence(env: Env) -> None:
    ddl = env.inv.execute("SELECT sql FROM sqlite_master WHERE name='events'").fetchone()[0]
    assert "AUTOINCREMENT" in ddl.upper()


def test_migration_preserves_existing_audit_rowids(tmp_path) -> None:
    import sqlite3

    from vigie_api import schema

    path = tmp_path / "overrides.db"
    conn = sqlite3.connect(path, isolation_level=None)
    for migration in schema.OVERRIDES_MIGRATIONS[:2]:
        for statement in migration:
            conn.execute(statement)
    conn.execute("PRAGMA user_version=2")
    for i, rid in enumerate((5, 9)):
        conn.execute(
            "INSERT INTO audit_log (rowid, id, ts, principal, action) VALUES (?,?,?,?,?)",
            (rid, f"a{i}", ts(), "cli", "device.patch"),
        )
    conn.close()
    migrated = schema.open_overrides(path)
    got = migrated.execute("SELECT rowid, id FROM audit_log ORDER BY rowid").fetchall()
    assert [(r[0], r[1]) for r in got] == [(5, "a0"), (9, "a1")]
    migrated.close()
