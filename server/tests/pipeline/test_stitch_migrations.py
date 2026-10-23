"""The one stitching migration (#4): a fresh install and an upgrade from main's v3 schema."""

from __future__ import annotations

import pytest

from vigie_pipeline import schema
from vigie_pipeline.schema import (
    PIPELINE_TABLES,
    apply_pipeline_migrations,
    open_pipeline_inventory,
)
from vigie_pipeline.stitch_db import emit_once

NEW_TABLES = {
    "mac_activity",
    "mac_first_received",
    "evidence_gaps",
    "rule_attachments",
    "stitch_state",
}


def test_a_fresh_install_has_the_final_shape_and_no_legacy_columns(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 4
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert NEW_TABLES <= names and set(PIPELINE_TABLES) <= names
    assert not names & {"mac_last_seen", "mac_collectors", "collector_gaps"}
    cols = [r[1] for r in conn.execute("PRAGMA table_info(mac_first_received)")]
    assert cols == ["mac", "received"]  # no legacy marker: there is nothing legacy to mark
    cols = [r[1] for r in conn.execute("PRAGMA table_info(rule_attachments)")]
    assert cols == ["mac", "rule_id", "target", "hostname", "mdns_name", "opt55", "opt60", "views",
                    "attached_at"]  # fmt: skip
    assert "dedup" in [r[1] for r in conn.execute("PRAGMA table_info(events)")]
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"uq_events_dedup", "uq_candidates_pair", "idx_candidates_b", "idx_suggestions_pair",
            "idx_suggestions_into", "idx_obs_fp_host", "idx_obs_fp_mdns", "idx_obs_fp_first",
            "idx_obs_rule", "idx_mac_activity_end", "idx_evidence_gaps_end"} <= indexes  # fmt: skip
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
                        " AND tbl_name='mac_activity'").fetchone()[0] == 0  # fmt: skip
    assert apply_pipeline_migrations(conn) == 4  # re-apply is a no-op
    assert conn.execute("SELECT COUNT(*) FROM pipeline_schema").fetchone()[0] == 4


def test_main_has_no_stitching_table_to_migrate_from(tmp_path, monkeypatch):
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:3])
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert not names & NEW_TABLES
    assert "dedup" not in [r[1] for r in conn.execute("PRAGMA table_info(events)")]


def test_upgrade_from_a_populated_main_v3_database_keeps_every_row(tmp_path, monkeypatch):
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:3])
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    ins = (
        "INSERT INTO events (id, device_id, ts, kind, severity, summary)"
        " VALUES (?, 'd', 't', 'identity_candidate', 'info', 's')"
    )
    conn.execute(ins, ("e1",))
    conn.execute(ins, ("e2",))
    conn.execute(
        "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
        " created_at) VALUES ('c1','a','b',0.8,'{}','open','t')"
    )
    conn.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES ('s1','merge_identity','[\"a\", \"b\"]','{}','x','{}','t','u')"
    )
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, link_source, first_seen,"
        " last_seen) VALUES ('m','d',1,'self','t','t')"
    )
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 3
    conn.close()
    monkeypatch.undo()
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 4
    rows = conn.execute("SELECT id, dedup FROM events ORDER BY seq").fetchall()
    assert [tuple(r) for r in rows] == [("e1", None), ("e2", None)]  # NULL dedup stays NULL
    assert conn.execute("SELECT COUNT(*) FROM identity_candidates").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM mac_activity").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM mac_first_received").fetchone()[0] == 0  # no anchors
    conn.execute(ins, ("e3",))  # NULLs never collide on the partial unique index
    assert emit_once(conn, "d", "k", "warn", "s", "tok", 1.0) is True
    assert emit_once(conn, "d", "k", "warn", "s", "tok", 1.0) is False
    assert apply_pipeline_migrations(conn) == 4


def test_a_newer_pipeline_schema_is_refused(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute("INSERT INTO pipeline_schema (version) VALUES (99)")
    with pytest.raises(RuntimeError):
        apply_pipeline_migrations(conn)


def test_the_into_index_serves_the_orphan_lookup(tmp_path):
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute(
        "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
        " expires_at) VALUES ('s1','merge_identity','[\"a\", \"b\"]','{}','x','{}','t','u')"
    )
    row = conn.execute(
        "SELECT id FROM suggestions WHERE action='merge_identity'"
        " AND json_extract(device_ids, '$[1]')=? AND expires_at >= ?", ("b", "t"),
    ).fetchone()  # fmt: skip
    assert row[0] == "s1"
    plan = " ".join(
        r[3] for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM suggestions WHERE action='merge_identity'"
            " AND json_extract(device_ids, '$[1]')=? AND expires_at >= ?", ("b", "t"),
        )
    )  # fmt: skip
    assert "idx_suggestions_into" in plan


def test_upgrade_from_mains_frozen_schema_text_survives_duplicate_candidate_rows(
    tmp_path, monkeypatch
):
    """main's migrations as committed on main (a frozen copy, not this branch's own list), with
    rows in every table and a duplicate (device_a, device_b) pair that the unique index must not
    abort on."""
    from fixtures.main_pipeline_schema import MAIN_PIPELINE_MIGRATIONS

    assert MAIN_PIPELINE_MIGRATIONS == schema.PIPELINE_MIGRATIONS[:3]  # migrations 1-3 unchanged
    path = tmp_path / "inventory.db"
    monkeypatch.setattr(schema, "PIPELINE_MIGRATIONS", MAIN_PIPELINE_MIGRATIONS)
    conn = open_pipeline_inventory(path, migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen) VALUES ('m','d',1,'Éloïse','Straße','self','t','t')"
    )
    for cid in ("c1", "c2"):
        conn.execute(
            "INSERT INTO identity_candidates (id, device_a, device_b, score, evidence, state,"
            " created_at) VALUES (?,'a','b',0.8,'{}','open',?)", (cid, cid),
        )  # fmt: skip
    conn.close()
    monkeypatch.undo()
    conn = open_pipeline_inventory(path)
    assert conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] == 4
    rows = conn.execute("SELECT id FROM identity_candidates ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["c2"]  # the newest of the duplicates is kept
    folds = conn.execute("SELECT hostname_fold, mdns_fold FROM observations").fetchone()
    assert tuple(folds) == ("éloïse", "strasse")  # back-filled for main's rows


@pytest.mark.timeout(20)
def test_the_fold_backfill_terminates_on_empty_and_null_names(tmp_path):
    from vigie_pipeline.schema import refresh_folds as backfill_folds

    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen) VALUES ('e','d',1,'','','self','t','t')"
    )
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen) VALUES ('n','d',1,NULL,NULL,'self','t','t')"
    )
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen) VALUES ('h','d',1,'Ｓtraße',NULL,'self','t','t')"
    )
    assert backfill_folds(conn) == 1
    assert backfill_folds(conn) == 0  # nothing left: the empty names are not re-selected forever
    rows = conn.execute("SELECT mac, hostname_fold FROM observations ORDER BY mac").fetchall()
    assert [tuple(r) for r in rows] == [("e", None), ("h", "strasse"), ("n", None)]


def test_stored_folds_are_recomputed_when_the_fold_version_changes(tmp_path):
    import unicodedata

    from vigie_pipeline import schema as schema_mod
    from vigie_pipeline.schema import refresh_folds
    from vigie_pipeline.stitch_types import fold

    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    old_fold = unicodedata.normalize("NFKC", "ß́-PC").casefold()  # the previous function
    assert old_fold != fold("ß́-PC")
    conn.execute(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen, hostname_fold, mdns_fold)"
        " VALUES ('m','d',1,'ß́-PC','','self','t','t',?,NULL)", (old_fold,),
    )  # fmt: skip
    conn.execute("UPDATE pipeline_meta SET value='stale' WHERE key='fold_version'")
    assert refresh_folds(conn) == 1  # every row recomputed with the current fold
    assert conn.execute("SELECT hostname_fold FROM observations").fetchone()[0] == fold("ß́-PC")
    marker = conn.execute("SELECT value FROM pipeline_meta WHERE key='fold_version'").fetchone()[0]
    assert marker == f"{schema_mod.FOLD_VERSION}/{unicodedata.unidata_version}"
    before = conn.total_changes
    assert refresh_folds(conn) == 0 and conn.total_changes == before  # a no-op afterwards
    conn.close()
    conn = open_pipeline_inventory(tmp_path / "inventory.db")  # the open path runs it too
    assert conn.execute("SELECT hostname_fold FROM observations").fetchone()[0] == fold("ß́-PC")


def test_a_fold_recompute_is_resumable_and_terminates_on_empty_names(tmp_path):
    from vigie_pipeline.schema import refresh_folds
    from vigie_pipeline.stitch_types import fold

    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    conn.execute("BEGIN")
    conn.execute("INSERT INTO devices (id, first_seen, last_seen) VALUES ('d','t','t')")
    conn.executemany(
        "INSERT INTO observations (mac, device_id, is_randomized, hostname, mdns_name, link_source,"
        " first_seen, last_seen, hostname_fold) VALUES (?,'d',1,?,?,'self','t','t','stale')",
        [(f"m{i:04d}", f"Host{i}", "" if i % 2 else None) for i in range(5000)],
    )
    conn.execute("UPDATE pipeline_meta SET value='stale' WHERE key='fold_version'")
    conn.execute("COMMIT")
    assert refresh_folds(conn, chunk=2000) == 5000
    rows = conn.execute(
        "SELECT COUNT(*) FROM observations WHERE hostname_fold=?", (fold("Host7"),)
    ).fetchone()
    assert (
        rows[0] == 1
        and conn.execute(
            "SELECT COUNT(*) FROM observations WHERE mdns_fold IS NOT NULL"
        ).fetchone()[0]
        == 0
    )
    assert refresh_folds(conn) == 0
