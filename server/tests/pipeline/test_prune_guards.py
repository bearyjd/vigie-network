"""prune_retired_macs fails closed on an unusable overrides.db and every guard is pinned."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_pipeline import processor
from vigie_pipeline.config import RETIRED_MAC_RETENTION_S, PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.processor import prune_retired_macs, run_once

RETENTION = RETIRED_MAC_RETENTION_S
LATER = T0 + 91 * 86400
NIC = "00:11:22:33:44:55"
STAMP = "2026-01-01T00:00:00Z"


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    """Other suites leave the logger non-propagating; caplog needs it to propagate."""
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def migrated_overrides(root: Path) -> Path:
    path = root / "overrides.db"
    open_overrides(path).close()
    return path


def sql(path: Path, statement: str, *args: object) -> None:
    conn = sqlite3.connect(path)
    conn.execute(statement, args)
    conn.commit()
    conn.close()


def retire(data: Data, count: int = 1) -> dict[str, str]:
    """MAC -> device id of `count` transient devices that have been retired."""
    macs = [f"aa:bb:cc:00:00:{i:02x}" for i in range(1, count + 1)]
    data.add_batch(T0, neigh=macs)
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 86400)
    return {r["mac"]: r["device_id"] for r in data.q("SELECT mac, device_id FROM observations")}


def prune(data: Data, now: float = LATER) -> int:
    conn = open_overrides_ro(data.root / "overrides.db")
    try:
        return prune_retired_macs(data.inv, conn, now)
    finally:
        if conn is not None:
            conn.close()


def counter(data: Data) -> str:
    sql_ = "SELECT value FROM pipeline_meta WHERE key=?"
    return data.q(sql_, processor.PRUNED_COUNTER_KEY)[0][0]


def rows(data: Data) -> int:
    return len(data.q("SELECT 1 FROM observations"))


def test_a_usable_overrides_db_lets_old_retired_rows_go(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data) == 1
    assert rows(data) == 0
    assert counter(data) == "1"


# ---- fail closed ------------------------------------------------------------------------


def test_a_missing_overrides_db_prunes_nothing(data, caplog):
    macs = retire(data)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert "prune_skipped" in caplog.text
    assert not any(mac in caplog.text for mac in macs)


def test_run_once_with_no_overrides_db_prunes_nothing(data):
    retire(data)
    run_once(PipelineConfig(data_dir=data.root), now=LATER)
    assert rows(data) == 1


def test_a_zero_byte_overrides_db_prunes_nothing(data):
    retire(data)
    (data.root / "overrides.db").write_bytes(b"")
    assert prune(data) == 0
    assert rows(data) == 1


def test_an_older_schema_prunes_nothing(data):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) - 1}")
    assert prune(data) == 0
    assert rows(data) == 1


def test_a_newer_than_known_schema_prunes_nothing(data):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS) + 1}")
    assert prune(data) == 0
    assert rows(data) == 1


@pytest.mark.parametrize(
    "table", ["device_overrides", "identity_links", "identity_rules", "essential_devices"]
)
def test_a_missing_required_table_prunes_nothing(data, table):
    retire(data)
    sql(migrated_overrides(data.root), f"DROP TABLE {table}")
    assert prune(data) == 0
    assert rows(data) == 1


def test_an_unreadable_table_is_skipped_not_raised(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, "DROP TABLE identity_rules")
    sql(path, "CREATE TABLE identity_rules (id TEXT)")  # right name, no device_id column
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert "prune_skipped" in caplog.text


def test_an_exclusively_locked_overrides_db_prunes_nothing(data):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, "PRAGMA journal_mode=DELETE")
    reader = open_overrides_ro(path)
    assert reader is not None
    reader.execute("PRAGMA busy_timeout=0")
    writer = sqlite3.connect(path, isolation_level=None)
    writer.execute("BEGIN EXCLUSIVE")
    try:
        assert prune_retired_macs(data.inv, reader, LATER) == 0
    finally:
        writer.execute("ROLLBACK")
        writer.close()
        reader.close()
    assert rows(data) == 1


# ---- protection sources: each alone keeps a retired device's row ------------------------

PROTECTIONS = {
    "device_overrides": (
        "INSERT INTO device_overrides (device_id, updated_at, updated_by) VALUES (?, ?, 'u')"
    ),
    "essential_devices": (
        "INSERT INTO essential_devices (device_id, updated_at, updated_by, version)"
        " VALUES (?, ?, 'u', 1)"
    ),
    "identity_rules": (
        "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by)"
        " VALUES ('r1', ?, 'sig', ?, 'u')"
    ),
    "link_from": (
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
        " VALUES (?, 'someone-else', 'm1', ?, 'u')"
    ),
    "link_into": (
        "INSERT INTO identity_links (from_device, into_device, merge_id, created_at, created_by)"
        " VALUES ('someone-else', ?, 'm1', ?, 'u')"
    ),
}


@pytest.mark.parametrize("source", PROTECTIONS)
def test_each_protection_source_keeps_the_row_and_the_rest_still_go(data, source):
    macs = retire(data, count=2)
    protected, free = sorted(macs)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS[source], macs[protected], STAMP)
    assert prune(data) == 1
    kept = [r["mac"] for r in data.q("SELECT mac FROM observations")]
    assert kept == [protected]
    assert free not in kept


def test_a_human_merged_retired_device_survives_through_run_once(data):
    macs = retire(data)
    transient = macs["aa:bb:cc:00:00:01"]
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["link_from"].replace("someone-else", "active-dev"), transient, STAMP)
    run_once(PipelineConfig(data_dir=data.root), now=LATER)
    assert rows(data) == 1


# ---- the row filters ---------------------------------------------------------------------


def test_only_self_linked_rows_are_pruned(data):
    macs = retire(data)
    data.inv.execute("UPDATE observations SET link_source='human'")
    migrated_overrides(data.root)
    assert prune(data) == 0
    assert rows(data) == 1
    assert list(macs)  # the retired device exists; only its link_source keeps the row


def test_only_retired_devices_are_pruned(data):
    data.add_batch(T0, neigh=[NIC, "aa:bb:cc:00:00:01"])
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 60)  # active + still-transient
    migrated_overrides(data.root)
    assert {r["status"] for r in data.q("SELECT status FROM devices")} == {"active", "transient"}
    assert prune(data) == 0
    assert rows(data) == 2


def test_the_retention_boundary_is_exclusive(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, T0 + RETENTION) == 0  # exactly 90 days: kept
    assert rows(data) == 1
    assert prune(data, T0 + RETENTION + 1) == 1  # one second past: pruned
    assert rows(data) == 0


def test_one_pass_prunes_at_most_the_batch_cap(data, monkeypatch):
    retire(data, count=2)
    migrated_overrides(data.root)
    monkeypatch.setattr(processor, "PRUNE_BATCH_ROWS", 1)
    assert prune(data) == 1
    assert rows(data) == 1
    assert counter(data) == "1"
