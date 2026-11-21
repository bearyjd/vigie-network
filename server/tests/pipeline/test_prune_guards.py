"""prune_retired_macs fails closed on an unusable overrides.db and every guard is pinned."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest
from pipeline_helpers import T0, Data, data  # noqa: F401

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import RETIRED_MAC_RETENTION_S, PipelineConfig
from vigie_pipeline.overrides import PROTECTED_TABLES
from vigie_pipeline.processor import prune_retired_macs, run_once

RETENTION = RETIRED_MAC_RETENTION_S
RETIRED_AT = T0 + 86400  # the server time `retire` retires its devices
FRONTIER = T0 + 400 * 86400  # `last_sent_ts` `retire` leaves every collector: ahead of every `now`
LATER = RETIRED_AT + RETENTION + 86400  # a day past the retention, counted from the retirement
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
    set_clock(data, None)  # a floor left by an earlier call would stamp the retirement ahead
    run_once(PipelineConfig(data_dir=data.root), now=RETIRED_AT)
    set_clock(data, FRONTIER)
    return {r["mac"]: r["device_id"] for r in data.q("SELECT mac, device_id FROM observations")}


def set_clock(data: Data, last_sent_ts: int | None) -> None:
    """Every collector's `last_sent_ts` (None: none has ever sent): the prune's trusted clock."""
    data.inv.execute("UPDATE collectors SET last_sent_ts=?", (last_sent_ts or 0,))


def prune(data: Data, now: float = LATER) -> int:
    path = data.root / "overrides.db"
    return prune_retired_macs(data.inv, path, now)


def counter(data: Data) -> str:
    sql_ = "SELECT value FROM pipeline_meta WHERE key=?"
    return data.q(sql_, prune_module.PRUNED_COUNTER_KEY)[0][0]


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
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
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


# Spelled out on purpose: read back from PROTECTED_TABLES, the list would follow any edit of it.
REQUIRED_TABLES = [
    "candidate_decisions",
    "device_overrides",
    "essential_devices",
    "identity_links",
    "identity_merges",
    "identity_rules",
    "incident_decisions",
    "suggestion_decisions",
]


def test_the_required_tables_are_exactly_these():
    assert sorted(PROTECTED_TABLES) == REQUIRED_TABLES


@pytest.mark.parametrize("table", REQUIRED_TABLES)
def test_a_missing_required_table_prunes_nothing(data, table, caplog):
    """The guard names the table; without it the next SELECT would fail with a bare sqlite error."""
    retire(data)
    sql(migrated_overrides(data.root), f"DROP TABLE {table}")
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert any(f"lacks table(s): {table}" in r.fields.get("error", "") for r in caplog.records)


def test_an_unreadable_table_is_skipped_not_raised(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, "DROP TABLE identity_rules")
    sql(path, "CREATE TABLE identity_rules (id TEXT)")  # right name, no device_id column
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert "prune_skipped" in caplog.text


def test_an_exclusively_locked_overrides_db_prunes_nothing(data, monkeypatch):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, "PRAGMA journal_mode=DELETE")
    real = prune_module.open_overrides_ro
    monkeypatch.setattr(prune_module, "open_overrides_ro", lambda p: real(p, timeout=0.05))
    writer = sqlite3.connect(path, isolation_level=None)
    writer.execute("BEGIN EXCLUSIVE")
    try:
        assert prune(data) == 0
    finally:
        writer.execute("ROLLBACK")
        writer.close()
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
    data.add_batch(T0, neigh=[NIC, "02:00:5e:00:00:51"])
    run_once(PipelineConfig(data_dir=data.root), now=T0 + 60)  # active + still-transient
    migrated_overrides(data.root)
    set_clock(data, FRONTIER)  # the clock is vouched for: only the status guard can hold
    active, transient = (
        data.q("SELECT id FROM devices WHERE status=? ORDER BY id", status)[0][0]
        for status in ("active", "transient")
    )
    assert {r["status"] for r in data.q("SELECT status FROM devices")} == {"active", "transient"}
    data.inv.execute(  # both carry a stamp far older than the retention: only status protects
        "INSERT OR REPLACE INTO transient_state (device_id, since) VALUES (?,?), (?,?)",
        (active, "2000-01-01T00:00:00Z", transient, "2000-01-01T00:00:00Z"),
    )
    assert prune(data) == 0
    assert rows(data) == 2


def test_a_recent_last_seen_keeps_a_row_whose_retirement_stamp_is_old(data):
    retire(data)
    migrated_overrides(data.root)
    data.inv.execute(  # retired long ago, yet the MAC itself was last seen 10 days before `now`
        "UPDATE observations SET last_seen=?", (iso_utc(LATER - 10 * 86400),)
    )
    assert prune(data) == 0
    assert rows(data) == 1


def test_the_running_total_adds_up_across_pruning_passes(data, monkeypatch):
    retire(data, count=3)
    migrated_overrides(data.root)
    monkeypatch.setattr(prune_module, "PRUNE_BATCH_ROWS", 2)
    assert prune(data) == 2
    assert counter(data) == "2"
    assert prune(data) == 1
    assert counter(data) == "3"


def test_the_running_total_adds_each_pass_by_the_rows_it_pruned(data, monkeypatch):
    retire(data, count=5)
    migrated_overrides(data.root)
    monkeypatch.setattr(prune_module, "PRUNE_BATCH_ROWS", 2)
    assert [prune(data), prune(data), prune(data)] == [2, 2, 1]
    assert counter(data) == "5"


def test_a_pass_that_prunes_nothing_leaves_pipeline_meta_alone(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, RETIRED_AT + RETENTION) == 0  # trusted clock, nothing past 90 days yet
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", prune_module.PRUNED_COUNTER_KEY) == []


def test_the_retention_boundary_is_exclusive(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, RETIRED_AT + RETENTION) == 0  # exactly 90 days after retirement: kept
    assert rows(data) == 1
    assert prune(data, RETIRED_AT + RETENTION + 1) == 1  # one second past: pruned
    assert rows(data) == 0


def test_one_pass_prunes_at_most_the_batch_cap(data, monkeypatch):
    retire(data, count=2)
    migrated_overrides(data.root)
    monkeypatch.setattr(prune_module, "PRUNE_BATCH_ROWS", 1)
    assert prune(data) == 1
    assert rows(data) == 1
    assert counter(data) == "1"


def test_the_last_seen_boundary_is_exclusive(data):
    retire(data)
    migrated_overrides(data.root)
    cutoff = iso_utc(LATER - RETENTION)  # the trusted clock is `now`: the frontier leads it
    data.inv.execute("UPDATE observations SET last_seen=?", (cutoff,))
    assert prune(data, LATER) == 0
    data.inv.execute("UPDATE observations SET last_seen=?", (iso_utc(LATER - RETENTION - 1),))
    assert prune(data, LATER) == 1


def test_the_prunes_own_overrides_connection_is_closed_afterwards(data, monkeypatch):
    retire(data)
    migrated_overrides(data.root)
    opened = []
    real = prune_module.open_overrides_ro

    def remember(*args, **kwargs):
        opened.append(real(*args, **kwargs))
        return opened[-1]

    monkeypatch.setattr(prune_module, "open_overrides_ro", remember)
    prune(data)
    (conn,) = opened
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_a_protection_removed_between_two_passes_on_one_connection_no_longer_protects(data):
    """The protected ids are loaded afresh each call: a decision gone from overrides.db must not
    keep protecting through what an earlier call left on the connection."""
    macs = retire(data, count=2)
    first, second = sorted(macs)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["identity_rules"], macs[first], STAMP)
    sql(path, PROTECTIONS["essential_devices"], "unrelated", STAMP)  # keeps the lost-file marker
    assert prune(data) == 1  # `second` goes, `first` is protected
    sql(path, "DELETE FROM identity_rules")
    assert prune(data) == 1
    assert rows(data) == 0
