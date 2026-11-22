"""With VIGIE_PRUNE_RETIRED_MACS off the prune deletes nothing and stays quiet, but it keeps the
overrides.db history markers (audit high-water mark, presence marker, lost-decisions latch) exactly
as the enabled prune does, so a restore or loss made while off is seen when it is turned on."""

from __future__ import annotations

import logging
import shutil
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_decided_suggestions import DECIDE
from test_prune_guards import LATER, PROTECTIONS, STAMP, migrated_overrides, retire, rows, sql
from test_prune_overrides_rollback import AUDIT, decide

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.prune import (
    OVERRIDES_AUDIT_ID_KEY,
    OVERRIDES_AUDIT_KEY,
    OVERRIDES_LATCH_KEY,
    OVERRIDES_SEEN_KEY,
    PRUNED_COUNTER_KEY,
)
from vigie_pipeline.sources import ShardReadError


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def _overridden(path) -> None:
    """One decision that can be deleted again (essential marks cannot) and two audit rows."""
    sql(path, PROTECTIONS["identity_rules"], "d1", STAMP)
    for n in range(2):
        sql(path, AUDIT, f"a{n}", STAMP)


def off(data, n=0):
    processor.run_once(PipelineConfig(data_dir=data.root), now=LATER + n)


def on(data, n=0):
    processor.run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=LATER + n)


def state(data) -> dict[str, str]:
    return {r["key"]: r["value"] for r in data.q("SELECT key, value FROM stitch_state")}


def prune_state(data) -> dict[str, str]:
    return {k: v for k, v in state(data).items() if k.startswith("prune_")}


def test_off_deletes_nothing_and_advances_the_history_markers(data):
    retire(data, count=2)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    for n in range(3):
        off(data, n)
    assert rows(data) == 2
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", PRUNED_COUNTER_KEY) == []
    marks = prune_state(data)
    assert marks[OVERRIDES_SEEN_KEY] == "1"
    assert marks[OVERRIDES_AUDIT_KEY] == "3"
    assert marks[OVERRIDES_AUDIT_ID_KEY]
    assert OVERRIDES_LATCH_KEY not in marks
    decide(path, "d2", 2)
    off(data, 5)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "5"
    assert rows(data) == 2


def test_off_touches_nothing_but_the_markers(data):
    retire(data)
    decide(migrated_overrides(data.root), "d1", 2)

    def snapshot():
        return (
            [tuple(r) for r in data.q("SELECT * FROM observations ORDER BY mac")],
            [tuple(r) for r in data.q("SELECT * FROM mac_last_ip ORDER BY mac")],
        )

    before = snapshot()
    off(data)
    assert snapshot() == before


def test_a_restored_older_overrides_db_seen_while_off_latches_and_enabling_still_refuses(
    data, caplog
):
    macs = retire(data, count=2)
    named = sorted(macs)[0]
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    backup = path.with_name("backup.db")
    shutil.copy(path, backup)
    decide(path, macs[named], 2)
    off(data)  # the newer file is seen while off
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "4"
    shutil.copy(backup, path)  # restored while off: the decision on `named` is gone
    off(data, 1)
    assert prune_state(data)[OVERRIDES_LATCH_KEY] == "overrides_rolled_back"
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        on(data, 2)
    assert rows(data) == 2  # enabling afterwards still refuses to prune
    assert any(r.fields.get("reason") == "overrides_latched" for r in caplog.records)
    sql(data.root / "inventory.db", "DELETE FROM stitch_state WHERE key LIKE 'prune_overrides_%'")
    on(data, 3)
    assert rows(data) < 2  # the owner cleared the markers: the prune resumes


def test_a_poorer_overrides_db_seen_while_off_latches_lost_decisions(data):
    retire(data)
    path = migrated_overrides(data.root)
    _overridden(path)
    off(data)
    assert OVERRIDES_SEEN_KEY in prune_state(data)
    sql(path, "DELETE FROM identity_rules")  # every decision gone, the audit counter intact
    off(data, 1)
    assert prune_state(data)[OVERRIDES_LATCH_KEY] == "overrides_lost_decisions"
    on(data, 2)
    assert rows(data) == 1


def test_a_decided_suggestion_counts_as_a_decision(data):
    retire(data)
    sql(migrated_overrides(data.root), DECIDE, "s1", "accepted", STAMP)
    off(data)
    assert prune_state(data)[OVERRIDES_SEEN_KEY] == "1"


def test_an_existing_latch_is_respected(data):
    retire(data)
    path = migrated_overrides(data.root)
    sql(data.root / "inventory.db", "INSERT INTO stitch_state (key, value) VALUES (?, 'mine')",
        OVERRIDES_LATCH_KEY)  # fmt: skip
    decide(path, "d1", 3)
    off(data)
    assert prune_state(data) == {OVERRIDES_LATCH_KEY: "mine"}


def test_a_missing_overrides_db_changes_no_marker(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    off(data)
    before = prune_state(data)
    assert OVERRIDES_AUDIT_KEY in before
    sql(data.root / "inventory.db", "SELECT 1")
    path.rename(path.with_name("moved-away.db"))
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        off(data, 1)
    assert prune_state(data) == before
    assert [r for r in caplog.records if r.getMessage().startswith("prune")] == []


def test_an_unreadable_overrides_db_changes_no_marker(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    off(data)
    before = prune_state(data)
    path.write_bytes(b"not a database" * 100)
    off(data, 1)
    assert prune_state(data) == before
    assert OVERRIDES_LATCH_KEY not in before


def test_a_normal_off_pass_logs_nothing_at_warning_or_above(data, caplog):
    retire(data)
    decide(migrated_overrides(data.root), "d1", 2)
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        for n in range(3):
            off(data, n)
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_a_latched_off_pass_stays_quiet_every_pass(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    _overridden(path)
    off(data)
    sql(path, "DELETE FROM identity_rules")
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        for n in range(1, 4):
            off(data, n)
    assert prune_state(data)[OVERRIDES_LATCH_KEY] == "overrides_lost_decisions"
    # (the malformed rule is the stitcher's own complaint); an off pass logs DEBUG at most
    loud = [r for r in caplog.records if r.levelno >= logging.INFO]
    assert [r for r in loud if r.getMessage().startswith(("prune", "overrides"))] == []


def test_a_corrupt_overrides_db_while_off_logs_no_prune_error(data, caplog):
    retire(data)
    (data.root / "overrides.db").write_bytes(b"not a database" * 100)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        for n in range(3):
            off(data, n)
    names = [r.getMessage().split()[0] for r in caplog.records if r.levelno >= logging.INFO]
    assert names.count("overrides_unreadable") == 3  # the processor's own: one per pass, no second
    assert not [n for n in names if n.startswith(("prune", "overrides_history"))]
    assert rows(data) == 1


class _Spy:
    def __init__(self, conn):
        self.conn, self.closed = conn, False

    def __getattr__(self, name):
        return getattr(self.conn, name)

    def close(self):
        self.closed = True
        self.conn.close()


def test_the_off_tracker_closes_its_overrides_connection(data, monkeypatch):
    retire(data)
    decide(migrated_overrides(data.root), "d1", 3)
    spies = []

    def spying_open(p, **kwargs):
        spies.append(_Spy(open_overrides_ro(p, **kwargs)))
        return spies[-1]

    monkeypatch.setattr(prune_module, "open_overrides_ro", spying_open)
    off(data)
    assert spies
    assert all(s.closed for s in spies)


def test_kill_m14_a_different_file_with_a_larger_counter_latches_while_off(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 2)
    off(data)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "2"
    other = path.with_name("other.db")
    shutil.copy(path, other)
    sql(other, "DELETE FROM audit_log")
    for n in range(6):
        sql(other, AUDIT, f"other{n}", STAMP)  # another file whose counter is past the stored one
    shutil.copy(other, path)
    off(data, 1)
    assert prune_state(data)[OVERRIDES_LATCH_KEY] == "overrides_rolled_back"
    on(data, 2)
    assert rows(data) == 1


def test_kill_m15_a_busy_inventory_while_off_does_not_crash(data, monkeypatch):
    retire(data)
    decide(migrated_overrides(data.root), "d1", 3)

    def busy(_inv):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(prune_module, "immediate", busy)
    off(data)  # the tracker swallows it: the pass goes on
    assert OVERRIDES_AUDIT_KEY not in prune_state(data)


def _break_shard(data, mac):
    data.add_batch(LATER, neigh=[mac])
    conn = connect(data.root / shard_name(utc_day(LATER)))
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.close()


def _unusable_snapshot(path) -> None:
    conn = sqlite3.connect(path)
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        conn.execute(f'DROP TRIGGER "{name}"')
    conn.execute("DELETE FROM identity_version")
    conn.commit()
    conn.close()


def test_kill_m21_off_tracks_even_on_a_failed_batch_read(data):
    ((mac, _),) = retire(data).items()
    decide(migrated_overrides(data.root), "d1", 3)
    _break_shard(data, mac)
    with pytest.raises(ShardReadError):
        off(data)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "3"


def test_kill_m22_off_tracks_even_when_the_snapshot_is_unusable(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    _unusable_snapshot(path)
    off(data)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "3"


def test_on_tracks_even_on_a_failed_batch_read(data):
    ((mac, _),) = retire(data).items()
    decide(migrated_overrides(data.root), "d1", 3)
    _break_shard(data, mac)
    with pytest.raises(ShardReadError):
        on(data)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "3"
    assert rows(data) == 1


def test_on_tracks_even_when_the_snapshot_is_unusable(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    _unusable_snapshot(path)
    on(data)
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "3"
    assert rows(data) == 1


def test_a_restore_during_an_on_pass_with_an_unread_batch_still_latches(data):
    ((mac, _),) = retire(data).items()
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    backup = path.with_name("backup.db")
    shutil.copy(path, backup)
    decide(path, "d2", 2)
    _break_shard(data, mac)
    with pytest.raises(ShardReadError):
        on(data)  # the file is at mark 4 while a shard keeps failing
    assert prune_state(data)[OVERRIDES_AUDIT_KEY] == "4"
    shutil.copy(backup, path)  # restored from the older backup
    with pytest.raises(ShardReadError):
        on(data, 1)
    assert prune_state(data)[OVERRIDES_LATCH_KEY] == "overrides_rolled_back"
