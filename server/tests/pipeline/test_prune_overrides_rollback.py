"""overrides.db only moves forward: its audit counter (`audit_log.seq`, never reused) is kept as a
high-water mark, so an older backup restored over it, or a file recreated and given one new
decision, is seen as a different history and skips the prune. The presence marker alone could not
tell: both files still hold some decision."""

from __future__ import annotations

import logging
import shutil

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import (
    LATER,
    PROTECTIONS,
    STAMP,
    migrated_overrides,
    prune,
    retire,
    rows,
    sql,
)

from vigie_api.schema import open_overrides
from vigie_pipeline import prune as prune_module
from vigie_pipeline.prune import OVERRIDES_AUDIT_KEY, OVERRIDES_SEEN_KEY, _decisions_not_lost

AUDIT = (
    "INSERT INTO audit_log (id, ts, principal, action, target, detail)"
    " VALUES (?, ?, 'u', 'x', 't', '')"
)


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def decide(path, device, audits):
    """A decision on `device` with `audits` audit rows, as the API writes them together."""
    sql(path, PROTECTIONS["essential_devices"], device, STAMP)
    for n in range(audits):
        sql(path, AUDIT, f"a{device}{n}", STAMP)


def mark(data):
    rows_ = data.q("SELECT value FROM stitch_state WHERE key=?", OVERRIDES_AUDIT_KEY)
    return [r[0] for r in rows_]


def test_the_audit_high_water_mark_follows_the_file_forward(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    prune(data)
    assert mark(data) == ["3"]
    decide(path, "d2", 2)
    prune(data)
    assert mark(data) == ["5"]


def test_an_older_overrides_db_restored_over_the_live_one_skips_the_prune(data, caplog):
    macs = retire(data, count=2)
    named, other = sorted(macs)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    backup = path.with_name("backup.db")
    shutil.copy(path, backup)  # the backup predates the owner naming `named`
    decide(path, macs[named], 2)
    assert prune(data) == 1  # `other` goes; `named` is protected by the newer file
    shutil.copy(backup, path)  # restored: the decision on `named` is gone
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert any(r.fields.get("reason") == "overrides_rolled_back" for r in caplog.records)


def test_an_overrides_db_recreated_with_one_new_decision_skips_the_prune(data, caplog):
    macs = retire(data, count=2)
    path = migrated_overrides(data.root)
    decide(path, macs[sorted(macs)[0]], 3)
    assert prune(data) == 1
    path.unlink()
    open_overrides(path).close()
    decide(path, "unrelated", 1)  # one decision again: the presence marker would pass
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1


def test_an_equal_high_water_mark_prunes_as_usual(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    assert prune(data) == 1
    assert mark(data) == ["2"]
    retire(data)
    assert prune(data) == 1  # same file, same mark: not a rollback


def test_an_unreadable_stored_mark_fails_closed(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 1)
    data.inv.execute(
        "INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?, 'garbage')",
        (OVERRIDES_AUDIT_KEY,),
    )
    assert prune(data) == 0
    assert rows(data) == 1


@pytest.mark.parametrize("key", [OVERRIDES_SEEN_KEY, OVERRIDES_AUDIT_KEY])
def test_a_missing_file_is_an_error_once_either_marker_is_set(data, caplog, key):
    retire(data)
    data.inv.execute("INSERT OR REPLACE INTO stitch_state (key, value) VALUES (?, '1')", (key,))
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert any(
        r.levelno == logging.ERROR and r.fields.get("reason") == "overrides_missing"
        for r in caplog.records
    )


def test_a_missing_file_before_any_decision_stays_a_debug_line(data, caplog):
    retire(data)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_a_fresh_install_with_no_audit_rows_sets_no_mark(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data, LATER) == 1
    assert mark(data) == []


def restore_older_file(data, macs):
    """The owner decided on one device after the backup; the backup is then restored over the file
    (that decision gone) and the prune notices. Returns the overrides path."""
    named = sorted(macs)[0]
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    backup = path.with_name("backup.db")
    shutil.copy(path, backup)
    decide(path, macs[named], 2)
    assert prune(data) == 1
    shutil.copy(backup, path)
    assert prune(data) == 0
    return path


def test_a_restored_file_stays_skipped_once_its_audit_counter_catches_up(data, caplog):
    macs = retire(data, count=2)
    path = restore_older_file(data, macs)
    for n in range(4):  # unrelated audit rows (a token, an evidence write): no decision
        sql(path, AUDIT, f"catch-up{n}", STAMP)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1
    assert any(r.fields.get("reason") == "overrides_latched" for r in caplog.records)


def test_a_recreated_file_that_regrows_a_decision_stays_skipped(data):
    macs = retire(data, count=2)
    path = migrated_overrides(data.root)
    decide(path, macs[sorted(macs)[0]], 2)
    assert prune(data) == 1
    path.unlink()
    open_overrides(path).close()
    assert prune(data) == 0  # empty: the decision is lost
    decide(path, "unrelated", 5)  # one decision again, and the counter is past the mark
    assert prune(data) == 0
    assert rows(data) == 1


def test_deleting_the_marker_rows_resumes_the_prune(data):
    macs = retire(data, count=2)
    path = restore_older_file(data, macs)
    for n in range(4):
        sql(path, AUDIT, f"catch-up{n}", STAMP)
    data.inv.execute("DELETE FROM stitch_state WHERE key LIKE 'prune_overrides_%'")
    assert prune(data) == 1
    assert rows(data) == 0


def test_lost_decisions_are_latched_even_when_the_audit_counter_never_fell(data):
    macs = retire(data, count=2)
    path = migrated_overrides(data.root)
    sql(path, PROTECTIONS["identity_rules"], macs[sorted(macs)[0]], STAMP)
    for n in range(2):
        sql(path, AUDIT, f"a{n}", STAMP)
    assert prune(data) == 1
    sql(path, "DELETE FROM identity_rules")  # decisions gone, audit rows (and the mark) intact
    assert prune(data) == 0
    decide(path, "unrelated", 1)  # a decision again: the presence marker would pass
    assert prune(data) == 0
    assert rows(data) == 1


def test_unchanged_markers_take_no_write_lock(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    assert prune(data) == 1  # sets both markers
    traced = []
    data.inv.set_trace_callback(traced.append)
    assert _decisions_not_lost(data.inv, True, 2)
    data.inv.set_trace_callback(None)
    assert not [s for s in traced if s.upper().startswith("BEGIN")]


def test_a_recreated_file_whose_counter_passed_the_mark_before_the_next_look_stays_skipped(
    data, caplog
):
    """The mark is a counter AND the id of the row at that counter: a new file that collected as
    many audit rows as the old one held (while a skipped pass looked away) is another history."""
    macs = retire(data, count=2)
    protected = macs[sorted(macs)[0]]
    path = migrated_overrides(data.root)
    decide(path, protected, 3)
    assert prune(data) == 1  # `other` goes, the mark is 3
    path.unlink()
    open_overrides(path).close()
    decide(path, "unrelated", 5)  # a new decision and a counter past the old mark
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1  # the formerly protected MAC row is still there
    assert any(r.fields.get("reason") == "overrides_rolled_back" for r in caplog.records)
    assert data.q("SELECT 1 FROM stitch_state WHERE key=?", prune_module.OVERRIDES_LATCH_KEY)


def test_a_mark_without_the_id_of_its_row_fails_closed(data):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 2)
    assert prune(data) == 1
    data.inv.execute("DELETE FROM stitch_state WHERE key=?", (prune_module.OVERRIDES_AUDIT_ID_KEY,))
    retire(data)
    assert prune(data) == 0
    assert rows(data) == 1


def test_trimmed_older_audit_rows_do_not_look_like_a_rollback(data):
    """The high-water mark is the largest `seq`, never a row count: trimming old rows keeps it."""
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "unrelated", 5)
    assert prune(data) == 1
    sql(path, "DELETE FROM audit_log WHERE seq<=3")
    retire(data)
    assert prune(data) == 1
    assert rows(data) == 0
    assert mark(data) == ["5"]
