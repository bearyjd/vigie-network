"""The protected read must be trustworthy: every id is non-empty text, the file is the one that
was read, and the version check runs on a connection no earlier stage can hold still."""

from __future__ import annotations

import logging
import os
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import (
    LATER,
    RETIRED_AT,
    migrated_overrides,
    prune,
    retire,
    rows,
    sql,
)
from test_prune_overrides_recheck import ESSENTIAL, commit_after_protected_read

from vigie_api.schema import open_overrides
from vigie_pipeline import processor
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.overrides import OverridesNotUsable, open_overrides_ro, protected_device_ids

STAMP = "2026-01-01T00:00:00Z"
ESSENTIAL_ANY = (
    "INSERT INTO essential_devices (device_id, updated_at, updated_by, version)"
    " VALUES (?, ?, 'u', 1)"
)


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


# ---- 9a: a protected value that is not text is not a protection that works --------------------


@pytest.mark.parametrize("value", [b"\x01\x02", ""], ids=["blob", "empty"])
def test_a_protected_id_that_is_not_non_empty_text_fails_the_prune_closed(data, caplog, value):
    retire(data)
    path = migrated_overrides(data.root)
    conn = sqlite3.connect(path)
    conn.execute(ESSENTIAL_ANY, (value, STAMP))
    conn.commit()
    conn.close()
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert "prune_skipped" in caplog.text
    assert rows(data) == 1


def test_protected_device_ids_names_the_unusable_value_kind_not_its_content(data):
    path = migrated_overrides(data.root)
    sql(path, ESSENTIAL_ANY, b"\xde\xad", STAMP)
    conn = open_overrides_ro(path)
    with pytest.raises(OverridesNotUsable) as raised:
        protected_device_ids(conn)
    conn.close()
    assert "dead" not in str(raised.value).lower()


def test_an_overrides_db_removed_after_the_protected_read_defers(data, monkeypatch, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    real = processor.protected_device_ids

    def read_then_remove(conn):
        protected = real(conn)
        path.unlink()
        return protected

    monkeypatch.setattr(processor, "protected_device_ids", read_then_remove)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert "prune_deferred" in caplog.text
    assert rows(data) == 1


def test_an_overrides_db_replaced_after_the_protected_read_defers(data, monkeypatch):
    retire(data)
    path = migrated_overrides(data.root)
    spare = path.with_name("spare.db")
    open_overrides(spare).close()
    real = processor.protected_device_ids

    def read_then_replace(conn):
        protected = real(conn)
        os.replace(spare, path)  # a restored backup: a new inode under the same name
        return protected

    monkeypatch.setattr(processor, "protected_device_ids", read_then_replace)
    assert prune(data) == 0
    assert rows(data) == 1


def test_an_overrides_db_replaced_between_the_stat_and_the_open_defers(data, monkeypatch):
    retire(data)
    path = migrated_overrides(data.root)
    spare = path.with_name("spare.db")
    open_overrides(spare).close()
    real = processor.open_overrides_ro

    def replace_then_open(target, *args, **kwargs):
        os.replace(spare, path)
        return real(target, *args, **kwargs)

    monkeypatch.setattr(processor, "open_overrides_ro", replace_then_open)
    assert prune(data) == 0
    assert rows(data) == 1


# ---- 9b: a dedicated connection, not one an earlier stage may hold still ----------------------


def test_an_open_cursor_on_the_pipelines_own_overrides_connection_cannot_hide_a_commit(
    data, monkeypatch
):
    macs = retire(data)
    path = migrated_overrides(data.root)
    real_open = processor.open_overrides_ro
    held = []

    def open_and_hold_a_cursor(target, *args, **kwargs):
        conn = real_open(target, *args, **kwargs)
        if not held:  # the first open is the pipeline's own connection
            cursor = conn.execute("SELECT name FROM sqlite_master")
            cursor.fetchone()  # a read left open: this connection's data_version stays frozen
            held.append(cursor)
        return conn

    monkeypatch.setattr(processor, "open_overrides_ro", open_and_hold_a_cursor)
    commit_after_protected_read(monkeypatch, path, ESSENTIAL, next(iter(macs.values())))
    processor.run_once(PipelineConfig(data_dir=data.root), now=LATER)
    assert held
    assert rows(data) == 1


# ---- 9d: a missing file is normal, an unusable one is an error -------------------------------


def test_a_missing_overrides_db_skips_the_prune_quietly(data, caplog):
    retire(data)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert "prune_skipped" not in caplog.text
    assert rows(data) == 1


def test_a_missing_overrides_db_is_a_debug_line(data, caplog):
    retire(data)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        prune(data)
    assert [r.levelno for r in caplog.records if r.getMessage() == "prune_skipped"] == [
        logging.DEBUG
    ]


def test_an_existing_but_unusable_overrides_db_is_an_error(data, caplog):
    retire(data)
    (data.root / "overrides.db").write_bytes(b"not a database" * 50)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        prune(data)
    assert logging.ERROR in [r.levelno for r in caplog.records if r.getMessage() == "prune_skipped"]


def test_the_untouched_file_still_prunes_after_the_identity_checks(data):
    retire(data)
    migrated_overrides(data.root)
    assert prune(data) == 1
    assert RETIRED_AT < LATER
