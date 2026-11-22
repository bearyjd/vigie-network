"""The owner's decision on a suggestion lives only in overrides.db, keyed by suggestion id: the
devices it concerns come from the inventory's suggestions row. Whatever the action, and expired or
not, a decided suggestion keeps the MAC rows of every device it names."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_exclusions import EXPIRED, LIVE
from test_prune_guards import LATER, STAMP, migrated_overrides, prune, retire, rows, sql

from vigie_ingest.db import iso_utc
from vigie_pipeline import prune_exclusions
from vigie_pipeline.overrides import OverridesNotUsable, decided_suggestion_ids, open_overrides_ro
from vigie_pipeline.prune import OVERRIDES_SEEN_KEY

DECIDE = (
    "INSERT INTO suggestion_decisions (suggestion_id, state, decided_by, decided_at)"
    " VALUES (?1, ?2, 'u', ?3)"
)
SUGGEST = (
    "INSERT INTO suggestions (id, action, device_ids, payload, reason_code, basis, created_at,"
    " expires_at) VALUES ('s1', ?, ?, '[]', 'rc', 'b', 'x', ?)"
)
ACTIONS = {
    "merge_from": ("merge_identity", '["{dev}","z"]'),
    "merge_into": ("merge_identity", '["z","{dev}"]'),
    "label": ("label", '["{dev}"]'),
    "move_group": ("move_group", '["{dev}"]'),
    "quarantine": ("quarantine", '["{dev}"]'),
}


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def suggest(data, key, device, expires=EXPIRED, sid="s1"):
    action, ids = ACTIONS[key]
    data.inv.execute(
        SUGGEST.replace("'s1'", f"'{sid}'"), (action, ids.replace("{dev}", device), expires)
    )


@pytest.mark.parametrize("state", ["accepted", "rejected"])
@pytest.mark.parametrize("key", ACTIONS)
def test_a_decided_expired_suggestion_keeps_the_row_of_every_device_it_names(data, key, state):
    macs = retire(data, count=2)
    kept, free = sorted(macs)
    path = migrated_overrides(data.root)
    suggest(data, key, macs[kept])
    sql(path, DECIDE, "s1", state, STAMP)
    assert prune(data) == 1
    assert [r["mac"] for r in data.q("SELECT mac FROM observations")] == [kept]
    assert free != kept


@pytest.mark.parametrize("key", ACTIONS)
def test_an_undecided_expired_suggestion_of_any_action_does_not_pin(data, key):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    suggest(data, key, device)
    assert prune(data) == 1


@pytest.mark.parametrize("key", ACTIONS)
def test_an_undecided_live_suggestion_of_any_action_pins(data, key):
    ((mac, device),) = retire(data).items()
    migrated_overrides(data.root)
    suggest(data, key, device, expires=LIVE)
    assert prune(data) == 0
    assert rows(data) == 1


def test_a_decided_suggestion_naming_two_retired_devices_keeps_both(data):
    macs = retire(data, count=2)
    first, second = sorted(macs.values())
    path = migrated_overrides(data.root)
    data.inv.execute(SUGGEST, ("merge_identity", f'["{first}","{second}"]', EXPIRED))
    sql(path, DECIDE, "s1", "rejected", STAMP)
    assert prune(data) == 0
    assert rows(data) == 2


def test_a_decision_for_a_suggestion_the_inventory_no_longer_has_protects_nothing_else(data):
    retire(data)
    sql(migrated_overrides(data.root), DECIDE, "gone", "rejected", STAMP)
    assert prune(data) == 1


def test_a_decided_suggestion_does_not_pin_an_unrelated_device(data):
    macs = retire(data, count=2)
    kept, free = sorted(macs)
    path = migrated_overrides(data.root)
    suggest(data, "label", macs[kept])
    sql(path, DECIDE, "s1", "accepted", STAMP)
    prune(data)
    assert free not in [r["mac"] for r in data.q("SELECT mac FROM observations")]


@pytest.mark.parametrize("raw", ['{"a": 1}', "[1, 2]", '[""]', "null"])
def test_a_decided_suggestion_whose_device_list_cannot_be_read_fails_the_prune_closed(
    data, caplog, raw
):
    retire(data)
    path = migrated_overrides(data.root)
    data.inv.execute(SUGGEST, ("label", raw, EXPIRED))
    sql(path, DECIDE, "s1", "accepted", STAMP)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert "prune_skipped" in caplog.text
    assert rows(data) == 1


@pytest.mark.parametrize("raw", ["not json{", "", None, b"\xff"], ids=repr)
def test_a_device_list_that_is_not_json_fails_closed(raw):
    """The inventory's own JSON index refuses to store such a value, so this guards a damaged
    file: an unreadable list must never read as "names no device"."""
    with pytest.raises(OverridesNotUsable):
        prune_exclusions._devices_of(raw)


def test_a_decided_suggestion_id_that_is_not_text_fails_the_prune_closed(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    sql(path, DECIDE, b"\x01", "accepted", STAMP)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert rows(data) == 1


def test_a_missing_suggestion_decisions_table_prunes_nothing(data):
    retire(data)
    sql(migrated_overrides(data.root), "DROP TABLE suggestion_decisions")
    assert prune(data) == 0
    assert rows(data) == 1


def test_decided_suggestion_ids_reads_every_decision(data):
    path = migrated_overrides(data.root)
    sql(path, DECIDE, "a", "accepted", STAMP)
    sql(path, DECIDE, "b", "rejected", STAMP)
    conn = open_overrides_ro(path)
    assert decided_suggestion_ids(conn) == {"a", "b"}
    conn.close()
    with pytest.raises(OverridesNotUsable):
        decided_suggestion_ids(None)


def test_many_decided_suggestions_are_looked_up_in_chunks_none_skipped(data, monkeypatch):
    macs = retire(data, count=5)
    path = migrated_overrides(data.root)
    monkeypatch.setattr(prune_exclusions, "SUGGESTION_ID_CHUNK", 2)
    for n, device in enumerate(sorted(macs.values())):
        suggest(data, "label", device, sid=f"x{n}")
        sql(path, DECIDE, f"x{n}", "rejected", STAMP)
    assert prune(data) == 0
    assert rows(data) == 5


def test_a_decision_on_a_suggestion_alone_sets_the_lost_overrides_marker(data):
    retire(data)
    sql(migrated_overrides(data.root), DECIDE, "s9", "rejected", STAMP)
    prune(data)
    assert [
        r[0] for r in data.q("SELECT value FROM stitch_state WHERE key=?", OVERRIDES_SEEN_KEY)
    ] == ["1"]
    assert iso_utc(LATER) > STAMP


def test_the_suggestion_id_chunk_fits_sqlite_variable_limit():
    limit = sqlite3.connect(":memory:").getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
    assert 0 < prune_exclusions.SUGGESTION_ID_CHUNK <= limit
