"""Review round: type-confusion hardening, orphan closing, reader-side bounds, idle passes."""

from __future__ import annotations

import json
import logging
import sqlite3

import pytest
from probe_helpers import (
    NOW,
    build_fixture,
    dump,
    run_fixture,
    state_doc,
    target_state,
    write_probe_file,
)
from test_probes import DAY, START, events, fold, inv, kinds, outage, recovered, settings, status  # noqa: F401

from vigie_pipeline import probes
from vigie_pipeline.probe_file import ProbeFileInvalid, parse_probe_doc


@pytest.fixture(autouse=True)
def _reset_log_memory():
    probes._last_invalid = None
    yield
    probes._last_invalid = None


def raw(**over) -> bytes:
    return json.dumps(state_doc(target_state(**over))).encode()


# ---------------------------------------------------------------- 1: type confusion
CONFUSED = {}
for field in ("state", "note", "last_error_class"):
    for label, value in (("list", []), ("dict", {}), ("nested", [[]]), ("int", 5), ("bool", True)):
        CONFUSED[f"{field}_{label}"] = raw(**{field: value})
for position in range(4):
    for label, value in (("list", []), ("dict", {})):
        entry = [1, False, None, None]
        entry[position] = value
        CONFUSED[f"ring{position}_{label}"] = raw(ring=[entry])
CONFUSED |= {
    "ring_issue_example": raw(ring=[[1, False, None, []]]),
    "ring_bool_minute": raw(ring=[[True, False, None, None]]),
    "ring_str_minute": raw(ring=[["1", False, None, None]]),
    "ring_ok_int": raw(ring=[[1, 1, None, None]]),
    "str_count": raw(consecutive_fail="3"),
    "str_epoch": raw(last_ok_at="1"),
    "bool_count": raw(consecutive_fail=True),
    "id_list": raw(id=[]),
    "day_list": raw(episodes_day=[]),
    "flag_list": raw(flapping=[]),
    "suppressed_str": raw(suppressed="no"),
}


@pytest.mark.parametrize("name", sorted(CONFUSED))
def test_type_confused_values_are_invalid_not_a_crash(name):
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(CONFUSED[name])


@pytest.mark.parametrize("name", ["state_list", "last_error_class_dict", "ring3_list"])
def test_corrupt_file_after_an_ok_status_turns_it_unavailable(inv, settings, name):
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    assert status(inv)["stale"] is False
    write_probe_file(settings.file, CONFUSED[name])
    fold(inv, settings, now=NOW + 35)
    snap = status(inv)
    assert (snap["stale"], snap["reason"], snap["targets"]) == (True, "invalid", [])
    assert kinds(inv) == ["probe_stale"]


def test_unexpected_exception_in_the_parser_is_invalid_not_a_crash(monkeypatch):
    def boom(_):
        raise TypeError("unhashable")

    monkeypatch.setattr("vigie_pipeline.probe_file._target", boom)
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(json.dumps(state_doc(target_state())).encode())


# ---------------------------------------------------------------- 2: orphan outages close
def test_outage_superseded_by_a_newer_episode_is_closed(inv, settings):
    write_probe_file(settings.file, state_doc(outage(episode_start=int(NOW) - 900)))
    fold(inv, settings)
    old = int(NOW) - 900
    # the file goes stale; the runner recovers meanwhile and opens a newer episode
    newer = outage(episode_start=int(NOW) - 100)
    write_probe_file(settings.file, state_doc(newer))
    fold(inv, settings)
    got = {(e[0], e[3]): e[2] for e in events(inv)}
    assert ("probe_recovered", f"router-dns:{old}") in got
    assert "superseded" in got[("probe_recovered", f"router-dns:{old}")]
    assert ("probe_outage", f"router-dns:{int(NOW) - 100}") in got
    assert ("probe_recovered", f"router-dns:{int(NOW) - 100}") not in got  # still open
    before = events(inv)
    fold(inv, settings)
    assert events(inv) == before  # replay-safe


def test_outage_of_a_removed_target_is_closed(inv, settings):
    write_probe_file(settings.file, state_doc(outage(), target_state("lan-web")))
    fold(inv, settings)
    write_probe_file(settings.file, state_doc(target_state("lan-web")))
    fold(inv, settings)
    closed = [e for e in events(inv) if e[0] == "probe_recovered"]
    assert [(e[3], "removed" in e[2]) for e in closed] == [(f"router-dns:{START}", True)]
    fold(inv, settings)
    assert len([e for e in events(inv) if e[0] == "probe_recovered"]) == 1


def test_an_open_outage_of_a_present_unchanged_target_is_not_closed(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    for _ in range(3):
        fold(inv, settings)
    assert kinds(inv) == ["probe_outage"]


def test_no_closing_while_the_file_is_unavailable(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    fold(inv, settings, now=NOW + 1000)  # stale
    assert kinds(inv) == ["probe_outage", "probe_stale"]


def test_missed_recover_is_closed_by_the_next_episode(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    later = outage(episode_start=START + 150, last_error_class="refused")
    write_probe_file(settings.file, state_doc(later))  # recovered and failed again unseen
    fold(inv, settings)
    assert kinds(inv).count("probe_recovered") == 1


def test_oscillating_episodes_each_get_one_open_and_one_close(inv, settings):
    for n in range(3):
        start = START + n * 40
        write_probe_file(settings.file, state_doc(outage(episode_start=start)))
        fold(inv, settings, now=NOW + 5 + n)
        write_probe_file(settings.file, state_doc(recovered(episode_start=start)))
        fold(inv, settings, now=NOW + 5 + n)
    assert kinds(inv).count("probe_outage") == 3 and kinds(inv).count("probe_recovered") == 3
    fold(inv, settings)
    assert kinds(inv).count("probe_outage") == 3


# ---------------------------------------------------------------- 4: reader-side bounds
def test_episode_start_after_written_at_is_invalid():
    future = raw(episode_start=int(NOW) + 10 * 86400)
    with pytest.raises(ProbeFileInvalid):
        parse_probe_doc(future)
    parse_probe_doc(raw(episode_start=int(NOW)))  # equal is fine


def test_no_events_when_episodes_day_is_not_the_day_of_written_at(inv, settings):
    write_probe_file(settings.file, state_doc(outage(episodes_day="2027-01-14")))
    fold(inv, settings)
    assert events(inv) == []
    write_probe_file(settings.file, state_doc(outage(episodes_day=None)))
    fold(inv, settings)
    assert events(inv) == []
    write_probe_file(settings.file, state_doc(outage(episodes_day=DAY)))
    fold(inv, settings)
    assert kinds(inv) == ["probe_outage"]


def test_flapping_needs_the_matching_day_too(inv, settings):
    write_probe_file(
        settings.file, state_doc(outage(flapping=True, suppressed=True, episodes_day="2027-01-14"))
    )
    fold(inv, settings)
    assert events(inv) == []


def test_at_most_three_outage_events_per_target_per_day(inv, settings):
    for n in range(10):  # a writer that ignores its own cap
        write_probe_file(settings.file, state_doc(outage(episode_start=START + n)))
        fold(inv, settings)
    assert kinds(inv).count("probe_outage") == 3


def test_the_cap_is_per_target_and_per_day(inv, settings):
    for n in range(5):
        a, b = outage(episode_start=START + n), outage(episode_start=START + n)
        b["id"] = "lan-web"
        write_probe_file(settings.file, state_doc(a, b))
        fold(inv, settings)
    assert kinds(inv).count("probe_outage") == 6
    tomorrow = outage(episode_start=int(NOW) + 86400 - 50, episodes_day="2027-01-16")
    write_probe_file(settings.file, state_doc(tomorrow, written_at=NOW + 86400))
    fold(inv, settings, now=NOW + 86405)
    assert kinds(inv).count("probe_outage") == 7


def test_cap_matches_ids_with_underscores_exactly(inv, settings):
    for ident in ("a_b", "axb"):  # '_' must not act as a LIKE wildcard
        for n in range(3):
            t = outage(episode_start=START + n)
            t["id"] = ident
            write_probe_file(settings.file, state_doc(t))
            fold(inv, settings)
    assert kinds(inv).count("probe_outage") == 6


# ---------------------------------------------------------------- 5: idle passes write nothing
def seq(inv) -> int:
    row = inv.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()
    return row[0] if row else 0


def test_an_idle_pass_writes_nothing_and_burns_no_rowid(inv, settings):
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    changes, rowid = inv.total_changes, seq(inv)
    for tick in range(1, 6):
        fold(inv, settings, now=NOW + 5 + tick * 30 // 10)
    assert (inv.total_changes, seq(inv)) == (changes, rowid)
    assert status(inv)["folded_at"] == int(NOW + 5)  # only folded_at differs: not rewritten


def test_a_changed_status_is_rewritten(inv, settings):
    write_probe_file(settings.file, state_doc(target_state()))
    fold(inv, settings)
    write_probe_file(settings.file, state_doc(target_state(consecutive_ok=2)))
    fold(inv, settings, now=NOW + 40)
    assert status(inv)["targets"][0]["consecutive_ok"] == 2
    assert status(inv)["folded_at"] == int(NOW + 40)


def test_an_unavailable_pass_repeated_burns_no_rowid(inv, settings):
    fold(inv, settings)
    changes, rowid = inv.total_changes, seq(inv)
    fold(inv, settings, now=NOW + 30)
    assert (inv.total_changes, seq(inv)) == (changes, rowid)


# ---------------------------------------------------------------- 6: log once per change
def test_probe_file_invalid_is_logged_once_per_change_of_reason(inv, settings, caplog):
    def count():
        return [r.getMessage() for r in caplog.records].count("probe_file_invalid")

    write_probe_file(settings.file, b"{nope")
    with caplog.at_level(logging.WARNING, logger="vigie_pipeline"):
        for tick in range(4):
            fold(inv, settings, now=NOW + tick)
        assert count() == 1
        write_probe_file(settings.file, CONFUSED["state_list"])
        fold(inv, settings)
        assert count() == 2
        write_probe_file(settings.file, state_doc(target_state()))
        fold(inv, settings)
        write_probe_file(settings.file, CONFUSED["state_list"])
        fold(inv, settings)
        assert count() == 3  # valid in between resets the memory


# ---------------------------------------------------------------- 3 + 9: run_once level
def test_probe_stage_runs_even_when_overrides_are_unreadable(tmp_path):
    build_fixture(tmp_path)
    (tmp_path / "overrides.db").write_bytes(b"not a database" * 100)
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(tmp_path / "absent.json"))
    meta = dict(dump(tmp_path)["pipeline_meta"])
    assert json.loads(meta["probe_status"])["reason"] == "missing"


def test_repeated_run_once_is_idempotent(tmp_path):
    from probe_helpers import CURRENT

    from vigie_ingest.db import iso_utc

    build_fixture(tmp_path)
    t = outage(episode_start=int(CURRENT) - 100, episodes_day=iso_utc(CURRENT + 3600)[:10])
    probe_file = write_probe_file(
        tmp_path / "probe-state.json", state_doc(t, written_at=CURRENT + 3600)
    )
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(probe_file))
    skip = ("characterization_cursor",)  # moves on the pipeline's first pass, not ours
    first = dump(tmp_path, exclude_meta=skip)
    for _ in range(3):
        run_fixture(tmp_path, VIGIE_PROBE_FILE=str(probe_file))
    assert dump(tmp_path, exclude_meta=skip) == first
    assert [e[0] for e in first["events"]] == ["probe_outage"]
    conn = sqlite3.connect(tmp_path / "inventory.db")
    try:
        assert (
            conn.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()[0] == 1
        )  # no burnt rowids
    finally:
        conn.close()
