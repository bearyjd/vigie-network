"""F6-b fix round 2: pins for the guards the mutation rounds found unpinned (constants, bounds,
lineage rules, event keys, close guards)."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from test_f6b_essential_absence import HOUR, Boom, H, env, logged, now_after  # noqa: F401
from test_f6b_fix1 import raw_incident
from test_f6b_fix2 import two_hours

from vigie_api import essential as api_essential
from vigie_ingest.db import iso_utc
from vigie_pipeline import essential_absence as ea


def events(env, kind=None):
    sql = "SELECT kind, severity, device_id, summary, dedup FROM events"
    sql += " WHERE kind=?" if kind else " WHERE ?1 IS NULL"
    return [tuple(r) for r in env.inv.execute(sql + " ORDER BY dedup", (kind,))]


def unjudged(env):
    return [e[4] for e in events(env, "essential_unjudged")]


# ---- constants (R1-18, R1-20) ---------------------------------------------------------------
def test_the_documented_limits_are_pinned():
    assert (ea.MAX_PER_DAY, ea.MAX_MARKS, ea.MAX_OPEN) == (8, 32, 65)
    assert (ea.MIN_S, ea.MAX_S, ea.MAX_MARKS) == (
        api_essential.MIN_S,
        api_essential.MAX_S,
        api_essential.MAX_ESSENTIAL,
    )
    assert (ea.MIN_S, ea.MAX_S) == (3600, 604800)  # fmt: skip


def test_32_marks_open_exactly_eight_incidents_the_first_day(env):
    for i in range(32):
        env.device(f"d{i:02d}")
        env.mark(f"d{i:02d}", 3600)
    env.cover(1, 3)
    env.sweep(now_after(3))
    assert len(env.rows()) == 8
    assert [e[4] for e in events(env, "essential_capped")] == [iso_utc(now_after(3))[:10]]


def test_the_cap_event_is_written_when_a_held_device_is_the_only_work(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 0)
    two_hours(env)
    assert env.sweep(now_after(2)) == 0 and env.rows() == []
    (cap,) = events(env, "essential_capped")
    assert cap[1] == "warn" and "0/day" in cap[3] and "1 held" in cap[3]


def test_the_cap_event_is_once_per_day_whatever_the_held_count(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 0)
    for i in range(3):
        env.device(f"d{i}")
        env.mark(f"d{i}", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.mark("d0", None)  # the held count changes from 3 to 2
    env.sweep(now_after(2) + 5)
    assert len(events(env, "essential_capped")) == 1
    env.sweep(now_after(2) + 86400)  # the next UTC day: a new event
    assert len(events(env, "essential_capped")) == 2


# ---- marks: bounds, types, overflow, smallest threshold (R1-21, R1-22) ---------------------------
@pytest.mark.parametrize(("canon", "alias"), [("m2", "m1"), ("m1", "m2")])  # alias first, last
def test_the_smallest_threshold_of_a_lineage_wins_whatever_the_id_order(env, canon, alias):
    env.device(canon)
    env.device(alias)
    env.mark(alias, 604800)
    env.mark(canon, 3600)
    env.merge(alias, canon)
    env.cover(1, 2)
    assert env.sweep(now_after(2)) == 1
    assert {json_threshold(r) for r in env.rows()} == {1}


def json_threshold(row) -> int:
    import json

    return json.loads(row["evidence"])["threshold_hours"]


def test_exactly_32_marks_is_complete_33_is_an_overflow(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_PER_DAY", 100)
    for i in range(33):
        env.device(f"d{i:02d}")
        env.mark(f"d{i:02d}", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    assert len(env.rows()) == 32 and "d32" not in {r["device_id"] for r in env.rows()}
    assert any("too many" in e[3] for e in events(env, "essential_unjudged"))


def test_exactly_32_marks_read_completely_allows_unmark_closes(env):
    for i in range(32):
        env.device(f"d{i:02d}")
        env.mark(f"d{i:02d}", 3600)
    env.device("gone")
    raw_incident(env, "j1", "gone")
    env.cover(1, 2)
    env.sweep(now_after(2))
    assert not any("too many" in e[3] for e in events(env, "essential_unjudged"))
    assert (
        env.inv.execute("SELECT state FROM monitoring_incidents WHERE id='j1'").fetchone()[0]
        == "resolved"
    )


@pytest.mark.parametrize(
    ("device", "secs", "version"),
    [("dv", 7200, "x")],  # a REAL or int in these columns is coerced by SQLite affinity
)
def test_marks_of_the_wrong_stored_type_are_not_judged(env, device, secs, version):
    env.device("dv")
    env.cover(1, 5)
    env.ovw.execute("PRAGMA ignore_check_constraints=ON")
    env.ovw.execute("INSERT INTO essential_devices VALUES (?,?,'t','u',?)", (device, secs, version))
    env.ovw.commit()
    assert env.sweep(now_after(5)) == 0 and env.rows() == []


def test_an_invalid_mark_on_a_merged_alias_protects_the_canonical_device(env):
    env.device("canon")
    env.device("alias")
    env.cover(1, 2)
    env.mark("canon", 3600)
    env.sweep(now_after(2))
    env.merge("alias", "canon")
    env.ovw.execute("PRAGMA ignore_check_constraints=ON")
    env.ovw.execute("UPDATE essential_devices SET absent_after_s=NULL, version=version+1")
    env.ovw.execute("INSERT INTO essential_devices VALUES ('alias',5,'t','u',1)")
    env.ovw.commit()
    env.sweep(now_after(2) + 5)  # the only mark is unusable: nothing may close as 'unmarked'
    assert [r["state"] for r in env.rows()] == ["open"]


# ---- _announced and _open_ids guards (R1-25) --------------------------------------------------
def foreign_incident(env, iid, device, episode, detector="essential_absence", collector="c1"):
    env.inv.execute("PRAGMA foreign_keys=OFF")
    raw_incident(env, iid, device, lineage=iid, episode=episode)
    env.inv.execute(
        "UPDATE monitoring_incidents SET detector=?, collector_id=?, state='resolved' WHERE id=?",
        (detector, collector, iid),
    )


@pytest.mark.parametrize(
    ("device", "episode", "detector", "collector", "suppresses"),
    [("d1", H, "essential_absence", "c1", True),
     ("d1", H, "essential_absence", "ghost", False),  # a deleted collector's row
     ("d1", H - 7200, "essential_absence", "c1", False),  # another episode
     ("other", H, "essential_absence", "c1", False),  # another device
     ("d1", H, "large_upload", "c1", False)],  # another detector
)  # fmt: skip
def test_only_this_absence_of_this_lineage_suppresses_an_announcement(
    env, device, episode, detector, collector, suppresses
):
    two_hours(env)
    foreign_incident(env, "x1", device, episode, detector, collector)
    assert env.sweep(now_after(2)) == (0 if suppresses else 1)


def test_every_open_incident_of_the_device_blocks_a_second_one(env):
    two_hours(env)
    raw_incident(env, "i1", "d1", lineage="L1", episode=H + 2 * HOUR, last=H)
    raw_incident(env, "i2", "d1", lineage="L2", episode=H + HOUR, last=H)
    env.decide(env.inv.execute("SELECT * FROM monitoring_incidents WHERE id='i1'").fetchone(),
               "acknowledged")  # fmt: skip
    env.sweep(now_after(2))  # i1 closes (reviewed); i2 stays open and keeps blocking
    states = {r["id"]: r["state"] for r in env.rows()}
    assert states == {"i1": "resolved", "i2": "open"}


# ---- _reviewed failure paths and the missing overrides (R1-27) --------------------------------
def test_a_review_lookup_failure_closes_nothing_and_is_named(env, monkeypatch, caplog):
    two_hours(env)
    env.sweep(now_after(2))
    env.decide(env.rows()[0], "acknowledged")

    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ea, "decided_incident_ids", locked)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["open"]
    text = logged(caplog)
    assert "essential_absence_review_failed" in text and "OperationalError" in text
    assert "essential_absence_failed" not in text and "locked" not in text


def test_a_missing_overrides_db_is_a_silent_no_op(env, caplog):
    two_hours(env)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        assert ea.sweep_essential_absence(env.inv, None, now_after(2)) == 0
    assert env.inv.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert "essential_absence_failed" not in logged(caplog)


# ---- unjudged and failure event keys (R1-28) ---------------------------------------------------
def test_each_device_gets_its_own_event_named_for_it_at_warn(env):
    for did in ("a", "b"):
        env.device(did, measured=False)
        env.mark(did, 3600)
    env.sweep(now_after(1))
    day_events = events(env, "essential_unjudged")
    assert [(e[1], e[2], e[4]) for e in day_events] == [
        ("warn", "a", "a:never_measured:v1"), ("warn", "b", "b:never_measured:v1")]  # fmt: skip


def test_a_remark_gives_a_per_version_reason_a_new_event(env):
    env.device("nomac")
    env.inv.execute("DELETE FROM observations WHERE device_id='nomac'")
    env.mark("nomac", 3600)
    env.sweep(now_after(1))
    env.mark("nomac", 7200)
    env.sweep(now_after(1) + 5)
    assert unjudged(env) == ["nomac:no_known_mac:v1", "nomac:no_known_mac:v2"]


def test_a_daily_reason_repeats_each_day_and_not_per_version(env):
    env.mark("ghost", 3600)
    env.merge("ghost", "ghost2")
    env.merge("ghost2", "ghost")  # a cycle: its lineage is unavailable
    env.sweep(now_after(1))
    env.mark("ghost", 7200)  # new version, same day: no new event
    env.sweep(now_after(1) + 5)
    env.sweep(now_after(1) + 86400)  # next day: a new event
    reasons = [u for u in unjudged(env) if ":identity_unavailable:" in u]
    assert len(reasons) == 2 and all(r.startswith("ghost:") for r in reasons)
    assert not any(":v" in r for r in reasons)


def test_the_failure_event_repeats_each_day_and_logs_debug_after_the_first(env, caplog):
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        for dt in (0, 5, 86400):
            ea.sweep_essential_absence(env.inv, Boom(sqlite3.OperationalError("x")), H + dt)
    levels = [r.levelno for r in caplog.records if "essential_absence_failed" in r.getMessage()]
    assert levels == [logging.ERROR, logging.DEBUG, logging.ERROR]
    assert len(events(env, "essential_failed")) == 2


# ---- evidence, last_hour, close guard, first MAC (R1-29) -----------------------------------------
def test_the_threshold_hours_round_up_and_last_hour_is_the_current_hour(env):
    env.device("d1")
    env.mark("d1", 7201)
    env.cover(1, 3)
    now = now_after(3)
    env.sweep(now)
    (row,) = env.rows()
    assert '"threshold_hours": 3' in row["evidence"]
    assert row["last_hour"] == now // HOUR * HOUR and row["last_hour"] != row["episode_start"]


def test_a_close_never_overwrites_a_state_that_changed_since_the_plan(env, monkeypatch):
    two_hours(env)
    env.sweep(now_after(2))
    env.mark("d1", None)  # the incident is to close as 'unmarked'
    real = ea._plan

    def plan_then_change(inv, ov, now):
        plan = real(inv, ov, now)
        inv.execute("UPDATE monitoring_incidents SET state='suppressed'")
        return plan

    monkeypatch.setattr(ea, "_plan", plan_then_change)
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["suppressed"]


def add_mac(env, did, mac, randomized, first_seen) -> None:
    env.inv.execute(
        "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen)"
        " VALUES (?,?,?,'self',?,?)",
        (mac, did, randomized, iso_utc(first_seen), iso_utc(first_seen)),
    )


@pytest.mark.parametrize(("randomized_first", "fires"), [(False, 1), (True, 0)])
def test_the_lineages_first_mac_is_the_oldest_not_the_lowest(env, randomized_first, fires):
    env.device("d1")  # its fixed MAC (00:00:5e..) first seen at H - 1 day
    env.mark("d1", 3600)
    env.cover(1, 2)
    if randomized_first:  # the randomized MAC is older but sorts after the fixed one
        env.inv.execute("UPDATE observations SET first_seen=? WHERE device_id='d1'", (iso_utc(H),))
        add_mac(env, "d1", "7e:00:00:00:00:01", 1, H - 2 * 86400)
    else:  # the randomized MAC is newer but sorts before the fixed one (00:00:5e..)
        add_mac(env, "d1", "00:00:00:00:00:01", 1, H)
    assert env.sweep(now_after(2)) == fires


def test_a_blob_device_id_is_skipped_without_a_report(env):
    env.ovw.execute("PRAGMA ignore_check_constraints=ON")
    env.ovw.execute("INSERT INTO essential_devices VALUES (?,7200,'t','u',1)", (b"\x00blob",))
    env.ovw.commit()
    assert env.sweep(now_after(2)) == 0 and env.rows() == []
    assert env.inv.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
