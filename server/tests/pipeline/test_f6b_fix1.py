"""F6-b fix round 1: flood exclusion, active-evidence anchor, abstentions, named events,
per-mark close behaviour, and the survivors of the first mutation round."""

from __future__ import annotations

import logging
import sqlite3

import pytest
from pipeline_helpers import T0
from test_f6b_essential_absence import HOUR, Boom, Env, H, env, now_after  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_pipeline import essential_absence as ea


def events_of(env):
    return env.inv.execute(
        "SELECT kind, device_id, summary, dedup FROM events ORDER BY ts, kind"
    ).fetchall()


def junk_macs(env, device, n=70):
    for i in range(n):
        env.inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,"
            "last_seen) VALUES (?,?,0,'self',?,?)",
            (f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}", device, iso_utc(H), iso_utc(H)),
        )


def raw_incident(env, iid, device, lineage="L", episode=1, last=1):
    env.inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES (?,'c1',?,?,'essential_absence','open',?,?,?,NULL,0,0,'{}')",
        (iid, device, lineage, episode, last, iso_utc(H)),
    )


# ---- 1: a flooded hour is not an eligible hour -------------------------------------------------
FLOOD_KEYS = [
    "leases",
    "neigh",
    "sightings",
    "sightings_dropped",
    "dns",
    "dns_out_of_window",
    "truncated_other",
]


@pytest.mark.parametrize("key", FLOOD_KEYS)
def test_a_flooded_hour_does_not_advance_the_clock(env, key):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 2)
    env.batch(H + HOUR + 60, H + HOUR + 900, {key: 7})
    assert env.sweep(now_after(2)) == 0  # one clean hour only
    env.cover(3, 1)
    assert env.sweep(now_after(3)) == 1  # a normal further hour counts


def test_a_normal_batch_or_zero_counter_does_not_exclude_the_hour(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 2)
    env.batch(H + HOUR + 60, H + HOUR + 900, {})
    env.batch(H + 2 * HOUR + 60, H + 2 * HOUR + 900, {"leases": 0, "ct_unmapped_flows": 4})
    assert env.sweep(now_after(2)) == 1


def test_a_flooded_batch_overlapping_two_hours_excludes_both(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 3)
    env.batch(H + 2 * HOUR - 100, H + 2 * HOUR + 100, {"neigh": 1})
    assert env.sweep(now_after(3)) == 0  # only hour H+3 is clean
    env.cover(4, 1)
    assert env.sweep(now_after(4)) == 1


def test_a_batch_of_another_collector_does_not_exclude_the_hour(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 2)
    env.inv.execute("INSERT INTO collectors(id,key_id) VALUES ('c2','k2')")
    env.batch(H + HOUR + 60, H + HOUR + 900, {"leases": 9}, collector="c2")
    assert env.sweep(now_after(2)) == 1


# ---- 2: only ACTIVE evidence anchors -----------------------------------------------------------
def test_restart_re_emitted_snapshot_rows_neither_move_the_anchor_nor_close(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.seen("d1", H + 2 * HOUR)  # a restart re-emits leases/neighbours stamped 'now'
    assert env.sweep(now_after(2) + 5) == 0
    assert [(r["state"], r["episode_start"]) for r in env.rows()] == [("open", H)]
    env.cover(3, 5)
    env.seen("d1", H + 6 * HOUR)  # restarts more often than N hours: still no phantom return
    assert env.sweep(now_after(7)) == 0 and len(env.rows()) == 1


def test_real_activity_in_a_later_hour_is_a_return(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.active("d1", 2)
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["resolved"]


def test_accepted_later_activity_survives_a_clock_rollback(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 2)
    env.active("d1", 5)
    assert env.sweep(now_after(2)) == 0


# ---- 6: randomized MACs ------------------------------------------------------------------------
def test_a_randomized_first_mac_abstains_with_a_named_event(env):
    env.device("d1", randomized=1)
    env.mark("d1", 3600)
    env.cover(1, 30)
    assert env.sweep(now_after(30)) == 0 and env.rows() == []
    ((kind, device, summary, _),) = events_of(env)
    assert (kind, device) == ("essential_unjudged", "d1")
    assert "randomized" in summary and "00:1a" not in summary
    env.sweep(now_after(30) + 90000)
    assert len(events_of(env)) == 1  # once per mark version, not daily


def test_a_fixed_first_mac_with_an_attached_randomized_mac_is_still_judged(env):
    env.device("d1")
    env.inv.execute(
        "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen)"
        " VALUES ('aa:bb:cc:00:00:99','d1',1,'rule',?,?)",
        (iso_utc(H), iso_utc(H)),
    )
    env.mark("d1", 3600)
    env.cover(1, 2)
    assert env.sweep(now_after(2)) == 1


# ---- 5 and 8a: events name the device, once per mark version -----------------------------------
def test_unjudged_events_name_the_device_without_a_mac(env):
    env.device("d1", measured=False)
    env.mark("d1", 3600)
    env.cover(1, 3)
    env.sweep(now_after(3))
    ((kind, device, summary, _),) = events_of(env)
    assert (kind, device) == ("essential_unjudged", "d1")
    assert "d1" not in summary and "00:1a" not in summary and "measur" in summary


def test_never_measured_is_one_event_per_mark_version_not_daily(env):
    env.device("d1", measured=False)
    env.mark("d1", 3600)
    env.cover(1, 3)
    for day in range(3):
        env.sweep(now_after(3) + day * 86400)
    assert len(events_of(env)) == 1
    env.mark("d1", 7200)  # the owner touched the mark: one more
    env.sweep(now_after(3) + 5 * 86400)
    assert len(events_of(env)) == 2


# ---- 4: overflow is incomplete -----------------------------------------------------------------
def test_more_than_32_marks_is_incomplete_and_closes_nothing_as_unmarked(env):
    env.device("z")
    env.mark("z", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    assert [r["state"] for r in env.rows()] == ["open"]
    for i in range(32):
        env.device(f"a{i:02d}")
        env.mark(f"a{i:02d}", 3600)
    env.sweep(now_after(2) + 5)  # 'z' sorts after 32 marks and is omitted: not 'unmarked'
    assert [r["state"] for r in env.rows() if r["device_id"] == "z"] == ["open"]
    assert [e for e in events_of(env) if "too many" in e[2]]


# ---- 3: unresolvable marks ---------------------------------------------------------------------
def test_an_unresolvable_mark_does_not_block_other_marks_closes_and_is_named(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.device("big")
    junk_macs(env, "big")  # more than 64 MACs: lineage is unavailable
    env.mark("big", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    assert [r["device_id"] for r in env.rows()] == ["d1"]
    env.mark("d1", None)
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["resolved"]
    named = [e for e in events_of(env) if e[0] == "essential_unjudged"]
    assert named and all(e[1] == "big" for e in named)


def test_an_unresolvable_mark_is_never_itself_closed_as_unmarked(env):
    env.device("big")
    junk_macs(env, "big")
    env.mark("big", 3600)
    env.cover(1, 2)
    raw_incident(env, "x", "big", episode=H, last=H)
    env.sweep(now_after(2))
    assert [r["state"] for r in env.rows()] == ["open"]


def test_a_device_without_any_known_mac_is_named_not_closed(env):
    env.mark("ghost", 3600)
    env.device("d1")
    env.cover(1, 2)
    env.sweep(now_after(2))
    named = [e for e in events_of(env) if e[0] == "essential_unjudged"]
    assert [e[1] for e in named] == [None] or [e[1] for e in named] == ["ghost"]


# ---- 7: survivors of the first round -----------------------------------------------------------
def test_an_alias_mark_is_judged_on_the_canonical_device_across_two_sweeps(env):
    env.device("canon")
    env.device("alias")
    env.merge("alias", "canon")
    env.mark("alias", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.sweep(now_after(2) + 5)
    assert [(r["device_id"], r["state"]) for r in env.rows()] == [("canon", "open")]


def test_an_alias_incident_is_merged_away_once_and_never_re_announced(env):
    env.device("canon")
    env.device("alias")
    env.mark("alias", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.merge("alias", "canon")
    env.sweep(now_after(2) + 5)
    env.sweep(now_after(2) + 10)
    assert [(r["device_id"], r["state"]) for r in env.rows()] == [("alias", "resolved")]


def test_an_out_of_range_mark_blocks_close_on_unmark_of_its_device(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.ovw.execute("PRAGMA ignore_check_constraints=ON")
    env.ovw.execute("UPDATE essential_devices SET absent_after_s=10, version=version+1")
    env.ovw.commit()
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["open"]  # marked, merely invalid


def test_an_open_incident_beyond_the_examined_window_is_never_duplicated(env, monkeypatch):
    monkeypatch.setattr(ea, "MAX_OPEN", 3)
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    for i in range(3):
        raw_incident(env, f"j{i}", f"junk{i}")
    raw_incident(env, "real", "d1", lineage="OLDKEY", episode=H - 7200, last=H)
    assert env.sweep(now_after(2)) == 0  # the open row is beyond the window: no second insert
    assert len([r for r in env.rows() if r["device_id"] == "d1"]) == 1


def test_nothing_to_write_opens_no_write_transaction(env):
    env.device("d1")
    env.mark("d1", 2 * 3600)
    env.cover(1, 1)
    seen: list[str] = []
    env.inv.set_trace_callback(seen.append)
    env.sweep(now_after(1))
    env.inv.set_trace_callback(None)
    assert not [s for s in seen if s.lstrip().upper().startswith(("BEGIN", "INSERT", "UPDATE"))]


# ---- 8b, 8d ------------------------------------------------------------------------------------
def test_a_lineage_with_no_macs_closes_the_incident_as_merged(env):
    env.device("d1")
    env.mark("d1", 3600)
    env.cover(1, 2)
    env.sweep(now_after(2))
    env.inv.execute("DELETE FROM observations WHERE device_id='d1'")
    env.sweep(now_after(2) + 5)
    assert [r["state"] for r in env.rows()] == ["resolved"]


def test_a_failing_sweep_logs_error_once_per_day(env, caplog):
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        for i in range(3):
            ea.sweep_essential_absence(env.inv, Boom(sqlite3.OperationalError("x")), T0 + i)
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 1


def test_the_failure_event_carries_the_class_name_only(env):
    ea.sweep_essential_absence(env.inv, Boom(sqlite3.OperationalError("path /secret")), T0)
    rows = env.inv.execute("SELECT summary FROM events WHERE kind='essential_failed'").fetchall()
    assert len(rows) == 1 and "OperationalError" in rows[0][0] and "secret" not in rows[0][0]
