"""F5 S2b fix round 1: plan, resume watermark, stale drop, merge, stalls, survivors.

Shares the helpers of test_f5_new_device_sweep.py. Never regenerate goldens.
"""

from __future__ import annotations

import re
import sqlite3
import time
import uuid

import pytest
from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from test_f5_new_device_sweep import (
    DAY,
    DWELL,
    MAC,
    arrive,
    device_of,
    events,
    incidents,
    macs,
    meas,
    run,
    staggered,
    start,
    ticks,
)

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline import new_device_notice as nd


def meta(data: Data, prefix: str) -> dict[str, str]:
    rows = data.q("SELECT key, value FROM pipeline_meta WHERE key LIKE ?", prefix + "%")
    return {r[0]: r[1] for r in rows}


def link(data: Data, from_mac: str, into_mac: str) -> None:
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(
        "INSERT INTO identity_links VALUES (?,?,'m','t','u',NULL)",
        (device_of(data, from_mac), device_of(data, into_mac)),
    )
    ov.commit()
    ov.close()


# ---- A: the candidate queries never scan the measurement or activity tables --------------------
def test_candidate_queries_use_the_primary_key_not_a_scan_per_candidate(data):
    start(data)
    p = (iso_utc(T0), nd.NOTICED, nd.SKIPPED, DWELL, 2, T0, 21)
    for sql, params in (
        (nd.FRESH_SQL, p),
        (nd.STALE_SQL, p),
        (nd.UNMEASURED_SQL, p),
        (nd._COLLECTOR, (MAC,)),
    ):
        plan = " | ".join(r[3] for r in data.inv.execute("EXPLAIN QUERY PLAN " + sql, params))
        assert not re.search(r"SCAN (m|a)\b", plan), plan


def test_thousands_of_unmeasured_candidates_stay_cheap_and_do_not_starve_the_queue(data):
    start(data)
    forged = macs(2000, "00:de:ad")
    for i, mac in enumerate(forged):
        data.inv.execute(
            "INSERT INTO devices(id,first_seen,last_seen) VALUES (?,?,?)",
            (f"dev-{i}", iso_utc(T0), iso_utc(T0)),
        )
        data.inv.execute(
            "INSERT INTO observations(mac,device_id,is_randomized,link_source,first_seen,last_seen)"
            " VALUES (?,?,0,'self',?,?)",
            (mac, f"dev-{i}", iso_utc(T0), iso_utc(T0)),
        )
    data.inv.executemany("INSERT INTO mac_first_received VALUES (?,?)", [(m, T0) for m in forged])
    data.inv.executemany(
        "INSERT INTO mac_activity VALUES (?,?,?)", [(m, T0, T0 + DWELL) for m in forged]
    )
    data.inv.executemany(
        "INSERT INTO measurements_hourly VALUES ('rtr-1',?,?,1,1,1,0)",
        [(f"aa:00:00:00:{i >> 8:02x}:{i & 255:02x}", T0 // HOUR * HOUR - i * HOUR)
         for i in range(30000)],
    )  # fmt: skip
    data.add_batch(T0)  # records the collector
    arrive(data, "00:1a:2b:77:00:01", at=T0 + 60)
    began = time.monotonic()
    run(data, T0 + DWELL + 100)
    assert time.monotonic() - began < 5
    assert len(incidents(data)) == 1  # the measured real device is not starved by 2000 others


# ---- B: resume watermark (the real on/off/on test lives in test_f5_new_device_sweep.py) ---------
def test_flag_off_still_writes_no_f5_key(data):
    start(data)
    before = meta(data, "f5_")
    run(data, T0 + 100, new_device_notice=False)
    assert meta(data, "f5_") == before


def test_a_short_gap_does_not_move_the_watermark(data):
    start(data)
    run(data, T0 + 5 * HOUR)  # inside RESUME_GAP_S (6 h)
    assert meta(data, "f5_enabled_since") == {"f5_enabled_since": str(T0 - 60)}


def test_a_gap_longer_than_resume_gap_counts_as_a_reenable(data):
    start(data)
    run(data, T0 + 6 * HOUR + 1)
    assert meta(data, "f5_enabled_since") == {"f5_enabled_since": str(T0 + 6 * HOUR + 1)}


def test_the_first_ever_run_sets_both_keys(data):
    start(data)
    assert meta(data, "f5_") == {
        "f5_enabled_since": str(T0 - 60),
        "f5_last_run": str(T0 - 60),
    }


def test_an_outage_longer_than_the_gap_never_notifies_what_arrived_during_it(data):
    start(data)
    arrive(data, MAC, at=T0 + 7 * HOUR)  # arrived while the pipeline was down
    run(data, T0 + 7 * HOUR + DWELL + 1)  # the first run after the outage
    assert incidents(data) == []


# ---- C: stale held devices are dropped, not announced late -------------------------------------
def test_held_devices_older_than_72h_are_dropped_and_a_fresh_one_is_noticed(data):
    start(data)
    staggered(data, 25)
    ticks(data, T0 + DWELL + 300, T0 + 76 * HOUR)
    assert len(incidents(data)) == 12  # 3 a day on UTC days 1-4, all within 72 h
    stale = [k for k, v in meta(data, "f5_skipped:").items() if v.endswith(" stale")]
    assert len(stale) == 13  # the rest of the 25
    fresh = "00:1a:2b:88:00:01"
    arrive(data, fresh, at=T0 + 76 * HOUR)
    ticks(data, T0 + 76 * HOUR + DWELL, T0 + 84 * HOUR)
    assert len(incidents(data)) == 13
    assert incidents(data)[-1]["device_id"] == device_of(data, fresh)
    capped = events(data, "new_device_capped")
    assert capped and all("held or dropped" in e["summary"] for e in capped)


# ---- D: a merge after a notice never makes a second incident -----------------------------------
def test_merging_a_noticed_device_into_a_held_one_does_not_notice_the_second(data):
    start(data, new_device_max_per_day=1)
    b, c = "00:1a:2b:00:01:01", "00:1a:2b:00:01:02"
    arrive(data, b, at=T0)
    arrive(data, c, at=T0 + 10)
    run(data, T0 + DWELL + 100, new_device_max_per_day=1)
    assert len(incidents(data)) == 1  # B noticed, C held
    link(data, b, c)  # the owner links B into C
    ticks(data, T0 + DWELL + 200, T0 + DWELL + 200 + 2 * DAY, new_device_max_per_day=1)
    assert len(incidents(data)) == 1
    assert meta(data, "f5_skipped:")[f"f5_skipped:{device_of(data, c)}"].endswith(" merged")


# ---- E: silent stalls --------------------------------------------------------------------------
def test_a_device_whose_lineage_keeps_failing_is_skipped_and_never_blocks_the_others(
    data, monkeypatch
):
    start(data)
    bad = "00:1a:2b:00:02:01"
    for i, mac in enumerate([bad, "00:1a:2b:00:02:02", "00:1a:2b:00:02:03"]):
        arrive(data, mac, at=T0 + i * 10)
    run(data, T0 + 10, new_device_notice=False)  # the devices exist; the sweep is off
    bad_id = device_of(data, bad)
    real = nd.lineage

    def flaky(inv, ov, device):
        if device == bad_id:
            raise nd.LineageUnavailable("too large")
        return real(inv, ov, device)

    monkeypatch.setattr(nd, "lineage", flaky)
    run(data, T0 + DWELL + 100)
    assert len(incidents(data)) == 2  # the others were noticed in the very first run
    assert meta(data, "f5_retry:") == {f"f5_retry:{bad_id}": "1"}
    run(data, T0 + DWELL + 130)
    run(data, T0 + DWELL + 160)
    assert meta(data, "f5_skipped:")[f"f5_skipped:{bad_id}"].endswith(" lineage_unavailable")
    assert meta(data, "f5_retry:") == {}  # bounded: the counter is dropped with the skip


def test_a_missing_lineage_table_is_systemic_and_skips_nobody(data):
    start(data)
    arrive(data, MAC)
    ov = open_overrides(data.root / "overrides.db")
    ov.execute("DROP TABLE monitoring_lineage_versions")
    ov.commit()
    ov.close()
    for step in range(5):
        run(data, T0 + DWELL + 1 + step * 30)
    assert incidents(data) == [] and meta(data, "f5_skipped:") == {}
    assert meta(data, "f5_retry:") == {}  # nobody was blamed


def test_a_failing_decision_store_is_logged_and_contained(data, caplog):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    ov = open_overrides(data.root / "overrides.db")
    ov.execute("DROP TABLE incident_decisions")
    ov.commit()
    ov.close()
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + DWELL + 60)
    assert "new_device_close_failed" in caplog.text
    assert incidents(data)[0]["state"] == "open"


def test_unmeasured_devices_are_counted_in_a_log_line_without_macs(data, caplog):
    start(data)
    arrive(data, MAC, measured=False)
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + DWELL + 1)
    assert "new_device_unmeasured" in caplog.text and MAC not in caplog.text


# ---- F: survivors ------------------------------------------------------------------------------
def test_a_returning_pre_watermark_device_never_notifies(data):
    """Only the d.first_seen >= watermark guard stops this: the flag goes on after the device's
    activity anchor expired, so the device is never a candidate before it returns; its fresh
    receipt anchor then looks new while the device row keeps its old first_seen."""
    arrive(data, MAC, at=T0 - 12 * DAY)
    ticks(data, T0 - 12 * DAY + DWELL + 1, T0 - 120, step=5 * HOUR, new_device_notice=False)
    assert data.q("SELECT * FROM mac_first_received") == []  # the anchor expired (7 d retention)
    start(data)
    arrive(data, MAC, at=T0)
    ticks(data, T0 + DWELL + 1, T0 + DWELL + 7 * 60, step=60)
    assert incidents(data) == [] and meta(data, "f5_skipped:") == {}


def test_a_device_first_received_before_the_watermark_never_notifies(data):
    """Collector stamps after the watermark cannot make a device new: its receipt anchor decides."""
    since = T0 + 1000
    run(data, since)
    data.add_batch(since + 10, neigh=[MAC], received=since - 100)
    data.add_batch(since + 10 + DWELL, neigh=[MAC])
    meas(data, MAC)
    run(data, since + DWELL + 20)
    assert incidents(data) == []


def test_a_device_merged_into_an_unmeasured_newer_one_is_not_noticed(data):
    """Only the canonical-device check stops this: both MACs are post-watermark and nobody was
    noticed, so the freshness and already-noticed checks pass."""
    start(data)
    a, b = "00:1a:2b:00:03:01", "00:1a:2b:00:03:02"
    data.add_batch(T0, neigh=[a, b])
    meas(data, b)  # A is never measured, so it is never a candidate itself
    run(data, T0 + 60)
    link(data, b, a)
    data.add_batch(T0 + DWELL, neigh=[a, b])
    run(data, T0 + DWELL + 100)
    assert incidents(data) == []
    assert meta(data, "f5_skipped:")[f"f5_skipped:{device_of(data, b)}"].endswith(" merged")


def test_a_run_reads_at_most_twenty_devices_and_reports_the_held_one(data):
    start(data, new_device_max_per_day=20)
    staggered(data, 30)
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert len(incidents(data)) == 20
    (capped,) = events(data, "new_device_capped")
    assert "; 1 held or dropped" in capped["summary"]  # 21 read, 20 handled: the bound is 20


def test_a_database_error_mid_sweep_is_contained_and_the_next_run_works(data, monkeypatch):
    start(data)
    arrive(data, MAC)
    real = nd._open_incident
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(nd, "_open_incident", boom)
    run(data, T0 + DWELL + 1)  # must not raise
    assert incidents(data) == [] and meta(data, "f5_noticed:") == {} and calls
    monkeypatch.setattr(nd, "_open_incident", real)
    run(data, T0 + DWELL + 30)
    assert len(incidents(data)) == 1


@pytest.mark.parametrize(
    ("dwell", "gap", "expected"),
    [(1800, 1800, 1), (600, 700, 0)],  # T0 sits 2800 s into its hour: +1800 crosses, +700 does not
)
def test_two_distinct_server_hours_are_required(data, dwell, gap, expected):
    start(data, transient_min_dwell_s=dwell)
    arrive(data, MAC, span=gap)
    run(data, T0 + gap + 10, transient_min_dwell_s=dwell)
    assert len(incidents(data)) == expected


def test_a_retired_device_is_not_noticed(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1, new_device_notice=False)
    data.inv.execute("UPDATE devices SET status='retired'")
    run(data, T0 + DWELL + 30)
    assert incidents(data) == []


def test_close_examines_close_max_open_incidents_per_run_and_all_get_their_turn(data, caplog):
    open_overrides(data.root / "overrides.db").close()
    start(data)
    ov = open_overrides(data.root / "overrides.db")
    for i in range(205):
        data.inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,"
            "evidence) VALUES (?,'rtr-1',?, 'L','new_device','open',?,?,?,NULL,0,0,'{}')",
            (f"i{i:03d}", f"d{i}", T0 // HOUR * HOUR, T0 // HOUR * HOUR, iso_utc(T0)),
        )
        ov.execute(
            "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
            "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
            " VALUES (?,'rtr-1',?, 'L','new_device',1,'expected',NULL,1,'u',?,?)",
            (f"i{i:03d}", f"d{i}", iso_utc(T0), str(uuid.uuid4())),
        )
    ov.commit()
    ov.close()

    def resolved() -> int:
        sql = "SELECT COUNT(*) FROM monitoring_incidents WHERE state='resolved'"
        return data.q(sql)[0][0]

    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + 30)
    assert "new_device_sweep_failed" not in caplog.text, caplog.text
    assert resolved() == 200
    run(data, T0 + 60)
    assert resolved() == 205  # the cursor wrapped: nobody starves
