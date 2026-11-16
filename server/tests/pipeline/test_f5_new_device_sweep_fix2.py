"""F5 S2b fix round 2: hold age from noticeability, clock steps, event visibility, lineage backoff,
receipt-bounded persistence, close cursor. Helpers come from the first two F5 test files.
"""

from __future__ import annotations

import uuid

from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from test_f5_new_device_sweep import (
    DAY,
    DWELL,
    MAC,
    SK,
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
    wide_gap,  # noqa: F401
)
from test_f5_new_device_sweep_fix1 import meta

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline import new_device_notice as nd


# ---- 1: the hold ages from when the device first became noticeable ------------------------------
def test_a_device_that_qualifies_late_is_noticed_not_dropped_as_stale(data):
    start(data)
    data.add_batch(T0, neigh=[MAC])  # seen for a minute, then gone
    meas(data, MAC)
    ticks(data, T0 + 60, T0 + 4 * DAY, step=5 * HOUR)
    assert incidents(data) == []
    arrive(data, MAC, at=T0 + 4 * DAY)  # back four days later, to stay
    ticks(data, T0 + 4 * DAY + DWELL + SK, T0 + 4 * DAY + DWELL + SK + 180, step=60)
    assert len(incidents(data)) == 1 and meta(data, "f5_skipped:") == {}


def test_a_device_no_collector_measured_for_days_is_noticed_once_measured(data):
    start(data)
    arrive(data, MAC, measured=False)
    ticks(data, T0 + DWELL + SK, T0 + 4 * DAY, step=5 * HOUR)
    assert incidents(data) == []
    meas(data, MAC)
    ticks(data, T0 + 4 * DAY + 60, T0 + 4 * DAY + 180, step=60)
    assert len(incidents(data)) == 1 and meta(data, "f5_skipped:") == {}


def test_a_genuinely_held_device_drops_72h_after_it_became_noticeable(data):
    start(data)
    staggered(data, 15)  # cap 3: all 15 are noticeable from the first pass
    ticks(data, T0 + DWELL + 300, T0 + 80 * HOUR)
    assert len(incidents(data)) == 12  # 3 a day on UTC days 1-4
    stale = [k for k, v in meta(data, "f5_skipped:").items() if v.endswith(" stale")]
    assert len(stale) == 3  # still unnoticed 72 h after becoming noticeable: dropped
    assert meta(data, "f5_eligible:") == {}  # nothing lingers once noticed or dropped
    fresh = "00:1a:2b:88:00:01"
    arrive(data, fresh, at=T0 + 80 * HOUR)
    ticks(data, T0 + 80 * HOUR + DWELL + SK, T0 + 90 * HOUR)
    assert incidents(data)[-1]["device_id"] == device_of(data, fresh)
    assert len(incidents(data)) == 13


# ---- 2: a clock step never pins the watermark in the future -------------------------------------
def test_a_first_run_with_the_clock_far_ahead_recovers_when_the_clock_is_corrected(data, caplog):
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + 30 * DAY)
    run(data, T0)  # corrected: this pass opens nothing and re-bases the last run
    assert meta(data, "f5_last_run") == {"f5_last_run": str(T0)}
    assert "new_device_watermark_moved" in caplog.text
    arrive(data, MAC, at=T0 + 60)
    run(data, T0 + DWELL + SK + 100)
    assert len(incidents(data)) == 1


def test_a_forward_clock_step_and_correction_does_not_disable_the_sweep(data):
    start(data)
    run(data, T0 + 10 * DAY)
    run(data, T0 + DAY)  # corrected back
    arrive(data, MAC, at=T0 + DAY + 60)
    run(data, T0 + DAY + DWELL + SK + 100)
    assert len(incidents(data)) == 1


def test_a_backward_step_skips_the_pass_and_leaves_the_floor_alone(data, caplog):
    start(data)
    run(data, T0 + 5 * HOUR)  # inside the resume gap, so only last_run moved
    floor = meta(data, "f5_floor")
    caplog.set_level("INFO", logger="vigie_pipeline")
    run(data, T0 + HOUR)  # the clock went back
    assert meta(data, "f5_floor") == floor
    assert meta(data, "f5_enabled_since") == {"f5_enabled_since": str(T0 - 60)}
    assert meta(data, "f5_last_run") == {"f5_last_run": str(T0 + HOUR)}
    assert "new_device_watermark_moved" in caplog.text


# ---- 3: event visibility ------------------------------------------------------------------------
def test_no_capped_event_when_the_cap_is_not_reached(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + SK + 10)
    assert len(incidents(data)) == 1 and events(data, "new_device_capped") == []


def test_the_capped_event_says_cap_reached_and_how_far_the_count_goes(data):
    start(data)
    staggered(data, 10)
    run(data, T0 + DWELL + 300)
    (capped,) = events(data, "new_device_capped")
    assert "cap 3/day reached; 7 held" in capped["summary"]
    assert "counted up to 200" in capped["summary"]


def test_an_unreached_cap_never_reports_held_devices(data, monkeypatch):
    start(data, new_device_max_per_day=20)
    macs_ = staggered(data, 21)  # 21 read, but 5 fail their lineage: room is left over
    run(data, T0 + 10, new_device_notice=False)
    failing(monkeypatch, {device_of(data, m) for m in macs_[:5]})
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert len(incidents(data)) == 15 and events(data, "new_device_capped") == []


def test_dropped_devices_get_their_own_cumulative_event_without_macs(data):
    start(data)
    nd._record_dropped(data.inv, "2026-10-14", 2, T0)
    nd._record_dropped(data.inv, "2026-10-14", 3, T0 + 60)
    nd._record_dropped(data.inv, "2026-10-15", 1, T0 + DAY)
    rows = events(data, "new_device_dropped")
    assert [r["summary"] for r in rows] == [
        "new-device notice: 5 held device(s) dropped as stale today",
        "new-device notice: 1 held device(s) dropped as stale today",
    ]
    assert list(meta(data, "f5_dropped:")) == ["f5_dropped:2026-10-15"]  # older days are cleaned


def test_a_stale_drop_writes_the_dropped_event(data):
    start(data)
    macs_ = staggered(data, 15)
    ticks(data, T0 + DWELL + 300, T0 + 80 * HOUR)
    (dropped,) = events(data, "new_device_dropped")
    assert "3 held device(s) dropped as stale" in dropped["summary"]
    assert not [m for m in macs_ if m in dropped["summary"]]


# ---- 4: a lineage failure backs off, never skips for good, never starves ------------------------
def failing(monkeypatch, bad_ids):
    real = nd.lineage
    calls = []

    def flaky(inv, ov, device):
        if device in bad_ids:
            calls.append(device)
            raise nd.LineageUnavailable("too large")
        return real(inv, ov, device)

    monkeypatch.setattr(nd, "lineage", flaky)
    return real, calls


def test_a_failing_lineage_backs_off_then_notices_once_it_resolves(data, monkeypatch):
    start(data)
    bad = "00:1a:2b:00:02:01"
    for i, mac in enumerate([bad, "00:1a:2b:00:02:02", "00:1a:2b:00:02:03"]):
        arrive(data, mac, at=T0 + i * 10)
    run(data, T0 + 10, new_device_notice=False)  # the devices exist; the sweep is off
    bad_id = device_of(data, bad)
    real, calls = failing(monkeypatch, {bad_id})
    now = T0 + DWELL + 100
    run(data, now)
    assert len(incidents(data)) == 2  # the others were noticed in the very first run
    assert meta(data, "f5_retry:") == {f"f5_retry:{bad_id}": f"1|{now + 3600}"}
    run(data, now + 30)
    assert len(calls) == 1  # backed off: not even tried again
    run(data, now + 3700)
    assert len(calls) == 2
    assert meta(data, "f5_retry:") == {f"f5_retry:{bad_id}": f"2|{now + 3700 + 7200}"}
    assert meta(data, "f5_skipped:") == {}  # never permanent
    monkeypatch.setattr(nd, "lineage", real)  # the lineage resolves
    run(data, now + 3700 + 7200 + 1)
    assert len(incidents(data)) == 3 and meta(data, "f5_retry:") == {}
    assert incidents(data)[-1]["device_id"] == bad_id


def test_backed_off_devices_never_starve_the_others(data, monkeypatch):
    start(data)
    macs_ = staggered(data, 26)  # 25 failing devices first, then one good one
    run(data, T0 + 10, new_device_notice=False)
    bad_ids = {device_of(data, m) for m in macs_[:25]}
    failing(monkeypatch, bad_ids)
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert incidents(data) == []  # the first 20 slots all failed and are backed off
    run(data, T0 + DWELL + 430, new_device_max_per_day=20)
    # the 5 unprocessed bad ones fail now; the good one (26th) is read in the same slice
    run(data, T0 + DWELL + 460, new_device_max_per_day=20)
    assert [r["device_id"] for r in incidents(data)] == [device_of(data, macs_[25])]


def test_the_systemic_reference_is_any_device_that_resolves(data, monkeypatch):
    start(data)
    macs_ = macs(3, "00:1a:2b:09")
    for mac in macs_:
        arrive(data, mac)
    run(data, T0 + 10, new_device_notice=False)
    ids = sorted(device_of(data, m) for m in macs_)
    failing(monkeypatch, {ids[0]})  # the lowest id is the broken one, the others resolve
    run(data, T0 + DWELL + SK + 10)
    assert len(incidents(data)) == 2  # the broken one is blamed, not the store


# ---- 5: persistence is receipt-bounded ----------------------------------------------------------
def test_clock_skew_cannot_manufacture_dwell(data):
    start(data)
    data.add_batch(T0, neigh=[MAC])
    data.add_batch(T0 + 7200, neigh=[MAC], received=T0 + 6900)  # stamped 300 s ahead
    meas(data, MAC)
    run(data, T0 + 7300)
    assert incidents(data) == []  # the receipts are only 6900 s apart


def test_clock_skew_cannot_manufacture_a_second_server_hour(data):
    start(data, transient_min_dwell_s=180)
    data.add_batch(T0 + 900, neigh=[MAC], received=T0 + 700)  # stamped 200 s ahead, next hour
    meas(data, MAC)
    run(data, T0 + 1000, transient_min_dwell_s=180)
    assert incidents(data) == []


# ---- 6: the close cursor reaches an incident past the first CLOSE_MAX ---------------------------
def test_a_review_on_the_last_of_250_open_incidents_is_reached_by_the_cursor(data):
    open_overrides(data.root / "overrides.db").close()
    start(data)
    ov = open_overrides(data.root / "overrides.db")
    hour = T0 // HOUR * HOUR
    for i in range(250):
        data.inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,"
            "evidence) VALUES (?,'rtr-1',?, 'L','new_device','open',?,?,?,NULL,0,0,'{}')",
            (f"i{i:03d}", f"d{i}", hour, hour, iso_utc(T0)),
        )
    ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES ('i249','rtr-1','d249','L','new_device',1,'acknowledged',NULL,1,'u',?,?)",
        (iso_utc(T0), str(uuid.uuid4())),
    )
    ov.close()

    def state() -> str:
        return data.q("SELECT state FROM monitoring_incidents WHERE id='i249'")[0][0]

    run(data, T0 + 30)
    assert state() == "open"  # past the first 200: not examined yet
    run(data, T0 + 60)
    assert state() == "resolved"  # the cursor moved on
    assert data.q("SELECT COUNT(*) FROM monitoring_incidents WHERE state='open'")[0][0] == 249
