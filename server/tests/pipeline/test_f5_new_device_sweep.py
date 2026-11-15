"""F5 S2b: the new-device sweep (flag OFF by default; nothing is read, written or swept when off).

Eligibility, daily cap, once-per-device-life, opaque ids, close-on-review, hostile input. The
policy versions are pinned through the shared freeze pins (never regenerate goldens).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid

import pytest
from delivery_runner_helpers import T0 as DT0
from delivery_runner_helpers import Clock, World, dconf
from pipeline_helpers import HOUR, T0, Data, data  # noqa: F401
from test_probe_freeze import POOLED_VERSION, TOD_VERSION

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline import processor
from vigie_pipeline.config import ACTIVITY_SKEW_S as SK
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.delivery_publish import FakePublisher
from vigie_pipeline.delivery_runner import run_delivery
from vigie_pipeline.processor import monitoring_policy, run_once
from vigie_pipeline.schema import open_pipeline_inventory

DWELL = 7200  # the default transient_min_dwell_s
MAC = "00:1a:2b:00:00:01"  # universal bit: not randomized
PRIVATE = "aa:bb:cc:00:00:01"  # locally administered: randomized
OPAQUE = re.compile(r"[0-9a-f]{64}")
EVIDENCE = {"reason_code": "new_device_first_seen", "randomized": False}


DAY = 86400


def ticks(data: Data, first: int, last: int, step: int = 3 * HOUR, **kw) -> None:
    """Pipeline passes at a steady cadence (a gap over RESUME_GAP_S would move the watermark)."""
    for t in range(first, last + 1, step):
        run(data, t, **kw)


def macs(n: int, prefix: str = "00:1a:2b:01") -> list[str]:
    return [f"{prefix}:{i >> 8:02x}:{i & 255:02x}" for i in range(n)]


def run(data: Data, now: float, **kw):
    kw.setdefault("new_device_notice", True)
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=now)


def start(data: Data, **kw) -> None:
    """The first enabled run: sets the watermark and creates the pipeline schema."""
    run(data, T0 - 60, **kw)


def meas(data: Data, mac: str, collector: str = "rtr-1") -> None:
    open_pipeline_inventory(data.root / "inventory.db", True).close()  # the pipeline tables
    data.inv.execute(
        "INSERT OR IGNORE INTO measurements_hourly VALUES (?,?,?,1,1,1,0)",
        (collector, mac, T0 // HOUR * HOUR),
    )


def arrive(data: Data, mac_list, at: int = T0, span: int = DWELL, measured: bool = True) -> None:
    mac_list = [mac_list] if isinstance(mac_list, str) else list(mac_list)
    data.add_batch(at, neigh=mac_list)
    data.add_batch(at + span + SK, neigh=mac_list)  # persistence is receipt-bounded: -SK
    for mac in mac_list:
        if measured:
            meas(data, mac)


def incidents(data: Data):
    return data.q("SELECT * FROM monitoring_incidents WHERE detector='new_device' ORDER BY seq")


def device_of(data: Data, mac: str) -> str:
    return data.q("SELECT device_id FROM observations WHERE mac=?", mac)[0][0]


def events(data: Data, kind: str):
    return data.q("SELECT * FROM events WHERE kind=?", kind)


def test_policy_versions_unchanged():
    assert monitoring_policy(PipelineConfig.from_env({})).version == POOLED_VERSION
    tod = PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod"})
    assert monitoring_policy(tod).version == TOD_VERSION


# ---- config ------------------------------------------------------------------------------------
def test_config_defaults_off_and_cap_three():
    cfg = PipelineConfig.from_env({})
    assert cfg.new_device_notice is False and cfg.new_device_max_per_day == 3


def test_config_reads_environment():
    env = {"VIGIE_NEW_DEVICE_NOTICE": "1", "VIGIE_NEW_DEVICE_MAX_PER_DAY": "20"}
    cfg = PipelineConfig.from_env(env)
    assert cfg.new_device_notice is True and cfg.new_device_max_per_day == 20


@pytest.mark.parametrize("bad", ["0", "21", "-1", "x", "", "3.5", "99999999999999999999", "1_0"])
def test_config_rejects_a_bad_cap_without_echoing_it(bad):
    with pytest.raises(ValueError, match="VIGIE_NEW_DEVICE_MAX_PER_DAY") as info:
        PipelineConfig.from_env({"VIGIE_NEW_DEVICE_MAX_PER_DAY": bad})
    assert repr(bad) not in str(info.value)


def test_config_rejects_garbage_flag_without_echoing_it():
    with pytest.raises(ValueError, match="VIGIE_NEW_DEVICE_NOTICE") as info:
        PipelineConfig.from_env({"VIGIE_NEW_DEVICE_NOTICE": "maybe-secret"})
    assert "maybe-secret" not in str(info.value)


@pytest.mark.parametrize("bad", ["1_0", " 3", "3 ", "+3", "٣", "0x3"])
def test_config_rejects_non_plain_digit_caps(bad):
    with pytest.raises(ValueError, match="VIGIE_NEW_DEVICE_MAX_PER_DAY"):
        PipelineConfig.from_env({"VIGIE_NEW_DEVICE_MAX_PER_DAY": bad})


def test_the_flag_is_in_no_policy_dataclass():
    from vigie_pipeline.baselines import BaselineConfig
    from vigie_pipeline.baselines_tod import TodConfig

    for family in (BaselineConfig, TodConfig):
        assert not [f for f in family.__dataclass_fields__ if "new_device" in f]


# ---- flag off: nothing read, written or swept --------------------------------------------------
def test_flag_off_never_calls_the_sweep_and_writes_nothing(data, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("sweep must not run with the flag off")

    monkeypatch.setattr(processor, "sweep_new_devices", boom, raising=False)
    start(data, new_device_notice=False)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1, new_device_notice=False)
    assert incidents(data) == []
    assert data.q("SELECT * FROM pipeline_meta WHERE key LIKE 'f5_%'") == []
    assert events(data, "new_device_capped") == []


def test_flag_off_database_is_unchanged_by_the_flag_plumbing(tmp_path):
    """Flag unset (the default) and flag explicitly off leave identical databases; neither holds
    an F5 key, incident or event (the byte-identical-to-main pins are the freeze goldens)."""

    def build(root, config_kw):
        d = Data(root)
        d.add_batch(T0, neigh=[MAC, PRIVATE])
        d.add_batch(T0 + DWELL, neigh=[MAC, PRIVATE])
        run_once(PipelineConfig(data_dir=root, **config_kw), now=T0 + DWELL + 1)
        rows = {
            t: [tuple(r) for r in d.q(f"SELECT * FROM {t} ORDER BY 1,2")]  # noqa: S608
            for t in ("monitoring_incidents", "mac_first_received", "events", "devices")
        }
        meta = d.q("SELECT key FROM pipeline_meta ORDER BY key")
        d.inv.close()
        return {k: [tuple(r[:1]) if k == "events" else r for r in v] for k, v in rows.items()}, [
            tuple(r) for r in meta
        ]

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    default, meta = build(tmp_path / "a", {})
    explicit, meta_off = build(tmp_path / "b", {"new_device_notice": False})
    assert meta == meta_off and not [k for (k,) in meta if k.startswith("f5_")]
    assert default["monitoring_incidents"] == explicit["monitoring_incidents"] == []


# ---- eligibility -------------------------------------------------------------------------------
def test_a_durable_non_randomized_new_device_gets_one_open_incident(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    (row,) = incidents(data)
    assert row["state"] == "open" and row["observed_bytes"] == 0 and row["threshold_bytes"] == 0
    assert json.loads(row["evidence"]) == {**EVIDENCE, "dwell_hours": 2}
    assert row["device_id"] == device_of(data, MAC) and row["collector_id"] == "rtr-1"
    assert row["baseline_id"] is None


def test_the_incident_row_and_marker_hold_no_mac_hostname_vendor_or_ip(data):
    start(data)
    data.add_batch(T0, leases=[(MAC, "evil-host.example", "[1,3]", "vendor-x-class")])
    data.add_batch(T0 + DWELL + SK, leases=[(MAC, "evil-host.example", "[1,3]", "vendor-x-class")])
    meas(data, MAC)
    run(data, T0 + DWELL + 1)
    text = json.dumps([tuple(r) for r in incidents(data)])
    text += json.dumps(
        [tuple(r) for r in data.q("SELECT * FROM pipeline_meta WHERE key LIKE 'f5_%'")]
    )
    for secret in (MAC, MAC.replace(":", ""), "evil-host", "vendor-x", "192.168"):
        assert secret not in text


def test_the_incident_id_is_opaque_random_and_not_derived_from_the_mac(tmp_path):
    ids = []
    for n in range(2):
        root = tmp_path / str(n)
        root.mkdir()
        d = Data(root)
        start(d)
        arrive(d, MAC)
        run(d, T0 + DWELL + 1)
        ids.append(incidents(d)[0]["id"])
        did = device_of(d, MAC)
        d.inv.close()
        assert OPAQUE.fullmatch(ids[-1])
        for guess in (MAC, MAC.replace(":", ""), did, f"{MAC}:{did}"):
            assert ids[-1] != hashlib.sha256(guess.encode()).hexdigest()
            assert guess not in ids[-1]
    assert ids[0] != ids[1]  # the same MAC on the same inputs: a different id (random, not derived)


def test_randomized_macs_never_notify_even_when_promoted(data):
    start(data)
    arrive(data, PRIVATE)
    run(data, T0 + DWELL + 1)
    assert data.q("SELECT status FROM devices")[0][0] == "active"  # promoted
    assert incidents(data) == []


def test_rotating_private_macs_never_notify(data):
    start(data)
    for i, mac in enumerate(macs(30, "aa:bb:cc:02")):
        arrive(data, mac, at=T0 + i * 60)
    run(data, T0 + 3 * DWELL)
    assert incidents(data) == []


def test_a_device_seen_before_the_watermark_never_notifies(data):
    arrive(data, MAC)  # exists before the first enabled run
    run(data, T0 + DWELL + 1, new_device_notice=False)
    run(data, T0 + DWELL + 100)  # the flag is turned on now: the watermark is set here
    run(data, T0 + DWELL + 200)
    assert incidents(data) == []


def test_a_flag_that_was_off_for_a_while_never_backfills(data):
    """A REAL on/off/on sequence through run_once with an advanced clock (no hand-edited meta)."""
    start(data)
    run(data, T0 - 30)
    arrive(data, MAC, at=T0)
    run(data, T0 + DWELL + 1, new_device_notice=False)  # appeared while the flag was off
    run(data, T0 + 2 * DAY, new_device_notice=False)
    run(data, T0 + 2 * DAY + 10)  # switched back on: the watermark moves to now
    run(data, T0 + 2 * DAY + 70)
    assert incidents(data) == []
    assert data.q("SELECT value FROM pipeline_meta WHERE key='f5_enabled_since'")[0][0] == str(
        T0 + 2 * DAY + 10
    )


@pytest.mark.parametrize(("delta", "expected"), [(-1, 0), (0, 1), (1, 1)])
def test_dwell_boundary(data, delta, expected):
    start(data)
    arrive(data, MAC, span=DWELL + delta)
    run(data, T0 + DWELL + 10)
    assert len(incidents(data)) == expected


def test_a_custom_dwell_applies(data):
    start(data, transient_min_dwell_s=3 * HOUR)
    arrive(data, MAC, span=2 * HOUR)
    run(data, T0 + 3 * HOUR, transient_min_dwell_s=3 * HOUR)
    assert incidents(data) == []


def test_forged_report_timestamps_cannot_fake_persistence(data):
    start(data)
    data.add_batch(T0, neigh=[MAC])
    data.add_batch(T0 + 3 * HOUR, neigh=[MAC], received=T0 + 60)  # stamps far ahead of receipt
    meas(data, MAC)
    run(data, T0 + 4 * HOUR)
    assert incidents(data) == []


def test_a_device_without_any_measurement_waits_and_notifies_once_it_has_one(data):
    start(data)
    arrive(data, MAC, measured=False)
    run(data, T0 + DWELL + 1)
    assert incidents(data) == []
    meas(data, MAC)
    run(data, T0 + DWELL + 100)
    assert len(incidents(data)) == 1


def test_a_device_stitched_into_an_older_one_never_notifies(data):
    data.add_batch(T0 - 10 * HOUR, neigh=["00:1a:2b:00:00:09"])
    run(data, T0 - 9 * HOUR, new_device_notice=False)
    start(data)
    data.add_batch(T0, neigh=[MAC])  # first sighting only: the dwell is not met yet
    meas(data, MAC)
    run(data, T0 + 60)
    data.add_batch(T0 + DWELL + SK, neigh=[MAC])
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(
        "INSERT INTO identity_links VALUES (?,?,'m','t','u',NULL)",
        (device_of(data, MAC), device_of(data, "00:1a:2b:00:00:09")),
    )
    ov.commit()
    ov.close()
    run(data, T0 + DWELL + 1)
    assert incidents(data) == []
    run(data, T0 + DWELL + 100)  # and it does not keep occupying the bounded sweep
    assert incidents(data) == []


def test_an_older_device_merged_into_the_new_one_makes_it_not_new(data):
    data.add_batch(T0 - 10 * HOUR, neigh=["00:1a:2b:00:00:09"])
    run(data, T0 - 9 * HOUR, new_device_notice=False)
    start(data)
    data.add_batch(T0, neigh=[MAC])  # first sighting only: the dwell is not met yet
    meas(data, MAC)
    run(data, T0 + 60)
    data.add_batch(T0 + DWELL + SK, neigh=[MAC])
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(
        "INSERT INTO identity_links VALUES (?,?,'m','t','u',NULL)",
        (device_of(data, "00:1a:2b:00:00:09"), device_of(data, MAC)),
    )
    ov.commit()
    ov.close()
    run(data, T0 + DWELL + 1)
    assert incidents(data) == []


def test_a_cloned_known_mac_is_not_new_and_does_not_notify(data):
    arrive(data, MAC, at=T0 - 5 * DWELL)
    run(data, T0 - 3 * DWELL, new_device_notice=False)
    start(data)
    arrive(data, MAC, at=T0)  # an attacker (or the owner) re-uses a known MAC: documented gap
    run(data, T0 + DWELL + 1)
    assert incidents(data) == []


# ---- daily cap ---------------------------------------------------------------------------------
def staggered(data: Data, n: int) -> list[str]:
    out = macs(n)
    for i, mac in enumerate(out):
        arrive(data, mac, at=T0 + i * 10)
    return out


def test_ten_eligible_devices_give_three_incidents_and_one_capped_event(data):
    start(data)
    out = staggered(data, 10)
    run(data, T0 + DWELL + 200)
    got = [r["device_id"] for r in incidents(data)]
    assert got == [device_of(data, m) for m in out[:3]]  # deterministic: (first_seen, id)
    (capped,) = events(data, "new_device_capped")
    assert capped["device_id"] is None and "7" in capped["summary"]
    for mac in out:
        assert mac not in capped["summary"] and mac.replace(":", "") not in capped["summary"]
    run(data, T0 + DWELL + 300)  # the same UTC day: still 3 and still one capped event
    assert len(incidents(data)) == 3 and len(events(data, "new_device_capped")) == 1


def test_the_next_utc_day_resets_the_cap(data):
    start(data)
    out = staggered(data, 10)
    ticks(data, T0 + DWELL + 200, T0 + DWELL + 200 + DAY)
    got = [r["device_id"] for r in incidents(data)]
    assert got == [device_of(data, m) for m in out[:6]]
    assert len(events(data, "new_device_capped")) == 2  # one per UTC day


def test_the_cap_is_configurable_and_a_run_sweeps_at_most_twenty(data):
    start(data, new_device_max_per_day=20)
    staggered(data, 30)
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert len(incidents(data)) == 20
    assert len(events(data, "new_device_capped")) == 1


def test_a_universal_bit_mac_flood_is_bounded(data):
    start(data)
    flood = macs(300, "02:00:00:00")[:0] or macs(300, "00:de:ad:be")  # all universal-bit
    data.add_batch(T0, neigh=flood)  # seen once, never persists
    run(data, T0 + DWELL + 1)
    assert incidents(data) == []  # the dwell gate stops them all
    for mac in flood:
        meas(data, mac)
    arrive(data, flood, at=T0 + HOUR)  # a persistent flood: capped by the daily limit
    run(data, T0 + HOUR + DWELL + 1)
    assert len(incidents(data)) == 3 and len(events(data, "new_device_capped")) == 1


# ---- once per device life ----------------------------------------------------------------------
def test_rerunning_the_sweep_never_makes_a_second_incident(data):
    start(data)
    arrive(data, MAC)
    for step in range(4):
        run(data, T0 + DWELL + 1 + step * 60)
    assert len(incidents(data)) == 1


def test_a_closed_incident_is_not_recreated(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    data.inv.execute("UPDATE monitoring_incidents SET state='resolved'")
    run(data, T0 + DWELL + 100)
    assert [r["state"] for r in incidents(data)] == ["resolved"]


def test_a_retired_then_revived_device_is_not_noticed_twice(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    data.inv.execute("UPDATE devices SET status='retired'")
    data.inv.execute("DELETE FROM monitoring_incidents")  # even with the incident long pruned
    later = T0 + 20 * DWELL
    data.add_batch(later, neigh=[MAC])  # seen again: revived as transient
    run(data, later + 10)
    data.add_batch(later + 3 * DWELL, neigh=[MAC])
    run(data, later + 3 * DWELL + 10)
    assert incidents(data) == []


def test_a_lineage_change_does_not_make_a_second_incident(data):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    data.add_batch(T0 - 10 * HOUR, neigh=["00:1a:2b:00:00:09"])
    run(data, T0 + DWELL + 50)
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(  # an older device is merged into the noticed one: its lineage key changes
        "INSERT INTO identity_links VALUES (?,?,'m','t','u',NULL)",
        (device_of(data, "00:1a:2b:00:00:09"), device_of(data, MAC)),
    )
    ov.commit()
    ov.close()
    data.inv.execute("UPDATE monitoring_incidents SET state='resolved'")
    run(data, T0 + DWELL + 100)
    assert len(incidents(data)) == 1


# ---- close on review ---------------------------------------------------------------------------
def decide(data: Data, incident, status: str | None, until: int | None = None) -> None:
    ov = open_overrides(data.root / "overrides.db")
    ov.execute(
        "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,detector,"
        "episode_start,status,snooze_until,version,decided_by,decided_at,id)"
        " VALUES (?,?,?,?,?,?,?,?,1,'u','2026-10-14T00:00:00Z',?)",
        (incident["id"], incident["collector_id"], incident["device_id"], incident["lineage"],
         "new_device", incident["episode_start"], status, until, str(uuid.uuid4())),
    )  # fmt: skip
    ov.commit()
    ov.close()


@pytest.mark.parametrize(("status", "closed"), [("acknowledged", True), ("expected", True),
                                                ("snoozed", False), (None, False)])  # fmt: skip
def test_owner_review_closes_the_incident_only_for_a_quiet_decision(data, status, closed):
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    (row,) = incidents(data)
    until = T0 + 10 * DWELL if status == "snoozed" else None
    decide(data, row, status, until)
    run(data, T0 + DWELL + 100)
    assert incidents(data)[0]["state"] == ("resolved" if closed else "open")


def test_a_resolved_new_device_incident_sends_no_recover_and_is_prunable(data):
    delivery = {"VIGIE_DELIVERY_ENABLED": "1", "VIGIE_DELIVERY_FILE": str(data.root / "out.jsonl"),
                "VIGIE_DELIVERY_DETECTORS": "large_upload,upload_deviation,new_device"}  # fmt: skip
    cfg = PipelineConfig.from_env({**delivery, "VIGIE_DATA_DIR": str(data.root),
                                   "VIGIE_NEW_DEVICE_NOTICE": "1"})  # fmt: skip
    open_overrides(data.root / "overrides.db").close()  # delivery needs the decision store
    start(data, delivery=cfg.delivery)
    arrive(data, MAC)
    now = T0 + DWELL + 1
    for step in range(3):
        run_once(cfg, now=now + step * 120)
    (row,) = incidents(data)
    assert [r["kind"] for r in data.q("SELECT kind FROM incident_deliveries")] == ["open"]
    decide(data, row, "expected")
    for step in range(3, 8):
        run_once(cfg, now=now + step * 120)
    assert incidents(data)[0]["state"] == "resolved"
    assert [(r["kind"], r["state"]) for r in data.q("SELECT * FROM incident_deliveries")] == [
        ("open", "sent")
    ]
    sent = (data.root / "out.jsonl").read_text()
    assert sent.count("\n") == 1 and "recover" not in sent
    assert MAC not in sent and "00:1a" not in sent
    from vigie_pipeline.monitoring_engine import prune_monitoring

    data.inv.execute("DELETE FROM incident_deliveries")
    prune_monitoring(data.inv, T0 + 200 * 86400)
    assert incidents(data) == []


# ---- allowlist backlog -------------------------------------------------------------------------
@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    w.close()


def test_adding_the_detector_enqueues_only_fresh_open_incidents_never_the_backlog(world):
    for i in range(30):  # 30 stale open notices (days of an unreviewed daily cap)
        world.incident(f"old{i}", detector="new_device", at=DT0 - (i + 2) * 86400)
    world.incident("fresh1", detector="new_device", at=DT0 - 60)
    world.incident("fresh2", detector="new_device", at=DT0 - 3600)
    pub, clock = FakePublisher(), Clock(DT0 + 10)
    allow = ("large_upload", "upload_deviation", "new_device")
    run_delivery(world.inv, world.ro, pub, dconf(eligible_since=DT0 - 40 * 86400), clock,
                 detectors=allow)  # fmt: skip
    assert {r["incident_id"] for r in world.rows()} == {"fresh1", "fresh2"}


def test_open_incidents_per_day_never_exceed_the_cap_so_the_backlog_is_bounded(data):
    start(data, new_device_max_per_day=20)
    staggered(data, 25)
    run(data, T0 + DWELL + 400, new_device_max_per_day=20)
    assert len(incidents(data)) <= 20  # one UTC day can never open more than the cap


# ---- hostile input, text ----------------------------------------------------------------------
def test_hostile_hostnames_and_dhcp_never_change_eligibility_or_text(data, tmp_path):
    start(data)
    evil = "x'; DROP TABLE devices;--"
    data.add_batch(T0, leases=[(MAC, evil, "[1,2]", evil)])
    data.add_batch(T0 + DWELL + SK, leases=[(MAC, evil, "[1,2]", evil)])
    meas(data, MAC)
    other = "00:1a:2b:00:00:02"
    data.add_batch(T0, leases=[(other, None, None, None)])
    data.add_batch(T0 + DWELL + SK, leases=[(other, None, None, None)])
    meas(data, other)
    run(data, T0 + DWELL + 1)
    assert len(incidents(data)) == 2  # the hostname is no signal in either direction
    blob = json.dumps([tuple(r) for r in incidents(data)])
    assert "DROP" not in blob and evil not in blob


def test_the_existing_new_device_event_still_carries_the_mac_known_followup(data):
    """The pre-existing event (processor._create_device) embeds the MAC; F5 does not touch it."""
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    assert any(MAC in e["summary"] for e in events(data, "new_device"))
    blob = json.dumps([tuple(r) for r in incidents(data)])
    assert MAC not in blob and "new device" not in blob


def test_known_detectors_all_have_notification_text_or_engine_semantics():
    from vigie_api.models import IncidentOut
    from vigie_pipeline.delivery_publish import DETECTOR_TITLES
    from vigie_pipeline.delivery_types import OPEN_ONLY_DETECTORS
    from vigie_pipeline.monitoring_engine import ENGINE_DETECTORS

    known = set(IncidentOut.model_fields["detector"].annotation.__args__)
    for detector in known - set(ENGINE_DETECTORS):
        assert detector in OPEN_ONLY_DETECTORS and (detector, "open") in DETECTOR_TITLES
    assert iso_utc(0)  # keep the import used
