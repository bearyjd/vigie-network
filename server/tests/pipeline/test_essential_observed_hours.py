"""The essential detector can count an hour only with durable, positive observation evidence."""

import pytest
from test_f6b_essential_absence import HOUR, H, accept_batch, env, now_after  # noqa: F401

from vigie_ingest.db import iso_utc
from vigie_ingest.retention import purge_batches
from vigie_pipeline import essential_absence as ea


def candidate(env, hours=1):
    mac = env.device("d")
    env.mark("d", hours * HOUR)
    env.cover(1, hours)
    return mac


def test_generic_coverage_without_positive_observation_abstains(env):
    candidate(env)
    env.inv.execute("DELETE FROM essential_observation_hours")
    assert env.sweep(now_after(1)) == 0


def test_qualified_seconds_are_the_union_of_accepted_windows(env):
    candidate(env)
    env.inv.execute("DELETE FROM essential_observation_hours")
    start = H + HOUR
    accept_batch(env, start, start + 1800)
    accept_batch(env, start + 1, start + 1801)
    assert ea._eligible_hours(env.inv, "c1", H, now_after(1)) == 0
    accept_batch(env, start + 1801, start + 3420)
    assert ea._eligible_hours(env.inv, "c1", H, now_after(1)) == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"truncated": {"dns_dropped": 1}},
        {"health": None},
        {"health": {"dns_log_quiet": True}},
        {"dropped_batches": 1},
    ],
)
def test_late_dirty_observation_veto_survives_purge(env, bad):
    candidate(env, 2)
    env.processed(accept_batch(env, H + 2 * HOUR - 3, H + 2 * HOUR + 3, **bad))
    purge_batches(env.inv, H + 10 * 86400, 7)
    for hour in (H + HOUR, H + 2 * HOUR):
        env.processed(accept_batch(env, hour, hour + HOUR))
    assert ea._eligible_hours(env.inv, "c1", H, H + 10 * 86400) == 0


def test_cross_hour_flow_and_dns_at_window_end_move_the_anchor(env):
    mac = candidate(env, 2)
    flow = dict(mac=mac, proto="udp", bytes_up=1, bytes_down=0, flows=1)
    accept_batch(env, H + 2 * HOUR - 5, H + 2 * HOUR + 5, conntrack=[flow])
    assert ea._anchor(env.inv, (mac,)) == ("c1", H + 2 * HOUR)
    accept_batch(
        env,
        H + 3 * HOUR - 5,
        H + 3 * HOUR,
        dns=[dict(mac=mac, ts=H + 3 * HOUR, qname="example.test", qtype="A")],
    )
    assert ea._anchor(env.inv, (mac,)) == ("c1", H + 3 * HOUR)
    assert env.sweep(now_after(2)) == 0


def test_maximum_threshold_uses_168_durable_hours(env):
    candidate(env, 168)
    purge_batches(env.inv, H + 10 * 86400, 7)
    assert env.sweep(now_after(167)) == 0
    assert env.sweep(now_after(168)) == 1


def test_older_ingest_without_validated_payload_cannot_certify_an_hour(env):
    candidate(env)
    env.inv.execute(
        "INSERT INTO batches(collector_id,batch_id,received_at,window_start,"
        "window_end,observation_kind) VALUES ('c1','unknown',?,?,?,'observation')",
        (iso_utc(H + 2 * HOUR), H + HOUR, H + 2 * HOUR),
    )
    purge_batches(env.inv, H + 10 * 86400, 7)
    assert env.sweep(now_after(1)) == 0


@pytest.mark.parametrize("missing", ["dns", "conntrack", "truncated", "dropped_batches"])
def test_omitted_sections_do_not_certify_an_hour(env, missing):
    candidate(env)
    accept_batch(env, H + HOUR + 1, H + HOUR + 2, **{missing: Ellipsis})
    assert env.sweep(now_after(1)) == 0


def test_active_evidence_between_plan_and_insert_prevents_stale_open(env, monkeypatch):
    mac = candidate(env)
    plan = ea._plan

    def then_receive(inv, ov, now):
        result = plan(inv, ov, now)
        assert result.opens
        env.processed(
            accept_batch(
                env,
                H + HOUR + 1,
                H + HOUR + 10,
                dns=[dict(ts=H + HOUR + 2, mac=mac, qname="example.test", qtype="A")],
            )
        )
        return result

    monkeypatch.setattr(ea, "_plan", then_receive)
    assert env.sweep(now_after(1)) == 0
    assert env.rows() == []


def test_dirty_evidence_between_plan_and_insert_prevents_stale_open(env, monkeypatch):
    candidate(env)
    plan = ea._plan

    def then_receive(inv, ov, now):
        result = plan(inv, ov, now)
        assert result.opens
        env.processed(accept_batch(env, H + HOUR + 1, H + HOUR + 10, truncated={"dns_dropped": 1}))
        return result

    monkeypatch.setattr(ea, "_plan", then_receive)
    assert env.sweep(now_after(1)) == 0
    assert env.rows() == []


def test_off_batches_after_opt_in_fence_even_when_clock_and_collector_reset(env):
    from vigie_ingest.store import provision_collector

    candidate(env)
    ea.configure_recording(env.inv, False, H)
    accept_batch(env, H + HOUR + 1, H + HOUR + 10)
    purge_batches(env.inv, H + 10 * 86400, 7)
    provision_collector(env.inv, "c1", "k1", force=True)
    ea.configure_recording(env.inv, True, H - 10 * 86400)
    assert env.sweep(now_after(1)) == 0


def test_aggregate_expiry_keeps_vetoes_expired_after_clock_rollback(env):
    from vigie_pipeline.monitoring_engine import prune_monitoring

    candidate(env)
    prune_monitoring(env.inv, H + 95 * 86400)
    accept_batch(env, H + HOUR, H + 2 * HOUR)
    assert ea._eligible_hours(env.inv, "c1", H, now_after(1)) == 0


def test_clean_pre_activation_history_is_unknown_even_with_retained_measurements(tmp_path):
    from vigie_pipeline.schema import open_pipeline_inventory

    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    try:
        inv.execute("INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (H,))
        ea.configure_recording(inv, False, H)
        assert inv.execute("SELECT * FROM essential_recording").fetchall() == []
        ea.configure_recording(inv, True, H)
        assert ea._eligible_hours(inv, "c1", H - HOUR, H + HOUR) == 0
    finally:
        inv.close()


def test_an_unprocessed_clean_observation_holds_opening_until_identity_and_coverage_catch_up(env):
    candidate(env)
    b = accept_batch(env, H + HOUR + 1, H + HOUR + 5)
    assert env.sweep(now_after(1)) == 0
    env.inv.execute(
        "INSERT INTO measurement_batches VALUES (?,?,?,?,?,?,?)",
        ("c1", b.batch_id, b.window_start, b.window_end, iso_utc(b.window_end), H + HOUR, "[]"),
    )
    assert env.sweep(now_after(1)) == 1


def test_expired_anchor_cannot_open_before_prune_on_first_run_after_downtime(env):
    candidate(env)
    env.cover(24 * 91, 1)
    assert env.sweep(now_after(24 * 91)) == 0


def test_recording_failure_holds_absence_and_continues_monitoring(env, monkeypatch):
    import sqlite3

    from vigie_pipeline import processor
    from vigie_pipeline.config import PipelineConfig

    delivered = []

    def busy(*args):
        raise sqlite3.OperationalError("busy")

    monkeypatch.setattr(processor, "configure_recording", busy)
    monkeypatch.setattr(
        processor, "sweep_essential_absence", lambda *args: pytest.fail("sweep ran")
    )
    monkeypatch.setattr(
        processor, "run_delivery_stage", lambda *a, **kw: delivered.append(kw["held"])
    )
    processor.run_once(PipelineConfig(data_dir=env.root, essential_absence=True), now=H)
    assert delivered == [frozenset({"essential_absence"})]


def test_deferred_notices_recheck_each_historical_threshold_after_late_veto(env):
    from vigie_pipeline.essential_absence import deferred_absence_notices

    candidate(env)
    env.device("two")
    env.mark("two", 2 * HOUR)
    env.cover(2, 1)
    assert env.sweep(now_after(2)) == 2
    ids = {row["device_id"]: row["id"] for row in env.rows()}
    assert deferred_absence_notices(env.inv, env.ov, now_after(2)) == frozenset()
    env.batch(H + HOUR + 30, H + HOUR + 60, {"dns_dropped": 1})
    assert deferred_absence_notices(env.inv, env.ov, now_after(2)) == {ids["two"]}
    assert len(env.rows("open")) == 2
    env.cover(3, 1)
    assert deferred_absence_notices(env.inv, env.ov, now_after(3)) == frozenset()


def test_purge_of_unprocessed_certified_batch_invalidates_hour_and_releases_pending(env):
    candidate(env)
    accept_batch(env, H + HOUR + 50, H + HOUR + 60)
    assert ea.pending_observations(env.inv)
    purge_batches(env.inv, H + 10 * 86400, 7)
    assert not ea.pending_observations(env.inv)
    assert env.sweep(now_after(1)) == 0


def test_real_accepted_batches_open_after_pipeline_measures_the_absence(env):
    from vigie_ingest.models import Batch
    from vigie_ingest.store import apply_batch
    from vigie_pipeline.config import PipelineConfig
    from vigie_pipeline.processor import run_once

    mac = env.device("d", measured=False)
    env.mark("d", HOUR)
    cfg = PipelineConfig(data_dir=env.root, essential_absence=True)
    for n in (0, 1):
        start = H + n * HOUR
        end = start + HOUR
        b = Batch.model_validate(
            dict(
                collector_id="c1",
                key_id="k1",
                boot_id="b",
                seq=n + 1,
                batch_id=f"018ce870-0000-7000-8000-{n:012x}",
                window_start=start,
                window_end=end,
                sent_ts=end,
                observation_kind="observation",
                dropped_batches=0,
                truncated={},
                conntrack=[],
                health={"dns_log_quiet": False},
                dns=[] if n else [dict(mac=mac, ts=start + 5, qname="example.test", qtype="A")],
            )
        )
        assert apply_batch(env.root / "inventory.db", env.root, b, end, 300) == "applied"
    assert ea.pending_observations(env.inv)
    run_once(cfg, now=H + 2 * HOUR + 1)
    assert not ea.pending_observations(env.inv)
    assert [r["episode_start"] for r in env.rows("open")] == [H]


def test_v11_upgrade_keeps_coverage_and_starts_with_no_recording(tmp_path, monkeypatch):
    from vigie_pipeline import schema

    path = tmp_path / "inventory.db"
    with monkeypatch.context() as m:
        m.setattr(schema, "PIPELINE_MIGRATIONS", schema.PIPELINE_MIGRATIONS[:11])
        db = schema.open_pipeline_inventory(path, migrate=True)
        db.execute("INSERT INTO coverage_hourly VALUES ('c1',?,3600,3600,'[]')", (H,))
        db.close()
    inv = schema.open_pipeline_inventory(path)
    try:
        assert inv.execute("SELECT * FROM essential_recording").fetchall() == []
        assert tuple(inv.execute("SELECT * FROM coverage_hourly").fetchone()) == (
            "c1",
            H,
            3600,
            3600,
            "[]",
        )
        assert inv.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        inv.close()


def test_purging_a_processed_receipt_after_its_detail_keeps_certified_hours(env):
    candidate(env)
    env.batch(H + HOUR + 15, H + HOUR + 16, {})
    assert not ea.pending_observations(env.inv)
    env.inv.execute("DELETE FROM measurement_batches")
    purge_batches(env.inv, H + 10 * 86400, 7)
    assert not ea.pending_observations(env.inv)
    assert env.sweep(now_after(1)) == 1


def test_probe_never_changes_recording_fence_presence_coverage_or_pending_receipts(env):
    mac = candidate(env)

    def snapshot():
        return [
            [tuple(row) for row in env.inv.execute(f"SELECT * FROM {table}")]  # noqa: S608
            for table in (
                "essential_recording",
                "essential_activity",
                "essential_observation_hours",
                "essential_pending",
            )
        ]

    before = snapshot()
    accept_batch(
        env,
        H + HOUR,
        H + 2 * HOUR,
        observation_kind="probe",
        truncated={"dns_dropped": 1},
        dns=[dict(mac=mac, ts=H + HOUR + 5, qname="example.test", qtype="A")],
    )
    assert snapshot() == before


def test_unexpected_notice_check_failure_holds_absence_and_other_stages_continue(env, monkeypatch):
    import json
    from dataclasses import replace

    from test_f6b_fix2_run import deliver_cfg, old_watermark

    from vigie_pipeline import processor
    from vigie_pipeline.config import ProbeSettings

    candidate(env)
    now = now_after(1)
    assert env.sweep(now) == 1
    env.inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,observed_bytes,threshold_bytes,evidence)"
        " SELECT 'upload',collector_id,device_id,lineage,'large_upload',state,episode_start,"
        "last_hour,detected_at,1,1,'{}' FROM monitoring_incidents"
    )
    old_watermark(env)
    cfg, output = deliver_cfg(env, essential_absence=True)
    cfg = replace(cfg, probes=ProbeSettings(file=env.root / "probe.json"))
    folded, errors = [], []

    def check_failed(inv):
        raise RuntimeError("private stored detail")

    monkeypatch.setattr(ea, "pending_observations", check_failed)
    monkeypatch.setattr(
        ea, "log", lambda logger, level, event, **fields: errors.append((event, fields))
    )
    monkeypatch.setattr(processor, "fold_probes", lambda *args: folded.append(True))
    processor.run_once(cfg, now=now)

    assert [json.loads(line)["link"] for line in output.read_text().splitlines()] == [
        "/ui/#incident=upload"
    ]
    assert folded == [True]
    assert errors == [("essential_delivery_check_failed", {"error": "RuntimeError"})]
