"""The pipeline reads incident_decisions read-only: the detectors ignore decisions (byte-identical
monitoring tables); only new_device closes its incident on a quiet review."""

import shutil

from pipeline_helpers import T0, data  # noqa: F401
from test_f5_new_device_sweep import (  # noqa: F401
    DWELL,
    MAC,
    arrive,
    decide,
    incidents,
    run,
    start,
    wide_gap,
)
from test_monitoring import HOUR, recorded

from vigie_api.schema import open_overrides
from vigie_ingest.db import open_inventory
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

TABLES = ("monitoring_incidents", "monitoring_suspicious", "monitoring_baselines")
LATER = (HOUR + 3 * 3600, HOUR + 30 * 3600)


def dump(root):
    inv = open_inventory(root / "inventory.db")
    out = {
        t: [tuple(r) for r in inv.execute(f"SELECT * FROM {t} ORDER BY 1,2,3")]  # noqa: S608
        for t in TABLES
    }
    inv.close()
    return out


def decide_everything(root):
    inv = open_inventory(root / "inventory.db")
    ids = [r["id"] for r in inv.execute("SELECT id FROM monitoring_incidents")]
    inv.close()
    ov = open_overrides(root / "overrides.db")
    for incident_id in ids:
        ov.execute(
            "INSERT INTO incident_decisions (incident_id,collector_id,device_id,lineage,"
            "detector,episode_start,status,snooze_until,version,decided_by,decided_at,id)"
            " VALUES (?,'c1','d','l','large_upload',1,'snoozed',9999999999,1,'app:t',"
            "'2026-01-01T00:00:00Z','x')",
            (incident_id,),
        )
    ov.close()
    return len(ids)


def test_pipeline_run_with_decisions_matches_run_without(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    recorded(plain, 1, HOUR, HOUR + 3540, 1024**3)
    open_overrides(plain / "overrides.db").close()
    for now in (HOUR + 3541, HOUR + 3601):
        run_once(PipelineConfig(data_dir=plain), now=now)
    decided = tmp_path / "decided"
    shutil.copytree(plain, decided)
    assert decide_everything(decided) == 1
    for now in LATER:
        run_once(PipelineConfig(data_dir=plain), now=now)
        run_once(PipelineConfig(data_dir=decided), now=now)
    assert dump(plain)["monitoring_incidents"]
    for root in (plain, decided):  # the new schema must not make overrides "unreadable"
        inv = open_inventory(root / "inventory.db")
        assert not inv.execute("SELECT 1 FROM events WHERE kind='stitching_skipped'").fetchall()
        inv.close()
    assert dump(plain) == dump(decided)


def test_new_device_decision_closes_only_that_incident_when_the_notice_is_on(data):
    """The one place the pipeline acts on a decision: a quiet review closes a new_device incident
    (state only; the review status stays the human's), and nothing else changes."""
    start(data)
    arrive(data, MAC)
    run(data, T0 + DWELL + 1)
    (row,) = incidents(data)
    assert row["state"] == "open"
    decide(data, row, "acknowledged")
    before = data.q("SELECT * FROM monitoring_incidents WHERE detector<>'new_device'")
    run(data, T0 + DWELL + 100)
    assert incidents(data)[0]["state"] == "resolved"
    assert data.q("SELECT * FROM monitoring_incidents WHERE detector<>'new_device'") == before
    ov = open_overrides(data.root / "overrides.db")
    assert ov.execute("SELECT status FROM incident_decisions").fetchall()[0][0] == "acknowledged"
    ov.close()
