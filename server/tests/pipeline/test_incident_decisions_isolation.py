"""The pipeline must not notice incident_decisions: byte-identical monitoring tables."""

import shutil

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
