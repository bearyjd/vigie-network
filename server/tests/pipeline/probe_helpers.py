"""Shared fixtures for the probe tests: a runner-written state file and a fixed monitoring DB."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

from test_monitoring_engine import HOUR, MIB, history, hour, seeded

from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import run_once

RUNNER = Path(__file__).parents[3] / "deploy" / "persistent" / "probe_runner.py"
_spec = importlib.util.spec_from_file_location("probe_runner_for_server_tests", RUNNER)
pr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pr
_spec.loader.exec_module(pr)

NOW = 1_800_000_000.0
CURRENT = HOUR + 20 * 86400
DUMPED = (
    "coverage_hourly",
    "measurements_hourly",
    "monitoring_incidents",
    "monitoring_profiles",
    "monitoring_baselines",
    "incident_deliveries",
    "monitoring_revision",
    "devices",
    "observations",
    "pipeline_meta",
)


def target_state(ident="router-dns", **over):
    base = {
        "id": ident, "state": "ok", "consecutive_fail": 0, "consecutive_ok": 1,
        "last_ok_at": NOW, "last_error_class": None, "last_latency_ms": 4,
        "episode_start": None, "last_attempt": NOW, "ring": [[int(NOW // 60), True, 4, None]],
        "episodes_day": "2027-01-15", "episodes_today": 0, "flapping": False,
        "suppressed": False, "note": None,
    }  # fmt: skip
    return {**base, **over}


def state_doc(*targets, written_at=NOW, **over):
    return {"v": 1, "written_at": written_at, "targets": list(targets), **over}


def write_probe_file(path: Path, doc) -> Path:
    path.write_bytes(doc if isinstance(doc, bytes) else json.dumps(doc).encode())
    return path


def build_fixture(root: Path) -> None:
    """Fixed monitoring history with one open upload_deviation incident."""
    inv, ov = seeded(root)
    try:
        history(inv)
        hour(inv, CURRENT - 3600, 51 * MIB)
        hour(inv, CURRENT, 51 * MIB)
    finally:
        inv.close()
        ov.close()


def run_fixture(root: Path, **env: str) -> None:
    config = PipelineConfig.from_env({"VIGIE_DATA_DIR": str(root), **env})
    run_once(config, now=CURRENT + 3610)


def dump(root: Path, *, exclude_meta: tuple[str, ...] = ()) -> dict[str, object]:
    conn = sqlite3.connect(root / "inventory.db")
    try:
        out: dict[str, object] = {}
        for table in DUMPED:
            width = len(conn.execute(f"PRAGMA table_info({table})").fetchall())
            order = ",".join(str(i + 1) for i in range(width))
            rows = [tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {order}")]  # noqa: S608
            if table == "pipeline_meta":
                rows = [r for r in rows if r[0] not in exclude_meta]
            out[table] = rows
        out["events"] = [
            tuple(r)
            for r in conn.execute(
                "SELECT kind, severity, summary, dedup, ts, device_id IS NULL FROM events"
                " ORDER BY kind, dedup, summary"
            )
        ]
        return out
    finally:
        conn.close()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
