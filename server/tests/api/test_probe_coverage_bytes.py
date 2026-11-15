"""Freeze: probe status and probe events never change the bytes of /coverage.

GOLDEN_SHA256 was captured from origin/main (73bd7f6) with the same fixture; do not regenerate it.
"""

import hashlib
import json

from api_helpers import NOW, Env, env, ts  # noqa: F401
from test_api_monitoring import HOUR, seed

from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.probes import fold_probes

GOLDEN_SHA256 = "440755092000a969b402fd00d1254bff3db117f37fabdede089fb5bea841d36a"
QUERY = {"collector_id": "c1", "from_hour": HOUR - 3600, "to_hour": HOUR + 3600, "limit": 50}


def coverage_bytes(env: Env) -> bytes:
    response = env.get("/coverage", **QUERY)
    assert response.status_code == 200, response.text
    return response.content


def test_coverage_bytes_are_unchanged_by_probe_rows(env: Env, tmp_path):
    seed(env)
    before = coverage_bytes(env)
    assert hashlib.sha256(before).hexdigest() == GOLDEN_SHA256
    probe_file = tmp_path / "probe-state.json"
    target = {
        "id": "router-dns", "state": "outage", "consecutive_fail": 3, "consecutive_ok": 0,
        "last_ok_at": None, "last_error_class": "timeout", "last_latency_ms": None,
        "episode_start": int(NOW) - 100, "last_attempt": NOW, "ring": [],
        "episodes_day": ts()[:10], "episodes_today": 1, "flapping": False, "suppressed": False,
        "note": None,
    }  # fmt: skip
    probe_file.write_text(json.dumps({"v": 1, "written_at": NOW, "targets": [target]}))
    fold_probes(env.inv, ProbeSettings(file=probe_file), lambda: NOW + 1)
    assert env.inv.execute("SELECT COUNT(*) FROM events WHERE kind='probe_outage'").fetchone()[0]
    assert env.inv.execute("SELECT 1 FROM pipeline_meta WHERE key='probe_status'").fetchone()
    assert coverage_bytes(env) == before
