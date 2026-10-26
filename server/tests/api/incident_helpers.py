from __future__ import annotations

import json
from typing import Any

from api_helpers import NOW, Env, ts

HOUR = int(NOW) // 3600 * 3600 - 3600
EVIDENCE = {
    "reason_code": "large_upload_threshold",
    "hour": HOUR,
    "previous_hour": None,
    "observed_bytes": 1073741824,
    "threshold_bytes": 1073741824,
    "baseline_id": None,
    "algorithm": "pooled-median-v1",
    "config_version": "cfg",
    "coverage_required_seconds": 3420,
    "lineage": "line",
    "unusual_is_not_malicious": True,
}


def seed_collector(env: Env, device: str = "d1") -> None:
    env.inv.execute("INSERT OR IGNORE INTO collectors(id,key_id) VALUES ('c1','k1')")
    env.inv.execute("INSERT OR IGNORE INTO collectors(id,key_id) VALUES ('c2','k2')")
    env.device(device)
    env.mac("aa:bb:cc:00:00:01", device)


def incident(
    env: Env,
    incident_id: str,
    *,
    state: str = "open",
    device: str = "d1",
    collector: str = "c1",
    lineage: str = "line",
    detector: str = "large_upload",
    episode: int = HOUR,
) -> str:
    env.inv.execute(
        "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
        "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,evidence)"
        " VALUES (?,?,?,?,?,?,?,?,'now',NULL,1073741824,1073741824,?)",
        (incident_id, collector, device, lineage, detector, state, episode, episode,
         json.dumps(EVIDENCE)),
    )  # fmt: skip
    return incident_id


def post(env: Env, incident_id: str, action: str, body: dict[str, Any] | None = None, *,
         collector: str = "c1", headers: dict[str, str] | None = None, auth: bool = True):  # fmt: skip
    sent = {**(env.auth if auth else {}), **(headers or {})}
    return env.client.post(
        f"/incidents/{incident_id}/{action}",
        params={"collector_id": collector},
        json={"expected_version": 0} if body is None else body,
        headers=sent,
    )


def until(offset: float) -> str:
    return ts(offset)


def decisions(env: Env) -> list[dict[str, Any]]:
    return [
        dict(r) for r in env.ov.execute("SELECT * FROM incident_decisions ORDER BY incident_id")
    ]


def audits(env: Env, prefix: str = "monitoring.incident.") -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in env.ov.execute(
            "SELECT * FROM audit_log WHERE action LIKE ? ORDER BY seq", (prefix + "%",)
        )
    ]
