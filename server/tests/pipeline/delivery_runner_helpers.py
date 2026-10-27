"""Real migrated databases and a manual clock for the delivery runner tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.delivery_plan import DeliveryConfig
from vigie_pipeline.overrides import open_overrides_ro
from vigie_pipeline.schema import open_pipeline_inventory

T0 = 1_792_000_000
SINCE = T0 - 100


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class World:
    """inventory.db (pipeline schema) and overrides.db (rw for the test, ro for the runner)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
        self.ov = open_overrides(root / "overrides.db")
        self.ro = open_overrides_ro(root / "overrides.db")

    def incident(self, iid="i1", state="open", device="dev-1", at=T0, evidence="{}") -> None:
        self.inv.execute(
            "INSERT OR REPLACE INTO monitoring_incidents(id,collector_id,device_id,lineage,"
            "detector,state,episode_start,last_hour,detected_at,baseline_id,observed_bytes,"
            "threshold_bytes,evidence) VALUES (?,?,?,?,?,?,?,?,?,NULL,?,?,?)",
            (
                iid,
                "c1",
                device,
                iid,
                "upload",
                state,
                at,
                at,
                iso_utc(at),
                999_999_999,
                1,
                evidence,
            ),
        )

    def set_state(self, iid: str, state: str) -> None:
        self.inv.execute("UPDATE monitoring_incidents SET state=? WHERE id=?", (state, iid))

    def name(self, device: str, name: str) -> None:
        self.ov.execute(
            "INSERT INTO device_overrides(device_id,name,updated_at,updated_by) VALUES (?,?,?,?)",
            (device, name, "2026-01-01T00:00:00Z", "t"),
        )

    def decide(self, iid: str, status: str | None, until: int | None = None) -> None:
        self.ov.execute(
            "INSERT OR REPLACE INTO incident_decisions(incident_id,collector_id,device_id,"
            "lineage,detector,episode_start,status,snooze_until,version,decided_by,decided_at,id)"
            " VALUES (?,?,?,?,?,?,?,?,1,'t','2026-01-01T00:00:00Z',?)",
            (iid, "c1", "dev-1", "L", "upload", T0, status, until, "id-" + iid),
        )

    def rows(self) -> list[sqlite3.Row]:
        cur = self.inv.execute("SELECT * FROM incident_deliveries ORDER BY row_id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]

    def states(self) -> dict[str, str]:
        return {r["kind"]: r["state"] for r in self.rows()}

    def close(self) -> None:
        for conn in (self.inv, self.ov, self.ro):
            if conn is not None:
                conn.close()


def dconf(**kw) -> DeliveryConfig:
    base = {"eligible_since": SINCE, "transmit_deadline_seconds": 1, "lease_seconds": 60}
    return DeliveryConfig(**(base | kw))
