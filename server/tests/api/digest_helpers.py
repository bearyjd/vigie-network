"""Fixtures for the pilot-digest tests: synthetic databases built in tmp_path, then copied."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vigie_api import cli
from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.schema import open_pipeline_inventory

DAY = "2026-11-20"
LO = int(datetime(2026, 11, 20, tzinfo=UTC).timestamp())
HI = LO + 86400
NOW = iso_utc(HI + 2 * 86400)
MAC = "00:00:5e:00:53:01"
HOSTNAME = "kitchen-laptop"
IP = "192.0.2.10"
POOLED_V = BaselineConfig().version


@dataclass
class Live:
    root: Path
    inv: sqlite3.Connection
    ov: sqlite3.Connection
    n: int = 0

    def network(self, cid: str, qualified: int = 24) -> None:
        self.inv.execute("INSERT OR IGNORE INTO collectors(id,key_id) VALUES (?,?)", (cid, cid))
        for h in range(qualified):
            self.cover(cid, LO + h * 3600)

    def cover(self, cid: str, hour: int, seconds: int = 3600, reasons: str = "[]") -> None:
        self.inv.execute(
            "INSERT OR REPLACE INTO coverage_hourly VALUES (?,?,?,?,?)",
            (cid, hour, 3600, seconds, reasons),
        )

    def incident(self, iid: str, cid: str = "c1", detector: str = "large_upload",
                 at: int = LO + 7200, state: str = "open") -> None:  # fmt: skip
        self.n += 1  # one open incident per device scope: a lineage per incident
        self.inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,"
            "evidence) VALUES (?,?,?,?,?,?,?,?,?,NULL,1,1,?)",
            (iid, cid, "dev-1", f"lin-{self.n}", detector, state, at - 3600,
             at // 3600 * 3600 - 3600, iso_utc(at), json.dumps({"mac": MAC, "ip": IP})),
        )  # fmt: skip

    def open_row(self, iid: str, state: str, at: int | None = None) -> None:
        self.n += 1
        when = LO + 7300 if at is None else at
        pending = when + 60 if state in ("pending", "sending") else None
        self.inv.execute(
            "INSERT INTO incident_deliveries(delivery_id,incident_id,kind,state,next_attempt_at,"
            "last_error,created_at,updated_at) VALUES (?,?,'open',?,?,?,?,?)",
            (f"{self.n:032d}", iid, state, pending, f"err {IP}", when, when),
        )

    def decide(self, iid: str, status: str | None, cid: str = "c1") -> None:
        self.n += 1
        self.ov.execute(
            "INSERT INTO incident_decisions(incident_id,collector_id,device_id,lineage,detector,"
            "episode_start,status,snooze_until,version,decided_by,decided_at,id) "
            "VALUES (?,?,'dev-1','lin-1','large_upload',0,?,?,1,'owner',?,?)",
            (iid, cid, status, HI if status == "snoozed" else None, iso_utc(HI), f"d{self.n}"),
        )

    def watermark(self, at: int) -> None:
        self.inv.execute(
            "INSERT OR REPLACE INTO pipeline_meta(key,value) VALUES ('delivery_eligible_since',?)",
            (str(at),),
        )

    def engine_ran(self) -> None:
        self.inv.execute(
            "INSERT OR IGNORE INTO monitoring_profiles VALUES "
            "('c1','dev-1','lin-1',?,0,'mature',NULL,?,0,0)",
            (POOLED_V, HI),
        )

    def snapshot(self, name: str = "copy") -> Path:
        """Checkpointed copies, like a verified backup: rollback journal, no sidecars."""
        self.inv.commit()
        out = self.root / name
        out.mkdir()
        for conn, file in ((self.inv, "inventory.db"), (self.ov, "overrides.db")):
            conn.execute("VACUUM INTO ?", (str(out / file),))
        return out


@pytest.fixture
def live(tmp_path: Path) -> Iterator[Live]:
    (tmp_path / "live").mkdir()
    inv = open_pipeline_inventory(tmp_path / "live" / "inventory.db", migrate=True)
    ov = open_overrides(tmp_path / "live" / "overrides.db")
    inv.execute("INSERT INTO devices(id,first_seen,last_seen) VALUES ('dev-1','x','x')")
    inv.execute(
        "INSERT INTO observations(mac,device_id,is_randomized,hostname,link_source,first_seen,"
        "last_seen) VALUES (?,'dev-1',0,?,'self','x','x')",
        (MAC, HOSTNAME),
    )
    inv.execute("INSERT INTO mac_last_ip VALUES (?,?,1,'lease')", (MAC, IP))
    item = Live(tmp_path, inv, ov)
    item.watermark(LO)
    item.engine_ran()
    yield item
    inv.close()
    ov.close()


def run(snap: Path, capsys, *extra: str, day: str = DAY, now: str = NOW) -> tuple[int, str, str]:
    argv = ["pilot-digest", "--inventory", str(snap / "inventory.db"), "--overrides",
            str(snap / "overrides.db"), "--day", day, "--now", now, *extra]  # fmt: skip
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def digest(live: Live, capsys, **kw) -> dict:
    code, out, err = run(live.snapshot(), capsys, "--format", "json", **kw)
    assert code == 0, err
    return json.loads(out)


def items(d: dict) -> dict[str, dict]:
    return {i["incident_id"]: i for i in d["items"]}
