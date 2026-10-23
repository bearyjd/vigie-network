from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.schema import open_pipeline_inventory

NOW = 1_792_000_000.0
SUGGESTIONS_DDL = """CREATE TABLE IF NOT EXISTS suggestions (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL CHECK (action IN ('label','move_group','quarantine','merge_identity')),
  device_ids TEXT NOT NULL, payload TEXT NOT NULL,
  reason_code TEXT NOT NULL, reason_text TEXT, basis TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL
)"""


def ts(offset: float = 0) -> str:
    return iso_utc(NOW + offset)


@dataclass
class Env:
    root: Path
    settings: Settings
    inv: sqlite3.Connection
    ov: sqlite3.Connection
    token: str
    client: TestClient
    _n: int = field(default=0)

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def device(
        self,
        device_id: str,
        *,
        status: str = "active",
        identity_state: str = "ok",
        inferred_type: str | None = None,
        source: str | None = None,
        confidence: float | None = None,
        last_seen: float = 0,
    ) -> str:
        self.inv.execute(
            "INSERT INTO devices (id, first_seen, last_seen, inferred_type, inferred_confidence,"
            " inferred_source, identity_state, status) VALUES (?,?,?,?,?,?,?,?)",
            (device_id, ts(-1000), ts(last_seen), inferred_type, confidence, source,
             identity_state, status),
        )  # fmt: skip
        return device_id

    def mac(
        self,
        mac: str,
        device_id: str,
        *,
        link_source: str = "self",
        rule: str | None = None,
        first: float = -1000,
        last: float = 0,
    ) -> None:
        self.inv.execute(
            "INSERT INTO observations (mac, device_id, is_randomized, hostname, link_source,"
            " link_rule_id, first_seen, last_seen) VALUES (?,?,0,'host',?,?,?,?)",
            (mac, device_id, link_source, rule, ts(first), ts(last)),
        )

    def event(self, device_id: str | None, when: float, kind: str = "new_device",
              severity: str = "info") -> str:  # fmt: skip
        eid = str(uuid.uuid4())
        self.inv.execute(
            "INSERT INTO events (id, device_id, ts, kind, severity, summary) VALUES (?,?,?,?,?,?)",
            (eid, device_id, ts(when), kind, severity, f"{kind} {device_id}"),
        )
        return eid

    def suggestion(self, sid: str, *, expires: float, created: float = -10) -> None:
        self.inv.execute(
            "INSERT INTO suggestions VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, "label", json.dumps(["d1"]), json.dumps({"name": "x"}), "rc", None,
             json.dumps({"d1": 0}), ts(created), ts(expires)),
        )  # fmt: skip

    def link(self, from_device: str, into_device: str) -> None:
        self.ov.execute(
            "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
            " VALUES (?,?,?,?,?)",
            (from_device, into_device, "m1", ts(), "test"),
        )

    def get(self, path: str, **params: Any):
        return self.client.get(path, params=params, headers=self.auth)

    def patch(self, path: str, body: dict[str, Any], version: str | None = None):
        headers = dict(self.auth)
        if version is not None:
            headers["If-Match"] = version
        return self.client.patch(path, json=body, headers=headers)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    inv.execute(SUGGESTIONS_DDL)
    ov = open_overrides(tmp_path / "overrides.db")
    token_id, token = tokens.create_token(ov, "test")
    assert token_id == "test"
    settings = Settings(data_dir=tmp_path)
    app = create_app(settings, clock=lambda: NOW)
    with TestClient(app) as client:
        yield Env(tmp_path, settings, inv, ov, token, client)
    inv.close()
    ov.close()
