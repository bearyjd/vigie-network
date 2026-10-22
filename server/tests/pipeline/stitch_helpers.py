"""Builders for stitching tests: explicit activity windows and a seeded overrides.db."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pipeline_helpers import T0, Data

from vigie_api.schema import open_overrides
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import RunStats, run_once

OPT55 = "[1,121,3,6,15,119,252]"
OPT60 = "android-dhcp-14"
HOST = "Daves-Phone"
MDNS = "Daves Phone"
NOW = T0 + 6 * 3600


def mac(n: int) -> str:
    return f"ae:00:00:00:00:{n:02x}"  # locally administered => randomized


def appear(
    data: Data,
    n: int,
    start: int,
    end: int,
    *,
    host: str | None = HOST,
    mdns: str | None = MDNS,
    opt55: str | None = OPT55,
    opt60: str | None = OPT60,
    step: int = 60,
) -> str:
    """One MAC (mac(n)) active over [start, end] (relative to T0), seen with a signature."""
    m = mac(n)
    data.add_batch(
        T0 + start,
        received=T0 + end,  # a batch is received after the rows it carries
        leases=[(m, host, opt55, opt60)],
        sightings=[(m, "mdns", mdns)] if mdns else (),
        dns=[(m, T0 + t) for t in range(start, end + 1, step)],
    )
    return m


def device_of(data: Data, mac_addr: str) -> str:
    return data.q("SELECT device_id FROM observations WHERE mac=?", mac_addr)[0][0]


def run(data: Data, **kw) -> RunStats:
    return run_once(PipelineConfig(data_dir=data.root, **kw), now=NOW)


def dump(data: Data, *tables: str) -> list[list[sqlite3.Row]]:
    return [data.q(f"SELECT * FROM {t}") for t in tables]  # noqa: S608


def kinds(data: Data, kind: str) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM events WHERE kind=? ORDER BY seq", kind)


def suggestions(data: Data) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM suggestions ORDER BY created_at, id")


def candidates(data: Data) -> list[sqlite3.Row]:
    return data.q("SELECT * FROM identity_candidates ORDER BY created_at, id")


class Overrides:
    """Read-write overrides.db built through the api's own migrations (the test plays vigie-api)."""

    def __init__(self, root: Path) -> None:
        self.path = root / "overrides.db"
        self.conn = open_overrides(self.path)

    def rule(self, rid: str, device_id: str, sig: dict, **kw: str | None) -> None:
        self.conn.execute(
            "INSERT INTO identity_rules (id, device_id, signature, created_at, created_by,"
            " expires_at, revoked_at) VALUES (?,?,?,?,?,?,?)",
            (rid, device_id, json.dumps(sig), "2026-10-01T00:00:00Z", "owner",
             kw.get("expires_at"), kw.get("revoked_at")),
        )  # fmt: skip

    def override(self, device_id: str, group: str | None, version: int = 1) -> None:
        self.conn.execute(
            "INSERT INTO device_overrides (device_id, group_id, version, updated_at, updated_by)"
            " VALUES (?,?,?,?,?)",
            (device_id, group, version, "2026-10-01T00:00:00Z", "owner"),
        )

    def decide(self, suggestion_id: str, state: str) -> None:
        self.conn.execute(
            "INSERT INTO suggestion_decisions (suggestion_id, state, decided_by, decided_at)"
            " VALUES (?,?,?,?)",
            (suggestion_id, state, "owner", "2026-10-01T00:00:00Z"),
        )

    def link(self, from_device: str, into_device: str) -> None:
        self.conn.execute(
            "INSERT INTO identity_links VALUES (?,?,?,?,?)",
            (from_device, into_device, "m1", "2026-10-01T00:00:00Z", "owner"),
        )

    def close(self) -> None:
        self.conn.close()


def sig(**kw: object) -> dict:
    base: dict[str, object] = {"opt55": OPT55 and "1,121,3,6,15,119,252", "opt60": OPT60,
                               "hostname": HOST}  # fmt: skip
    base.update(kw)
    return base
