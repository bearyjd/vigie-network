from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from vigie_ingest.db import connect, ensure_shard, iso_utc, open_inventory, utc_day

T0 = 1_792_000_000  # fixed test clock (2026-10-14)
HOUR = 3600


@dataclass
class Data:
    """A data dir with an ingest-migrated inventory.db and hand-built shard rows."""

    root: Path
    inv: sqlite3.Connection = field(init=False)

    def __post_init__(self) -> None:
        self.inv = open_inventory(self.root / "inventory.db")

    def add_batch(
        self,
        ts: int = T0,
        *,
        collector: str = "rtr-1",
        record: bool = True,
        received: int | None = None,
        leases: Iterable[tuple] = (),
        neigh: Iterable[str] = (),
        sightings: Iterable[tuple] = (),
        dns: Iterable[tuple[str, int]] = (),
        flows: Iterable[str] = (),
    ) -> str:
        """leases: (mac, hostname, opt55 json, opt60); sightings: (mac, kind, name);
        dns: (mac, ts). record=False simulates a crashed commit (shard rows, no batches row)."""
        batch_id = str(uuid.uuid4())
        head = (batch_id, collector, ts)
        shard = ensure_shard(self.root, utc_day(ts))
        conn = connect(shard)
        for mac, host, opt55, opt60 in leases:
            conn.execute(
                "INSERT INTO raw_lease (batch_id, collector_id, ts, mac, ip, hostname, opt55,"
                " opt60) VALUES (?,?,?,?,?,?,?,?)",
                (*head, mac, "192.168.8.2", host, opt55, opt60),
            )
        for mac in neigh:
            conn.execute(
                "INSERT INTO raw_neigh (batch_id, collector_id, ts, ip, mac, family)"
                " VALUES (?,?,?,?,?,?)",
                (*head, "fe80::1", mac, "inet6"),
            )
        for mac, kind, name in sightings:
            conn.execute(
                "INSERT INTO raw_sighting (batch_id, collector_id, ts, mac, kind, name)"
                " VALUES (?,?,?,?,?,?)",
                (*head, mac, kind, name),
            )
        for mac, dts in dns:
            conn.execute(
                "INSERT INTO raw_dns (batch_id, collector_id, ts, device_mac, qname, qtype)"
                " VALUES (?,?,?,?,?,?)",
                (batch_id, collector, dts, mac, "secret-qname.example", "A"),
            )
        for mac in flows:
            conn.execute(
                "INSERT INTO raw_flow (batch_id, collector_id, ts, device_mac, proto, bytes_up,"
                " bytes_down, flows) VALUES (?,?,?,?,?,?,?,?)",
                (batch_id, collector, ts, mac, "tcp", 1, 2, 1),
            )
        conn.close()
        if record:
            self.inv.execute(
                "INSERT OR IGNORE INTO collectors (id, key_id) VALUES (?, 'k1')", (collector,)
            )
            self.inv.execute(
                "INSERT INTO batches (collector_id, batch_id, received_at) VALUES (?,?,?)",
                (collector, batch_id, iso_utc(ts if received is None else received)),
            )
        return batch_id

    def q(self, sql: str, *args: object) -> list[sqlite3.Row]:
        return self.inv.execute(sql, args).fetchall()

    def make_overrides(self) -> Path:
        path = self.root / "overrides.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE identity_links (
              from_device TEXT PRIMARY KEY, into_device TEXT NOT NULL, merge_id TEXT NOT NULL,
              created_at TEXT NOT NULL, created_by TEXT NOT NULL,
              CHECK (from_device <> into_device));
            """
        )
        conn.close()
        return path


@pytest.fixture
def data(tmp_path: Path) -> Iterator[Data]:
    d = Data(tmp_path)
    yield d
    d.inv.close()
