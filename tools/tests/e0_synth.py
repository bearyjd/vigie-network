"""Synthetic builders for the E0 endpoint feasibility tests. Every value is invented.

LAN 192.168.8.0/24 mirrors tools/trafficgen; WAN destinations use documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32). MACs are locally administered.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

e0 = importlib.import_module("endpoint_e0")

HOST = "desk-1"
DEVICE = "dev-synthetic-1"
MAC = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"
SRC = "192.168.8.100"
COLLECTOR = "rtr-1"
T0 = 1_700_006_400  # 2023-11-15T00:00:00Z, a UTC midnight
DAY = 86400
WINDOW = 60


def scope_dict(**over: object) -> dict:
    base = {
        "host_id": HOST,
        "device_id": DEVICE,
        "macs": [{"mac": MAC}],
        "lan_prefixes": ["192.168.8.0/24", "fd00:8::/64"],
        "router_ips": ["192.168.8.1"],
        "period_start": T0,
        "period_end": T0 + 2 * DAY,
    }
    base.update(over)
    return base


def scope(**over: object):
    return e0.inputs.parse_scope(json.dumps(scope_dict(**over)))


def event(t: object, dst: str = "192.0.2.10", port: int = 443, proto: str = "tcp", **over):
    base = {
        "time": t,
        "protocol": proto,
        "src_ip": SRC,
        "src_port": 40000,
        "dst_ip": dst,
        "dst_port": port,
        "dst_host": "a.example",
        "process_path": "/usr/bin/synthetic",
        "user_id": 1000,
        "Action": "allow",
        "Rule": "r1",
        "Type": 0,
        "host_id": HOST,
    }
    base.update(over)
    return base


def lines(*events: dict) -> list[bytes]:
    return [json.dumps(e).encode() for e in events]


def batch(bid: str, start: int | None, end: int | None, **over):
    return e0.model.Batch(
        collector_id=over.get("collector_id", COLLECTOR),
        batch_id=bid,
        start=start,
        end=end,
        reasons=tuple(over.get("reasons", ())),
    )


def flow(bid: str, ts: int, dst: str | None = "192.0.2.10", port: int | None = 443, **over):
    return e0.model.Flow(
        collector_id=over.get("collector_id", COLLECTOR),
        batch_id=bid,
        ts=ts,
        mac=over.get("mac", MAC),
        dst_ip=dst,
        dst_port=port,
        proto=over.get("proto", "tcp" if dst is not None else "other"),
        bytes_up=over.get("up", 100),
        bytes_down=over.get("down", 900),
        flows=over.get("flows", 1),
    )


def write_inventory(path: Path, rows: list[tuple]) -> None:
    """rows: (collector, batch, window_start, window_end, kind, health, truncated, dropped)."""
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE batches (collector_id TEXT NOT NULL, batch_id TEXT NOT NULL, "
        "received_at TEXT NOT NULL, truncated TEXT, dropped_batches INTEGER NOT NULL DEFAULT 0, "
        "window_start INTEGER, window_end INTEGER, observation_kind TEXT, health TEXT, "
        "dns_queries INTEGER, PRIMARY KEY (collector_id, batch_id))"
    )
    db.executemany(
        "INSERT INTO batches (collector_id,batch_id,received_at,window_start,window_end,"
        "observation_kind,health,truncated,dropped_batches) VALUES (?,?,'x',?,?,?,?,?,?)",
        rows,
    )
    db.commit()
    db.close()


def write_shard(raw_dir: Path, day: str, rows: list[tuple]) -> None:
    """rows: (collector_id, ts, mac, dst_ip, dst_port, proto, up, down, flows, batch_id)."""
    db = sqlite3.connect(raw_dir / f"raw-{day}.db")
    db.execute(
        "CREATE TABLE IF NOT EXISTS raw_flow (collector_id TEXT NOT NULL, ts INTEGER NOT NULL, "
        "device_mac TEXT NOT NULL, dst_ip TEXT, dst_port INTEGER, proto TEXT NOT NULL, "
        "bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL, flows INTEGER NOT NULL, "
        "batch_id TEXT)"
    )
    db.executemany("INSERT INTO raw_flow VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    db.commit()
    db.close()


HEALTH = json.dumps({"uptime_s": 1})
