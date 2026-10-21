"""Read one recorded batch's raw rows from the daily shards (read-only) and fold them per MAC.

Only the columns needed for identity are selected; qnames are never read.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from vigie_ingest.db import SHARD_RE
from vigie_pipeline.logs import log

logger = logging.getLogger("vigie_pipeline")

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
RANDOMIZED_DIGITS = frozenset("26ae")  # second hex digit of first octet: locally administered


@dataclass
class MacActivity:
    first_ts: int
    last_ts: int
    hours: set[int] = field(default_factory=set)
    hostname: str | None = None
    opt55: str | None = None
    opt60: str | None = None
    mdns_name: str | None = None


def normalize_mac(raw: str | None) -> str | None:
    """Lower-case canonical MAC, or None for malformed or multicast/broadcast addresses."""
    mac = (raw or "").strip().lower()
    if not MAC_RE.match(mac) or int(mac[1], 16) & 1:
        return None
    return mac


def is_randomized(mac: str) -> bool:
    return mac[1] in RANDOMIZED_DIGITS


def opt55_string(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return raw.strip() or None
    if isinstance(parsed, list):
        return ",".join(str(int(x)) for x in parsed if isinstance(x, int)) or None
    return None


def _clean(value: str | None) -> str | None:
    return (value or "").strip() or None


def shard_paths(data_dir: Path) -> list[Path]:
    return sorted(p for p in data_dir.glob("raw-*.db") if SHARD_RE.match(p.name))


def _note(
    acts: dict[str, MacActivity], skipped: set[str], raw_mac: str | None, ts: int
) -> MacActivity | None:
    mac = normalize_mac(raw_mac)
    if mac is None:
        skipped.add(raw_mac or "")
        return None
    act = acts.get(mac)
    if act is None:
        act = acts[mac] = MacActivity(first_ts=ts, last_ts=ts)
    act.first_ts = min(act.first_ts, ts)
    act.last_ts = max(act.last_ts, ts)
    act.hours.add(ts // 3600)
    return act


def _fold_shard(
    conn: sqlite3.Connection, key: tuple[str, str], acts: dict[str, MacActivity], skipped: set[str]
) -> None:
    where = "WHERE collector_id=? AND batch_id=?"
    for r in conn.execute(f"SELECT ts, mac, hostname, opt55, opt60 FROM raw_lease {where}", key):  # noqa: S608
        act = _note(acts, skipped, r["mac"], r["ts"])
        if act:
            act.hostname = _clean(r["hostname"]) or act.hostname
            act.opt55 = opt55_string(r["opt55"]) or act.opt55
            act.opt60 = _clean(r["opt60"]) or act.opt60
    for r in conn.execute(f"SELECT ts, mac FROM raw_neigh {where}", key):  # noqa: S608
        _note(acts, skipped, r["mac"], r["ts"])
    for r in conn.execute(f"SELECT ts, mac, kind, name FROM raw_sighting {where}", key):  # noqa: S608
        act = _note(acts, skipped, r["mac"], r["ts"])
        if act and r["kind"] == "mdns":
            act.mdns_name = _clean(r["name"]) or act.mdns_name
    for r in conn.execute(f"SELECT ts, device_mac FROM raw_dns {where}", key):  # noqa: S608
        _note(acts, skipped, r["device_mac"], r["ts"])
    for r in conn.execute(f"SELECT ts, device_mac FROM raw_flow {where}", key):  # noqa: S608
        _note(acts, skipped, r["device_mac"], r["ts"])


def read_batch(
    data_dir: Path, collector_id: str, batch_id: str
) -> tuple[dict[str, MacActivity], int]:
    """Fold a recorded batch's rows across every shard it spans. Returns (acts, skipped_macs).
    A shard deleted by retention mid-read is skipped, not fatal."""
    acts: dict[str, MacActivity] = {}
    skipped: set[str] = set()
    for path in shard_paths(data_dir):
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        except sqlite3.Error:
            log(logger, logging.WARNING, "shard_unreadable", shard=path.name)
            continue
        conn.row_factory = sqlite3.Row
        try:
            _fold_shard(conn, (collector_id, batch_id), acts, skipped)
        except sqlite3.Error as exc:
            log(logger, logging.WARNING, "shard_read_failed", shard=path.name, error=str(exc))
        finally:
            conn.close()
    return acts, len(skipped)
