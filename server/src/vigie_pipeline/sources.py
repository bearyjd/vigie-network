"""Read one recorded batch's raw rows from the daily shards (read-only) and fold them per MAC.

Only the columns needed for identity are selected; qnames are never read.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from vigie_ingest.db import SHARD_RE
from vigie_pipeline.logs import log
from vigie_pipeline.sanitize import clean_text

logger = logging.getLogger("vigie_pipeline")

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
RANDOMIZED_DIGITS = frozenset("26ae")  # second hex digit of first octet: locally administered
ZERO_MAC = "00:00:00:00:00:00"
OPT55_MAX_ENTRIES = 64
OPT55_MAX_CHARS = 256


class ShardReadError(RuntimeError):
    """A shard that exists could not be read; the batch must stay pending."""


@dataclass
class MacActivity:
    first_ts: int
    last_ts: int
    hours: set[int] = field(default_factory=set)
    stamps: set[int] = field(default_factory=set)  # every row ts seen, for activity intervals
    hostname: str | None = None
    opt55: str | None = None
    opt60: str | None = None
    mdns_name: str | None = None


def normalize_mac(raw: str | None) -> str | None:
    """Lower-case canonical MAC, or None for malformed or multicast/broadcast addresses."""
    mac = (raw or "").strip().lower()
    if not MAC_RE.match(mac) or int(mac[1], 16) & 1 or mac == ZERO_MAC:
        return None
    return mac


def is_randomized(mac: str) -> bool:
    return mac.strip().lower()[1] in RANDOMIZED_DIGITS


def _cap_opt55(entries: list[str]) -> str | None:
    text = ",".join(entries[:OPT55_MAX_ENTRIES])
    if len(text) > OPT55_MAX_CHARS:
        text = text[:OPT55_MAX_CHARS].rpartition(",")[0]  # cut on an entry boundary
    return text or None


def opt55_string(raw: str | None) -> str | None:
    """Canonical 'n,n,n' request-list string, bounded so one lease cannot bloat the table."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return _cap_opt55([raw.strip()]) if raw.strip() else None
    if isinstance(parsed, list):
        return _cap_opt55([str(x) for x in parsed if isinstance(x, int)])
    return None


def _clean(value: str | None) -> str | None:
    return clean_text(value)


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
    act.stamps.add(ts)
    return act


def _steps(
    acts: dict[str, MacActivity], skipped: set[str]
) -> tuple[tuple[str, str, Callable[[sqlite3.Row], object]], ...]:
    def lease(r: sqlite3.Row) -> None:
        act = _note(acts, skipped, r["mac"], r["ts"])
        if act:
            act.hostname = _clean(r["hostname"]) or act.hostname
            act.opt55 = opt55_string(r["opt55"]) or act.opt55
            act.opt60 = _clean(r["opt60"]) or act.opt60

    def sighting(r: sqlite3.Row) -> None:
        act = _note(acts, skipped, r["mac"], r["ts"])
        if act and r["kind"] == "mdns":
            act.mdns_name = _clean(r["name"]) or act.mdns_name

    return (
        ("raw_lease", "ts, mac, hostname, opt55, opt60", lease),
        ("raw_neigh", "ts, mac", lambda r: _note(acts, skipped, r["mac"], r["ts"])),
        ("raw_sighting", "ts, mac, kind, name", sighting),
        ("raw_dns", "ts, device_mac", lambda r: _note(acts, skipped, r["device_mac"], r["ts"])),
        ("raw_flow", "ts, device_mac", lambda r: _note(acts, skipped, r["device_mac"], r["ts"])),
    )


def _fold_shard(
    conn: sqlite3.Connection,
    key: tuple[str, str],
    acts: dict[str, MacActivity],
    skipped: set[str],
    shard: str,
) -> list[str]:
    """Read each table independently so every failure is reported; returns failed tables."""
    failed: list[str] = []
    for table, columns, handle in _steps(acts, skipped):
        sql = (
            f"SELECT {columns} FROM {table} "  # noqa: S608  (fixed names, not user input)
            "WHERE collector_id=? AND batch_id=? ORDER BY ts, rowid"
        )
        try:
            for row in conn.execute(sql, key):
                handle(row)
        except sqlite3.Error as exc:
            failed.append(table)
            log(
                logger, logging.ERROR, "shard_read_failed", shard=shard, table=table, error=str(exc)
            )
    return failed


def read_batch(
    data_dir: Path, collector_id: str, batch_id: str
) -> tuple[dict[str, MacActivity], int]:
    """Fold a recorded batch's rows across every shard it spans. Returns (acts, skipped_macs).
    A shard FILE that is gone (retention) is skipped; any other failure raises ShardReadError
    so the caller leaves the batch pending."""
    acts: dict[str, MacActivity] = {}
    skipped: set[str] = set()
    failures: list[str] = []
    for path in shard_paths(data_dir):
        if not path.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=5.0)
        except sqlite3.Error as exc:
            failures.append(path.name)
            log(logger, logging.ERROR, "shard_read_failed", shard=path.name, error=str(exc))
            continue
        conn.row_factory = sqlite3.Row
        try:
            failed = _fold_shard(conn, (collector_id, batch_id), acts, skipped, path.name)
        finally:
            conn.close()
        failures.extend(f"{path.name}:{t}" for t in failed)
    if failures:
        raise ShardReadError(f"batch {batch_id} unreadable: {', '.join(failures)}")
    return acts, len(skipped)
