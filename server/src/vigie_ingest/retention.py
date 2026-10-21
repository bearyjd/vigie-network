"""Retention: raw shard files are deleted by age; batch dedupe rows are purged after 7 days."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vigie_ingest.config import SHARD_RETENTION_MAX_DAYS, Settings
from vigie_ingest.db import SHARD_RE, iso_utc, open_inventory

log = logging.getLogger("vigie.ingest.retention")
_SIDECARS = ("-wal", "-shm")


def purge_shards(data_dir: Path, now: float, retention_days: int) -> list[str]:
    """Delete raw-YYYYMMDD.db shards (and WAL/SHM sidecars) older than `retention_days`.

    A shard for day D is kept while D >= today(UTC) - retention_days. Only files whose names
    match the shard pattern exactly are ever touched.
    """
    if not 1 <= retention_days <= SHARD_RETENTION_MAX_DAYS:
        raise ValueError(f"retention_days must be 1..{SHARD_RETENTION_MAX_DAYS}")
    cutoff = datetime.fromtimestamp(now, tz=UTC).date() - timedelta(days=retention_days)
    removed: list[str] = []
    for entry in sorted(data_dir.iterdir()):
        match = SHARD_RE.fullmatch(entry.name)
        if not match or not entry.is_file() or entry.is_symlink():
            continue
        try:
            day = datetime(*(int(g) for g in match.groups()), tzinfo=UTC).date()
        except ValueError:
            continue
        if day < cutoff:
            entry.unlink()
            for suffix in _SIDECARS:
                Path(f"{entry}{suffix}").unlink(missing_ok=True)
            removed.append(entry.name)
    return removed


def purge_batches(conn: sqlite3.Connection, now: float, retention_days: int) -> int:
    cutoff = iso_utc(now - retention_days * 86400)
    cursor = conn.execute("DELETE FROM batches WHERE received_at < ?", (cutoff,))
    return cursor.rowcount


def run_maintenance(settings: Settings, now: float) -> tuple[list[str], int]:
    removed = purge_shards(settings.data_dir, now, settings.shard_retention_days)
    conn = open_inventory(settings.inventory_path)
    try:
        purged = purge_batches(conn, now, settings.batch_retention_days)
    finally:
        conn.close()
    log.info("maintenance: %d shards removed, %d batch rows purged", len(removed), purged)
    return removed, purged
