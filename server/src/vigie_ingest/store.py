"""Batch persistence: state checks and the crash-safe apply.

Apply order (SQLite WAL is not atomic across files):
  1. For each shard day: one transaction that DELETEs this batch's rows then INSERTs them
     (idempotent, so a retry after a crash converges to exactly one copy). Committed first.
  2. Inventory: BEGIN IMMEDIATE, re-check state, insert the batches row, advance seq, COMMIT.
A crash between 1 and 2 leaves shard rows but no batches row; the collector's retry is applied
normally (not reported as a duplicate) and replaces those rows.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from vigie_ingest.db import (
    SHARD_LOCK,
    SHARD_TABLES,
    connect,
    ensure_shard,
    immediate,
    iso_utc,
    shard_name,
    utc_day,
)
from vigie_ingest.models import Batch

Rejection = Literal["duplicate", "bad_ts", "seq_regression"]
Outcome = Literal["applied", "revoked"] | Rejection

_INSERTS: dict[str, str] = {
    "raw_dns": "(batch_id, collector_id, ts, device_mac, qname, qtype, answer_ip)",
    "raw_flow": "(batch_id, collector_id, ts, device_mac, dst_ip, dst_port, proto,"
    " bytes_up, bytes_down, flows)",
    "raw_lease": "(batch_id, collector_id, ts, mac, ip, hostname, opt55, opt60)",
    "raw_neigh": "(batch_id, collector_id, ts, ip, mac, family)",
    "raw_sighting": "(batch_id, collector_id, ts, mac, kind, name, service, ua)",
    "raw_health": "(batch_id, collector_id, ts, dns_log_quiet, rss_kb, spool_batches, uptime_s)",
}

ShardRows = dict[str, list[tuple]]


@dataclass(frozen=True)
class CollectorRow:
    id: str
    key_id: str
    last_seq: int
    boot_id: str | None
    revoked: bool
    last_sent_ts: int


def provision_collector(
    conn: sqlite3.Connection, collector_id: str, key_id: str, force: bool = False
) -> None:
    """Register a collector. Re-provisioning a revoked one needs force and resets its state."""
    existing = get_collector(conn, collector_id)
    if existing is None:
        conn.execute("INSERT INTO collectors (id, key_id) VALUES (?, ?)", (collector_id, key_id))
    elif existing.revoked and not force:
        raise ValueError(f"collector {collector_id!r} is revoked; re-provisioning needs force")
    elif existing.revoked or force:
        conn.execute(
            "UPDATE collectors SET key_id=?, last_seq=0, boot_id=NULL, last_sent_ts=0, revoked=0"
            " WHERE id=?",
            (key_id, collector_id),
        )
    else:
        conn.execute("UPDATE collectors SET key_id=? WHERE id=?", (key_id, collector_id))


def revoke_collector(conn: sqlite3.Connection, collector_id: str) -> bool:
    return conn.execute("UPDATE collectors SET revoked=1 WHERE id=?", (collector_id,)).rowcount > 0


def _row(row: sqlite3.Row) -> CollectorRow:
    return CollectorRow(
        row["id"], row["key_id"], row["last_seq"], row["boot_id"], bool(row["revoked"]),
        row["last_sent_ts"],
    )  # fmt: skip


def get_collector(conn: sqlite3.Connection, collector_id: str) -> CollectorRow | None:
    row = conn.execute("SELECT * FROM collectors WHERE id=?", (collector_id,)).fetchone()
    return None if row is None else _row(row)


def active_collectors(conn: sqlite3.Connection) -> list[CollectorRow]:
    return [_row(r) for r in conn.execute("SELECT * FROM collectors WHERE revoked=0 ORDER BY id")]


def check_state(
    conn: sqlite3.Connection,
    collector: CollectorRow,
    batch_id: str,
    boot_id: str,
    seq: int,
    sent_ts: int,
    now: float,
    max_skew_s: int,
) -> Rejection | None:
    """PRP section 4 order: duplicate batch_id, then |sent_ts-now|, then seq within boot_id.

    A different boot_id resets seq, but only forward in time: a batch signed before the last
    accepted one (sent_ts < last_sent_ts) cannot be replayed by switching back to an old boot.
    """
    dup = conn.execute(
        "SELECT 1 FROM batches WHERE collector_id=? AND batch_id=?", (collector.id, batch_id)
    ).fetchone()
    if dup:
        return "duplicate"
    if abs(sent_ts - now) > max_skew_s:
        return "bad_ts"
    if boot_id == collector.boot_id:
        if seq <= collector.last_seq:
            return "seq_regression"
    elif collector.boot_id is not None and sent_ts < collector.last_sent_ts:
        return "seq_regression"
    return None


def record_parse_failure(conn: sqlite3.Connection, collector_id: str) -> None:
    conn.execute(
        "UPDATE collectors SET parse_failures = parse_failures + 1 WHERE id=?", (collector_id,)
    )


def _clamp(ts: int, low: int, high: int) -> int:
    return max(low, min(high, ts))


def rows_by_day(batch: Batch) -> dict[date, ShardRows]:
    """Split a batch into per-shard-day rows; each record's own ts, clamped to the window."""
    out: dict[date, ShardRows] = defaultdict(lambda: defaultdict(list))
    ws, we = batch.window_start, batch.window_end
    head = (batch.batch_id, batch.collector_id)

    def add(table: str, ts: int, *fields: object) -> None:
        out[utc_day(ts)][table].append((*head, ts, *fields))

    for q in batch.dns:
        add("raw_dns", _clamp(q.ts, ws, we), q.mac, q.qname, q.qtype, q.answer_ip)
    for c in batch.conntrack:
        add("raw_flow", we, c.mac, c.dst_ip, c.dst_port, c.proto, c.bytes_up, c.bytes_down,
            c.flows)  # fmt: skip
    for lease in batch.leases:
        add("raw_lease", we, lease.mac, lease.ip, lease.hostname, json.dumps(lease.opt55),
            lease.opt60)  # fmt: skip
    for n in batch.neigh:
        add("raw_neigh", we, n.ip, n.mac, n.family)
    for s in batch.sightings:
        add("raw_sighting", we, s.mac, s.kind, s.name, s.service, s.ua)
    if batch.health is not None:
        h = batch.health
        add("raw_health", we, int(h.dns_log_quiet), h.rss_kb, h.spool_batches, h.uptime_s)
    return out


def _after_shard_commit() -> None:
    """Test seam: crash tests replace this to simulate dying before the inventory commit."""


def _write_shard(data_dir: Path, day: date, tables: ShardRows, batch: Batch) -> None:
    ensure_shard(data_dir, day)
    conn = connect(data_dir / shard_name(day))
    try:
        with immediate(conn):
            _delete_batch_rows(conn, batch)
            for table, rows in tables.items():
                marks = ",".join("?" * len(rows[0]))
                conn.executemany(
                    f"INSERT INTO {table} {_INSERTS[table]} VALUES ({marks})",  # noqa: S608
                    rows,
                )
    finally:
        conn.close()


def _delete_batch_rows(conn: sqlite3.Connection, batch: Batch) -> None:
    for table in SHARD_TABLES:
        conn.execute(
            f"DELETE FROM {table} WHERE collector_id=? AND batch_id=?",  # noqa: S608
            (batch.collector_id, batch.batch_id),
        )


def _remove_shard_rows(data_dir: Path, days: list[date], batch: Batch) -> None:
    with SHARD_LOCK:
        for day in days:
            path = data_dir / shard_name(day)
            if not path.exists():
                continue
            conn = connect(path)
            try:
                with immediate(conn):
                    _delete_batch_rows(conn, batch)
            finally:
                conn.close()


def apply_batch(
    inventory_path: Path, data_dir: Path, batch: Batch, now: float, max_skew_s: int
) -> Outcome:
    """Apply one validated batch; see the module docstring for the ordering guarantees."""
    by_day = rows_by_day(batch)
    with SHARD_LOCK:
        for day, tables in by_day.items():
            _write_shard(data_dir, day, tables, batch)
    _after_shard_commit()

    conn = connect(inventory_path)
    try:
        with immediate(conn):
            result = _commit_inventory(conn, batch, now, max_skew_s)
    finally:
        conn.close()
    if result not in ("applied", "duplicate"):
        _remove_shard_rows(data_dir, list(by_day), batch)  # rejected: compensate
    return result


def _commit_inventory(
    conn: sqlite3.Connection, batch: Batch, now: float, max_skew_s: int
) -> Outcome:
    collector = get_collector(conn, batch.collector_id)
    if collector is None or collector.revoked or collector.key_id != batch.key_id:
        return "revoked"
    rejection = check_state(
        conn, collector, batch.batch_id, batch.boot_id, batch.seq, batch.sent_ts, now, max_skew_s
    )
    if rejection:
        return rejection
    conn.execute(
        "INSERT INTO batches (collector_id, batch_id, received_at, truncated, dropped_batches)"
        " VALUES (?,?,?,?,?)",
        (batch.collector_id, batch.batch_id, iso_utc(now), json.dumps(batch.truncated),
         batch.dropped_batches),
    )  # fmt: skip
    conn.execute(
        "UPDATE collectors SET last_seq=?, boot_id=?, last_sent_ts=MAX(last_sent_ts, ?)"
        " WHERE id=?",
        (batch.seq, batch.boot_id, batch.sent_ts, batch.collector_id),
    )
    return "applied"
