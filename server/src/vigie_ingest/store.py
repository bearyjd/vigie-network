"""Batch persistence: state checks and the single-transaction apply."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from vigie_ingest.db import connect, ensure_shard, iso_utc, shard_name, utc_day
from vigie_ingest.models import Batch

Rejection = Literal["duplicate", "bad_ts", "seq_regression"]


@dataclass(frozen=True)
class CollectorRow:
    id: str
    key_id: str
    last_seq: int
    boot_id: str | None
    revoked: bool


def provision_collector(conn: sqlite3.Connection, collector_id: str, key_id: str) -> None:
    conn.execute(
        "INSERT INTO collectors (id, key_id) VALUES (?, ?) "
        "ON CONFLICT(id) DO UPDATE SET key_id=excluded.key_id, revoked=0",
        (collector_id, key_id),
    )


def revoke_collector(conn: sqlite3.Connection, collector_id: str) -> bool:
    return conn.execute("UPDATE collectors SET revoked=1 WHERE id=?", (collector_id,)).rowcount > 0


def get_collector(conn: sqlite3.Connection, collector_id: str) -> CollectorRow | None:
    row = conn.execute(
        "SELECT id, key_id, last_seq, boot_id, revoked FROM collectors WHERE id=?",
        (collector_id,),
    ).fetchone()
    if row is None:
        return None
    return CollectorRow(
        row["id"], row["key_id"], row["last_seq"], row["boot_id"], bool(row["revoked"])
    )


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
    """PRP section 4 order: duplicate batch_id, then |sent_ts-now|, then seq within boot_id."""
    if conn.execute("SELECT 1 FROM batches WHERE batch_id=?", (batch_id,)).fetchone():
        return "duplicate"
    if abs(sent_ts - now) > max_skew_s:
        return "bad_ts"
    if boot_id == collector.boot_id and seq <= collector.last_seq:
        return "seq_regression"
    return None


def record_parse_failure(conn: sqlite3.Connection, collector_id: str) -> None:
    conn.execute(
        "UPDATE collectors SET parse_failures = parse_failures + 1 WHERE id=?", (collector_id,)
    )


def _shard_days(batch: Batch) -> set[date]:
    days = {utc_day(q.ts) for q in batch.dns}
    if batch.conntrack:
        days.add(utc_day(batch.window_end))
    return days


def apply_batch(
    inventory_path: Path,
    data_dir: Path,
    batch: Batch,
    now: float,
    max_skew_s: int,
) -> Rejection | Literal["applied", "revoked"]:
    """Apply one validated batch atomically: shard rows, batch id, and seq/boot_id advance.

    State checks are repeated under the write lock (BEGIN IMMEDIATE) so concurrent posts of the
    same batch_id cannot both apply. On any failure the transaction is rolled back.
    """
    aliases: dict[date, str] = {}
    for day in sorted(_shard_days(batch)):
        ensure_shard(data_dir, day)
        aliases[day] = f"s{day:%Y%m%d}"

    conn = connect(inventory_path)
    try:
        for day, alias in aliases.items():
            conn.execute(f"ATTACH DATABASE ? AS {alias}", (str(data_dir / shard_name(day)),))  # noqa: S608
            conn.execute(f"PRAGMA {alias}.secure_delete=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = _apply_locked(conn, aliases, batch, now, max_skew_s)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        if result == "applied":
            conn.execute("COMMIT")
        else:
            conn.execute("ROLLBACK")
        return result
    finally:
        conn.close()


def _apply_locked(
    conn: sqlite3.Connection,
    aliases: dict[date, str],
    batch: Batch,
    now: float,
    max_skew_s: int,
) -> Rejection | Literal["applied", "revoked"]:
    collector = get_collector(conn, batch.collector_id)
    if collector is None or collector.revoked or collector.key_id != batch.key_id:
        return "revoked"
    rejection = check_state(
        conn, collector, batch.batch_id, batch.boot_id, batch.seq, batch.sent_ts, now, max_skew_s
    )
    if rejection:
        return rejection

    for q in batch.dns:
        conn.execute(
            f"INSERT INTO {aliases[utc_day(q.ts)]}.raw_dns "  # noqa: S608
            "(collector_id, ts, device_mac, qname, qtype, answer_ip) VALUES (?,?,?,?,?,?)",
            (batch.collector_id, q.ts, q.mac, q.qname, q.qtype, q.answer_ip),
        )
    for c in batch.conntrack:
        conn.execute(
            f"INSERT INTO {aliases[utc_day(batch.window_end)]}.raw_flow "  # noqa: S608
            "(collector_id, ts, device_mac, dst_ip, dst_port, proto, bytes_up, bytes_down, flows) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                batch.collector_id, batch.window_end, c.mac, c.dst_ip, c.dst_port, c.proto,
                c.bytes_up, c.bytes_down, c.flows,
            ),
        )
    conn.execute(
        "INSERT INTO batches (batch_id, collector_id, received_at) VALUES (?,?,?)",
        (batch.batch_id, batch.collector_id, iso_utc(now)),
    )
    conn.execute(
        "UPDATE collectors SET last_seq=?, boot_id=? WHERE id=?",
        (batch.seq, batch.boot_id, batch.collector_id),
    )
    return "applied"
