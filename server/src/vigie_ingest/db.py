"""SQLite connections, versioned migrations, and shard helpers."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path

BUSY_TIMEOUT_MS = 5000
# Connections opened under SHARD_LOCK wait less, so a stuck writer cannot stall every request.
LOCKED_BUSY_TIMEOUT_MS = 1500
WAL_RETRIES = 8
# Serialises shard writes with shard-file deletion (in-process; one ingest process per data dir).
SHARD_LOCK = threading.RLock()
SHARD_TABLES = ("raw_dns", "raw_flow", "raw_lease", "raw_neigh", "raw_sighting", "raw_health")
SHARD_RE = re.compile(r"^raw-(\d{4})(\d{2})(\d{2})\.db$")

INVENTORY_MIGRATIONS: Sequence[str] = (
    # v1: PRP section 5. devices/observations are owned by the pipeline; created, unused here.
    """
    CREATE TABLE devices (
      id TEXT PRIMARY KEY,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      inferred_type TEXT, inferred_confidence REAL, inferred_source TEXT,
      inferred_reason_code TEXT, inferred_reason_text TEXT,
      inferred_model_version TEXT, inferred_updated_at TEXT,
      identity_state TEXT NOT NULL DEFAULT 'ok'
        CHECK (identity_state IN ('ok','conflict','pending_confirm')),
      status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','transient','retired'))
    );
    CREATE TRIGGER no_device_delete BEFORE DELETE ON devices
      BEGIN SELECT RAISE(ABORT,'devices are retired, never deleted'); END;
    CREATE TABLE observations (
      mac TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
      is_randomized INTEGER NOT NULL, dhcp_fingerprint TEXT, vendor_class TEXT, hostname TEXT,
      mdns_name TEXT,
      link_source TEXT NOT NULL CHECK (link_source IN ('self','rule','human')),
      link_rule_id TEXT, link_score REAL,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
    );
    CREATE INDEX idx_obs_device ON observations(device_id, last_seen);
    CREATE TABLE collectors (
      id TEXT PRIMARY KEY, key_id TEXT NOT NULL,
      last_seq INTEGER NOT NULL DEFAULT 0, boot_id TEXT,
      revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE batches (
      batch_id TEXT PRIMARY KEY, collector_id TEXT NOT NULL, received_at TEXT NOT NULL
    );
    """,
    # v2: parse-failure counter (post-auth rejects are counted, never applied); purge index.
    """
    ALTER TABLE collectors ADD COLUMN parse_failures INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX idx_batches_received ON batches(received_at);
    """,
    # v3: boot_id-rollback guard, per-collector batch ids, truncation counters on the batch row.
    """
    ALTER TABLE collectors ADD COLUMN last_sent_ts INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE batches_new (
      collector_id TEXT NOT NULL, batch_id TEXT NOT NULL, received_at TEXT NOT NULL,
      truncated TEXT, dropped_batches INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (collector_id, batch_id)
    );
    INSERT INTO batches_new (collector_id, batch_id, received_at)
      SELECT collector_id, batch_id, received_at FROM batches;
    DROP TABLE batches;
    ALTER TABLE batches_new RENAME TO batches;
    CREATE INDEX idx_batches_received ON batches(received_at);
    """,
    # v4: retain observation windows beyond raw shards; NULL means legacy unknown.
    """
    ALTER TABLE batches ADD COLUMN window_start INTEGER;
    ALTER TABLE batches ADD COLUMN window_end INTEGER;
    ALTER TABLE batches ADD COLUMN observation_kind TEXT;
    ALTER TABLE batches ADD COLUMN health TEXT;
    """,
)

SHARD_MIGRATIONS: Sequence[str] = (
    """
    CREATE TABLE raw_dns (
      collector_id TEXT NOT NULL, ts INTEGER NOT NULL, device_mac TEXT NOT NULL,
      qname TEXT NOT NULL, qtype TEXT NOT NULL, answer_ip TEXT
    );
    CREATE TABLE raw_flow (
      collector_id TEXT NOT NULL, ts INTEGER NOT NULL, device_mac TEXT NOT NULL,
      dst_ip TEXT, dst_port INTEGER, proto TEXT NOT NULL,
      bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL, flows INTEGER NOT NULL
    );
    CREATE INDEX idx_raw_dns_ts ON raw_dns(ts);
    CREATE INDEX idx_raw_flow_ts ON raw_flow(ts);
    """,
    # v2: batch_id for idempotent re-apply (delete-by-batch then insert) + remaining payloads.
    """
    ALTER TABLE raw_dns ADD COLUMN batch_id TEXT;
    ALTER TABLE raw_flow ADD COLUMN batch_id TEXT;
    CREATE INDEX idx_raw_dns_batch ON raw_dns(collector_id, batch_id);
    CREATE INDEX idx_raw_flow_batch ON raw_flow(collector_id, batch_id);
    CREATE TABLE raw_lease (
      batch_id TEXT NOT NULL, collector_id TEXT NOT NULL, ts INTEGER NOT NULL,
      mac TEXT NOT NULL, ip TEXT NOT NULL, hostname TEXT, opt55 TEXT, opt60 TEXT
    );
    CREATE TABLE raw_neigh (
      batch_id TEXT NOT NULL, collector_id TEXT NOT NULL, ts INTEGER NOT NULL,
      ip TEXT NOT NULL, mac TEXT NOT NULL, family TEXT NOT NULL
    );
    CREATE TABLE raw_sighting (
      batch_id TEXT NOT NULL, collector_id TEXT NOT NULL, ts INTEGER NOT NULL,
      mac TEXT NOT NULL, kind TEXT NOT NULL, name TEXT, service TEXT, ua TEXT
    );
    CREATE TABLE raw_health (
      batch_id TEXT NOT NULL, collector_id TEXT NOT NULL, ts INTEGER NOT NULL,
      dns_log_quiet INTEGER NOT NULL, rss_kb INTEGER, spool_batches INTEGER, uptime_s INTEGER
    );
    CREATE INDEX idx_raw_lease_batch ON raw_lease(collector_id, batch_id);
    CREATE INDEX idx_raw_neigh_batch ON raw_neigh(collector_id, batch_id);
    CREATE INDEX idx_raw_sighting_batch ON raw_sighting(collector_id, batch_id);
    CREATE INDEX idx_raw_health_batch ON raw_health(collector_id, batch_id);
    """,
)


def connect(path: Path | str, busy_timeout_ms: int = BUSY_TIMEOUT_MS) -> sqlite3.Connection:
    """Open a connection with the mandatory pragmas (WAL, secure_delete, busy timeout)."""
    conn = sqlite3.connect(str(path), timeout=busy_timeout_ms / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    _enable_wal(conn)
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _enable_wal(conn: sqlite3.Connection) -> None:
    """WAL is persistent in the file; switching it can fail with 'locked' under contention
    (busy_timeout does not cover the mode switch), so only switch when needed and retry."""
    for attempt in range(WAL_RETRIES):
        if conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal":
            return
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            if attempt == WAL_RETRIES - 1:
                raise
            time.sleep(0.05 * (attempt + 1))


@contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[None]:
    """BEGIN IMMEDIATE ... COMMIT; any failure (including COMMIT itself) rolls back."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def migrate(conn: sqlite3.Connection, migrations: Sequence[str]) -> int:
    """Apply pending migrations in order, each in its own transaction. Returns the version."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > len(migrations):
        raise RuntimeError(f"database schema v{current} is newer than this build")
    for index in range(current, len(migrations)):
        conn.execute("BEGIN IMMEDIATE")
        try:
            (version,) = conn.execute("PRAGMA user_version").fetchone()
            if version == index:  # another process may have migrated while we waited
                for statement in _split(migrations[index]):
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version={index + 1}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _split(script: str) -> list[str]:
    """Split a migration script into statements; write one statement per line-end (triggers
    may span lines and keep their BEGIN..END)."""
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines():
        buffer += line + "\n"
        stripped = buffer.strip()
        if stripped.endswith(";") and sqlite3.complete_statement(stripped):
            statements.append(stripped)
            buffer = ""
    return statements


def open_inventory(path: Path) -> sqlite3.Connection:
    conn = connect(path)
    migrate(conn, INVENTORY_MIGRATIONS)
    return conn


def shard_name(day: date) -> str:
    return f"raw-{day:%Y%m%d}.db"


def ensure_shard(data_dir: Path, day: date, busy_timeout_ms: int = BUSY_TIMEOUT_MS) -> Path:
    path = data_dir / shard_name(day)
    conn = connect(path, busy_timeout_ms)
    try:
        migrate(conn, SHARD_MIGRATIONS)
    finally:
        conn.close()
    return path


def utc_day(ts: int) -> date:
    return datetime.fromtimestamp(ts, tz=UTC).date()


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
