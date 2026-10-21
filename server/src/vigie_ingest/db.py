"""SQLite connections, versioned migrations, and shard helpers."""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path

BUSY_TIMEOUT_MS = 5000
WAL_RETRIES = 8
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
)


def connect(path: Path | str) -> sqlite3.Connection:
    """Open a connection with the mandatory pragmas (WAL, secure_delete, busy timeout)."""
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
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


def ensure_shard(data_dir: Path, day: date) -> Path:
    path = data_dir / shard_name(day)
    conn = connect(path)
    try:
        migrate(conn, SHARD_MIGRATIONS)
    finally:
        conn.close()
    return path


def utc_day(ts: int) -> date:
    return datetime.fromtimestamp(ts, tz=UTC).date()


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
