"""Pipeline-owned inventory.db tables.

devices/observations/collectors/batches are created by ingest's migrations (user_version).
The pipeline versions its own tables separately (pipeline_schema) so the two migration
streams cannot collide, and so ingest can keep appending migrations.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

from vigie_ingest.db import INVENTORY_MIGRATIONS, connect, immediate, open_inventory

# Each migration is a tuple of single statements (triggers keep their BEGIN..END intact).
PIPELINE_MIGRATIONS: Sequence[Sequence[str]] = (
    (
        """CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, device_id TEXT REFERENCES devices(id), ts TEXT NOT NULL,
          kind TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL
        )""",
        # one new_device event per device, enforced by the database (event-once guard)
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_events_new_device ON events(device_id)"
        " WHERE kind = 'new_device'",
        """CREATE TABLE IF NOT EXISTS identity_candidates (
          id TEXT PRIMARY KEY, device_a TEXT NOT NULL, device_b TEXT NOT NULL,
          score REAL NOT NULL, evidence TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open',
          created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS pipeline_cursor (
          collector_id TEXT PRIMARY KEY,
          last_batch_rowid INTEGER NOT NULL,   -- highest batches.rowid fully processed
          last_batch_id TEXT NOT NULL,         -- its batch_id: detects rowid reuse after a purge
          updated_at TEXT NOT NULL
        )""",
        # distinct SERVER-received hours a transient device was seen in; pruned on exit
        """CREATE TABLE IF NOT EXISTS transient_hours (
          device_id TEXT NOT NULL REFERENCES devices(id), hour TEXT NOT NULL,
          PRIMARY KEY (device_id, hour)
        )""",
    ),
    (
        # server-side clock only: when a device became (or re-became) transient
        """CREATE TABLE IF NOT EXISTS transient_state (
          device_id TEXT PRIMARY KEY REFERENCES devices(id), since TEXT NOT NULL
        )""",
        "INSERT OR IGNORE INTO transient_state (device_id, since)"
        " SELECT id, first_seen FROM devices WHERE status='transient'",
        # promotions issued per server hour (cap) and whether the rate-limit event was emitted
        """CREATE TABLE IF NOT EXISTS promotion_log (
          hour TEXT PRIMARY KEY, promoted INTEGER NOT NULL DEFAULT 0,
          limited_emitted INTEGER NOT NULL DEFAULT 0
        )""",
    ),
)

PIPELINE_TABLES = (
    "events",
    "identity_candidates",
    "pipeline_cursor",
    "transient_hours",
    "transient_state",
    "promotion_log",
)


def apply_pipeline_migrations(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS pipeline_schema (version INTEGER NOT NULL)")
    row = conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()
    current = row[0] or 0
    if current > len(PIPELINE_MIGRATIONS):
        raise RuntimeError(f"pipeline schema v{current} is newer than this build")
    for index in range(current, len(PIPELINE_MIGRATIONS)):
        with immediate(conn):
            seen = conn.execute("SELECT MAX(version) FROM pipeline_schema").fetchone()[0] or 0
            if seen == index:  # another process may have migrated while we waited
                for statement in PIPELINE_MIGRATIONS[index]:
                    conn.execute(statement)
                conn.execute("INSERT INTO pipeline_schema (version) VALUES (?)", (index + 1,))
    return len(PIPELINE_MIGRATIONS)


class SchemaVersionError(RuntimeError):
    """ingest-owned schema is missing, behind, or newer than this build understands."""


def _ingest_schema_version(path: Path) -> int:
    """Read user_version without writing; 0 for a database that does not exist yet."""
    if not path.exists():
        return 0
    conn = sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True, timeout=5.0)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def open_pipeline_inventory(path: Path, migrate: bool = False) -> sqlite3.Connection:
    """Open inventory.db rw. Ingest owns devices/observations/collectors/batches: by default the
    pipeline only verifies their schema version and refuses to run ingest's migrations; pass
    migrate=True (CLI --migrate) to bootstrap or upgrade them. A newer schema is always refused."""
    expected = len(INVENTORY_MIGRATIONS)
    version = _ingest_schema_version(path)
    if version > expected:
        raise SchemaVersionError(
            f"inventory schema v{version} is newer than this pipeline build (v{expected})"
        )
    if version < expected and not migrate:
        raise SchemaVersionError(
            f"inventory schema is v{version}, expected v{expected}; start ingest first "
            "or pass --migrate to let the pipeline apply ingest's migrations"
        )
    conn = open_inventory(path) if version < expected else connect(path)
    apply_pipeline_migrations(conn)
    return conn
