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
    (
        # events gets a monotonic AUTOINCREMENT seq (the API's paging cursor): rowids can be
        # renumbered by VACUUM or reused after deleting the newest row. Rows keep rowid order.
        """CREATE TABLE events_v3 (
          seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
          device_id TEXT REFERENCES devices(id), ts TEXT NOT NULL,
          kind TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL
        )""",
        "INSERT INTO events_v3 (id, device_id, ts, kind, severity, summary)"
        " SELECT id, device_id, ts, kind, severity, summary FROM events ORDER BY rowid",
        "DROP TABLE events",
        "ALTER TABLE events_v3 RENAME TO events",
        "CREATE UNIQUE INDEX uq_events_new_device ON events(device_id) WHERE kind = 'new_device'",
        # PRP section 5; immutable by convention, decisions live in overrides.db
        """CREATE TABLE IF NOT EXISTS suggestions (
          id TEXT PRIMARY KEY,
          action TEXT NOT NULL CHECK (
            action IN ('label','move_group','quarantine','merge_identity')),
          device_ids TEXT NOT NULL,
          payload TEXT NOT NULL,
          reason_code TEXT NOT NULL, reason_text TEXT,
          basis TEXT NOT NULL,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL
        )""",
    ),
    (
        # Identity stitching (docs/stitching.md), one additive migration. Main's v3 has no
        # stitching table, so nothing here has a legacy shape to migrate from.
        # Per-MAC activity intervals derived from the raw shards (7 d retention, like raw); at
        # most INTERVALS_PER_MAC rows per MAC. `end` is quoted because END is an SQL keyword.
        """CREATE TABLE IF NOT EXISTS mac_activity (
          mac TEXT NOT NULL, start INTEGER NOT NULL, "end" INTEGER NOT NULL,
          PRIMARY KEY (mac, start)
        )""",
        'CREATE INDEX IF NOT EXISTS idx_mac_activity_end ON mac_activity("end")',
        # SERVER time (batch receipt) a MAC was first folded into mac_activity: the maturity anchor
        "CREATE TABLE IF NOT EXISTS mac_first_received ("
        "mac TEXT PRIMARY KEY, received INTEGER NOT NULL)",
        # spans in which evidence from ANY collector is known to be missing (stamps dropped for
        # the report lag); merged within one activity gap at write time, pruned with the activity
        'CREATE TABLE IF NOT EXISTS evidence_gaps (start INTEGER NOT NULL, "end" INTEGER NOT NULL)',
        'CREATE INDEX IF NOT EXISTS idx_evidence_gaps_end ON evidence_gaps("end")',
        # What justified a rule attach, fixed at attach time: the fields each matched rule
        # required (views) and the MAC's values then. The re-check uses these, so renaming an
        # attached MAC (or revoking/expiring its rule) cannot erase the evidence of a later overlap.
        "CREATE TABLE IF NOT EXISTS rule_attachments ("
        "mac TEXT PRIMARY KEY, rule_id TEXT NOT NULL, target TEXT NOT NULL,"
        " hostname TEXT, mdns_name TEXT, opt55 TEXT, opt60 TEXT, views TEXT NOT NULL,"
        " attached_at TEXT NOT NULL)",
        # small key/value state of the stitcher (round-robin cursors)
        "CREATE TABLE IF NOT EXISTS stitch_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        # indexed once-only guard for stitching events
        "ALTER TABLE events ADD COLUMN dedup TEXT",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_events_dedup ON events(kind, dedup)"
        " WHERE dedup IS NOT NULL",
        # one candidate row per (from, into) pair (main never wrote the table; any duplicate pair
        # keeps its newest row so the unique index cannot abort the upgrade)
        "DELETE FROM identity_candidates WHERE rowid NOT IN (SELECT MAX(rowid) FROM"
        " identity_candidates GROUP BY device_a, device_b)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_candidates_pair"
        " ON identity_candidates(device_a, device_b)",
        "CREATE INDEX IF NOT EXISTS idx_candidates_b ON identity_candidates(device_b, device_a)",
        # suggestion look-ups by pair and by target device: never a table scan inside the lock
        "CREATE INDEX IF NOT EXISTS idx_suggestions_pair"
        " ON suggestions(action, device_ids, expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_suggestions_into"
        " ON suggestions(action, json_extract(device_ids, '$[1]'), expires_at)",
        # the ONE name fold (NFKC + Unicode casefold, computed in Python: stitch_types.fold),
        # stored and indexed; back-filled for existing rows by open_pipeline_inventory
        "ALTER TABLE observations ADD COLUMN hostname_fold TEXT",
        "ALTER TABLE observations ADD COLUMN mdns_fold TEXT",
        # neighbourhood lookups: (fingerprint, folded name) buckets newest-last_seen first, the
        # fingerprint by first sighting, and the rule-attached MACs
        "CREATE INDEX IF NOT EXISTS idx_obs_fp_host ON observations(dhcp_fingerprint,"
        " vendor_class, hostname_fold, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_obs_fp_mdns ON observations(dhcp_fingerprint,"
        " vendor_class, mdns_fold, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_obs_fp_first ON observations(dhcp_fingerprint,"
        " vendor_class, first_seen)",
        "CREATE INDEX IF NOT EXISTS idx_obs_rule ON observations(mac) WHERE link_source = 'rule'",
    ),
)

PIPELINE_TABLES = (
    "events",
    "identity_candidates",
    "pipeline_cursor",
    "transient_hours",
    "transient_state",
    "promotion_log",
    "suggestions",
    "mac_activity",
    "mac_first_received",
    "evidence_gaps",
    "rule_attachments",
    "stitch_state",
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
    backfill_folds(conn)
    return conn


def backfill_folds(conn: sqlite3.Connection, chunk: int = 2000) -> int:
    """Store the fold of every observation name that has none yet (rows written before the
    pipeline knew the column); chunked, idempotent, one short transaction per chunk."""
    from vigie_pipeline.stitch_types import fold  # noqa: PLC0415 - avoid an import cycle

    columns = {r[1] for r in conn.execute("PRAGMA table_info(observations)")}
    if "hostname_fold" not in columns:  # a schema sliced below migration 4 (tests)
        return 0
    done = 0
    while True:
        rows = conn.execute(
            "SELECT mac, hostname, mdns_name FROM observations WHERE (hostname <> '' AND"
            " hostname_fold IS NULL) OR (mdns_name <> '' AND mdns_fold IS NULL) LIMIT ?",
            (chunk,),
        ).fetchall()
        if not rows:
            return done
        with immediate(conn):
            conn.executemany(
                "UPDATE observations SET hostname_fold=?, mdns_fold=? WHERE mac=?",
                [(fold(r[1]) if r[1] else None, fold(r[2]) if r[2] else None, r[0]) for r in rows],
            )
        done += len(rows)
