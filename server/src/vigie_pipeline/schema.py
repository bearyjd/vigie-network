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
        # identity stitching: per-MAC activity intervals derived from the raw shards (7 d
        # retention, like raw). `end` is quoted because END is an SQL keyword.
        """CREATE TABLE IF NOT EXISTS mac_activity (
          mac TEXT NOT NULL, start INTEGER NOT NULL, "end" INTEGER NOT NULL,
          PRIMARY KEY (mac, start)
        )""",
        'CREATE INDEX IF NOT EXISTS idx_mac_activity_end ON mac_activity("end")',
        # one candidate row per (from, into) pair
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_candidates_pair"
        " ON identity_candidates(device_a, device_b)",
    ),
    (
        # indexed once-only guard for stitching events (replaces an instr() scan of summaries)
        "ALTER TABLE events ADD COLUMN dedup TEXT",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_events_dedup ON events(kind, dedup)"
        " WHERE dedup IS NOT NULL",
    ),
    (
        # SERVER time (batch receipt) a MAC was first folded into mac_activity: the maturity
        # anchor. Legacy rows fall back to their earliest stored stamp.
        "CREATE TABLE IF NOT EXISTS mac_first_received ("
        "mac TEXT PRIMARY KEY, received INTEGER NOT NULL)",
        "INSERT OR IGNORE INTO mac_first_received (mac, received)"
        " SELECT mac, MIN(start) FROM mac_activity GROUP BY mac",
        # small key/value state of the stitcher (re-check cursor)
        "CREATE TABLE IF NOT EXISTS stitch_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        # suggestion look-ups are by (action, device_ids): no table scan inside the write lock
        "CREATE INDEX IF NOT EXISTS idx_suggestions_pair"
        " ON suggestions(action, device_ids, expires_at)",
        # Migration 5 added events.dedup but left it NULL on rows written before it: give the
        # recognised stitching events their token (same format as the emit_once call sites) so the
        # once-only guard keeps holding. UPDATE OR IGNORE: a legacy duplicate that would break the
        # unique index keeps NULL (nothing is deleted).
        "UPDATE OR IGNORE events SET dedup = substr(summary, length('identity overlap veto ') + 1)"
        " WHERE dedup IS NULL AND kind = 'identity_overlap_veto'"
        " AND summary LIKE 'identity overlap veto %'",
        "UPDATE OR IGNORE events SET dedup = device_id"
        " WHERE dedup IS NULL AND kind = 'identity_candidate_ambiguous' AND device_id IS NOT NULL",
        "UPDATE OR IGNORE events SET dedup = substr(summary, length('identity candidate ') + 1,"
        " instr(summary, ' score ') - length('identity candidate ') - 1)"
        " WHERE dedup IS NULL AND kind = 'identity_candidate'"
        " AND summary LIKE 'identity candidate % score %'",
        "UPDATE OR IGNORE events SET dedup = substr(summary, length('rule attach suspect ') + 1, 8)"
        " || '~' || device_id WHERE dedup IS NULL AND kind = 'rule_attach_suspect'"
        " AND device_id IS NOT NULL AND summary LIKE 'rule attach suspect %'",
        "UPDATE OR IGNORE events SET dedup = substr(summary, length('signature flood ') + 1, 8)"
        " || ':' || substr(ts, 1, 10) WHERE dedup IS NULL AND kind = 'signature_flood'"
        " AND summary LIKE 'signature flood %'",
        "UPDATE OR IGNORE events SET dedup = substr(ts, 1, 10)"
        " WHERE dedup IS NULL AND kind = 'stitch_budget_exhausted'",
        "UPDATE OR IGNORE events SET dedup = 'summary:' || substr(ts, 1, 10)"
        " WHERE dedup IS NULL AND kind = 'signature_flood_summary'",
    ),
    (
        # What justified a rule attach, fixed at attach time: the name fields the rule required
        # and the MAC's values then. The re-check uses these, so renaming an attached MAC (or
        # revoking/expiring its rule) cannot erase the evidence of a later overlap.
        "CREATE TABLE IF NOT EXISTS rule_attachments ("
        "mac TEXT PRIMARY KEY, rule_id TEXT NOT NULL, target TEXT NOT NULL,"
        " hostname TEXT, mdns_name TEXT, attached_at TEXT NOT NULL)",
    ),
    (
        # the fingerprints at attach time too (the re-check searches the same buckets), and the
        # evidence gaps: periods in which a collector's evidence is known to be missing
        "ALTER TABLE rule_attachments ADD COLUMN opt55 TEXT",
        "ALTER TABLE rule_attachments ADD COLUMN opt60 TEXT",
        "CREATE TABLE IF NOT EXISTS collector_gaps ("
        'collector_id TEXT NOT NULL, start INTEGER NOT NULL, "end" INTEGER NOT NULL,'
        " recorded INTEGER NOT NULL)",
        'CREATE INDEX IF NOT EXISTS idx_collector_gaps_end ON collector_gaps("end")',
    ),
    (
        # Migration 6 anchored legacy MACs at their earliest stored COLLECTOR stamp (untrusted).
        # Re-anchor those rows (anchor == earliest stored stamp) at the migration time on the
        # server clock and mark them legacy; honest rows (a server receipt time) are untouched.
        "ALTER TABLE mac_first_received ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0",
        "UPDATE mac_first_received SET legacy = 1,"
        " received = MAX(received, CAST(strftime('%s', 'now') AS INTEGER))"
        " WHERE received = (SELECT MIN(start) FROM mac_activity a"
        " WHERE a.mac = mac_first_received.mac)",
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
    "stitch_state",
    "rule_attachments",
    "collector_gaps",
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
