"""The pipeline migrations exactly as on main (git show main:server/src/vigie_pipeline/schema.py),
frozen here so the upgrade test cannot drift with this branch's own migration list."""

from __future__ import annotations

MAIN_PIPELINE_MIGRATIONS: tuple[tuple[str, ...], ...] = (
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
)
