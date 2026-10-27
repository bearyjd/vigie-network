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
        "CREATE INDEX IF NOT EXISTS idx_mac_first_received_received"
        " ON mac_first_received(received, mac)",
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
        # small key/value state of the stitcher (round-robin cursors, settle cursors)
        "CREATE TABLE IF NOT EXISTS stitch_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        # pipeline bookkeeping that is not stitching state: the fold version of the stored names
        "CREATE TABLE IF NOT EXISTS pipeline_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
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
        "CREATE INDEX IF NOT EXISTS idx_candidates_open_a ON identity_candidates(device_a)"
        " WHERE state IN ('open','suggested')",
        "CREATE INDEX IF NOT EXISTS idx_candidates_open_b ON identity_candidates(device_b)"
        " WHERE state IN ('open','suggested')",
        # suggestion look-ups by pair and by target device: never a table scan inside the lock
        "CREATE INDEX IF NOT EXISTS idx_suggestions_pair"
        " ON suggestions(action, device_ids, expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_suggestions_into"
        " ON suggestions(action, json_extract(device_ids, '$[1]'), expires_at)",
        # Orphan cleanup seeks by direction and id, including decided/expired history.
        "CREATE INDEX IF NOT EXISTS idx_suggestions_from_id"
        " ON suggestions(action, json_extract(device_ids, '$[0]'), id)",
        "CREATE INDEX IF NOT EXISTS idx_suggestions_into_id"
        " ON suggestions(action, json_extract(device_ids, '$[1]'), id)",
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
    (
        # A veto on any merged alias invalidates plans computed before this write.
        "INSERT INTO pipeline_meta (key,value) VALUES ('veto_generation','0')",
        "CREATE TRIGGER veto_generation_insert AFTER INSERT ON identity_candidates"
        " WHEN NEW.state='vetoed' BEGIN UPDATE pipeline_meta"
        " SET value=CAST(value AS INTEGER)+1 WHERE key='veto_generation'; END",
        "CREATE TRIGGER veto_generation_update AFTER UPDATE ON identity_candidates"
        " WHEN OLD.state='vetoed' OR NEW.state='vetoed' BEGIN UPDATE pipeline_meta"
        " SET value=CAST(value AS INTEGER)+1 WHERE key='veto_generation'; END",
        "CREATE TRIGGER veto_generation_delete AFTER DELETE ON identity_candidates"
        " WHEN OLD.state='vetoed' BEGIN UPDATE pipeline_meta"
        " SET value=CAST(value AS INTEGER)+1 WHERE key='veto_generation'; END",
    ),
    (
        """CREATE TABLE measurement_batches (
          collector_id TEXT NOT NULL, batch_id TEXT NOT NULL, window_start INTEGER,
          window_end INTEGER, received_at TEXT NOT NULL, hour INTEGER, quality TEXT NOT NULL,
          PRIMARY KEY(collector_id,batch_id))""",
        "CREATE INDEX idx_measurement_windows ON measurement_batches(collector_id,hour,window_end)",
        """CREATE TABLE measurements_hourly (
          collector_id TEXT NOT NULL, mac TEXT NOT NULL, hour INTEGER NOT NULL,
          bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL, flows INTEGER NOT NULL,
          dns_queries INTEGER NOT NULL, PRIMARY KEY(collector_id,mac,hour))""",
        """CREATE TABLE coverage_hourly (
          collector_id TEXT NOT NULL, hour INTEGER NOT NULL, observed_seconds INTEGER NOT NULL,
          qualified_seconds INTEGER NOT NULL, reasons TEXT NOT NULL,
          PRIMARY KEY(collector_id,hour))""",
    ),
    (
        "CREATE TABLE monitoring_assignment_versions (mac TEXT PRIMARY KEY, version IN"
        "TEGER NOT NULL)",
        """CREATE TRIGGER monitoring_assignment_change AFTER UPDATE OF
        device_id,link_source,link_rule_id
          ON observations WHEN OLD.device_id IS NOT NEW.device_id OR OLD.link_source IS NOT
          NEW.link_source
          OR OLD.link_rule_id IS NOT NEW.link_rule_id BEGIN
          INSERT INTO monitoring_assignment_versions VALUES (NEW.mac,1)
          ON CONFLICT(mac) DO UPDATE SET version=version+1; END""",
    ),
    (
        "CREATE TABLE monitoring_dirty (collector_id TEXT NOT NULL,mac TEXT NOT NULL,q"
        "ueued_at INTEGER NOT NULL, PRIMARY KEY(collector_id,mac))",
        "CREATE INDEX idx_monitoring_dirty_age ON monitoring_dirty(queued_at,collector_id,mac)",
        "CREATE TABLE monitoring_unavailable (collector_id TEXT NOT NULL,device_id TEXT NOT NULL,"
        "reason TEXT NOT NULL,retry_at INTEGER NOT NULL,PRIMARY KEY(collector_id,device_id))",
        "CREATE TABLE monitoring_quality_work (collector_id TEXT NOT NULL,hour INTEGER NOT NULL,"
        "after_mac TEXT NOT NULL,PRIMARY KEY(collector_id,hour))",
        "CREATE INDEX idx_monitoring_quality_work ON monitoring_quality_work(hour,collector_id)",
        "CREATE TABLE monitoring_revision (singleton INTEGER PRIMARY KEY CHECK(singlet"
        "on=1),value INTEGER NOT NULL)",
        "INSERT INTO monitoring_revision VALUES(1,0)",
        *tuple(
            "CREATE TRIGGER monitoring_revision_"  # noqa: S608
            + table
            + "_"
            + action.lower()
            + " AFTER "
            + action
            + " ON "
            + table
            + " BEGIN UPDATE monitoring_revision SET value=value+1 WHERE singleton=1; END"
            for table in ("measurements_hourly", "coverage_hourly")
            for action in ("INSERT", "UPDATE", "DELETE")
        ),
        """CREATE TABLE monitoring_profiles (
          collector_id TEXT NOT NULL,device_id TEXT NOT NULL,lineage TEXT NOT NULL,
          config_version TEXT NOT NULL,training_since INTEGER NOT NULL,state TEXT NOT NULL,
          baseline_id TEXT,updated_hour INTEGER NOT NULL,sample_hours INTEGER NOT NULL,
          distinct_days INTEGER NOT NULL,PRIMARY KEY(collector_id,device_id))""",
        """CREATE TABLE monitoring_baselines (
          id TEXT PRIMARY KEY,collector_id TEXT NOT NULL,device_id TEXT NOT NULL,lineage TEXT
          NOT NULL,
          algorithm TEXT NOT NULL,config_version TEXT NOT NULL,config_json TEXT NOT NULL,
          median_twice INTEGER NOT NULL,sample_hours INTEGER NOT NULL,distinct_days INTEGER NOT
          NULL,
          trained_until INTEGER NOT NULL,created_hour INTEGER NOT NULL,
          training_hours TEXT NOT NULL)""",
        """CREATE TABLE monitoring_incidents (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,collector_id TEXT NOT NULL,
          device_id TEXT NOT NULL,lineage TEXT NOT NULL,detector TEXT NOT NULL,state TEXT NOT NULL,
          episode_start INTEGER NOT NULL,last_hour INTEGER NOT NULL,detected_at TEXT NOT NULL,
          baseline_id TEXT,observed_bytes INTEGER NOT NULL,threshold_bytes INTEGER NOT NULL,
          evidence TEXT NOT NULL)""",
        "CREATE UNIQUE INDEX idx_monitoring_incident_open ON monitoring_incidents(coll"
        "ector_id,device_id,lineage,detector) WHERE state='open'",
        "CREATE INDEX idx_monitoring_incident_scope ON monitoring_incidents(collector_"
        "id,device_id,seq)",
        "CREATE TABLE monitoring_suspicious (collector_id TEXT NOT NULL,device_id TEXT"
        " NOT NULL,lineage TEXT NOT NULL,hour INTEGER NOT NULL,PRIMARY KEY(collector_i"
        "d,device_id,lineage,hour))",
        "CREATE INDEX idx_measurements_hour ON measurements_hourly(hour,collector_id,mac)",
        "CREATE INDEX idx_coverage_hour ON coverage_hourly(hour)",
        "CREATE INDEX idx_measurement_retention ON measurement_batches(window_end)",
        "CREATE INDEX idx_measurement_received ON measurement_batches(received_at)",
        "CREATE INDEX idx_monitoring_incident_retention ON monitoring_incidents(last_hour)",
        "CREATE INDEX idx_monitoring_incident_collector_seq ON monitoring_incidents(co"
        "llector_id,seq)",
        "CREATE INDEX idx_monitoring_suspicious_retention ON monitoring_suspicious(hour)",
    ),
    (
        "CREATE TABLE characterization_evidence (mac TEXT NOT NULL,kind TEXT NOT NULL,"
        "service TEXT NOT NULL,observed_at INTEGER NOT NULL,PRIMARY KEY(mac,kind,service))",
        "CREATE INDEX idx_characterization_expiry ON characterization_evidence(observed_at)",
        "CREATE TABLE characterization_overflow (mac TEXT PRIMARY KEY,until INTEGER NOT NULL)",
        "CREATE TABLE characterization_results (device_id TEXT PRIMARY KEY,result TEXT NOT NULL)",
        "CREATE TABLE characterization_dirty (device_id TEXT PRIMARY KEY)",
        "ALTER TABLE devices ADD COLUMN inferred_valid_until REAL",
    ),
    (
        "CREATE TABLE mac_last_ip (mac TEXT PRIMARY KEY,ip TEXT NOT NULL,"
        "observed_at INTEGER NOT NULL,source TEXT NOT NULL CHECK(source IN ('lease','neigh')))",
    ),
    (
        # Outbox for incident notifications (see vigie_pipeline.delivery_plan). Times are integer
        # epoch seconds. No FK to monitoring_incidents: incidents are pruned by retention while
        # deliveries age out on their own. delivery_id = sha256(f"{incident_id}\n{kind}") hex[:32].
        "CREATE TABLE incident_deliveries ("
        "delivery_id TEXT NOT NULL PRIMARY KEY CHECK(length(delivery_id)=32),"
        "incident_id TEXT NOT NULL,"
        "kind TEXT NOT NULL CHECK(kind IN ('open','recover')),"
        "state TEXT NOT NULL CHECK(state IN "
        "('pending','sent','failed','suppressed','expired','withdrawn')),"
        "attempts INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempts)='integer' AND attempts>=0),"
        "next_attempt_at INTEGER CHECK(next_attempt_at IS NULL OR "
        "typeof(next_attempt_at)='integer'),"
        "last_error TEXT CHECK(last_error IS NULL OR length(last_error)<=200),"
        "created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer'),"
        "updated_at INTEGER NOT NULL CHECK(typeof(updated_at)='integer'),"
        "version INTEGER NOT NULL DEFAULT 0 CHECK(typeof(version)='integer' AND version>=0),"
        "CHECK(state!='pending' OR next_attempt_at IS NOT NULL),CHECK(updated_at>=created_at),"
        "UNIQUE(incident_id,kind))",
        "CREATE INDEX idx_incident_deliveries_due ON incident_deliveries(state,next_attempt_at)",
    ),
)

PIPELINE_TABLES = (
    "mac_last_ip",
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
    refresh_folds(conn)
    return conn


# Bump when stitch_types.fold changes: every stored hostname_fold/mdns_fold is recomputed on the
# next open. The Unicode database version of the interpreter is part of the marker too.
FOLD_VERSION = 2


def _fold_marker() -> str:
    import unicodedata  # noqa: PLC0415 - a one-off at open

    return f"{FOLD_VERSION}/{unicodedata.unidata_version}"


def refresh_folds(conn: sqlite3.Connection, chunk: int = 2000) -> int:
    """Keep the stored name folds equal to `stitch_types.fold` of the names: when the fold
    version marker differs from the current one (the fold function or the Unicode database
    changed) EVERY row is recomputed, chunked by MAC in short transactions and resumable through a
    cursor; otherwise only rows that have no fold yet are filled (rows written before the
    pipeline knew the column). Empty and NULL names never get a fold and are never re-selected.
    Returns the rows written."""
    from vigie_pipeline.stitch_types import fold  # noqa: PLC0415 - avoid an import cycle

    columns = {r[1] for r in conn.execute("PRAGMA table_info(observations)")}
    if "hostname_fold" not in columns:  # a schema sliced below migration 4 (tests)
        return 0
    row = conn.execute("SELECT value FROM pipeline_meta WHERE key='fold_version'").fetchone()
    pending = conn.execute(
        "SELECT 1 FROM pipeline_meta WHERE key IN ('fold_cursor', 'fold_cursor_version') LIMIT 1"
    ).fetchone()
    # An interrupted upgrade may have overwritten rows even when rolling back to the last
    # completed version. Its pending cursor takes precedence over that completion marker.
    if pending is not None or row is None or row[0] != _fold_marker():
        return _recompute_folds(conn, chunk, fold)
    done = 0
    while True:
        rows = conn.execute(
            "SELECT mac, hostname, mdns_name FROM observations WHERE (hostname <> '' AND"
            " hostname_fold IS NULL) OR (mdns_name <> '' AND mdns_fold IS NULL) LIMIT ?",
            (chunk,),
        ).fetchall()
        if not rows:
            return done
        _write_folds(conn, rows, fold)
        done += len(rows)


def _recompute_folds(conn: sqlite3.Connection, chunk: int, fold) -> int:
    """Resume a cursor only for its target fold/Unicode version. Publish the completed
    version once the cursor has passed every row under that target."""
    target = _fold_marker()
    with immediate(conn):
        version = conn.execute(
            "SELECT value FROM pipeline_meta WHERE key='fold_cursor_version'"
        ).fetchone()
        if version is None or version[0] != target:
            conn.execute("DELETE FROM pipeline_meta WHERE key='fold_cursor'")
            conn.execute(
                "INSERT OR REPLACE INTO pipeline_meta (key, value)"
                " VALUES ('fold_cursor_version', ?)",
                (target,),
            )
    done = 0
    while True:
        cursor = conn.execute("SELECT value FROM pipeline_meta WHERE key='fold_cursor'").fetchone()
        after = cursor[0] if cursor else ""
        rows = conn.execute(
            "SELECT mac, hostname, mdns_name FROM observations WHERE mac > ? ORDER BY mac LIMIT ?",
            (after, chunk),
        ).fetchall()
        if not rows:
            with immediate(conn):
                conn.execute(
                    "DELETE FROM pipeline_meta WHERE key IN ('fold_cursor', 'fold_cursor_version')"
                )
                conn.execute(
                    "INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES ('fold_version', ?)",
                    (target,),
                )
            return done
        _write_folds(conn, rows, fold, cursor=rows[-1][0])
        done += len(rows)


def _write_folds(conn: sqlite3.Connection, rows, fold, cursor: str | None = None) -> None:
    with immediate(conn):
        conn.executemany(
            "UPDATE observations SET hostname_fold=?, mdns_fold=? WHERE mac=?",
            [(fold(r[1]) if r[1] else None, fold(r[2]) if r[2] else None, r[0]) for r in rows],
        )
        if cursor is not None:
            conn.execute(
                "INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES ('fold_cursor', ?)",
                (cursor,),
            )
