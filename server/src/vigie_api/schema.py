"""overrides.db schema (PRP section 5) and connection factories.

overrides.db is read-write for this process only. inventory.db is opened read-only
(`mode=ro` URI plus `query_only`), so a write through it is structurally impossible.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

BUSY_TIMEOUT_MS = 5000
LOG = logging.getLogger("vigie_api")


def _identity_triggers() -> tuple[str, ...]:
    """Keep invalidation in the writing transaction, including UPSERT and direct SQL paths.

    Identity input changes invalidate. Override labels/ETags and group display fields
    do not authorize attaches: only group membership and auto_inherit invalidate those tables.
    """
    statements = []
    columns = {
        "identity_rules": (
            "id",
            "device_id",
            "signature",
            "created_by",
            "expires_at",
            "revoked_at",
        ),
        "identity_links": ("from_device", "into_device", "revoked_at"),
        "suggestion_decisions": ("suggestion_id", "state"),
        "candidate_decisions": (
            "id",
            "candidate_id",
            "device_a",
            "device_b",
            "action",
            "decided_by",
            "decided_at",
        ),
        "device_overrides": ("device_id", "group_id"),
        "groups": ("id", "auto_inherit"),
    }
    for table, watched in columns.items():
        for event in ("INSERT", "UPDATE", "DELETE"):
            condition = ""
            if table == "device_overrides":
                if event == "INSERT":
                    condition = " WHEN NEW.group_id IS NOT NULL"
                elif event == "DELETE":
                    condition = " WHEN OLD.group_id IS NOT NULL"
                else:
                    condition = (
                        " WHEN OLD.group_id IS NOT NEW.group_id OR"
                        " (OLD.device_id IS NOT NEW.device_id AND"
                        " (OLD.group_id IS NOT NULL OR NEW.group_id IS NOT NULL))"
                    )
            elif event == "UPDATE":
                condition = " WHEN " + " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}" for column in watched
                )
            statements.append(
                f"CREATE TRIGGER identity_version_{table}_{event.lower()} AFTER {event}"  # noqa: S608
                f" ON {table}{condition} BEGIN"
                " UPDATE identity_version SET version=version+1 WHERE singleton=1; END"
            )
    return tuple(statements)


# Each migration is a tuple of single statements (the trigger keeps its BEGIN..END intact).
OVERRIDES_MIGRATIONS: Sequence[Sequence[str]] = (
    (
        """CREATE TABLE groups (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          enforcement_ref TEXT,
          auto_inherit INTEGER NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE device_overrides (
          device_id TEXT PRIMARY KEY,
          name TEXT, owner TEXT, type TEXT,
          group_id TEXT REFERENCES groups(id),
          version INTEGER NOT NULL DEFAULT 1,
          updated_at TEXT NOT NULL, updated_by TEXT NOT NULL
        )""",
        """CREATE TRIGGER no_override_delete BEFORE DELETE ON device_overrides
          BEGIN SELECT RAISE(ABORT, 'overrides are cleared by nulling fields, never deleted');
          END""",
        """CREATE TABLE identity_links (
          from_device TEXT PRIMARY KEY,
          into_device TEXT NOT NULL,
          merge_id TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
          CHECK (from_device <> into_device)
        )""",
        """CREATE TABLE identity_rules (
          id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
          signature TEXT NOT NULL,
          created_at TEXT NOT NULL, created_by TEXT NOT NULL,
          expires_at TEXT, revoked_at TEXT
        )""",
        """CREATE TABLE identity_merges (
          id TEXT PRIMARY KEY, ts TEXT NOT NULL, from_device TEXT NOT NULL,
          into_device TEXT NOT NULL,
          prior_overrides TEXT NOT NULL,
          suggestion_id TEXT, decided_by TEXT NOT NULL, undone_at TEXT
        )""",
        """CREATE TABLE suggestion_decisions (
          suggestion_id TEXT PRIMARY KEY,
          state TEXT NOT NULL CHECK (state IN ('accepted','rejected')),
          decided_by TEXT NOT NULL, decided_at TEXT NOT NULL, applied TEXT
        )""",
        """CREATE TABLE audit_log (
          id TEXT PRIMARY KEY, ts TEXT NOT NULL, principal TEXT NOT NULL,
          action TEXT NOT NULL, target TEXT, detail TEXT
        )""",
        "CREATE INDEX idx_audit_ts ON audit_log(ts, id)",
        """CREATE TABLE api_tokens (
          id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, scope TEXT NOT NULL,
          revoked INTEGER DEFAULT 0
        )""",
        "INSERT INTO groups (id, name, auto_inherit) VALUES ('trusted', 'Trusted', 0)",
        "INSERT INTO groups (id, name, auto_inherit) VALUES ('kids', 'Kids', 0)",
        "INSERT INTO groups (id, name, auto_inherit) VALUES ('iot', 'IoT', 1)",
        "INSERT INTO groups (id, name, auto_inherit) VALUES ('guest', 'Guest', 1)",
        "INSERT INTO groups (id, name, auto_inherit) VALUES ('quarantine', 'Quarantine', 0)",
    ),
    (
        # revoked: NOT NULL DEFAULT 0. A legacy NULL (never written by this code) fails closed.
        """CREATE TABLE api_tokens_new (
          id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, scope TEXT NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0
        )""",
        "INSERT INTO api_tokens_new SELECT id, token_hash, scope,"
        " CASE WHEN revoked IS NULL THEN 1 ELSE revoked END FROM api_tokens",
        "DROP TABLE api_tokens",
        "ALTER TABLE api_tokens_new RENAME TO api_tokens",
    ),
    (
        # /events pages on audit_log.rowid: AUTOINCREMENT so a rowid is never reused (deleting the
        # newest row or VACUUM would otherwise let a new row land behind a client's cursor).
        """CREATE TABLE audit_log_new (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE, ts TEXT NOT NULL, principal TEXT NOT NULL,
          action TEXT NOT NULL, target TEXT, detail TEXT
        )""",
        "INSERT INTO audit_log_new (seq, id, ts, principal, action, target, detail)"
        " SELECT rowid, id, ts, principal, action, target, detail FROM audit_log ORDER BY rowid",
        "DROP TABLE audit_log",
        "ALTER TABLE audit_log_new RENAME TO audit_log",
        "CREATE INDEX idx_audit_ts ON audit_log(ts, id)",
    ),
    (
        "ALTER TABLE identity_links ADD COLUMN revoked_at TEXT",
        """CREATE TABLE candidate_decisions (
          candidate_id TEXT PRIMARY KEY, device_a TEXT NOT NULL, device_b TEXT NOT NULL,
          action TEXT NOT NULL CHECK (action='clear_veto'), decided_by TEXT NOT NULL,
          decided_at TEXT NOT NULL, id TEXT NOT NULL UNIQUE
        )""",
        """CREATE TABLE api_write_receipts (
          id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL
        )""",
    ),
    (
        """CREATE TABLE identity_version (
          singleton INTEGER PRIMARY KEY CHECK (singleton=1),
          version INTEGER NOT NULL CHECK (typeof(version)='integer' AND version>=0)
        )""",
        "INSERT INTO identity_version (singleton,version) VALUES (1,0)",
        """CREATE TRIGGER identity_version_no_delete BEFORE DELETE ON identity_version
          BEGIN SELECT RAISE(ABORT, 'identity version singleton cannot be deleted'); END""",
        "CREATE INDEX idx_identity_rules_created ON identity_rules(created_at,id)",
        "CREATE INDEX idx_links_active_into ON identity_links(into_device,from_device)"
        " WHERE revoked_at IS NULL",
        *_identity_triggers(),
    ),
    (
        "CREATE TABLE monitoring_lineage_versions (device_id TEXT PRIMARY KEY, version"
        " INTEGER NOT NULL)",
        *tuple(
            "CREATE TRIGGER monitoring_link_"  # noqa: S608
            + action.lower()
            + " AFTER "
            + action
            + " ON identity_links BEGIN "
            + " ".join(
                "INSERT INTO monitoring_lineage_versions VALUES (" + ref + "." + column + ",1) "  # noqa: S608
                "ON CONFLICT(device_id) DO UPDATE SET version=version+1;"
                for ref in (
                    ("NEW",)
                    if action == "INSERT"
                    else ("OLD",)
                    if action == "DELETE"
                    else ("OLD", "NEW")
                )
                for column in ("from_device", "into_device")
            )
            + " END"
            for action in ("INSERT", "UPDATE", "DELETE")
        ),
    ),
)


def _migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > len(OVERRIDES_MIGRATIONS):
        raise RuntimeError(f"overrides schema v{current} is newer than this build")
    for index in range(current, len(OVERRIDES_MIGRATIONS)):
        conn.execute("BEGIN IMMEDIATE")
        try:
            seen = conn.execute("PRAGMA user_version").fetchone()[0]
            if seen == index:  # another process may have migrated while we waited
                for statement in OVERRIDES_MIGRATIONS[index]:
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version={index + 1}")
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


def _secure_file(path: Path) -> None:
    """Create the file 0600 up front (WAL/SHM siblings inherit its mode) and tighten an old one."""
    os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        try:
            path.chmod(0o600)
        except OSError as exc:
            LOG.warning("cannot restrict %s to 0600: %s", path, exc)


def open_overrides(path: Path) -> sqlite3.Connection:
    """Open (creating and migrating if needed) the read-write overrides.db (mode 0600)."""
    _secure_file(path)
    conn = sqlite3.connect(
        path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    _migrate(conn)
    return conn


def open_inventory_ro(path: Path) -> sqlite3.Connection | None:
    """Open inventory.db read-only; None when it does not exist (never created from here)."""
    if not path.exists():
        return None
    conn = sqlite3.connect(
        f"file:{quote(str(path.resolve()))}?mode=ro",
        uri=True,
        timeout=BUSY_TIMEOUT_MS / 1000,
        check_same_thread=False,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn
