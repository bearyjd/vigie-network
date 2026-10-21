"""overrides.db access. Human-owned: the pipeline opens it read-only, structurally."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

MAX_LINK_DEPTH = 32


def overrides_uri(path: Path) -> str:
    """Layer 1 of 2: SQLite refuses every write on a mode=ro connection."""
    return f"file:{quote(str(path.resolve()))}?mode=ro"


def open_overrides_ro(path: Path) -> sqlite3.Connection | None:
    """Open overrides.db with mode=ro (URI) plus query_only; None when it does not exist yet.
    The file is never created, written, or migrated from here."""
    if not path.exists():
        return None
    conn = sqlite3.connect(overrides_uri(path), uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def canonical_device(conn: sqlite3.Connection | None, device_id: str) -> str:
    """Follow identity_links (from_device -> into_device) to the canonical device.
    Links are flattened on merge, but a bounded walk also tolerates chains and cycles."""
    if conn is None:
        return device_id
    seen = {device_id}
    current = device_id
    for _ in range(MAX_LINK_DEPTH):
        try:
            row = conn.execute(
                "SELECT into_device FROM identity_links WHERE from_device=?", (current,)
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):  # api has not created the schema yet
                return device_id
            raise
        if row is None or row["into_device"] in seen:
            return current
        current = row["into_device"]
        seen.add(current)
    return current
