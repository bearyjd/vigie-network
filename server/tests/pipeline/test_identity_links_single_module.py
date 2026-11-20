"""identity_links is walked by raw SQL in exactly one pipeline module: overrides.py."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import vigie_pipeline
from vigie_pipeline.overrides import link_sources, link_target

PIPELINE = Path(vigie_pipeline.__file__).parent


def test_only_overrides_module_names_identity_links():
    offenders = [
        p.name
        for p in PIPELINE.glob("*.py")
        if p.name != "overrides.py" and "FROM identity_links" in p.read_text()
    ]
    assert offenders == []


def _conn(revoked_column: bool) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    extra = ", revoked_at REAL" if revoked_column else ""
    conn.execute(f"CREATE TABLE identity_links (from_device TEXT, into_device TEXT{extra})")
    conn.execute("INSERT INTO identity_links (from_device, into_device) VALUES ('a','b')")
    conn.execute("INSERT INTO identity_links (from_device, into_device) VALUES ('c','b')")
    if revoked_column:
        conn.execute("INSERT INTO identity_links VALUES ('d','b',1.0)")
    return conn


def test_link_target_and_sources_skip_revoked():
    conn = _conn(True)
    assert link_target(conn, "a") == "b"
    assert link_target(conn, "d") is None
    assert sorted(link_sources(conn, "b")) == ["a", "c"]


def test_link_helpers_without_revocation_column():
    conn = _conn(False)
    assert link_target(conn, "a") == "b"
    assert sorted(link_sources(conn, "b")) == ["a", "c"]
