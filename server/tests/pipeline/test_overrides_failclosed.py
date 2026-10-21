"""Unreadable overrides.db means "no identity links, no rules", never a grant of trust."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from vigie_pipeline.overrides import canonical_device, open_overrides_ro


def test_garbage_file_is_logged_and_treated_as_no_links(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "overrides.db"
    path.write_bytes(b"not a database" * 200)
    with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
        conn = open_overrides_ro(path)
    assert conn is None
    assert "overrides_unreadable" in caplog.text
    assert canonical_device(conn, "dev-1") == "dev-1"  # no links: a device is only itself


def test_missing_file_is_no_links_and_not_created(tmp_path: Path) -> None:
    assert open_overrides_ro(tmp_path / "overrides.db") is None
    assert not (tmp_path / "overrides.db").exists()


def test_unreadable_permissions_are_logged_and_ignored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import os
    import sqlite3

    path = tmp_path / "overrides.db"
    sqlite3.connect(path).close()
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running as a user that ignores file modes")
        with caplog.at_level(logging.ERROR, logger="vigie_pipeline"):
            assert open_overrides_ro(path) is None
        assert "overrides_unreadable" in caplog.text
    finally:
        path.chmod(0o600)
