"""API-suite guard: the GUI preview tests must never touch the user's real preview lock."""

from __future__ import annotations

import os

import pytest

REAL_PREVIEW_LOCK = "/tmp/vigie-gui-preview-18745.lock"  # noqa: S108 -- the path under guard.


@pytest.fixture(autouse=True)
def never_touch_the_real_preview_lock(request, monkeypatch):
    if not request.module.__name__.startswith(("test_gui_preview", "gui_preview")):
        return
    real_open = os.open

    def guarded(path, *args, **kwargs):
        if os.fspath(path) == REAL_PREVIEW_LOCK:
            raise AssertionError(f"{request.node.nodeid} opened the real preview lock")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded)
