from __future__ import annotations

import threading
from pathlib import Path

import pytest
from api_helpers import Env, env  # noqa: F401

from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.schema import open_inventory_ro, open_overrides
from vigie_api.writes import patch_override


def test_concurrent_patches_with_same_version_exactly_one_wins(env: Env) -> None:
    env.device("d1")
    barrier = threading.Barrier(4)
    outcomes: list[str] = []

    def worker(i: int) -> None:
        inv = open_inventory_ro(env.root / "inventory.db")
        ov = open_overrides(env.root / "overrides.db")
        barrier.wait()
        try:
            patch_override(
                inv, ov, device_id="d1", expected_version=0, changes={"name": f"n{i}"},
                principal="app:t", now_iso="t",
            )  # fmt: skip
            outcomes.append("ok")
        except ApiError as exc:
            outcomes.append(str(exc.status))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["412", "412", "412", "ok"]
    row = env.ov.execute("SELECT version FROM device_overrides WHERE device_id='d1'").fetchone()
    assert row["version"] == 1
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_streamed_oversized_body_without_content_length_rejected(env: Env) -> None:
    env.device("d1")

    def chunks():
        for _ in range(8):
            yield b'{"name": "' + b"x" * 4096 + b'"}'

    headers = {**env.auth, "If-Match": "0"}
    r = env.client.patch("/devices/d1", content=chunks(), headers=headers)
    assert r.status_code == 413
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0


def test_declared_content_length_over_cap_rejected_before_app_runs() -> None:
    import asyncio

    from vigie_api.bodylimit import BodyLimitMiddleware

    reached: list[bool] = []
    sent: list[dict] = []

    async def inner(scope, receive, send) -> None:
        reached.append(True)

    async def send(message) -> None:
        sent.append(message)

    async def receive() -> dict:
        raise AssertionError("body must not be read")

    for length in (b"101", b"abc"):
        sent.clear()
        scope = {"type": "http", "headers": [(b"content-length", length)]}
        asyncio.run(BodyLimitMiddleware(inner, max_bytes=100)(scope, receive, send))
        assert sent[0]["status"] == 413 and not reached


def test_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, max_body_bytes=0)
    s = Settings.from_env({"VIGIE_DATA_DIR": str(tmp_path), "VIGIE_API_RATE_LIMIT": "5"})
    assert s.rate_limit_per_window == 5 and s.overrides_path == tmp_path / "overrides.db"
