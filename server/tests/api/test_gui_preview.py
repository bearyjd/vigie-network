from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vigie_api.app import create_app
from vigie_api.config import Settings

SPEC = importlib.util.spec_from_file_location(
    "gui_preview", Path(__file__).resolve().parents[3] / "tools/gui/preview.py"
)
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)


def test_synthetic_seed_real_api_paginates_and_readonly_token_cannot_write(tmp_path):
    root = tmp_path / "synthetic"
    manifest = preview.seed(root)
    assert manifest["synthetic"] is True and manifest["devices"] == 55
    assert root.stat().st_mode & 0o777 == 0o700
    token = (root / "read-token.private").read_text().strip()
    for name in ("read-token.private", "manifest.json", "inventory.db", "overrides.db"):
        assert (root / name).stat().st_mode & 0o777 == 0o600
    with TestClient(create_app(Settings(data_dir=root))) as client:
        assert client.get("/devices").status_code == 401
        headers = {"Authorization": "Bearer " + token}
        first = client.get("/devices?limit=50", headers=headers).json()
        assert len(first["data"]) == 50 and first["page"]["next_cursor"]
        second = client.get(
            "/devices",
            params={"limit": 50, "cursor": first["page"]["next_cursor"]},
            headers=headers,
        ).json()
        assert len(second["data"]) == 5
        rows = first["data"] + second["data"]
        assert any(row["last_observed_ip"] is None for row in rows)
        assert any(":" in (row["last_observed_ip"] or "") for row in rows)
        assert any("." in (row["last_observed_ip"] or "") for row in rows)
        attack = client.get("/devices/" + preview.ATTACK_DEVICE, headers=headers).json()["data"]
        assert "<img" in attack["name"] and attack["type"] == "unknown"
        scope = {"collector_id": preview.COLLECTOR}
        coverage = client.get("/coverage", params=scope, headers=headers).json()["data"]
        assert coverage["collector"]["source_flags_latest"] == 8
        assert any(row["state"] == "missing" for row in coverage["hours"])
        activity = client.get(
            "/devices/" + preview.ATTACK_DEVICE + "/activity",
            params=scope,
            headers=headers,
        ).json()["data"]
        assert activity["baseline"]["state"] == "learning"
        assert any(row["bytes_up"] is None for row in activity["hours"])
        incidents = client.get("/incidents", params=scope, headers=headers).json()["data"]
        assert len(incidents) == 1 and incidents[0]["id"] == preview.INCIDENT
        headers["If-Match"] = '"1"'
        assert (
            client.patch(
                "/devices/" + preview.ATTACK_DEVICE,
                headers=headers,
                json={"name": "overwrite"},
            ).status_code
            == 403
        )
        assert token not in client.get("/ui/").text


def test_preview_refuses_existing_seed_and_symlinked_database(tmp_path):
    root = tmp_path / "synthetic"
    preview.seed(root)
    with pytest.raises(FileExistsError):
        preview.seed(root)
    database = root / "inventory.db"
    database.rename(root / "original.db")
    database.symlink_to(root / "original.db")
    with pytest.raises(ValueError, match="regular single-link"):
        preview.serve(root)


def test_preview_server_ignores_production_environment_and_has_bounded_lifetime(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "synthetic"
    preview.seed(root)
    monkeypatch.setenv("VIGIE_INVENTORY_PATH", "/must-not-open/inventory.db")
    monkeypatch.setenv("VIGIE_OVERRIDES_PATH", "/must-not-open/overrides.db")
    configs = []

    class Server:
        def __init__(self, config):
            configs.append(config)

        def run(self):
            pass

    monkeypatch.setattr(preview.uvicorn, "Server", Server)
    preview.serve(root)
    assert len(configs) == 1
    config = configs[0]
    assert config.host == "127.0.0.1" and config.port == 18745
    assert config.app.state.settings.inventory_path == root / "inventory.db"
    assert config.app.state.settings.overrides_path == root / "overrides.db"
    assert preview.PREVIEW_SECONDS == 8 * 3600
