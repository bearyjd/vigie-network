"""VIGIE_OVERRIDES_PATH / VIGIE_INVENTORY_PATH address the databases directly (no symlink)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vigie_api import cli as api_cli
from vigie_api.config import Settings as ApiSettings
from vigie_ingest.config import Settings as IngestSettings
from vigie_pipeline import cli as pipeline_cli
from vigie_pipeline.config import PipelineConfig


def _env(tmp_path: Path) -> dict[str, str]:
    return {
        "VIGIE_DATA_DIR": str(tmp_path / "raw"),
        "VIGIE_INVENTORY_PATH": str(tmp_path / "inv" / "inventory.db"),
        "VIGIE_OVERRIDES_PATH": str(tmp_path / "ovr" / "overrides.db"),
    }


def test_defaults_stay_under_data_dir(tmp_path: Path) -> None:
    env = {"VIGIE_DATA_DIR": str(tmp_path)}
    assert ApiSettings.from_env(env).overrides_path == tmp_path / "overrides.db"
    assert PipelineConfig.from_env(env).overrides_path == tmp_path / "overrides.db"
    assert IngestSettings.from_env(env).inventory_path == tmp_path / "inventory.db"


def test_api_settings_take_the_env_paths(tmp_path: Path) -> None:
    s = ApiSettings.from_env(_env(tmp_path))
    assert s.overrides_path == tmp_path / "ovr" / "overrides.db"
    assert s.inventory_path == tmp_path / "inv" / "inventory.db"


def test_pipeline_from_env_takes_the_env_paths(tmp_path: Path) -> None:
    c = PipelineConfig.from_env(_env(tmp_path))
    assert c.overrides_path == tmp_path / "ovr" / "overrides.db"
    assert c.inventory_path == tmp_path / "inv" / "inventory.db"


def test_pipeline_cli_config_keeps_the_env_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The real entry point rebuilds the config field by field; the paths must survive that.
    for key, value in _env(tmp_path).items():
        monkeypatch.setenv(key, value)
    args = pipeline_cli._parser().parse_args(["run", "--once"])
    config = pipeline_cli._config(args)
    assert config.overrides_path == tmp_path / "ovr" / "overrides.db"
    assert config.inventory_path == tmp_path / "inv" / "inventory.db"


def test_ingest_settings_take_the_inventory_path(tmp_path: Path) -> None:
    s = IngestSettings.from_env(_env(tmp_path))
    assert s.inventory_path == tmp_path / "inv" / "inventory.db"
    assert s.data_dir == tmp_path / "raw"


def test_api_tokens_cli_writes_the_env_overrides_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env = _env(tmp_path)
    (tmp_path / "ovr").mkdir()
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert api_cli.main(["tokens", "create", "--id", "ctl"]) == 0
    assert (tmp_path / "ovr" / "overrides.db").exists()
    assert not (tmp_path / "raw" / "overrides.db").exists()
