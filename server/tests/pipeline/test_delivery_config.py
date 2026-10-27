"""Delivery settings: default off, strict parsing, fail-fast validation, .env.example coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from vigie_pipeline.cli import _config, _parser
from vigie_pipeline.config import PipelineConfig

ENV_EXAMPLE = Path(__file__).resolve().parents[3] / "deploy" / ".env.example"
NAMES = (
    "VIGIE_DELIVERY_ENABLED VIGIE_DELIVERY_FILE VIGIE_DELIVERY_LEASE_S "
    "VIGIE_DELIVERY_TRANSMIT_DEADLINE_S VIGIE_DELIVERY_MAX_ATTEMPTS VIGIE_DELIVERY_BACKOFF_BASE_S "
    "VIGIE_DELIVERY_BACKOFF_CAP_S VIGIE_DELIVERY_TTL_S VIGIE_DELIVERY_RETENTION_S "
    "VIGIE_DELIVERY_MAX_PER_RUN"
).split()


def cfg(**env):
    return PipelineConfig.from_env({"VIGIE_DATA_DIR": "/nonexistent/x", **env})


def test_default_is_off_with_documented_knobs():
    d = cfg().delivery
    assert d.enabled is False and d.file is None
    dc = d.delivery_config(eligible_since=5)
    assert (dc.lease_seconds, dc.transmit_deadline_seconds, dc.max_attempts) == (300, 30, 6)
    assert (dc.backoff_base_seconds, dc.backoff_cap_seconds) == (60, 3600)
    assert (dc.pending_ttl_seconds, dc.retention_seconds) == (86400, 30 * 86400)
    assert dc.eligible_since == 5 and d.max_per_run == 20


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", " Yes "])
def test_enable_values(value):
    assert cfg(VIGIE_DELIVERY_ENABLED=value, VIGIE_DELIVERY_FILE="/nonexistent/o").delivery.enabled


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_off_values(value):
    assert cfg(VIGIE_DELIVERY_ENABLED=value).delivery.enabled is False


@pytest.mark.parametrize("value", ["ture", "2", "enabled", "y"])
def test_garbage_is_a_startup_error_not_a_silent_off(value):
    with pytest.raises(ValueError, match="VIGIE_DELIVERY_ENABLED"):
        cfg(VIGIE_DELIVERY_ENABLED=value)


def test_enabled_requires_file():
    with pytest.raises(ValueError, match="VIGIE_DELIVERY_FILE"):
        cfg(VIGIE_DELIVERY_ENABLED="1")
    with pytest.raises(ValueError, match="VIGIE_DELIVERY_FILE"):
        cfg(VIGIE_DELIVERY_ENABLED="1", VIGIE_DELIVERY_FILE="")


def test_file_alone_does_not_enable():
    d = cfg(VIGIE_DELIVERY_FILE="/nonexistent/o").delivery
    assert d.enabled is False and d.file == Path("/nonexistent/o")


@pytest.mark.parametrize(
    "env",
    [
        {"VIGIE_DELIVERY_LEASE_S": "30"},
        {"VIGIE_DELIVERY_TRANSMIT_DEADLINE_S": "200"},
        {"VIGIE_DELIVERY_MAX_ATTEMPTS": "0"},
        {"VIGIE_DELIVERY_BACKOFF_BASE_S": "9999"},
        {"VIGIE_DELIVERY_MAX_PER_RUN": "0"},
        {"VIGIE_DELIVERY_TTL_S": "abc"},
        {"VIGIE_DELIVERY_RETENTION_S": "-5"},
    ],
)
def test_bad_knobs_fail_fast_even_when_disabled(env):
    with pytest.raises(ValueError):
        cfg(**env)


def test_knobs_flow_into_delivery_config():
    d = cfg(
        VIGIE_DELIVERY_LEASE_S="600", VIGIE_DELIVERY_TRANSMIT_DEADLINE_S="20",
        VIGIE_DELIVERY_MAX_ATTEMPTS="3", VIGIE_DELIVERY_MAX_PER_RUN="7",
    ).delivery  # fmt: skip
    dc = d.delivery_config(None)
    assert (dc.lease_seconds, dc.transmit_deadline_seconds, dc.max_attempts) == (600, 20, 3)
    assert d.max_per_run == 7


def test_cli_keeps_delivery_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIE_DELIVERY_ENABLED", "1")
    monkeypatch.setenv("VIGIE_DELIVERY_FILE", str(tmp_path / "o"))
    args = _parser().parse_args(["run", "--once", "--data-dir", str(tmp_path)])
    assert _config(args).delivery.enabled is True


def test_every_env_var_is_in_env_example():
    text = ENV_EXAMPLE.read_text()
    missing = [n for n in NAMES if n not in text]
    assert not missing
