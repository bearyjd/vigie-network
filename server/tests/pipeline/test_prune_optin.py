"""The retired-MAC prune is OPT-IN (VIGIE_PRUNE_RETIRED_MACS): off, a pass never calls it, logs
nothing about it and writes none of its stitch_state/pipeline_meta markers."""

from __future__ import annotations

import logging

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, PROTECTIONS, STAMP, migrated_overrides, retire, rows, sql

from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import monitoring_policy


@pytest.fixture(autouse=True)
def _visible_pipeline_log(monkeypatch):
    logger = logging.getLogger("vigie_pipeline")
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "disabled", False)


def _decided_overrides(data) -> None:
    """An overrides.db holding a decision: the prune would write its presence/audit markers."""
    sql(
        migrated_overrides(data.root),
        PROTECTIONS["device_overrides"],
        "some-other-device",
        STAMP,
    )


def _state_keys(data) -> set[str]:
    return {r["key"] for r in data.q("SELECT key FROM stitch_state")}


def test_the_default_config_has_the_prune_off():
    assert PipelineConfig(data_dir=None).prune_retired_macs is False  # type: ignore[arg-type]
    assert PipelineConfig.from_env({}).prune_retired_macs is False


def test_default_config_prunes_nothing_and_writes_no_prune_marker(data, caplog):
    retire(data)
    _decided_overrides(data)
    before = _state_keys(data)
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        for n in range(3):
            processor.run_once(PipelineConfig(data_dir=data.root), now=LATER + n)
    assert rows(data) == 1
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", prune_module.PRUNED_COUNTER_KEY) == []
    new = _state_keys(data) - before
    assert not {k for k in new if k.startswith("prune_")}
    assert prune_module.OVERRIDES_SEEN_KEY not in _state_keys(data)
    assert prune_module.OVERRIDES_AUDIT_KEY not in _state_keys(data)
    assert not {k for k in _state_keys(data) if k.startswith("prune_")}
    assert not [r for r in caplog.records if "prune" in r.getMessage()]


def test_default_config_never_calls_the_prune(data, monkeypatch):
    retire(data)
    migrated_overrides(data.root)

    def boom(*args, **kwargs):
        raise AssertionError("prune_retired_macs called with the flag off")

    monkeypatch.setattr(processor, "prune_retired_macs", boom)
    processor.run_once(PipelineConfig(data_dir=data.root), now=LATER)


def test_flag_on_prunes_as_before(data):
    retire(data)
    _decided_overrides(data)
    processor.run_once(PipelineConfig(data_dir=data.root, prune_retired_macs=True), now=LATER)
    assert rows(data) == 0
    assert data.q("SELECT value FROM pipeline_meta WHERE key=?", prune_module.PRUNED_COUNTER_KEY)
    keys = _state_keys(data)  # the markers the off pass lacks
    assert prune_module.OVERRIDES_SEEN_KEY in keys


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        (" 1 ", True),
        ("0", False),
        ("", False),
        ("off", False),
        ("garbage", False),
        ("2", False),
        ("enable", False),
        ("tru", False),
    ],
)
def test_env_parsing_fails_closed_to_off(raw, expected):
    config = PipelineConfig.from_env({"VIGIE_PRUNE_RETIRED_MACS": raw})
    assert config.prune_retired_macs is expected


def test_an_unset_env_var_is_off():
    assert PipelineConfig.from_env({}).prune_retired_macs is False


def test_the_flag_is_not_in_the_monitoring_policy_hash():
    off = monitoring_policy(PipelineConfig.from_env({}))
    on = monitoring_policy(PipelineConfig.from_env({"VIGIE_PRUNE_RETIRED_MACS": "1"}))
    assert off.version.startswith("f2326b78a328")
    assert on.version == off.version
