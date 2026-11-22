"""The retired-MAC prune is OPT-IN (VIGIE_PRUNE_RETIRED_MACS): off, a pass never calls it, deletes
nothing and logs nothing about it; the only thing it keeps is the overrides.db history markers
(test_prune_off_tracking.py)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pipeline_helpers import data  # noqa: F401
from test_prune_guards import LATER, PROTECTIONS, STAMP, migrated_overrides, retire, rows, sql
from test_prune_overrides_rollback import decide

from vigie_ingest.db import connect, shard_name, utc_day
from vigie_pipeline import processor
from vigie_pipeline import prune as prune_module
from vigie_pipeline.config import DeliverySettings, PipelineConfig, ProbeSettings
from vigie_pipeline.processor import monitoring_policy
from vigie_pipeline.sources import ShardReadError


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


def test_default_config_prunes_nothing_and_writes_no_prune_counter(data, caplog):
    retire(data)
    path = migrated_overrides(data.root)
    decide(path, "d1", 3)
    _decided_overrides(data)
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        for n in range(3):
            processor.run_once(PipelineConfig(data_dir=data.root), now=LATER + n)
    assert rows(data) == 1
    assert data.q("SELECT 1 FROM pipeline_meta WHERE key=?", prune_module.PRUNED_COUNTER_KEY) == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def break_shard(data) -> None:
    conn = connect(data.root / shard_name(utc_day(LATER)))
    conn.execute("ALTER TABLE raw_neigh RENAME TO raw_neigh_gone")
    conn.close()


def _off(data, n=0):
    processor.run_once(PipelineConfig(data_dir=data.root), now=LATER + n)


def test_an_unreadable_overrides_db_while_off_logs_nothing_about_the_prune(data, caplog):
    retire(data)
    (data.root / "overrides.db").write_bytes(b"not a database" * 100)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"):
        _off(data)
    assert rows(data) == 1
    assert not [r for r in caplog.records if "prune" in r.getMessage()]
    assert (
        len(
            [
                r
                for r in caplog.records
                if r.levelno >= logging.WARNING
                and r.getMessage().startswith("overrides_unreadable")
            ]
        )
        == 1
    )
    assert prune_module.OVERRIDES_SEEN_KEY not in _state_keys(data)  # nothing readable, no marker


def test_a_failed_batch_read_with_the_flag_off_logs_nothing_about_the_prune(data, caplog):
    ((mac, _),) = retire(data).items()
    migrated_overrides(data.root)
    data.add_batch(LATER, neigh=[mac])
    break_shard(data)
    with caplog.at_level(logging.DEBUG, logger="vigie_pipeline"), pytest.raises(ShardReadError):
        _off(data)
    assert rows(data) == 1
    assert not [r for r in caplog.records if "prune" in r.getMessage()]


@pytest.mark.parametrize(
    "extra",
    ["notice", "probes", "delivery", "tod"],
)
def test_other_opt_in_flags_never_arm_the_prune(data, tmp_path, extra):
    retire(data)
    migrated_overrides(data.root)
    kwargs = {
        "notice": {"new_device_notice": True},
        "probes": {"probes": ProbeSettings(file=tmp_path / "probe.json")},
        "delivery": {"delivery": DeliverySettings(enabled=True, file=tmp_path / "out.jsonl")},
        "tod": {"monitoring_baseline": "tod"},
    }[extra]
    config = PipelineConfig(data_dir=data.root, **kwargs)
    assert config.prune_retired_macs is False
    processor.run_once(config, now=LATER)
    assert rows(data) == 1


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
        ("on", False),
        ("y", False),
        ("enabled", False),
        ("True ", True),
        ("\uff11", False),  # a full-width 1
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


DEPLOY_MD = Path(__file__).resolve().parents[3] / "docs" / "deploy.md"


def _restore_passages() -> dict[str, str]:
    text = DEPLOY_MD.read_text()
    step = text.split("7. After restoring `overrides.db`", 1)[1].split("## Retention", 1)[0]
    bullet = text.split("went back to an older state", 1)[1].split("A randomized MAC", 1)[0]
    return {"restore step 7": step, "retention bullet": bullet}


def test_both_restore_passages_in_deploy_md_name_every_overrides_marker():
    keys = {
        value
        for name, value in vars(prune_module).items()
        if name.startswith("OVERRIDES_") and name.endswith("_KEY")
    }
    assert len(keys) == 4
    for where, passage in _restore_passages().items():
        flat = " ".join(passage.split())
        assert not [k for k in keys if k not in flat], where
