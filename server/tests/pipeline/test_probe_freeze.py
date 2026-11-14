"""Freeze: probes (off, or on with an outage file) leave the monitoring contract untouched.

The golden digests were captured from origin/main (73bd7f6), before any probe code existed in
vigie_pipeline, by running the same fixture. They must never be regenerated to make a test pass.
"""

from __future__ import annotations

import json
from dataclasses import fields

import pytest
from probe_helpers import (
    CURRENT,
    build_fixture,
    digest,
    dump,
    run_fixture,
    state_doc,
    target_state,
    write_probe_file,
)

from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.processor import monitoring_policy

POOLED_VERSION = "f2326b78a3286c8b26efcdbeeb33597e010c3976ab519047e27c8a5b62d915bc"
TOD_VERSION = "eb1f1e884ce34d9157d70c402002c110d6255b0417f20a86ed88a36807937337"
# every dumped table except pipeline_meta, from a run on origin/main
GOLDEN_TABLES = "2568eb941b23f1e1c5f3d205b962fe50162674536a48a30e81f78d04d06bdb0e"
GOLDEN_META = "6c13347ac1310851a7ab64fe8607b5d6142bf885e68ac3ccd92aab8caf4dff9a"
PROBE_KINDS = {"probe_outage", "probe_recovered", "probe_flapping", "probe_stale"}


def tables(snapshot):
    return {k: v for k, v in snapshot.items() if k != "pipeline_meta"}


@pytest.mark.parametrize("probe_env", [{}, {"VIGIE_PROBE_FILE": "/nonexistent/probe.json"}])
def test_policy_versions_are_pinned_with_and_without_probes(probe_env):
    pooled = monitoring_policy(PipelineConfig.from_env({**probe_env}))
    tod = monitoring_policy(
        PipelineConfig.from_env({"VIGIE_MONITORING_BASELINE": "tod", **probe_env})
    )
    assert isinstance(pooled, BaselineConfig) and pooled.version == POOLED_VERSION
    assert isinstance(tod, TodConfig) and tod.version == TOD_VERSION


def test_probe_settings_are_in_no_policy_dataclass():
    for family in (BaselineConfig, TodConfig):
        assert not [f.name for f in fields(family) if "probe" in f.name]


def test_disabled_run_is_byte_identical_to_main(tmp_path):
    build_fixture(tmp_path)
    run_fixture(tmp_path)
    snap = dump(tmp_path)
    assert digest(tables(snap)) == GOLDEN_TABLES
    assert digest(snap["pipeline_meta"]) == GOLDEN_META
    assert snap["monitoring_incidents"], "the fixture must exercise a real incident"
    assert snap["events"] == []
    assert not any(r[0] == "probe_status" for r in snap["pipeline_meta"])


def without_events(snap):
    return digest({**tables(snap), "events": []})


def test_enabled_with_an_outage_file_changes_only_probe_rows(tmp_path):
    build_fixture(tmp_path)
    outage = target_state(
        state="outage", consecutive_fail=3, episode_start=int(CURRENT) - 100,
        last_error_class="timeout",
    )  # fmt: skip
    probe_file = write_probe_file(
        tmp_path / "probe-state.json", state_doc(outage, written_at=CURRENT + 3600)
    )
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(probe_file))
    snap = dump(tmp_path)
    assert without_events(snap) == GOLDEN_TABLES
    assert [e[0] for e in snap["events"]] == ["probe_outage"]
    assert snap["events"][0][5] == 1  # device_id IS NULL
    others = [r for r in snap["pipeline_meta"] if r[0] != "probe_status"]
    assert digest(others) == GOLDEN_META
    status = json.loads(dict(snap["pipeline_meta"])["probe_status"])
    assert status["stale"] is False and status["targets"][0]["state"] == "outage"


def test_enabled_with_a_missing_file_changes_only_probe_rows(tmp_path):
    build_fixture(tmp_path)
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(tmp_path / "absent.json"))
    snap = dump(tmp_path)
    assert without_events(snap) == GOLDEN_TABLES
    assert {e[0] for e in snap["events"]} == {"probe_stale"}
    assert {e[0] for e in snap["events"]} <= PROBE_KINDS


def test_disabled_never_runs_the_probe_stage(tmp_path, monkeypatch):
    from vigie_pipeline import processor

    def boom(*args, **kwargs):
        raise AssertionError("fold_probes must not run when probes are disabled")

    monkeypatch.setattr(processor, "fold_probes", boom)
    build_fixture(tmp_path)
    run_fixture(tmp_path)  # would raise if the stage ran


def test_a_broken_probe_stage_never_aborts_the_pass(tmp_path, monkeypatch):
    from vigie_pipeline import probes

    def boom(*args, **kwargs):
        raise RuntimeError("probe stage exploded")

    monkeypatch.setattr(probes, "_fold", boom)
    build_fixture(tmp_path)
    run_fixture(tmp_path, VIGIE_PROBE_FILE=str(tmp_path / "x.json"))
    assert without_events(dump(tmp_path)) == GOLDEN_TABLES
