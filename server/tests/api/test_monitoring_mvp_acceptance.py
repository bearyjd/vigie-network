"""Synthetic monitoring workflow over signed ingest, the pipeline and the public owner API."""

from __future__ import annotations

import importlib.util
import sys
from contextlib import closing
from itertools import count
from pathlib import Path

import pytest
from conftest import COLLECTOR, NOW, Env, make_batch
from fastapi.testclient import TestClient

from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides
from vigie_api.tokens import create_token
from vigie_pipeline.config import PipelineConfig, ProbeSettings
from vigie_pipeline.processor import run_once

HOUR = 3600
DAY = 24 * HOUR
DAY0 = int(NOW) // DAY * DAY
MIB = 1024**2
MAC = "00:11:22:33:44:55"


@pytest.fixture
def owner_api(env: Env):
    settings = Settings(data_dir=env.settings.data_dir)
    with closing(open_overrides(settings.data_dir / "overrides.db")) as overrides:
        _, token = create_token(overrides, "synthetic-owner")
    app = create_app(settings, clock=lambda: env.clock[0])
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as client:
        yield client


def data(api: TestClient, path: str, **params):
    response = api.get(path, params=params)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def run_hour(env: Env, cfg: PipelineConfig, seq: int, hour: int, upload: int):
    end = hour + HOUR
    batch = make_batch(
        seq,
        window_start=hour,
        window_end=end,
        sent_ts=end,
        observation_kind="observation",
        leases=[{"mac": MAC, "ip": "192.168.8.10", "hostname": "synthetic-laptop"}],
        conntrack=[
            {
                "mac": MAC,
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "proto": "tcp",
                "bytes_up": upload,
                "bytes_down": 100,
                "flows": 1,
            }
        ],
        dns=[],
        neigh=[],
        sightings=[],
    )
    env.clock[0] = end + 1
    ingested = env.post(batch)
    assert ingested.status_code == 200 and ingested.json() == {"duplicate": False}, ingested.text
    assert run_once(cfg, now=env.clock[0]).batches == 1
    return batch


def test_synthetic_monitoring_owner_workflow(env: Env, owner_api: TestClient):
    cfg = PipelineConfig(data_dir=env.settings.data_dir, migrate=True)
    seq = count(1)
    # Twenty qualified hours across fourteen UTC dates, then an independent episode.
    training = sorted(
        [DAY0 + day * DAY + HOUR for day in range(14)]
        + [DAY0 + day * DAY + 2 * HOUR for day in range(6)]
    )
    run_hour(env, cfg, next(seq), training[0], 10 * MIB)

    (device,) = data(owner_api, "/devices")
    device_id = device["id"]
    assert data(owner_api, f"/macs/{MAC}")["device_id"] == device_id
    activity = f"/devices/{device_id}/activity"
    scope = {"collector_id": COLLECTOR}
    first = data(owner_api, activity, **scope, from_hour=training[0], to_hour=training[0] + HOUR)
    (first_hour,) = first["hours"]
    assert (first_hour["bytes_up"], first_hour["state"]) == (10 * MIB, "eligible")
    assert first["baseline"]["state"] == "learning"
    assert first["baseline"]["baseline_id"] is None
    assert data(owner_api, "/incidents", **scope) == []

    for hour in training[1:-1]:
        run_hour(env, cfg, next(seq), hour, 10 * MIB)
    almost = data(owner_api, activity, **scope)["baseline"]
    assert (almost["state"], almost["sample_hours"], almost["distinct_days"]) == (
        "learning",
        19,
        13,
    )
    run_hour(env, cfg, next(seq), training[-1], 10 * MIB)
    baseline = data(owner_api, activity, **scope)["baseline"]
    assert baseline["baseline_id"]
    assert (baseline["state"], baseline["sample_hours"], baseline["distinct_days"]) == (
        "mature",
        20,
        14,
    )
    assert baseline["median_upload_bytes"] == 10 * MIB
    assert baseline["trained_until"] == training[-1]

    gap = training[-1] + 2 * HOUR
    run_hour(env, cfg, next(seq), gap - HOUR, 51 * MIB)
    env.clock[0] = gap + HOUR + 1
    assert run_once(cfg, now=env.clock[0]).batches == 0
    covered = data(owner_api, "/coverage", **scope, from_hour=gap - HOUR, to_hour=gap + HOUR)
    assert [h["state"] for h in covered["hours"]] == ["eligible", "missing"]
    assert covered["hours"][1]["reasons"] == ["missing"]
    last_window = covered["collector"]["latest_window_end"]
    assert last_window == gap and HOUR < env.clock[0] - last_window <= 2 * HOUR
    (missing,) = data(owner_api, activity, **scope, from_hour=gap, to_hour=gap + HOUR)["hours"]
    assert missing["bytes_up"] is missing["qualified_seconds"] is None

    run_hour(env, cfg, next(seq), gap + HOUR, 51 * MIB)
    # One high hour on either side of the gap is insufficient.
    assert data(owner_api, "/incidents", **scope) == []
    last = run_hour(env, cfg, next(seq), gap + 2 * HOUR, 51 * MIB)
    (incident,) = data(owner_api, "/incidents", **scope)
    detail = f"/incidents/{incident['id']}"
    assert data(owner_api, detail, **scope) == incident
    assert incident["detector"] == "upload_deviation"
    assert incident["state"] == "open" and incident["attention"] and incident["review"] is None
    assert incident["current_lineage"] and incident["device_id"] == device_id
    evidence = incident["evidence"]
    assert evidence["reason_code"] == "two_qualified_upload_hours"
    assert (evidence["previous_hour"], evidence["hour"]) == (gap + HOUR, gap + 2 * HOUR)
    assert (evidence["observed_bytes"], evidence["threshold_bytes"]) == (51 * MIB, 50 * MIB)
    assert evidence["baseline_id"] == baseline["baseline_id"]
    assert evidence["unusual_is_not_malicious"] is True

    # An ingest retry and two pipeline passes leave the completed window and incident unchanged.
    for _ in range(2):
        retried = env.post(last)
        assert retried.status_code == 200 and retried.json() == {"duplicate": True}, retried.text
        assert run_once(cfg, now=env.clock[0]).batches == 0
    after_retry = data(
        owner_api, activity, **scope, from_hour=gap + 2 * HOUR, to_hour=gap + 3 * HOUR
    )
    assert after_retry["baseline"] == baseline
    (last_hour,) = after_retry["hours"]
    assert (last_hour["bytes_up"], last_hour["flows"]) == (51 * MIB, 1)
    assert data(owner_api, "/incidents", **scope) == [incident]

    request = {
        "params": scope,
        "json": {"expected_version": incident["decision_version"]},
        "headers": {"X-Request-ID": "synthetic-owner-ack"},
    }
    ack = owner_api.post(f"{detail}/acknowledge", **request)
    ack_retry = owner_api.post(f"{detail}/acknowledge", **request)
    assert ack.status_code == ack_retry.status_code == 200, (ack.text, ack_retry.text)
    assert ack_retry.json() == ack.json()
    reviewed = data(owner_api, detail, **scope)
    assert reviewed["state"] == "open" and not reviewed["attention"]
    assert reviewed["decision_version"] == 1
    assert reviewed["review"]["status"] == "acknowledged"
    (audit,) = data(owner_api, "/events", kind="monitoring.incident.acknowledge")
    assert audit["source"] == "audit" and incident["id"] in audit["summary"]


@pytest.fixture
def probe_runner(monkeypatch):
    path = Path(__file__).resolve().parents[3] / "deploy" / "persistent" / "probe_runner.py"
    spec = importlib.util.spec_from_file_location("monitoring_mvp_probe_runner", path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, runner)
    spec.loader.exec_module(runner)
    return runner


def test_synthetic_probe_outage_reaches_owner_api(env: Env, owner_api: TestClient, probe_runner):
    """The real runner writes the handoff. Only its network adapter is replaced."""
    tick = 60  # probe.timer cadence
    state_file = env.settings.data_dir / "probe-state.json"
    runner_config = probe_runner.parse_config(
        {
            "enabled": True,
            "state_file": str(state_file),
            "targets": [{"id": "router", "kind": "tcp_lan", "address": "192.168.8.1", "port": 443}],
        }
    )
    pipeline = PipelineConfig(
        data_dir=env.settings.data_dir, migrate=True, probes=ProbeSettings(file=state_file)
    )
    state = probe_runner.empty_state()
    fail = False

    def connect(_address, _port, _timeout_s):
        if fail:
            raise TimeoutError

    def no_dns(*_args):
        pytest.fail("The TCP probe must not issue a DNS query")

    def step():
        nonlocal state
        state = probe_runner.run_pass(
            runner_config, state, now=lambda: env.clock[0], dns=no_dns, connect=connect
        )
        probe_runner.write_state(str(state_file), state)
        run_once(pipeline, now=env.clock[0])
        view = data(owner_api, "/probes")
        assert view["enabled"] and not view["stale"]
        (target,) = view["targets"]
        return target

    assert step()["state"] == "ok"
    fail = True
    first_failure = env.clock[0] + tick
    for number in range(3):
        env.clock[0] = first_failure + number * tick
        target = step()
        assert target["state"] == ("ok" if number < 2 else "outage")
    assert target["episode_start"] == first_failure + 2 * tick
    assert target["last_error_class"] == "timeout"
    run_once(pipeline, now=env.clock[0] + 1)
    (event,) = data(owner_api, "/events", kind="probe_outage")
    assert event["source"] == "inventory"
