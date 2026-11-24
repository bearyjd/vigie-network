"""A real probe-runner state file driven through outage, recovery, stale and collector loss, read
back through both GET /probes and GET /events (synthetic data, injected clock, no network)."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from api_helpers import NOW, SUGGESTIONS_DDL, Env
from fastapi.testclient import TestClient
from test_api_probes import pr

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.probes import _reset_log_memory, fold_probes
from vigie_pipeline.schema import open_pipeline_inventory

STEP_S = 60.0
RESOLVER, QNAME = "10.0.0.7", "svc.home.lan"


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[tuple[Env, list[float]]]:
    """The api_helpers Env, but with a clock the test can move."""
    _reset_log_memory()
    clock = [NOW]
    inv = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    inv.execute(SUGGESTIONS_DDL)
    ov = open_overrides(tmp_path / "overrides.db")
    _, token = tokens.create_token(ov, "test")
    settings = Settings(data_dir=tmp_path)
    with TestClient(create_app(settings, clock=lambda: clock[0])) as client:
        yield Env(tmp_path, settings, inv, ov, token, client), clock
    inv.close()
    ov.close()


class Resolver:
    """A fake dns function: answers with a valid reply, or times out."""

    def __init__(self) -> None:
        self.up = True

    def __call__(self, resolver: str, packet: bytes, timeout_s: float) -> bytes:
        if not self.up:
            raise TimeoutError
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x0a\0\0\x01"
        return packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + packet[12:] + answer


def test_outage_recovery_stale_and_collector_loss_end_to_end(lab: tuple[Env, list[float]]) -> None:
    env, clock = lab
    state_file = env.root / "probe-state.json"
    settings = ProbeSettings(file=state_file)
    cfg = pr.parse_config(
        {"enabled": True, "state_file": str(state_file),
         "targets": [{"id": "router-dns", "kind": "dns_local", "resolver": RESOLVER,
                      "qname": QNAME}]}
    )  # fmt: skip
    resolver = Resolver()
    state = pr.empty_state()
    batches = [0]

    def collector_batch() -> None:
        batches[0] += 1
        env.inv.execute("INSERT OR IGNORE INTO collectors (id, key_id) VALUES ('c1', 'k1')")
        env.inv.execute(
            "INSERT INTO batches (collector_id, batch_id, received_at, observation_kind)"
            " VALUES ('c1', ?, ?, 'observation')",
            (f"b{batches[0]}", iso_utc(clock[0])),
        )

    def tick(*, up: bool, collector: bool = True) -> dict[str, Any]:
        """One runner pass (real state file) then one pipeline fold, then GET /probes."""
        nonlocal state
        clock[0] += STEP_S
        resolver.up = up
        state = pr.run_pass(cfg, state, now=lambda: clock[0], dns=resolver, connect=None)
        pr.write_state(str(state_file), state)
        if collector:
            collector_batch()
        fold_probes(env.inv, settings, lambda: clock[0])
        r = env.get("/probes")
        assert r.status_code == 200, r.text
        return r.json()["data"]

    def kinds() -> list[str]:
        r = env.get("/events")
        assert r.status_code == 200, r.text
        return [e["kind"] for e in r.json()["data"] if e["kind"].startswith("probe_")]

    # three failures: the outage opens on the third and not before
    assert tick(up=False)["verdict"] == "unknown"
    assert tick(up=False)["verdict"] == "unknown" and kinds() == []
    outage = tick(up=False)
    assert outage["verdict"] == "router_resolver_down" and outage["stale"] is False
    assert [t["state"] for t in outage["targets"]] == ["outage"]
    assert kinds() == ["probe_outage"]

    # three successes: recovery on the third and not before
    assert tick(up=True)["verdict"] == "router_resolver_down"
    assert tick(up=True)["verdict"] == "router_resolver_down"
    assert kinds() == ["probe_outage"]
    recovered = tick(up=True)
    assert recovered["verdict"] == "normal" and recovered["targets"][0]["state"] == "ok"
    assert kinds() == ["probe_outage", "probe_recovered"]

    # the runner stops: past VIGIE_PROBE_STALE_S nothing may still read ok
    clock[0] += settings.stale_s + 60
    fold_probes(env.inv, settings, lambda: clock[0])
    stale = env.get("/probes").json()["data"]
    assert stale["stale"] is True and stale["verdict"] == "unknown" and stale["targets"] == []
    assert kinds() == ["probe_outage", "probe_recovered", "probe_stale"]

    # runner back and ok, but no observation batch for more than 900 s: Vigie is blind
    clock[0] += 900
    blind = tick(up=True, collector=False)
    assert blind["stale"] is False and blind["targets"][0]["state"] == "ok"
    assert blind["verdict"] == "vigie_blind"
    # the same ok state with a fresh collector batch is normal again
    assert tick(up=True)["verdict"] == "normal"
    assert kinds() == ["probe_outage", "probe_recovered", "probe_stale"]
