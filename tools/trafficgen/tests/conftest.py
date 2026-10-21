from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from vigie_ingest import store
from vigie_ingest.app import create_app
from vigie_ingest.config import Settings
from vigie_ingest.db import open_inventory

from trafficgen import DEFAULT_KEY, Emission, Scenario, cli, generate
from trafficgen.transport import Result, run

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "tests" / "fixtures" / "synthetic"
COLLECTOR, KEY_ID = "rtr-1", "k1"


def macs_of(scenario: Scenario) -> set[str]:
    out: set[str] = set()
    for em in scenario.emissions:
        b = em.batch
        out |= {
            x["mac"] for k in ("leases", "neigh", "dns", "conntrack", "sightings") for x in b[k]
        }
    return out


@pytest.fixture(scope="session")
def gen() -> Callable[..., Scenario]:
    cache: dict[tuple[Any, ...], Scenario] = {}

    def make(profile: str = "baseline", seed: int = 1, windows: int = 20, **kw: Any) -> Scenario:
        key = (profile, seed, windows, tuple(sorted(kw.items())))
        if key not in cache:
            cache[key] = generate(profile, seed=seed, windows=windows, **kw)
        return cache[key]

    return make


class Ingest:
    """A live ingest app (FastAPI TestClient) plus a mutable server clock."""

    def __init__(self, tmp_path: Path) -> None:
        data, secrets = tmp_path / "data", tmp_path / "secrets"
        self.data_dir = data
        data.mkdir()
        secrets.mkdir()
        (secrets / f"collector_key_{KEY_ID}").write_text(DEFAULT_KEY.hex())
        settings = Settings(data_dir=data, secrets_dir=secrets, rate_limit_per_window=100000)
        self.clock = [0.0]
        self.client = TestClient(create_app(settings, clock=lambda: self.clock[0]))
        self.client.__enter__()
        conn = open_inventory(settings.inventory_path)
        store.provision_collector(conn, COLLECTOR, KEY_ID)
        conn.close()

    def post(self, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        resp = self.client.post("/v1/batch", content=body, headers=headers)
        return resp.status_code, resp.json()

    def replay(self, emissions: list[Emission]) -> list[Result]:
        return run(
            emissions,
            DEFAULT_KEY,
            self.post,
            on_arrival=lambda ts: self.clock.__setitem__(0, float(ts)),
        )


@pytest.fixture
def ingest(tmp_path: Path):
    app = Ingest(tmp_path)
    yield app
    app.client.__exit__(None, None, None)


T0 = 1_900_000_000.0


class FakeTime:
    """Fake wall clock: sleep() advances it. The ingest app's clock follows it."""

    def __init__(self, ingest) -> None:
        self.now = T0
        self.ingest = ingest
        self.slept = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept += s
        self.now += s


class _Closable:
    def close(self) -> None:
        pass


@pytest.fixture
def fake(monkeypatch, ingest):
    ft = FakeTime(ingest)
    monkeypatch.setattr(cli, "time", SimpleNamespace(time=ft.time, sleep=ft.sleep))

    def post(body, headers):
        ingest.clock[0] = ft.now
        return ingest.post(body, headers)

    monkeypatch.setattr(cli, "http_post", lambda url, **kw: (post, _Closable()))
    return ft


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "k"
    p.write_text(DEFAULT_KEY.hex())
    return p
