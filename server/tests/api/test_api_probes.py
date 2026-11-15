"""GET /probes: read-only view of the stored probe status; stored values are hostile."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from api_helpers import NOW, Env, env, ts  # noqa: F401

from vigie_api import tokens
from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.probes import fold_probes

_RUNNER = Path(__file__).parents[3] / "deploy" / "persistent" / "probe_runner.py"
_spec = importlib.util.spec_from_file_location("probe_runner_for_api_tests", _RUNNER)
pr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pr
_spec.loader.exec_module(pr)


def target(ident: str = "dns-local", kind: str | None = "dns_local", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": ident, "kind": kind, "state": "ok", "consecutive_fail": 0, "consecutive_ok": 5,
        "last_ok_at": NOW - 30, "last_error_class": None, "last_latency_ms": 4,
        "episode_start": None, "flapping": False, "suppressed": False, "ring": [],
    }  # fmt: skip
    return {**base, **over}


def store(env: Env, *targets: dict[str, Any], **over: Any) -> None:
    status = {
        "v": 1, "folded_at": int(NOW), "stale": False, "reason": None,
        "written_at": NOW - 30.0, "valid_until": int(NOW + 270), "targets": list(targets),
    }  # fmt: skip
    put(env, json.dumps({**status, **over}))


def put(env: Env, text: str) -> None:
    env.inv.execute(
        "INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES ('probe_status', ?)", (text,)
    )


def fresh_collector(env: Env, age_s: float = 60) -> None:
    env.inv.execute("INSERT INTO collectors (id, key_id) VALUES ('c1', 'k1')")
    env.inv.execute(
        "INSERT INTO batches (collector_id, batch_id, received_at, observation_kind)"
        " VALUES ('c1', 'b1', ?, 'observation')",
        (ts(-age_s),),
    )


def data(env: Env) -> dict[str, Any]:
    r = env.get("/probes")
    assert r.status_code == 200, r.text
    return r.json()["data"]


def test_requires_token(env: Env) -> None:
    r = env.client.get("/probes")
    assert r.status_code == 401
    assert env.client.get("/probes", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_rate_limited_like_other_gets(env: Env) -> None:
    limit = env.settings.rate_limit_per_window
    codes = [env.client.get("/probes", headers=env.auth).status_code for _ in range(limit + 1)]
    assert codes[:limit] == [200] * limit and codes[-1] == 429
    _, other = tokens.create_token(env.ov, "other")
    assert (
        env.client.get("/probes", headers={"Authorization": f"Bearer {other}"}).status_code == 200
    )


def test_disabled_when_key_absent(env: Env) -> None:
    assert data(env) == {
        "enabled": False, "written_at": None, "stale": False, "targets": [], "verdict": "unknown",
    }  # fmt: skip


def test_disabled_status_reads_as_disabled(env: Env) -> None:
    store(env, stale=True, reason="disabled", written_at=None, valid_until=None, targets=[])
    assert data(env)["enabled"] is False


def test_normal_verdict_and_target_shape(env: Env) -> None:
    fresh_collector(env)
    store(env, target(), target("canary", "dns_upstream", last_latency_ms=12))
    d = data(env)
    assert d["enabled"] is True and d["stale"] is False and d["verdict"] == "normal"
    assert d["written_at"] == int(NOW - 30)
    assert d["targets"][0] == {
        "id": "dns-local", "kind": "dns_local", "state": "ok", "last_ok_at": NOW - 30,
        "last_error_class": None, "last_latency_ms": 4, "episode_start": None,
    }  # fmt: skip


def test_verdict_table(env: Env) -> None:
    fresh_collector(env)
    out = target(state="outage", last_error_class="timeout", episode_start=int(NOW - 200))
    store(env, out, target("canary", "dns_upstream"))
    assert data(env)["verdict"] == "router_resolver_down"
    store(env, target(), target("canary", "dns_upstream", state="outage"))
    assert data(env)["verdict"] == "upstream_unreachable"
    store(env, target(), target("canary", "dns_upstream", state="unknown"))
    assert data(env)["verdict"] == "normal"


def test_vigie_blind_when_collector_not_fresh(env: Env) -> None:
    fresh_collector(env, age_s=7200)
    store(env, target())
    assert data(env)["verdict"] == "vigie_blind"


def test_vigie_blind_without_any_collector_data(env: Env) -> None:
    store(env, target())
    assert data(env)["verdict"] == "vigie_blind"


def test_resolver_down_wins_over_stale_collector(env: Env) -> None:
    store(env, target(state="outage"))
    assert data(env)["verdict"] == "router_resolver_down"


def test_stale_by_valid_until_forces_unknown(env: Env) -> None:
    """A stopped pipeline cannot rewrite 'ok': the reader expires it from valid_until."""
    fresh_collector(env)
    store(env, target(), valid_until=int(NOW - 1))
    d = data(env)
    assert d["stale"] is True and d["verdict"] == "unknown"
    assert {t["state"] for t in d["targets"]} == {"unknown"}


def test_stale_flag_from_pipeline(env: Env) -> None:
    store(env, stale=True, reason="stale", written_at=None, valid_until=None, targets=[])
    d = data(env)
    assert (d["enabled"], d["stale"], d["verdict"], d["targets"]) == (True, True, "unknown", [])


def test_future_written_at_is_stale(env: Env) -> None:
    store(env, target(), written_at=int(NOW + 3600), valid_until=int(NOW + 3900))
    assert data(env)["stale"] is True


def test_missing_valid_until_is_stale(env: Env) -> None:
    store(env, target(), valid_until=None)
    assert data(env)["stale"] is True


def test_legacy_target_without_kind(env: Env) -> None:
    fresh_collector(env)
    store(env, target(kind=None))
    d = data(env)
    assert d["targets"][0]["kind"] == "unknown" and d["verdict"] == "unknown"


def test_hostile_stored_values_are_dropped(env: Env) -> None:
    fresh_collector(env)
    evil = "<script>alert(1)</script>"
    store(
        env,
        target(evil),  # bad id: whole target dropped
        target("ok-id", "bogus<kind>", state=evil, last_error_class=evil, last_latency_ms=10**9,
               last_ok_at=-5, episode_start="x"),
        target("ok-id", "dns_local"),  # duplicate id dropped
        target("b" * 33),
        *[target(f"t{i}") for i in range(30)],
        written_at=True,
    )  # fmt: skip
    r = env.get("/probes")
    assert r.status_code == 200 and evil not in r.text and "bogus" not in r.text
    d = r.json()["data"]
    assert len(d["targets"]) <= 10
    first = d["targets"][0]
    assert first == {
        "id": "ok-id", "kind": "unknown", "state": "unknown", "last_ok_at": None,
        "last_error_class": None, "last_latency_ms": None, "episode_start": None,
    }  # fmt: skip
    assert d["written_at"] is None and d["stale"] is True


def test_non_json_and_non_object_status(env: Env) -> None:
    for text in ("{not json", "[1,2]", "null", '"x"', "1e999999", "[" * 50000):
        put(env, text)
        d = data(env)
        assert d["enabled"] is True and d["stale"] is True and d["targets"] == []
        assert d["verdict"] == "unknown"


def test_non_finite_numbers_dropped(env: Env) -> None:
    put(env, '{"written_at": NaN, "valid_until": Infinity, "targets": []}')
    d = data(env)
    assert d["written_at"] is None and d["stale"] is True


def test_read_only(env: Env) -> None:
    store(env, target())
    before = env.inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()
    env.get("/probes")
    after = env.inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()
    assert before[0] == after[0]


def test_a_real_runner_state_folded_by_the_pipeline_reads_as_fresh_normal(
    env: Env, tmp_path
) -> None:
    """The runner's own serializer writes written_at as a float; the pipeline keeps it a float."""
    fresh_collector(env)
    written = NOW - 20.0
    ts_ = pr.TargetState(
        id="router-dns", kind="dns_local", state="ok", consecutive_ok=3, last_ok_at=written,
        last_latency_ms=4, last_attempt=written, episodes_day=ts()[:10],
    )  # fmt: skip
    path = tmp_path / "probe-state.json"
    path.write_bytes(pr.serialize_state(pr.State(written_at=written, targets=(ts_,))))
    assert isinstance(json.loads(path.read_text())["written_at"], float)
    fold_probes(env.inv, ProbeSettings(file=path), lambda: NOW)
    stored = json.loads(
        env.inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()[0]
    )
    assert isinstance(stored["written_at"], float)
    d = data(env)
    assert d["stale"] is False and d["written_at"] == int(written) and d["verdict"] == "normal"


def test_returned_ids_are_unique(env: Env) -> None:
    fresh_collector(env)
    store(env, target("a"), target("a", state="outage"), target("b"), target("a"))
    ids = [t["id"] for t in data(env)["targets"]]
    assert ids == ["a", "b"]


def test_status_over_64_kib_reads_stale(env: Env) -> None:
    store(env, target(), ring=["x" * 1000] * 70)
    assert (
        len(
            env.inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()[
                0
            ]
        )
        > 64 * 1024
    )
    d = data(env)
    assert d["enabled"] is True and d["stale"] is True and d["targets"] == []
    assert d["verdict"] == "unknown"


def test_the_pipelines_own_stale_flag_is_honoured(env: Env) -> None:
    fresh_collector(env)
    store(env, target(), stale=True, reason="stale")  # timestamps themselves are valid
    d = data(env)
    assert d["stale"] is True and d["verdict"] == "unknown" and d["targets"] == []


def test_an_outage_wins_over_an_unknown_sibling_dns_local(env: Env) -> None:
    fresh_collector(env)
    store(env, target("a", state="unknown"), target("b", state="outage"))
    assert data(env)["verdict"] == "router_resolver_down"


def test_a_storage_error_is_the_uniform_500_like_other_routes(env: Env) -> None:
    env.inv.execute("DROP TABLE pipeline_meta")
    r = env.get("/probes")
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error"
