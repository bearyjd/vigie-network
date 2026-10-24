"""Merge approvals bound evidence and keep inventory work outside the writer lock."""

import json
from dataclasses import replace

import pytest
from api_helpers import NOW, env, ts  # noqa: F401
from test_api_identity_writes import suggestion

from vigie_api import identity_writes as domain
from vigie_api import tokens
from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.models import SuggestionDecision
from vigie_pipeline.config import PipelineConfig


def decide(e, *, limits=None, remember=False, versions=None):
    return domain.decide(
        e.inv,
        e.ov,
        sid="s",
        accept=True,
        body=SuggestionDecision(expected_versions=versions or {"a": 0, "b": 0}, remember=remember),
        principal=tokens.Principal("human", tokens.SCOPE_RULES),
        now=ts(),
        request_id="bounded",
        config=PipelineConfig(data_dir=e.root),
        merge_limits=limits or Settings(data_dir=e.root),
    )


@pytest.mark.parametrize("limit", ["aliases", "observations", "activity_rows", "flatten_writes"])
def test_oversized_merge_fails_before_writer_transaction_without_writes(env, limit):
    suggestion(env)
    env.device("alias")
    env.link("alias", "a")
    env.mac("02:00:00:00:00:01", "a")
    env.mac("02:00:00:00:00:02", "b")
    env.inv.executemany(
        'INSERT INTO mac_activity (mac,start,"end") VALUES (?,?,?)',
        [("02:00:00:00:00:01", n, n + 1) for n in range(2)],
    )
    limits = replace(Settings(data_dir=env.root), **{f"max_merge_{limit}": 1})
    statements = []
    env.ov.set_trace_callback(statements.append)
    with pytest.raises(ApiError) as error:
        decide(env, limits=limits)
    env.ov.set_trace_callback(None)
    assert error.value.status == 409
    assert error.value.code == "merge_too_large"
    assert not any(sql == "BEGIN IMMEDIATE" for sql in statements)
    assert env.ov.execute("SELECT count(*) FROM identity_links").fetchone()[0] == 1
    for table in ("identity_merges", "suggestion_decisions", "audit_log", "api_write_receipts"):
        assert env.ov.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


@pytest.mark.parametrize("history_rows", [3, 3000])
def test_allowed_merge_has_bounded_sqlite_work_under_writer_lock(env, history_rows):
    suggestion(env)
    env.mac("02:00:00:00:00:01", "a")
    env.inv.execute("BEGIN")
    env.inv.executemany(
        'INSERT INTO mac_activity (mac,start,"end") VALUES (?,?,?)',
        [("02:00:00:00:00:01", NOW - 10000 + n, NOW - 9999 + n) for n in range(history_rows)],
    )
    env.inv.execute("COMMIT")
    env.ov.execute("BEGIN")
    env.ov.executemany(
        "INSERT INTO identity_links (from_device,into_device,merge_id,created_at,created_by)"
        " VALUES (?,?,'old',?,'test')",
        [(f"unrelated-{n}", f"other-{n}", ts()) for n in range(10000)],
    )
    env.ov.execute("COMMIT")
    locked = False
    steps = 0
    inventory_under_lock = []

    def trace(sql):
        nonlocal locked
        if sql == "BEGIN IMMEDIATE":
            locked = True
        elif sql in {"COMMIT", "ROLLBACK"}:
            locked = False

    def progress():
        nonlocal steps
        steps += int(locked)
        return int(steps > 10000)

    env.ov.set_trace_callback(trace)
    env.ov.set_progress_handler(progress, 1)
    env.inv.set_progress_handler(progress, 1)
    env.inv.set_trace_callback(lambda sql: inventory_under_lock.append(sql) if locked else None)
    try:
        assert decide(env)["state"] == "accepted"
    finally:
        env.ov.set_trace_callback(None)
        env.ov.set_progress_handler(None, 0)
        env.inv.set_progress_handler(None, 0)
        env.inv.set_trace_callback(None)
    assert steps < 10000
    assert not any("mac_activity" in sql or "observations" in sql for sql in inventory_under_lock)


@pytest.mark.parametrize("group_id", [None, "kids"])
def test_remember_audit_contains_complete_inserted_rule_and_effective_group(env, group_id):
    suggestion(env)
    if group_id:
        env.ov.execute(
            "INSERT INTO device_overrides (device_id,group_id,version,updated_at,updated_by)"
            " VALUES ('b',?,1,?,'test')",
            (group_id, ts()),
        )
        env.inv.execute("UPDATE suggestions SET basis=?", (json.dumps({"a": 0, "b": 1}),))
    env.inv.execute(
        "UPDATE identity_candidates SET evidence=?",
        (json.dumps({"opt55": "1,3", "opt60": "vendor", "hostname": "HOST"}),),
    )
    result = decide(env, remember=True, versions={"a": 0, "b": 1} if group_id else None)
    stored = dict(
        env.ov.execute("SELECT * FROM identity_rules WHERE id=?", (result["rule_id"],)).fetchone()
    )
    after = json.loads(env.ov.execute("SELECT detail FROM audit_log").fetchone()[0])["after"]
    assert after["remembered_rule"] == stored
    assert "group_id" in after
    assert after["group_id"] == group_id


@pytest.mark.parametrize("change", ["incoming", "metadata", "version"])
def test_merge_revalidates_exact_component_and_versions_before_mutation(env, monkeypatch, change):
    suggestion(env)
    env.link("alias", "a")
    original_atomic = domain.atomic

    def concurrent_atomic(*args, **kwargs):
        if change == "incoming":
            env.link("new-alias", "alias")
        elif change == "metadata":
            env.ov.execute("UPDATE identity_links SET created_by='other' WHERE from_device='alias'")
        else:
            env.ov.execute(
                "INSERT INTO device_overrides (device_id,version,updated_at,updated_by)"
                " VALUES ('a',1,?,'other')",
                (ts(),),
            )
        return original_atomic(*args, **kwargs)

    monkeypatch.setattr(domain, "atomic", concurrent_atomic)
    with pytest.raises(ApiError) as error:
        decide(env)
    assert error.value.status == 409
    assert env.ov.execute("SELECT count(*) FROM identity_merges").fetchone()[0] == 0
    assert env.ov.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0
