"""Domain-level validation, privilege, transaction and retry boundaries."""

from __future__ import annotations

import json
import sqlite3

import pytest
from api_helpers import Env, env, ts  # noqa: F401

from vigie_api import identity_writes as domain
from vigie_api import tokens
from vigie_api.errors import ApiError
from vigie_api.models import RuleCreate, SuggestionDecision, VersionedWrite
from vigie_pipeline.config import PipelineConfig
from vigie_pipeline.snapshot import parse_rule
from vigie_pipeline.stitch_types import fold

SIGNATURE = {"opt55": "1,2,3", "opt60": "vendor", "hostname": "phone"}
CONTROL = tokens.Principal("human", tokens.SCOPE_RULES)


@pytest.mark.parametrize(
    "change",
    [
        {"unexpected": "x"},
        {"hostname": " "},
        {"opt60": "x" * 129},
        {"opt55": 123},
        {"opt55": True},
        {"opt55": [1, 2, 3]},
        {"mdns_name": False},
    ],
)
def test_signature_rejects_entire_rule_instead_of_weakening_it(change: dict) -> None:
    with pytest.raises(ValueError):
        domain.validate_signature({**SIGNATURE, **change})


def test_signature_unicode_fixedpoint_is_stored_and_parsed_consistently(env: Env) -> None:
    env.device("d1")
    raw = {**SIGNATURE, "hostname": "ＳＴＲＡＳＳＥ", "mdns_name": "Straße"}
    body = RuleCreate(device_id="d1", signature=raw, expected_version=0)
    assert body.signature["hostname"] == body.signature["mdns_name"] == fold("Straße")
    assert domain.validate_signature(body.signature) == body.signature
    domain.create_rule(env.inv, env.ov, body=body, principal=CONTROL, now=ts(), request_id="r")
    row = env.ov.execute("SELECT * FROM identity_rules").fetchone()
    assert json.loads(row["signature"]) == body.signature
    parsed = parse_rule(row)
    assert parsed is not None
    assert (parsed.opt55, parsed.opt60, parsed.hostname, parsed.mdns_name) == (
        "1,2,3",
        "vendor",
        body.signature["hostname"],
        body.signature["mdns_name"],
    )


@pytest.mark.parametrize("scope", ["service", "integration", "read-only"])
def test_rules_privilege_cannot_be_combined_with_noncontrol_scope(env: Env, scope: str) -> None:
    before = env.ov.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0]
    with pytest.raises(ValueError):
        tokens.create_token(env.ov, "invalid", scope=scope, rules_write=True)
    assert env.ov.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0] == before


@pytest.mark.parametrize("scope", ["service", "integration", "read-only"])
def test_noncontrol_principal_cannot_write_even_when_asking_for_rules(scope: str) -> None:
    principal = tokens.Principal("worker", scope)
    for rules in (False, True):
        with pytest.raises(ApiError) as error:
            principal.require_write(rules=rules)
        assert error.value.status == 403


def _empty_writes(env: Env) -> None:
    for table in (
        "identity_rules",
        "identity_links",
        "identity_merges",
        "device_overrides",
        "suggestion_decisions",
        "candidate_decisions",
        "audit_log",
        "api_write_receipts",
    ):
        assert env.ov.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608
    assert not env.ov.in_transaction


def _merge_suggestion(env: Env, *, evidence: dict | None = None) -> None:
    env.device("a")
    env.device("b")
    env.inv.execute(
        "INSERT INTO identity_candidates"
        " (id,device_a,device_b,score,evidence,state,created_at)"
        " VALUES ('candidate','a','b',0.8,?,'suggested',?)",
        (json.dumps(SIGNATURE if evidence is None else evidence), ts(-10)),
    )
    env.inv.execute(
        "INSERT INTO suggestions VALUES (?,?,?,?,?,?,?,?,?)",
        (
            "merge",
            "merge_identity",
            '["a","b"]',
            json.dumps(
                {
                    "from_device": "a",
                    "into_device": "b",
                    "evidence_summary": {"candidate_id": "candidate"},
                }
            ),
            "fingerprint_match",
            None,
            '{"a":0,"b":0}',
            ts(-10),
            ts(100),
        ),
    )


def _decide(env: Env, *, accept: bool, body: SuggestionDecision, request_id: str = "decision"):
    return domain.decide(
        env.inv,
        env.ov,
        sid="merge",
        accept=accept,
        body=body,
        principal=CONTROL,
        now=ts(),
        request_id=request_id,
        config=PipelineConfig(data_dir=env.root),
    )


def test_rule_create_rolls_back_when_audit_insert_fails(env: Env) -> None:
    env.device("d1")
    env.ov.execute(
        "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_log"
        " BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
    )
    body = RuleCreate(device_id="d1", signature=SIGNATURE, expected_version=0)
    with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
        domain.create_rule(
            env.inv,
            env.ov,
            body=body,
            principal=CONTROL,
            now=ts(),
            request_id="rule",
        )
    _empty_writes(env)


def test_remember_validation_rolls_back_already_inserted_merge_and_versions(env: Env) -> None:
    _merge_suggestion(env, evidence={"hostname": "incomplete"})
    with pytest.raises(ApiError) as error:
        _decide(
            env,
            accept=True,
            body=SuggestionDecision(
                expected_versions={"a": 0, "b": 0},
                remember=True,
            ),
        )
    assert error.value.code == "invalid_signature"
    _empty_writes(env)


def test_reject_replays_without_versions_and_rejects_opposite_decision(env: Env) -> None:
    _merge_suggestion(env)
    body = SuggestionDecision(expected_versions={"a": 0, "b": 0})
    first = _decide(env, accept=False, body=body)
    replay = _decide(
        env,
        accept=False,
        body=SuggestionDecision(
            expected_versions={"a": 999, "b": 999},
        ),
        request_id="new-retry",
    )
    assert replay == first
    assert env.ov.execute("SELECT COUNT(*) FROM device_overrides").fetchone()[0] == 0
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    assert env.ov.execute("SELECT COUNT(*) FROM api_write_receipts").fetchone()[0] == 1
    with pytest.raises(ApiError) as error:
        _decide(env, accept=True, body=body, request_id="opposite")
    assert error.value.code == "already_decided"
    assert not env.ov.in_transaction


def test_undo_refuses_later_human_edit_even_with_current_expected_versions(env: Env) -> None:
    _merge_suggestion(env)
    merged = _decide(env, accept=True, body=SuggestionDecision(expected_versions={"a": 0, "b": 0}))
    env.ov.execute(
        "UPDATE device_overrides SET owner='later',version=version+1 WHERE device_id='b'"
    )
    with pytest.raises(ApiError) as error:
        domain.undo(
            env.inv,
            env.ov,
            merge_id=merged["merge_id"],
            body=VersionedWrite(expected_versions={"a": 1, "b": 2}),
            principal=CONTROL,
            now=ts(),
            request_id="undo",
        )
    assert error.value.code == "merge_changed"
    owner = env.ov.execute("SELECT owner FROM device_overrides WHERE device_id='b'").fetchone()[0]
    assert owner == "later"
    link = env.ov.execute("SELECT revoked_at FROM identity_links WHERE from_device='a'").fetchone()
    assert link[0] is None
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    assert not env.ov.in_transaction


def test_clear_stale_rolls_back_and_replay_does_not_replace_decision(env: Env) -> None:
    _merge_suggestion(env)
    env.inv.execute("UPDATE identity_candidates SET state='vetoed'")
    with pytest.raises(ApiError) as error:
        domain.clear_veto(
            env.inv,
            env.ov,
            candidate_id="candidate",
            principal=CONTROL,
            now=ts(),
            body=VersionedWrite(expected_versions={"a": 1, "b": 0}),
            request_id="stale",
        )
    assert error.value.code == "version_mismatch"
    _empty_writes(env)
    args = dict(
        candidate_id="candidate",
        principal=CONTROL,
        now=ts(),
        request_id="clear",
        body=VersionedWrite(expected_versions={"a": 0, "b": 0}),
    )
    result = domain.clear_veto(env.inv, env.ov, **args)
    first_id = env.ov.execute("SELECT id FROM candidate_decisions").fetchone()[0]
    assert domain.clear_veto(env.inv, env.ov, **args) == result
    assert env.ov.execute("SELECT id FROM candidate_decisions").fetchone()[0] == first_id
    assert env.ov.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    assert env.inv.execute("SELECT state FROM identity_candidates").fetchone()[0] == "vetoed"
