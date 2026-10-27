"""Every planner action, applied through the shipped SQL to a table built by the production
migrations: real CHECKs, real affected-row counts."""

from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

import pytest

from vigie_pipeline import delivery_sql as sql
from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    IncidentView,
    ReviewView,
    delivery_id,
    plan,
)
from vigie_pipeline.schema import open_pipeline_inventory

NOW = 1_000_000
CFG = DeliveryConfig()
RET = CFG.retention_seconds
DOCS = Path(__file__).resolve().parents[3] / "docs" / "monitoring.md"


def row(kind="open", state="pending", attempts=0, nxt=NOW - 5, created=NOW - 5, ver=0, iid="i1"):
    return DeliveryView(iid, kind, state, attempts, nxt, created, created, ver)


def inc(state="open"):
    return IncidentView("i1", state, NOW - 10)


@pytest.fixture
def conn(tmp_path):
    db = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    db.isolation_level = None
    return db


INSERT_ROW = (
    "INSERT INTO incident_deliveries (delivery_id, incident_id, kind, state, attempts,"
    " next_attempt_at, created_at, updated_at, version) VALUES (?,?,?,?,?,?,?,?,?)"
)
SELECT_ROWS = (
    "SELECT incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at, version"
    " FROM incident_deliveries"
)


def load(conn, rows):
    for d in rows:
        conn.execute(INSERT_ROW, (delivery_id(d.incident_id, d.kind), *dataclasses.astuple(d)))


def fetch(conn):
    return {(r[0], r[1]): DeliveryView(*r) for r in conn.execute(SELECT_ROWS)}


ACK = {"i1": ReviewView("acknowledged", None)}
SNOOZE = {"i1": ReviewView("snoozed", NOW + 100)}
OLD = NOW - RET - 1
SCENARIOS = {
    "Enqueue": ([inc()], {}, []),
    "Suppress insert": ([inc()], ACK, []),
    "Suppress update": ([inc()], ACK, [row(ver=2)]),
    "Reschedule": ([inc()], SNOOZE, [row(nxt=NOW)]),
    "Requeue": ([inc()], {}, [row(state="suppressed", ver=3)]),
    "Expire": ([inc("resolved")], {}, [row(attempts=1, ver=4)]),
    "Fail": ([inc()], {}, [row(state="suppressed", attempts=CFG.max_attempts)]),
    "Withdraw": ([inc()], {}, [row(state="sent"), row("recover", ver=1)]),
    "Revive": ([inc("resolved")], {}, [row(state="sent"), row("recover", "withdrawn", ver=2)]),  # noqa: E501
    "Expire sending": (
        [inc("resolved")],
        {},
        [row(state="sending", attempts=1, nxt=NOW - 1, ver=3)],
    ),
    "Fail sending": (
        [inc()],
        {},
        [row(state="sending", attempts=CFG.max_attempts, nxt=NOW - 1, ver=3)],
    ),
    "Fail pending": ([inc()], {}, [row(attempts=CFG.max_attempts, nxt=NOW + 9, ver=1)]),
    "Withdraw sending": (
        [inc()],
        {},
        [row(state="sent"), row("recover", "sending", attempts=1, nxt=NOW - 1, ver=2)],
    ),
    "Reclaim": ([inc()], {}, [row(state="sending", attempts=2, nxt=NOW - 1, ver=3)]),
    "Forget": ([inc("superseded")], {}, [row(state="sent", created=OLD), row("recover", "sent", created=OLD)]),  # noqa: E501
}  # fmt: skip


@pytest.mark.parametrize("name", SCENARIOS)
def test_every_action_applies_through_the_sql_in_one_transaction(conn, name):
    incidents, reviews, rows = SCENARIOS[name]
    load(conn, rows)
    before = fetch(conn)
    actions = plan(incidents, reviews, rows, NOW, CFG)
    assert actions and name.split()[0] in {type(a).__name__ for a in actions}
    conn.execute("BEGIN IMMEDIATE")
    for a in actions:
        statement, params = sql.statement(a, NOW)
        assert conn.execute(statement, params).rowcount == 1, a  # no CHECK is violated either
    conn.execute("COMMIT")
    after = fetch(conn)
    touched = {(a.incident_id, a.kind) for a in actions if a.expected is not None}
    for key in touched & after.keys():  # an UPDATE: versions only grow, updated_at is stamped
        old, new = before[key], after[key]
        assert new.version == old.version + 1 and new.updated_at == NOW, (old, new)
    for key in before.keys() - touched:
        assert after[key] == before[key]  # nothing else moves


@pytest.mark.parametrize("name", SCENARIOS)
def test_a_stale_action_affects_no_row(conn, name):
    incidents, reviews, rows = SCENARIOS[name]
    load(conn, rows)
    actions = plan(incidents, reviews, rows, NOW, CFG)
    conn.execute("UPDATE incident_deliveries SET version=version+100")
    for a in actions:
        statement, params = sql.statement(a, NOW)
        expected_count = 1 if a.expected is None else 0
        if a.expected is None and any(k[0] == a.incident_id for k in fetch(conn)):
            expected_count = 0  # INSERT OR IGNORE over an existing row
        assert conn.execute(statement, params).rowcount == expected_count, a


def test_a_pending_recover_blocks_the_forget_of_its_open_row(conn):
    incidents, reviews, rows = SCENARIOS["Forget"]
    load(conn, rows[:1])
    (forget,) = plan(incidents, reviews, rows[:1], NOW, CFG)
    load(conn, [row("recover", created=NOW - 5)])  # a recover shows up before the delete runs
    statement, params = sql.statement(forget, NOW)
    assert conn.execute(statement, params).rowcount == 0
    conn.execute("UPDATE incident_deliveries SET state='sending' WHERE kind='recover'")
    assert conn.execute(statement, params).rowcount == 0  # a recover in flight blocks it too
    conn.execute("UPDATE incident_deliveries SET state='expired' WHERE kind='recover'")
    assert conn.execute(statement, params).rowcount == 1


def test_the_revive_statement_keeps_the_budget_and_sets_a_valid_row(conn):
    load(conn, [row(state="sent"), row("recover", "withdrawn", attempts=2, nxt=NOW + 300, ver=2)])
    incidents, reviews, rows = SCENARIOS["Revive"]
    rows = list(fetch(conn).values())
    (revive,) = plan(incidents, reviews, rows, NOW, CFG)
    assert conn.execute(*sql.statement(revive, NOW)).rowcount == 1
    got = fetch(conn)[("i1", "recover")]
    assert (got.state, got.attempts, got.next_attempt_at, got.version) == (
        "pending",
        2,
        NOW + 300,
        3,
    )
    assert got.updated_at == NOW and got.created_at == NOW - 5


def test_claim_counts_the_attempt_and_takes_the_lease(conn):
    load(conn, [row(nxt=NOW - 1)])
    claim = sql.claim_params(row(nxt=NOW - 1), NOW, CFG)
    assert conn.execute(sql.CLAIM, claim).rowcount == 1
    got = fetch(conn)[("i1", "open")]
    assert (got.state, got.attempts, got.version) == ("sending", 1, 1)
    assert (got.next_attempt_at, got.updated_at) == (NOW + CFG.lease_seconds, NOW)
    assert conn.execute(sql.CLAIM, claim).rowcount == 0  # one live claim per delivery_id


def test_claim_refuses_a_row_that_is_not_due_stale_or_out_of_budget(conn):
    load(conn, [row(nxt=NOW + 5), row("recover", attempts=CFG.max_attempts, nxt=NOW - 1)])
    not_due = sql.claim_params(row(nxt=NOW + 5), NOW, CFG)
    assert conn.execute(sql.CLAIM, not_due).rowcount == 0
    spent = row("recover", attempts=CFG.max_attempts, nxt=NOW - 1)
    assert conn.execute(sql.CLAIM, sql.claim_params(spent, NOW, CFG)).rowcount == 0
    stale = dataclasses.replace(row(nxt=NOW + 5), version=9)
    assert conn.execute(sql.CLAIM, sql.claim_params(stale, NOW + 10, CFG)).rowcount == 0


@pytest.mark.parametrize("kind", ["open", "recover"])
def test_completion_is_one_version_checked_rule_for_both_kinds(conn, kind):
    load(conn, [row(kind, nxt=NOW - 1)])
    conn.execute(sql.CLAIM, sql.claim_params(row(kind, nxt=NOW - 1), NOW, CFG))
    claimed = fetch(conn)[("i1", kind)]
    stale = dataclasses.replace(claimed, version=claimed.version - 1)
    for statement in (sql.COMPLETE_SENT, sql.COMPLETE_RETRY, sql.COMPLETE_FAILED):
        extra = {"next_attempt_at": NOW + 60}
        assert conn.execute(statement, sql.completion_params(stale, NOW + 1) | extra).rowcount == 0
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 1)).rowcount == 1
    done = fetch(conn)[("i1", kind)]
    assert (done.state, done.attempts, done.version) == ("sent", 1, 2)
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 2)).rowcount == 0


def test_a_failed_send_goes_back_to_pending_or_fails(conn):
    load(conn, [row(nxt=NOW - 1), row("recover", nxt=NOW - 1)])
    for kind in ("open", "recover"):
        conn.execute(sql.CLAIM, sql.claim_params(row(kind, nxt=NOW - 1), NOW, CFG))
    claimed = fetch(conn)
    retry = sql.completion_params(claimed[("i1", "open")], NOW + 1) | {"next_attempt_at": NOW + 61}
    assert conn.execute(sql.COMPLETE_RETRY, retry).rowcount == 1
    got = fetch(conn)[("i1", "open")]
    assert (got.state, got.attempts, got.next_attempt_at) == ("pending", 1, NOW + 61)
    failed = sql.completion_params(claimed[("i1", "recover")], NOW + 1)
    assert conn.execute(sql.COMPLETE_FAILED, failed).rowcount == 1
    assert fetch(conn)[("i1", "recover")].state == "failed"


def test_every_update_stamps_updated_at_and_bumps_the_version():
    for statement in sql.ALL_SQL:
        if statement.lstrip().startswith("UPDATE"):
            assert "updated_at=:now" in statement and "version=version+1" in statement, statement


def test_the_docs_quote_every_statement_verbatim():
    text = DOCS.read_text()
    start = text.index("### Incident delivery (planned)")
    section = " ".join(text[start : text.index("## Retention and verification limits")].split())
    for statement in sql.ALL_SQL:
        assert " ".join(statement.split()) in section, statement
    assert isinstance(sqlite3.sqlite_version, str)


def test_a_new_row_starts_at_the_epoch_second_so_versions_never_repeat(conn):
    from vigie_pipeline.delivery_plan import Enqueue, Suppress

    for action in (Enqueue("i1", "open", NOW), Suppress("i1", "recover", "acknowledged")):
        assert conn.execute(*sql.statement(action, NOW)).rowcount == 1
    assert {d.version for d in fetch(conn).values()} == {NOW}
    claim = sql.claim_params(fetch(conn)[("i1", "open")], NOW, CFG)
    assert conn.execute(sql.CLAIM, claim).rowcount == 1
    assert fetch(conn)[("i1", "open")].version == NOW + 1


def test_failure_statements_apply_to_a_claimed_row(conn):
    load(conn, [row(nxt=NOW - 1)])
    conn.execute(sql.CLAIM, sql.claim_params(row(nxt=NOW - 1), NOW, CFG))
    claimed = fetch(conn)[("i1", "open")]
    statement, params = sql.failure_statement(claimed, NOW + 1, CFG)
    assert statement == sql.COMPLETE_RETRY and conn.execute(statement, params).rowcount == 1
    assert fetch(conn)[("i1", "open")].next_attempt_at == NOW + 1 + 60
