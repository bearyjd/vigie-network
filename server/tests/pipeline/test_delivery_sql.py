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


def test_the_sender_statements(conn):
    load(conn, [row(), row("recover", attempts=1, ver=5)])
    opened, recover = (row(), row("recover", attempts=1, ver=5))
    stale = dataclasses.replace(opened, version=99)

    # an open completion ignores the version; a recover completion does not
    def run(statement, d, **extra):
        return conn.execute(statement, sql.sender_params(d, NOW) | extra).rowcount

    assert run(sql.SENDER_SENT, dataclasses.replace(recover, version=1)) == 0
    assert run(sql.SENDER_SENT, dataclasses.replace(recover, attempts=0)) == 0
    assert run(sql.SENDER_SENT, recover) == 1
    assert run(sql.SENDER_SENT, recover) == 0  # no longer pending
    assert run(sql.SENDER_SENT, stale) == 1
    got = fetch(conn)
    assert (got[("i1", "open")].state, got[("i1", "open")].attempts) == ("sent", 1)
    assert got[("i1", "recover")].version == 6 and got[("i1", "recover")].updated_at == NOW


def test_an_acknowledged_open_is_still_recorded_as_sent(conn):
    load(conn, [row(state="suppressed")])
    assert conn.execute(sql.SENDER_SENT, sql.sender_params(row(), NOW)).rowcount == 1
    assert fetch(conn)[("i1", "open")].state == "sent"


def test_a_failed_send_retries_or_gives_up_only_while_pending(conn):
    load(conn, [row(), row("recover", ver=1)])
    retry = sql.SENDER_RETRY
    assert (
        conn.execute(retry, sql.sender_params(row(), NOW) | {"next_attempt_at": NOW + 60}).rowcount
        == 1
    )
    got = fetch(conn)[("i1", "open")]
    assert (got.attempts, got.next_attempt_at, got.state) == (1, NOW + 60, "pending")
    assert (
        conn.execute(sql.SENDER_GIVE_UP, sql.sender_params(row("recover", ver=1), NOW)).rowcount
        == 1
    )
    assert fetch(conn)[("i1", "recover")].state == "failed"
    assert (
        conn.execute(sql.SENDER_GIVE_UP, sql.sender_params(row("recover", ver=1), NOW)).rowcount
        == 0
    )


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
