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
    Enqueue,
    IncidentView,
    ReviewView,
    Suppress,
    delivery_id,
    plan,
)
from vigie_pipeline.schema import open_pipeline_inventory

NOW = 100_000_000
CFG = DeliveryConfig()
RET = CFG.retention_seconds
DOCS = Path(__file__).resolve().parents[3] / "docs" / "monitoring.md"


def row(kind="open", state="pending", attempts=0, nxt=NOW - 5, created=NOW - 5, ver=0, iid="i1"):
    row_id = 1 if kind == "open" else 2  # explicit ids, so the params built from a row match
    return DeliveryView(iid, kind, state, attempts, nxt, created, created, ver, row_id)


def inc(state="open"):
    return IncidentView("i1", state, NOW - 10)


@pytest.fixture
def conn(tmp_path):
    db = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    db.isolation_level = None
    return db


INSERT_ROW = (
    "INSERT INTO incident_deliveries (row_id, delivery_id, incident_id, kind, state, attempts,"
    " next_attempt_at, created_at, updated_at, version) VALUES (?,?,?,?,?,?,?,?,?,?)"
)
SELECT_ROWS = (
    "SELECT incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at, version,"
    " row_id FROM incident_deliveries"
)


def load(conn, rows):
    for d in rows:
        values = dataclasses.astuple(d)
        conn.execute(INSERT_ROW, (d.row_id, delivery_id(d.incident_id, d.kind), *values[:-1]))


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
    "Suppress sending": (
        [inc()],
        ACK,
        [row(state="sending", attempts=1, nxt=NOW - 1, ver=3)],
    ),
    "Reclaim snoozed": (
        [inc()],
        {"i1": ReviewView("snoozed", NOW + 10_000)},
        [row(state="sending", attempts=1, nxt=NOW - 1, ver=3)],
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


def test_failure_statements_apply_to_a_claimed_row(conn):
    load(conn, [row(nxt=NOW - 1)])
    conn.execute(sql.CLAIM, sql.claim_params(row(nxt=NOW - 1), NOW, CFG))
    claimed = fetch(conn)[("i1", "open")]
    statement, params = sql.failure_statement(claimed, NOW + 1, CFG)
    assert statement == sql.COMPLETE_RETRY and conn.execute(statement, params).rowcount == 1
    assert fetch(conn)[("i1", "open")].next_attempt_at == NOW + 1 + 60


def test_a_lapsed_open_meets_the_current_decision_through_real_sql(conn):
    load(conn, [row(state="sending", attempts=1, nxt=NOW - 1, ver=3)])
    snoozed = {"i1": ReviewView("snoozed", NOW + 10_000)}
    (reclaim,) = plan([inc()], snoozed, list(fetch(conn).values()), NOW, CFG)
    assert reclaim.next_attempt_at == NOW + 10_000  # not before the snooze ends
    assert conn.execute(*sql.statement(reclaim, NOW)).rowcount == 1
    back = fetch(conn)[("i1", "open")]
    assert (back.state, back.attempts) == ("pending", 1)
    claim = sql.claim_params(back, NOW + 1000, CFG)
    assert conn.execute(sql.CLAIM, claim).rowcount == 0  # still snoozed: not claimable


def test_every_statement_binds_integers_even_for_a_fractional_clock(conn):
    now = NOW + 0.5
    for name, (incidents, reviews, rows) in SCENARIOS.items():
        conn.execute("DELETE FROM incident_deliveries")
        load(conn, rows)
        actions = plan(incidents, reviews, rows, now, CFG)
        for a in actions:
            statement, params = sql.statement(a, now)
            assert all(not isinstance(v, float) for v in params.values()), (name, params)
            assert conn.execute(statement, params).rowcount == 1, (name, a)
    conn.execute("DELETE FROM incident_deliveries")
    load(conn, [row(nxt=NOW - 1)])
    claimed_row = fetch(conn)[("i1", "open")]
    assert conn.execute(sql.CLAIM, sql.claim_params(claimed_row, now, CFG)).rowcount == 1
    claimed = fetch(conn)[("i1", "open")]
    statement, params = sql.failure_statement(claimed, now, CFG)
    assert all(not isinstance(v, float) for v in params.values())
    assert conn.execute(statement, params).rowcount == 1


def test_a_new_row_starts_at_version_zero_with_a_fresh_row_id(conn):
    for action in (Enqueue("i1", "open", NOW), Suppress("i1", "recover", "acknowledged")):
        assert conn.execute(*sql.statement(action, NOW)).rowcount == 1
    rows = fetch(conn)
    assert {d.version for d in rows.values()} == {0}
    assert rows[("i1", "open")].row_id != rows[("i1", "recover")].row_id


def test_row_ids_are_never_reused_after_a_delete(conn):
    """AUTOINCREMENT is the incarnation token: Forget then recreate gets a larger id."""
    ddl = conn.execute("SELECT sql FROM sqlite_master WHERE name='incident_deliveries'").fetchone()
    assert "AUTOINCREMENT" in ddl[0].upper()
    seen = []
    for round_ in range(5):
        conn.execute(*sql.statement(Enqueue("i1", "open", NOW + round_), NOW + round_))
        seen.append(fetch(conn)[("i1", "open")].row_id)
        conn.execute("DELETE FROM incident_deliveries")  # a Forget
    assert seen == sorted(set(seen)) and len(seen) == 5


def test_a_completion_needs_the_claimed_row_id(conn):
    load(conn, [row(nxt=NOW - 1)])
    conn.execute(sql.CLAIM, sql.claim_params(row(nxt=NOW - 1), NOW, CFG))
    claimed = fetch(conn)[("i1", "open")]
    other = dataclasses.replace(claimed, row_id=claimed.row_id + 1)  # another incarnation
    for statement in (sql.COMPLETE_SENT, sql.COMPLETE_RETRY, sql.COMPLETE_FAILED):
        params = sql.completion_params(other, NOW + 1) | {"next_attempt_at": NOW + 60}
        assert conn.execute(statement, params).rowcount == 0
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 1)).rowcount == 1


def _create_claim_and_forget(conn, at, cfg):
    """Create a delivery at `at`, claim it, and return the claim token; the row is then gone."""
    conn.execute(*sql.statement(Enqueue("i1", "open", at), at))
    conn.execute(sql.CLAIM, sql.claim_params(fetch(conn)[("i1", "open")], at, cfg))
    return fetch(conn)[("i1", "open")]


def test_a_clock_rolled_back_cannot_let_an_old_claim_complete_a_new_one(conn):
    """Codex's trace: create+claim at t, expire at t+60, forget at t+121, the clock rolls back to
    t, the delivery is recreated and claimed: the old completion must find nothing to match."""
    cfg = DeliveryConfig(retention_seconds=60, lease_seconds=60)
    old = _create_claim_and_forget(conn, NOW, cfg)
    conn.execute("UPDATE incident_deliveries SET state='expired', version=version+1")  # t+60
    conn.execute("DELETE FROM incident_deliveries")  # forgotten at t+121
    again = _create_claim_and_forget(conn, NOW, cfg)  # the clock is back at t
    assert (again.version, again.created_at) == (old.version, old.created_at)  # all else equal
    assert again.row_id != old.row_id
    statement, params = sql.failure_statement(dataclasses.replace(old, attempts=9), NOW + 1, cfg)
    assert conn.execute(statement, params).rowcount == 0
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(old, NOW + 1)).rowcount == 0
    assert fetch(conn)[("i1", "open")] == again


def test_codexs_same_second_reschedules_cannot_collide_with_a_recreated_row(conn):
    cfg = DeliveryConfig(retention_seconds=60, lease_seconds=60)
    tokens = []
    for _ in range(2):  # the same walk twice: 62 same-second updates, then a claim
        conn.execute(*sql.statement(Enqueue("i1", "open", NOW), NOW))
        conn.execute("UPDATE incident_deliveries SET version=version+62")
        conn.execute(sql.CLAIM, sql.claim_params(fetch(conn)[("i1", "open")], NOW, cfg))
        tokens.append(fetch(conn)[("i1", "open")])
        if len(tokens) == 1:
            conn.execute("DELETE FROM incident_deliveries")  # forgotten, then recreated
    old, new = tokens
    assert new.version == old.version and new.row_id != old.row_id  # versions may collide
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(old, NOW + 1)).rowcount == 0
    assert fetch(conn)[("i1", "open")] == new


def test_a_row_updated_thousands_of_times_still_transitions(conn):
    """No version ceiling: 5000 ack/clear/reschedule cycles, then the row still claims and ends."""
    conn.execute(*sql.statement(Enqueue("i1", "open", NOW), NOW))
    for k in range(5000):
        current = fetch(conn)[("i1", "open")]
        state, update = ("pending", sql.RESCHEDULE_UPDATE)
        params = {"row_id": current.row_id, "state": state, "attempts": 0, "now": NOW}
        params |= {"version": current.version, "next_attempt_at": NOW - 1}
        assert conn.execute(update, params).rowcount == 1, k
    current = fetch(conn)[("i1", "open")]
    assert current.version == 5000
    assert conn.execute(sql.CLAIM, sql.claim_params(current, NOW, CFG)).rowcount == 1
    claimed = fetch(conn)[("i1", "open")]
    assert conn.execute(sql.COMPLETE_SENT, sql.completion_params(claimed, NOW + 1)).rowcount == 1


@pytest.mark.parametrize("before,wait", [(0, 60), (3, 480)])
def test_a_lapsed_claim_suppressed_then_requeued_keeps_its_retry_backoff(conn, before, wait):
    """Codex: a normal Reclaim waits out the backoff; ack then clear must not skip it."""
    conn.execute(*sql.statement(Enqueue("i1", "open", NOW), NOW))
    conn.execute("UPDATE incident_deliveries SET attempts=?, next_attempt_at=?", (before, NOW))
    pending = fetch(conn)[("i1", "open")]
    assert conn.execute(sql.CLAIM, sql.claim_params(pending, NOW, CFG)).rowcount == 1
    t = NOW + CFG.lease_seconds  # the lease lapses with `before + 1` attempts counted
    for review in (ACK, {}):
        rows = list(fetch(conn).values())
        (action,) = plan([inc()], review, rows, t, CFG)
        assert conn.execute(*sql.statement(action, t)).rowcount == 1
    back = fetch(conn)[("i1", "open")]
    assert (back.state, back.attempts, back.next_attempt_at) == ("pending", before + 1, t + wait)
    assert conn.execute(sql.CLAIM, sql.claim_params(back, t, CFG)).rowcount == 0
    assert conn.execute(sql.CLAIM, sql.claim_params(back, t + wait - 1, CFG)).rowcount == 0
    assert conn.execute(sql.CLAIM, sql.claim_params(back, t + wait, CFG)).rowcount == 1


def test_a_failed_pass_names_the_delivery_and_row_to_look_at(conn):
    load(conn, [row(state="sent", ver=4)])
    stale = plan([inc("resolved")], {}, list(fetch(conn).values()), NOW, CFG)
    conn.execute("UPDATE incident_deliveries SET version=version+1")  # moved under the plan
    (recover,) = [a for a in stale if a.kind == "recover"]
    conn.execute("BEGIN IMMEDIATE")
    with pytest.raises(sql.PassError) as caught:
        sql.apply_actions(conn, [Enqueue("i1", "open", NOW), recover], NOW)
    conn.execute("ROLLBACK")
    message = str(caught.value)
    assert "Enqueue affected 0 rows" in message
    assert f"delivery_id={delivery_id('i1', 'open')}" in message and "row_id=" in message
    assert fetch(conn)[("i1", "open")].version == 5  # nothing else changed


def test_a_fractional_failure_time_does_not_let_the_pull_in_shorten_the_backoff(conn):
    """Codex: a failure at 1000.1 scheduled 1061, but updated_at was truncated to 1000, so planning
    at 1000.2 rebuilt 1060 and a claim succeeded early. One rounded-up integer now does both."""
    base = NOW  # 100_000_000
    conn.execute(*sql.statement(Enqueue("i1", "open", base), base))
    conn.execute(sql.CLAIM, sql.claim_params(fetch(conn)[("i1", "open")], base, CFG))
    claimed = fetch(conn)[("i1", "open")]
    statement, params = sql.failure_statement(claimed, base + 0.1, CFG)
    assert conn.execute(statement, params).rowcount == 1
    row = fetch(conn)[("i1", "open")]
    assert (row.updated_at, row.next_attempt_at) == (base + 1, base + 61)  # the same rounded now
    assert plan([inc()], {}, [row], base + 0.2, CFG) == ()  # nothing moves it earlier
    assert conn.execute(sql.CLAIM, sql.claim_params(row, base + 60, CFG)).rowcount == 0
    assert conn.execute(sql.CLAIM, sql.claim_params(row, base + 61, CFG)).rowcount == 1


def test_planning_never_shortens_a_retry_deadline_whatever_the_fractions(conn):
    for attempts in (1, 2, 3, 5):
        for failed_at in (0.0, 0.1, 0.5, 0.9, 0.999):
            conn.execute("DELETE FROM incident_deliveries")
            conn.execute(*sql.statement(Enqueue("i1", "open", NOW), NOW))
            conn.execute("UPDATE incident_deliveries SET attempts=?", (attempts - 1,))
            row = fetch(conn)[("i1", "open")]
            conn.execute(sql.CLAIM, sql.claim_params(row, NOW, CFG))
            claimed = fetch(conn)[("i1", "open")]
            conn.execute(*sql.failure_statement(claimed, NOW + failed_at, CFG))
            stored = fetch(conn)[("i1", "open")]
            for step in (0.0, 0.2, 0.7, 1.0, 1.9, 5.0):
                later = NOW + failed_at + step
                actions = plan([inc()], {}, [stored], later, CFG)
                assert all(
                    getattr(a, "next_attempt_at", stored.next_attempt_at) >= stored.next_attempt_at
                    for a in actions
                ), (attempts, failed_at, step, actions)


@pytest.mark.parametrize(
    "offset,claims", [(-1.0, 0), (-0.1, 0), (-1e-9, 0), (0, 1), (0.1, 1), (0.999, 1)]
)
def test_claim_is_never_early_and_works_at_the_stored_deadline(conn, offset, claims):
    deadline = 1061  # small numbers keep 1e-9 representable
    stored = row(nxt=deadline, created=900)
    load(conn, [stored])
    params = sql.claim_params(stored, deadline + offset, CFG)
    assert params["due_now"] == deadline + (-1 if offset < 0 else 0)  # compare with floor
    assert conn.execute(sql.CLAIM, params).rowcount == claims
    if claims:  # stamped with ceil: the lease end never promises early
        assert fetch(conn)[("i1", "open")].next_attempt_at == params["now"] + CFG.lease_seconds


def test_stamp_with_ceil_compare_with_floor():
    assert (sql.tick_ceil(1060.1), sql.tick_floor(1060.1)) == (1061, 1060)
    assert (sql.tick_ceil(1060.0), sql.tick_floor(1060.0)) == (1060, 1060)
