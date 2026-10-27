"""A real-SQLite applier and a seeded, adversarial world simulator for the delivery tests."""

from __future__ import annotations

import dataclasses
import math
import random
import sqlite3
from typing import NamedTuple

from vigie_pipeline import delivery_sql as sql
from vigie_pipeline import schema
from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    Forget,
    IncidentView,
    Reclaim,
    Requeue,
    ReviewView,
    Revive,
    Suppress,
    Withdraw,
    backoff,
    delivery_id,
    may_transmit,
    plan,
)

DAY = 86400
QUIET = ("acknowledged", "expected")
ALLOWED = {
    "pending": {"pending", "sending", "suppressed", "expired", "withdrawn"},
    "sending": {"sending", "sent", "pending", "failed", "expired", "withdrawn", "suppressed"},
    "withdrawn": {"withdrawn", "pending", "expired", "failed"},
    "suppressed": {"suppressed", "pending", "failed", "expired"},
    "sent": {"sent"},
    "failed": {"failed"},
    "expired": {"expired"},
}
TIGHT = DeliveryConfig(max_attempts=2, pending_ttl_seconds=900, retention_seconds=2000)
EDGE = DeliveryConfig(
    max_attempts=1,
    pending_ttl_seconds=60,
    retention_seconds=61,
    backoff_base_seconds=60,
    backoff_cap_seconds=60,
)


class Tx:
    """One transmission: when it ends, and whether it is a deadline violation (a hung send)."""

    def __init__(self, end):
        self.end, self.hung = end, False


class Token(NamedTuple):
    """What a sender holds after CLAIM: the claimed row, the outcome, the row's life, its send."""

    claimed: DeliveryView
    success: bool
    life: int
    tx: Tx | None = None


class PassAborted(AssertionError):
    """An action did not affect exactly one row: the whole pass was rolled back."""


COLUMNS = (
    "incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at, version, row_id"
)


class Store:
    """The production `incident_deliveries` table (migration 11) in an in-memory SQLite."""

    def __init__(self, rows=()):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        for statement in schema.PIPELINE_MIGRATIONS[10]:
            self.conn.execute(statement)
        self._cache = None
        for d in rows:
            self.add(d)

    def add(self, d):
        marks = ",".join("?" * 10)
        values = dataclasses.astuple(d)[:-1] + (d.row_id or None,)  # row_id 0: let SQLite assign
        self.conn.execute(
            f"INSERT INTO incident_deliveries (delivery_id, {COLUMNS}) VALUES ({marks})",  # noqa: S608
            (delivery_id(d.incident_id, d.kind), *values),
        )
        self._cache = None

    def rows(self):
        if self._cache is None:
            found = self.conn.execute(f"SELECT {COLUMNS} FROM incident_deliveries")  # noqa: S608
            views = [DeliveryView(*r) for r in found]
            self._cache = {(d.incident_id, d.kind): d for d in views}
        return self._cache

    def run(self, statement, params):
        self._cache = None
        return self.conn.execute(statement, params).rowcount

    def apply_pass(self, actions, now, retention=None):
        """One transaction; any action that does not affect exactly one row rolls it all back."""
        before = self.rows()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for a in actions:
                old = before.get((a.incident_id, a.kind))
                if isinstance(a, Forget) and retention is not None:
                    assert now - old.updated_at > retention, ("forgotten early", a, old)
                self._cache = None
                sql.apply_actions(self.conn, [a], now)
        except BaseException as error:
            self.conn.execute("ROLLBACK")
            self._cache = None
            if isinstance(error, sql.PassError):
                raise PassAborted(str(error)) from error
            raise
        self.conn.execute("COMMIT")


def apply_cas(rows, actions, now, retention=None, strict=False):
    """Apply actions through the real SQL. Lenient: skip the ones that miss (stale) and report
    them. Strict: the whole pass is atomic and a miss raises PassAborted."""
    store = Store(rows.values() if isinstance(rows, dict) else rows)
    skipped = []
    if strict:
        store.apply_pass(actions, now, retention)
    else:
        for a in actions:
            if store.run(*sql.statement(a, now)) != 1:
                skipped.append(a)
    return store.rows(), skipped


def check_transitions(before, after):
    for key in before.keys() | after.keys():
        b, a = before.get(key), after.get(key)
        if b is None:
            assert a is None or a.state in ("pending", "suppressed"), (key, a)
        elif a is not None:
            assert a.created_at == b.created_at, (b, a)
            claimed = b.state == "pending" and a.state == "sending"
            assert a.attempts == b.attempts + (1 if claimed else 0), (
                "attempts move at claim",
                b,
                a,
            )
            assert a.version >= b.version and a.state in ALLOWED[b.state], (b, a)
            assert a.version > b.version or a == b, ("change without a version bump", b, a)


class World:
    """Incidents, human decisions, a sender and the planner, driven by a seeded RNG."""

    def __init__(self, seed: int, cfg: DeliveryConfig | None = None):
        self.rnd = random.Random(seed)  # noqa: S311 - deterministic test data
        self.cfg = cfg or DeliveryConfig()
        self.now, self.since, self.next_id = 100_000_000, None, 0
        self.inc, self.reviews, self.store = {}, {}, Store()
        self.opened, self.owed_at, self.inflight, self.zombies = set(), {}, {}, []
        self.life, self.sends, self.violations = {}, {}, {}
        self.transmissions, self.successes, self.crashes = {}, {}, {}
        self.seen = set()

    @property
    def rows(self):
        return self.store.rows()

    def views(self):
        return tuple(
            IncidentView(i, s["state"], s["detected"]) for i, s in self.inc.items() if s["present"]
        )

    def _cfg(self):
        return dataclasses.replace(self.cfg, eligible_since=self.since)

    def plan(self):
        return plan(self.views(), self.reviews, tuple(self.rows.values()), self.now, self._cfg())

    # ---- events -------------------------------------------------------------------------
    def ev_new(self):
        self.next_id += 1
        detected = math.ceil(self.now) - self.rnd.randint(0, 3600)
        self.inc[f"i{self.next_id}"] = {"state": "open", "detected": detected, "present": True}

    def ev_transition(self):
        if not self.inc:
            return
        s = self.inc[self.rnd.choice(sorted(self.inc))]
        if not s["present"]:
            s["present"] = True
        elif s["state"] == "open":
            if self.rnd.random() < 0.25:
                s["present"] = False
            else:
                s["state"] = self.rnd.choice(["resolved", "resolved", "superseded"])
        elif s["state"] == "resolved" and self.rnd.random() < 0.3:
            s["state"] = "superseded"
        elif self.rnd.random() < 0.5:
            s["state"] = "open"  # reopened
        else:
            s["present"] = False

    def ev_flap(self):
        """The detector flaps: reopen an incident whose recover is still waiting to be sent."""
        for (iid, kind), d in sorted(self.rows.items()):
            s = self.inc[iid]
            if kind == "recover" and d.state in ("pending", "withdrawn") and s["present"]:
                s["state"] = "open" if s["state"] == "resolved" else "resolved"
                return

    def ev_decision(self):
        if not self.inc:
            return
        iid = self.rnd.choice(sorted(self.inc))
        pick = self.rnd.choice(["clear", "ack", "expected", "snooze", "short", "null", "bogus"])
        half = self.rnd.choice([0, 0.5])
        views = {
            "ack": ReviewView("acknowledged", None),
            "expected": ReviewView("expected", None),
            "snooze": ReviewView("snoozed", self.now + self.rnd.randint(1, 5000) + half),
            "short": ReviewView("snoozed", self.now + self.rnd.randint(1, 20) + half),
            "null": ReviewView(None, None),
            "bogus": ReviewView("weird", None),
        }
        if pick == "clear":
            self.reviews.pop(iid, None)
        else:
            self.reviews[iid] = views[pick]

    def ev_watermark(self):
        self.since = self.rnd.choice([None, None, self.now - 3600, self.now + 60, 0])

    def ev_time(self):
        ttl, ret = self.cfg.pending_ttl_seconds, self.cfg.retention_seconds
        steps = [0, 1, 59, 60, ttl - 1, ttl, ttl + 1, ret - 1, ret, ret + 1, DAY]
        self._advance(self.rnd.choice(steps) + self.rnd.choice([0, 0, 0.5, 0.999]))

    def ev_clock_back(self):
        """The wall clock steps backwards. Nothing may break: time-based rules just wait, and a
        row's incarnation never depends on the clock. Finished sends stay finished."""
        self.now -= self.rnd.choice([1, 59, 3600, DAY])
        for sends in self.sends.values():
            for tx in sends:
                if not tx.hung:
                    tx.end = min(tx.end, self.now)

    def _advance(self, delta):
        """Time passes. A contract-abiding sender records its result before its lease lapses, so
        it does so before the clock crosses the lease end (crash and violation are explicit
        events, never inferred)."""
        for key in sorted(self.inflight):
            if self.inflight[key].claimed.next_attempt_at <= self.now + delta:
                self._finish(key, self.inflight.pop(key))
        self.now += delta

    def ev_sender(self):
        """Claim, transmit and record in one step (a fast send)."""
        for key, d in sorted(self.rows.items()):
            if key not in self.inflight and self._due(key, d) and self.rnd.random() > 0.3:
                self._finish(key, self._claim(key, d))

    def _due(self, key, d):
        if d.state != "pending" or d.next_attempt_at > self.now:
            return False
        if key[1] == "recover":  # a recover is only ever sent for an announced open
            opened = self.rows.get((key[0], "open"))
            assert opened is not None and opened.state == "sent", ("recover w/o open", key)
        return True

    def _claim(self, key, d, success=None):
        """CLAIM (short transaction), then transmit outside any transaction. Every transmission
        is counted independently of the persisted attempts."""
        self._probe_claim_guards(d)
        count = self.store.run(sql.CLAIM, sql.claim_params(d, self.now, self.cfg))
        assert count == 1, ("a due pending row must be claimable", key, d)
        claimed, life = self.rows[key], self.life.get(key, 0)
        lease_end = math.ceil(self.now) + self.cfg.lease_seconds  # independent oracle for CLAIM
        assert (claimed.state, claimed.next_attempt_at) == ("sending", lease_end), claimed
        assert claimed.attempts == d.attempts + 1 and claimed.version == d.version + 1, claimed
        late = self.rnd.choice([0, 0, 0, self.cfg.transmit_deadline_seconds])  # a stalled sender
        allowed = may_transmit(claimed.updated_at, self.now + late, self.cfg)
        elapsed = self.now + late - claimed.updated_at  # updated_at is the rounded-up claim time
        assert allowed == (elapsed < self.cfg.transmit_deadline_seconds), ("may_transmit", late)
        if not allowed:
            self._observe()
            return Token(claimed, False, life)  # aborts without transmitting
        # the sender contract (hard timeout) keeps a transmission inside the deadline
        self.check_overlap(key)
        tx = Tx(self.now + self.rnd.randint(1, self.cfg.transmit_deadline_seconds - 1))
        self.sends.setdefault(key, []).append(tx)
        self.transmissions[key] = self.transmissions.get(key, 0) + 1
        assert self.transmissions[key] <= self.cfg.max_attempts, ("transmissions", key)
        success = self.rnd.random() < 0.6 if success is None else success
        if success:
            self.successes[key] = self.successes.get(key, 0) + 1
            # a second delivery needs an explicit crash or deadline violation first
            allowed = 1 + self.crashes.get(key, 0) + self.violations.get(key, 0)
            assert self.successes[key] <= allowed, ("delivered twice", key)
        self._observe()
        return Token(claimed, success, life, tx)

    def check_overlap(self, key):
        """A new transmission may only overlap a send that is individually a deadline violation."""
        live = [t for t in self.sends.get(key, []) if t.end > self.now]
        assert all(t.hung for t in live), ("two transmissions overlap", key, live)

    def ev_claim(self):
        for key, d in sorted(self.rows.items()):
            if key not in self.inflight and self._due(key, d) and self.rnd.random() < 0.5:
                self.inflight[key] = self._claim(key, d)

    def ev_overtake(self):
        """An ack lands while an open is in flight and is cleared again before the next send."""
        keys = [k for k in sorted(self.inflight) if k[1] == "open" and self.inc[k[0]]["present"]]
        if not keys:
            return
        key = self.rnd.choice(keys)
        was = self.reviews.get(key[0])
        self.reviews[key[0]] = ReviewView("acknowledged", None)
        self.ev_pass()
        if key in self.inflight:
            self._finish(key, self.inflight.pop(key))
        self.reviews.pop(key[0]) if was is None else self.reviews.update({key[0]: was})
        self.ev_pass()
        self.ev_sender()

    def ev_complete(self):
        for key in sorted(self.inflight):
            if self.rnd.random() < 0.6:
                self._finish(key, self.inflight.pop(key))

    def ev_crash(self):
        """The sender dies between transmitting and recording the result."""
        if self.inflight:
            self._crash(self.rnd.choice(sorted(self.inflight)))

    def _crash(self, key):
        token = self.inflight.pop(key)
        if token.tx is not None:
            token.tx.end = min(token.tx.end, self.now)  # a dead sender stops sending
        if token.success:
            self.crashes[key] = self.crashes.get(key, 0) + 1

    def ev_violate(self):
        """The sender violates its transmit deadline: it hangs, its send may still be going out
        when the lease lapses, and it records the result late."""
        if self.inflight:
            self._violate(self.rnd.choice(sorted(self.inflight)))

    def _violate(self, key):
        token = self.inflight.pop(key)
        if token.tx is not None:
            token.tx.hung, token.tx.end = True, self.now + 10 * self.cfg.lease_seconds
        self.zombies.append(token)
        if token.success:
            self.violations[key] = self.violations.get(key, 0) + 1

    def _fire(self, token):
        """A late completion carries its own claim token: it lands only on that incarnation."""
        key = (token.claimed.incident_id, token.claimed.kind)
        row = self.rows.get(key)
        same = (
            row is not None
            and self.life.get(key, 0) == token.life
            and row.state == "sending"
            and row.version == token.claimed.version
        )
        self._finish(key, token, expect=1 if same else 0)
        if token.tx is not None:
            token.tx.end = min(token.tx.end, self.now)  # the hung sender is done: exemption over

    def ev_zombie(self):
        if self.zombies:
            self._fire(self.zombies.pop(self.rnd.randrange(len(self.zombies))))

    def ev_zombie_race(self):
        """A hung sender's lease lapses, the row is reclaimed and claimed again, and only then
        does the hung sender record its result: it must not land on the new claim."""
        for key, d in sorted(self.rows.items()):
            if key in self.inflight or not self._due(key, d):
                continue
            self.inflight[key] = self._claim(key, d)
            self._violate(key)
            self._advance(self.cfg.lease_seconds + 1)
            self.ev_pass()  # Reclaim, or a cancellation
            row = self.rows.get(key)
            if row is not None and row.state == "pending":
                self._advance(max(0, row.next_attempt_at - self.now))
                self.ev_pass()
                row = self.rows.get(key)
                if row is not None and self._due(key, row) and key not in self.inflight:
                    self.inflight[key] = self._claim(key, row)
            self._fire(self.zombies.pop())
            return

    def ev_recreate_race(self):
        """A hung sender's row is cancelled, forgotten and created afresh; its late completion
        carries a version the new row must never share."""
        for iid, s in sorted(self.inc.items()):
            key = (iid, "open")
            row = self.rows.get(key)
            if not (s["present"] and s["state"] == "open" and row and key not in self.inflight):
                continue
            if not self._due(key, row):
                continue
            self.inflight[key] = self._claim(key, row)
            self._violate(key)
            self._advance(self.cfg.lease_seconds + 1)
            s["state"] = "resolved"
            self.ev_pass()  # the lapsed claim is cancelled
            self._advance(self.cfg.retention_seconds + 1)
            self.ev_pass()  # and forgotten
            s["state"], _ = "open", self.reviews.pop(iid, None)
            self.ev_pass()  # a new row, a new life
            fresh = self.rows.get(key)
            if fresh is not None and self._due(key, fresh) and key not in self.inflight:
                self.inflight[key] = self._claim(key, fresh)
            self._fire(self.zombies.pop())
            return

    def ev_park_and_clear(self):
        """A claim lapses while its incident is snoozed, so the row is parked at the snooze end;
        then the snooze is cleared and the row must come back to its backoff-based due time."""
        for iid, s in sorted(self.inc.items()):
            key, row = (iid, "open"), self.rows.get((iid, "open"))
            if not (s["present"] and s["state"] == "open" and row and key not in self.inflight):
                continue
            if not self._due(key, row):
                continue
            self.inflight[key] = self._claim(key, row)
            self._crash(key)
            self.reviews[iid] = ReviewView("snoozed", self.now + 7 * DAY)
            self._advance(self.cfg.lease_seconds + 1)
            self.ev_pass()  # the lapsed claim is parked at the snooze end
            self.reviews.pop(iid, None)
            self.ev_pass()  # cleared: it is pulled back in
            return

    def ev_retry_flap(self):
        """A recover send fails (a retry is queued), then the incident flaps: Withdraw, Revive."""
        for key, d in sorted(self.rows.items()):
            s = self.inc[key[0]]
            if key[1] != "recover" or key in self.inflight or not self._due(key, d):
                continue
            if not (s["present"] and s["state"] == "resolved"):
                continue
            self._finish(key, self._claim(key, d, success=False))
            s["state"] = "open"
            self.ev_pass()
            s["state"] = "resolved"
            self.ev_pass()
            return

    def _finish(self, key, token, expect=1):
        """Record the outcome with a short transaction, version-checked against the claim."""
        claimed, success = token.claimed, token.success
        before, params = dict(self.rows), sql.completion_params(claimed, self.now)
        if success:
            count = self.store.run(sql.COMPLETE_SENT, params)
        else:
            count = self.store.run(*sql.failure_statement(claimed, self.now, self._cfg()))
        assert count == expect, ("completion matches its own claim only", key, claimed, count)
        if count == 0:
            return
        assert self.rows[key].updated_at == math.ceil(self.now), (
            "completion stamps updated_at",
            key,
        )
        if success and key[1] == "open":
            self.owed_at[key[0]] = math.ceil(self.now)
        self._observe()
        check_transitions(before, self.rows)

    def _observe(self):
        for (iid, kind), d in self.rows.items():
            assert d.attempts <= self.cfg.max_attempts, ("attempt budget exceeded", d)
            if kind == "open" and d.state == "sent":
                self.opened.add(iid)

    # ---- planner passes -----------------------------------------------------------------
    def _apply(self, actions):
        """One planner pass = one transaction; a miss rolls it back and fails the test."""
        before = dict(self.rows)
        keys = [(a.incident_id, a.kind) for a in actions]
        assert len(keys) == len(set(keys)), actions  # (h)
        for a in actions:
            self._check_action(a)
        self._check_forgets(actions)
        for a in actions:
            if isinstance(a, Forget) and a.sibling_recover:
                self._probe_sibling_guard(a)
        live = {
            k: d for k, d in before.items() if d.state == "sending" and d.next_attempt_at > self.now
        }
        self.store.apply_pass(actions, self.now, self.cfg.retention_seconds)
        self.seen |= {type(a).__name__ for a in actions}
        for a in actions:
            if a.expected is None:  # an INSERT: the row starts a new life
                key = (a.incident_id, a.kind)
                self.life[key] = self.life.get(key, 0) + 1
        for a in actions:
            key = (a.incident_id, a.kind)
            if isinstance(a, Forget):  # a forgotten row ends its life: history starts over
                for book in (self.transmissions, self.successes, self.crashes, self.violations):
                    book.pop(key, None)
                if a.kind == "open":
                    self.opened.discard(a.incident_id)
                    self.owed_at.pop(a.incident_id, None)
        self._observe()
        check_transitions(before, self.rows)
        for key, d in live.items():
            assert self.rows.get(key) == d, ("the planner touched a live lease", d)
        for a in actions:  # every planner UPDATE stamps updated_at
            row = self.rows.get((a.incident_id, a.kind))
            if a.expected is not None and not isinstance(a, Forget | Withdraw | Revive) and row:
                assert row.updated_at == math.ceil(self.now), ("updated_at not stamped", a, row)
            if isinstance(a, Withdraw | Revive):
                assert self.rows[(a.incident_id, a.kind)].updated_at == math.ceil(self.now), a
        for (
            a
        ) in actions:  # a lapsed claim that is suppressed keeps the retry deadline a Reclaim has
            prior = before.get((a.incident_id, a.kind))
            if isinstance(a, Suppress) and prior is not None and prior.state == "sending":
                row = self.rows[(a.incident_id, a.kind)]
                due = math.ceil(self.now) + backoff(row.attempts, self.cfg)
                assert row.next_attempt_at == due, ("suppress dropped the backoff", a, row)
        moved = {
            (a.incident_id, a.kind) for a in actions if isinstance(a, Reclaim | Requeue | Revive)
        }
        self._check_pending_rows(moved)  # rows moved this pass meet the verdict on the next one

    def _probe_claim_guards(self, d):
        """On scratch copies, CLAIM refuses a row that is not due, out of budget or stale."""
        now = math.ceil(self.now)
        breaks = {
            "not due": "UPDATE incident_deliveries SET next_attempt_at=:now+5",
            "out of budget": "UPDATE incident_deliveries SET attempts=:max",
            "stale": "UPDATE incident_deliveries SET version=version+1",
            "already sending": "UPDATE incident_deliveries SET state='sending'",
            "another incarnation": "UPDATE incident_deliveries SET row_id=row_id+1000000",
        }
        for label, update in breaks.items():
            probe = Store(self.rows.values())
            args = {"now": now, "max": self.cfg.max_attempts, "kind": d.kind, "i": d.incident_id}
            probe.run(update + " WHERE kind=:kind AND incident_id=:i", args)
            assert probe.run(sql.CLAIM, sql.claim_params(d, self.now, self.cfg)) == 0, label

    def _probe_sibling_guard(self, a):
        """On a scratch copy, the DELETE of an open row must refuse while a recover is in flight."""
        for state in ("pending", "sending"):
            probe = Store(self.rows.values())
            probe.run(
                "DELETE FROM incident_deliveries WHERE kind='recover' AND incident_id=:i",
                {"i": a.incident_id},
            )
            now = math.ceil(self.now)
            probe.add(DeliveryView(a.incident_id, "recover", state, 1, now + 9, now, now, 0))
            assert probe.run(*sql.statement(a, self.now)) == 0, ("sibling guard", state, a)

    def _check_forgets(self, actions):
        """All-or-nothing: an incident's rows are forgotten together, all terminal."""
        forgotten = {}
        for a in actions:
            if isinstance(a, Forget):
                forgotten.setdefault(a.incident_id, set()).add(a.kind)
        for iid, kinds in forgotten.items():
            rows = {k[1]: d for k, d in self.rows.items() if k[0] == iid}
            terminal = {"sent", "failed", "suppressed", "expired", "withdrawn"}
            assert set(rows) == kinds, ("half-forgotten incident", iid, kinds, rows)
            assert all(d.state in terminal for d in rows.values()), ("forget of live rows", rows)

    def _verdict_ok(self, a):
        """An open delivery is never (re)scheduled for a quiet incident or before a snooze ends."""
        review = self.reviews.get(a.incident_id)
        if review is None:
            return
        assert review.status not in QUIET, ("scheduled while quiet", a, review)
        until = review.snooze_until
        if review.status == "snoozed" and isinstance(until, int | float) and self.now < until:
            due = getattr(a, "not_before", None) or a.next_attempt_at
            assert due >= math.ceil(until), ("before snooze ends", a, review)

    def _check_action(self, a):
        row = self.rows.get((a.incident_id, a.kind))
        inc = self.inc[a.incident_id]
        if row is not None and row.state == "sending":
            assert row.next_attempt_at <= self.now, ("action on a live lease", a, row)
            assert isinstance(a, Reclaim | Fail | Expire | Withdraw | Suppress), (
                "on a sending row",
                a,
                row,
            )
            if isinstance(a, Suppress):  # only an open that is still wanted meets the decision
                alive = inc["present"] and inc["state"] == "open"
                assert alive and self.now - row.created_at <= self.cfg.retention_seconds, (a, row)
        if a.expected is None:
            assert row is None and isinstance(a, Enqueue | Suppress), (a, row)
        else:
            exp = (a.expected.state, a.expected.attempts, a.expected.version, a.expected.row_id)
            got = None if row is None else (row.state, row.attempts, row.version, row.row_id)
            assert got == exp, (a, row)
        if isinstance(a, Enqueue | Requeue | Reclaim) and a.kind == "open":
            self._verdict_ok(a)
        if isinstance(a, Enqueue) and a.kind == "recover":
            opened = self.rows.get((a.incident_id, "open"))
            assert inc["state"] == "resolved" and opened is not None, ("recover owed?", a)
            assert opened.state == "sent", ("recover without a sent open", a, opened)
        if isinstance(a, Forget):
            assert not (inc["present"] and inc["state"] == "open"), ("forget while open", a)
            rec = self.rows.get((a.incident_id, "recover"))
            if a.kind == "open" and inc["present"] and inc["state"] == "resolved":
                done = ("sent", "failed", "suppressed", "expired")
                assert row.state != "sent" or (rec is not None and rec.state in done), (a, rec)
        if isinstance(a, Reclaim):
            assert inc["present"] and self.now - row.created_at <= self.cfg.retention_seconds, a
            closed = inc["state"] in ("resolved", "superseded")
            assert not (a.kind == "open" and closed), ("reclaim of a cancelled open", a)
            assert not (a.kind == "recover" and inc["state"] != "resolved"), ("reclaim", a)
            backoff_at = math.ceil(self.now) + backoff(row.attempts, self.cfg)
            assert a.next_attempt_at >= backoff_at, ("reclaim waits out a backoff", a, row)
        if isinstance(a, Revive):
            assert a.not_before >= row.next_attempt_at, ("revive before its backoff", a, row)
            opened = self.rows.get((a.incident_id, "open"))
            assert inc["state"] == "resolved" and row.state == "withdrawn", ("revive", a, row)
            assert opened is not None and opened.state == "sent", ("revive w/o sent open", a)
        if isinstance(a, Withdraw):
            assert row.state in ("pending", "sending") and inc["state"] != "resolved", (a, row)
        if isinstance(a, Requeue):
            assert self.now - row.created_at <= self.cfg.retention_seconds, ("lifetime", a, row)
            if row.attempts > 0 and row.next_attempt_at is not None:
                assert a.not_before >= row.next_attempt_at, ("backoff", a, row)
        owned = any(k[0] == a.incident_id for k in self.rows)
        if isinstance(a, Enqueue | Suppress) and not owned and a.kind == "open":
            detected = inc["detected"]
            assert self.since is None or detected >= self.since, ("watermark", a)  # (j)

    def _check_pending_rows(self, skip=()):
        """Nothing pending contradicts the current decision. A cleared decision has no review at
        all, so an absent review is a loud one."""
        for (iid, kind), d in self.rows.items():
            inc, review = self.inc[iid], self.reviews.get(iid)
            if kind != "open" or d.state != "pending" or not inc["present"] or (iid, kind) in skip:
                continue
            if inc["state"] != "open":
                continue
            until = review.snooze_until if review else None
            numeric = isinstance(until, int | float)
            if review is not None:
                assert review.status not in QUIET, ("pending while quiet", iid, review)
            cleared = review is None or (review.status is None and until is None)
            elapsed = review is not None and review.status == "snoozed" and numeric
            if cleared or (elapsed and self.now >= until):
                bound = math.ceil(self.now)  # a loud row is due no later than its backoff allows
                if d.attempts > 0:
                    bound = max(bound, math.ceil(d.updated_at) + backoff(d.attempts, self.cfg))
                assert d.next_attempt_at <= bound, ("held back by a cleared snooze", d, review)
            elif elapsed and d.attempts == 0:
                assert d.next_attempt_at >= math.ceil(until), ("due before snooze", d, review)

    def ev_pass(self):
        self._apply(self.plan())

    # ---- quiescence ---------------------------------------------------------------------
    def settle(self, limit=6):
        for _ in range(limit):
            actions = self.plan()
            if not actions:
                self._check_pending_rows()  # at quiescence nothing is exempt from the verdict
                return
            self._apply(actions)
        raise AssertionError(("no fixpoint", self.rows, self.inc, self.reviews))

    def check_quiescent(self):
        self.settle()
        assert self.plan() == ()  # (g)
        ttl, life = self.cfg.pending_ttl_seconds, self.cfg.retention_seconds
        for d in self.rows.values():
            if d.state == "pending":
                assert self.now - max(d.created_at, d.next_attempt_at) < ttl, d  # (e)
                assert self.now - d.created_at <= life, ("lifetime cap", d)
            if d.state == "sending":
                assert d.next_attempt_at > self.now, ("a lapsed lease was not reclaimed", d)
        for iid, s in self.inc.items():
            if not s["present"]:
                continue
            opened, rec = self.rows.get((iid, "open")), self.rows.get((iid, "recover"))
            if s["state"] == "open":
                assert rec is None or rec.state != "pending", (iid, rec)  # (d)
            else:
                assert opened is None or opened.state != "pending", ("open outlived", iid, opened)
            if s["state"] == "superseded":
                assert rec is None or rec.state != "pending", ("recover for superseded", iid)
            if s["state"] == "resolved" and iid in self.owed_at:  # (c) per episode
                assert rec is not None and rec.state != "withdrawn", ("recover owed", iid, rec)
                opened_row = self.rows[(iid, "open")]
                assert rec.row_id > opened_row.row_id, ("recover of an older incarnation", rec)
            self._check_announced(iid, s)

    def _check_announced(self, iid, s):
        """Obligation: an eligible, loud, open incident has an open row once the planner settled."""
        review = self.reviews.get(iid)
        until = review.snooze_until if review else None
        loud = review is None or (review.status is None and until is None)
        loud = loud or (
            review.status == "snoozed" and isinstance(until, int | float) and self.now >= until
        )
        owned = any(k[0] == iid for k in self.rows)
        eligible = self.since is None or s["detected"] >= self.since or owned
        if s["state"] == "open" and loud and eligible:
            assert (iid, "open") in self.rows, ("announcement dropped", iid, review)

    def run(self, steps=70):
        ops = [
            (self.ev_new, 2), (self.ev_transition, 6), (self.ev_decision, 8),
            (self.ev_watermark, 3), (self.ev_time, 4), (self.ev_sender, 2),
            (self.ev_claim, 3), (self.ev_complete, 4), (self.ev_overtake, 3),
            (self.ev_crash, 1), (self.ev_zombie, 2),
            (self.ev_violate, 1), (self.ev_zombie_race, 2), (self.ev_recreate_race, 2),
            (self.ev_retry_flap, 2), (self.ev_park_and_clear, 2), (self.ev_clock_back, 1),
            (self.ev_flap, 4), (self.ev_pass, 8),
        ]  # fmt: skip
        funcs = [f for f, w in ops for _ in range(w)]
        for _ in range(steps):
            self.rnd.choice(funcs)()
            if self.rnd.random() < 0.12:
                self.check_quiescent()
        self.check_quiescent()
        self.now += self.cfg.pending_ttl_seconds + 1
        self.check_quiescent()
        self.now += self.cfg.retention_seconds + 1
        self.check_quiescent()
