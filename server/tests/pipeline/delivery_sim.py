"""A real-SQLite applier and a seeded, adversarial world simulator for the delivery tests."""

from __future__ import annotations

import dataclasses
import math
import random
import sqlite3

from vigie_pipeline import delivery_sql as sql
from vigie_pipeline import schema
from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Fail,
    Forget,
    IncidentView,
    Requeue,
    ReviewView,
    Revive,
    Suppress,
    Withdraw,
    after_failure,
    delivery_id,
    plan,
)

DAY = 86400
QUIET = ("acknowledged", "expected")
ALLOWED = {
    "pending": {"pending", "sent", "failed", "suppressed", "expired", "withdrawn"},
    "withdrawn": {"withdrawn", "pending", "expired", "failed"},
    "suppressed": {"suppressed", "pending", "failed", "expired", "sent"},
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


class PassAborted(AssertionError):
    """An action did not affect exactly one row: the whole pass was rolled back."""


COLUMNS = "incident_id, kind, state, attempts, next_attempt_at, created_at, updated_at, version"


class Store:
    """The production `incident_deliveries` table (migration 11) in an in-memory SQLite."""

    def __init__(self, rows=()):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        for statement in schema.PIPELINE_MIGRATIONS[10]:
            self.conn.execute(statement)
        for d in rows:
            marks = ",".join("?" * 9)
            self.conn.execute(
                f"INSERT INTO incident_deliveries (delivery_id, {COLUMNS}) VALUES ({marks})",  # noqa: S608
                (delivery_id(d.incident_id, d.kind), *dataclasses.astuple(d)),
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
                count = self.run(*sql.statement(a, now))
                if count != 1:
                    raise PassAborted(("affected rows", count, a))
        except BaseException:
            self.conn.execute("ROLLBACK")
            self._cache = None
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


def complete_send(rows, captured, now):
    """The sender's completion UPDATE (version-checked only for a recover)."""
    store = Store(rows.values())
    done = store.run(sql.SENDER_SENT, sql.sender_params(captured, now)) == 1
    return store.rows(), done


def check_transitions(before, after):
    for key in before.keys() | after.keys():
        b, a = before.get(key), after.get(key)
        if b is None:
            assert a is None or a.state in ("pending", "suppressed"), (key, a)
        elif a is not None:
            assert a.created_at == b.created_at and a.attempts >= b.attempts, (b, a)
            assert a.version >= b.version and a.state in ALLOWED[b.state], (b, a)
            assert a.version > b.version or a == b, ("change without a version bump", b, a)


class World:
    """Incidents, human decisions, a sender and the planner, driven by a seeded RNG."""

    def __init__(self, seed: int, cfg: DeliveryConfig | None = None):
        self.rnd = random.Random(seed)  # noqa: S311 - deterministic test data
        self.cfg = cfg or DeliveryConfig()
        self.now, self.since, self.next_id = 1_000_000, None, 0
        self.inc, self.reviews, self.store = {}, {}, Store()
        self.delivered, self.episode, self.opened, self.owed_at = {}, {}, set(), {}
        self.inflight, self.dropped = {}, 0
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
        detected = int(self.now) - self.rnd.randint(0, 3600)
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
        self.now += self.rnd.choice(steps) + self.rnd.choice([0, 0, 0.5, 0.999])

    def ev_sender(self):
        """Claim, transmit and record in one step (a fast send)."""
        for key, d in sorted(self.rows.items()):
            if key not in self.inflight and self._due(key, d) and self.rnd.random() > 0.3:
                self._finish(key, *self._claim(key, d))

    def _due(self, key, d):
        if d.state != "pending" or d.next_attempt_at > self.now:
            return False
        if key[1] == "recover":  # a recover is only ever sent for an announced open
            opened = self.rows.get((key[0], "open"))
            assert opened is not None and opened.state == "sent", ("recover w/o open", key)
        return True

    def _claim(self, key, d):
        """The sender captures the row and transmits. A TRANSMISSION that reaches the user is
        counted here, whether or not its completion later lands."""
        success = self.rnd.random() < 0.6
        if success:
            episode = (key, self.episode.get(key, 0))  # a Revive starts a new recover episode
            self.delivered[episode] = self.delivered.get(episode, 0) + 1
            assert self.delivered[episode] == 1, ("delivered twice", episode)
        return d, success

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
            self._finish(key, *self.inflight.pop(key))
        self.reviews.pop(key[0]) if was is None else self.reviews.update({key[0]: was})
        self.ev_pass()
        self.ev_sender()

    def ev_complete(self):
        for key in sorted(self.inflight):
            if self.rnd.random() < 0.6:
                self._finish(key, *self.inflight.pop(key))

    def _finish(self, key, captured, success):
        """Record the outcome with the sender's own short transaction."""
        before, params = dict(self.rows), sql.sender_params(captured, self.now)
        if success:
            count = self.store.run(sql.SENDER_SENT, params)
        else:
            tried = dataclasses.replace(captured, attempts=captured.attempts + 1)
            act = after_failure(tried, self.now, self._cfg())
            if isinstance(act, Fail):
                count = self.store.run(sql.SENDER_GIVE_UP, params)
            else:
                count = self.store.run(
                    sql.SENDER_RETRY, params | {"next_attempt_at": act.next_attempt_at}
                )
        if count == 0:
            self.dropped += 1  # the planner's own transition stands; the result is dropped
        else:
            assert self.rows[key].updated_at == int(self.now), ("sender must stamp updated_at", key)
            if success and key[1] == "open":
                self.owed_at[key[0]] = int(self.now)
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
        self.store.apply_pass(actions, self.now, self.cfg.retention_seconds)
        self.seen |= {type(a).__name__ for a in actions}
        for a in actions:
            key = (a.incident_id, a.kind)
            if isinstance(a, Revive):
                self.episode[key] = self.episode.get(key, 0) + 1
            if isinstance(a, Forget):  # a forgotten row ends its life: history starts over
                for episode in [e for e in self.delivered if e[0] == key]:
                    del self.delivered[episode]
                self.episode.pop(key, None)
                self.inflight.pop(key, None)  # no send outlives retention
                if a.kind == "open":
                    self.opened.discard(a.incident_id)
                    self.owed_at.pop(a.incident_id, None)
        self._observe()
        check_transitions(before, self.rows)
        for a in actions:  # every planner UPDATE stamps updated_at
            row = self.rows.get((a.incident_id, a.kind))
            if a.expected is not None and not isinstance(a, Forget | Withdraw | Revive) and row:
                assert row.updated_at == int(self.now), ("updated_at not stamped", a, row)
            if isinstance(a, Withdraw | Revive):
                assert self.rows[(a.incident_id, a.kind)].updated_at == int(self.now), a
        self._check_pending_rows()

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
            assert a.not_before >= math.ceil(until), ("before snooze ends", a, review)

    def _check_action(self, a):
        row = self.rows.get((a.incident_id, a.kind))
        inc = self.inc[a.incident_id]
        if a.expected is None:
            assert row is None and isinstance(a, Enqueue | Suppress), (a, row)
        else:
            exp = (a.expected.state, a.expected.attempts, a.expected.version)
            assert row is not None and (row.state, row.attempts, row.version) == exp, (a, row)
        if isinstance(a, Enqueue | Requeue) and a.kind == "open":
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
        if isinstance(a, Revive):
            assert a.not_before >= row.next_attempt_at, ("revive before its backoff", a, row)
            opened = self.rows.get((a.incident_id, "open"))
            assert inc["state"] == "resolved" and row.state == "withdrawn", ("revive", a, row)
            assert opened is not None and opened.state == "sent", ("revive w/o sent open", a)
        if isinstance(a, Withdraw):
            assert row.state == "pending" and inc["state"] != "resolved", ("withdraw", a, row)
        if isinstance(a, Requeue):
            assert self.now - row.created_at <= self.cfg.retention_seconds, ("lifetime", a, row)
            if row.attempts > 0 and row.next_attempt_at is not None:
                assert a.not_before >= row.next_attempt_at, ("backoff", a, row)
        owned = any(k[0] == a.incident_id for k in self.rows)
        if isinstance(a, Enqueue | Suppress) and not owned and a.kind == "open":
            detected = inc["detected"]
            assert self.since is None or detected >= self.since, ("watermark", a)  # (j)

    def _check_pending_rows(self):
        """After a fresh pass, nothing pending contradicts the current decision."""
        for (iid, kind), d in self.rows.items():
            inc, review = self.inc[iid], self.reviews.get(iid)
            if kind != "open" or d.state != "pending" or not inc["present"]:
                continue
            if inc["state"] != "open" or review is None:
                continue
            assert review.status not in QUIET, ("pending while quiet", iid, review)
            until = review.snooze_until
            if review.status == "snoozed" and isinstance(until, int | float) and self.now < until:
                if d.attempts == 0:
                    assert d.next_attempt_at >= math.ceil(until), ("due before snooze", d, review)

    def ev_pass(self):
        self._apply(self.plan())

    # ---- quiescence ---------------------------------------------------------------------
    def settle(self, limit=6):
        for _ in range(limit):
            actions = self.plan()
            if not actions:
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
                assert rec.created_at >= self.owed_at[iid], ("recover of an older episode", rec)
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
