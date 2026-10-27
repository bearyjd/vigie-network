"""Compare-and-set applier and a seeded, adversarial world simulator for the delivery tests."""

from __future__ import annotations

import dataclasses
import math
import random

from vigie_pipeline.delivery_plan import (
    DeliveryConfig,
    DeliveryView,
    Enqueue,
    Expire,
    Fail,
    Forget,
    IncidentView,
    Requeue,
    Reschedule,
    ReviewView,
    Suppress,
    Withdraw,
    after_failure,
    plan,
)

DAY = 86400
QUIET = ("acknowledged", "expected")
ALLOWED = {
    "pending": {"pending", "sent", "failed", "suppressed", "expired"},
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


def _transition(a, old, t):
    bump = {"updated_at": t, "version": old.version + 1} if old is not None else {}
    if isinstance(a, Enqueue):
        return DeliveryView(a.incident_id, a.kind, "pending", 0, a.not_before, t, t, 0)
    if isinstance(a, Suppress):
        if old is None:
            return DeliveryView(a.incident_id, a.kind, "suppressed", 0, None, t, t, 0)
        return dataclasses.replace(old, state="suppressed", **bump)
    if isinstance(a, Requeue):
        return dataclasses.replace(old, state="pending", next_attempt_at=a.not_before, **bump)
    if isinstance(a, Reschedule):
        return dataclasses.replace(old, next_attempt_at=a.next_attempt_at, **bump)
    if isinstance(a, Expire):
        return dataclasses.replace(old, state="expired", **bump)
    if isinstance(a, Fail):
        return dataclasses.replace(old, state="failed", **bump)
    if isinstance(a, Forget | Withdraw):
        return None
    raise AssertionError(a)


def _stale(rows, a):
    """True when the conditional statement for `a` would affect 0 rows."""
    old, exp = rows.get((a.incident_id, a.kind)), a.expected
    if exp is None:
        return old is not None  # INSERT OR IGNORE
    if old is None or (old.state, old.attempts, old.version) != (
        exp.state,
        exp.attempts,
        exp.version,
    ):
        return True
    sibling = rows.get((a.incident_id, "recover"))
    blocked = isinstance(a, Forget) and a.sibling_recover and sibling and sibling.state == "pending"
    return bool(blocked)


def apply_cas(rows, actions, now, retention=None):
    """One conditional statement per action; 0 affected rows (a stale plan) is skipped."""
    out, skipped = dict(rows), []
    for a in actions:
        key = (a.incident_id, a.kind)
        if _stale(out, a):
            skipped.append(a)
            continue
        old = out.get(key)
        if isinstance(a, Forget) and retention is not None:
            assert now - old.updated_at > retention, ("forgotten early", a, old)
        new = _transition(a, old, int(now))
        if new is None:
            del out[key]
        else:
            out[key] = new
    return out, skipped


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
        self.inc, self.reviews, self.rows = {}, {}, {}
        self.sends, self.opened, self.recovered = {}, set(), set()
        self.seen, self.skips = set(), 0

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
        before = dict(self.rows)
        for key, d in sorted(self.rows.items()):
            if d.state != "pending" or d.next_attempt_at > self.now or self.rnd.random() < 0.3:
                continue
            if key[1] == "recover":  # a recover is only ever sent for an announced open
                opened = self.rows.get((key[0], "open"))
                assert opened is not None and opened.state == "sent", ("recover w/o open", key)
            # the sender claims the attempt with its own conditional UPDATE (version bump)
            tried = dataclasses.replace(
                d, attempts=d.attempts + 1, version=d.version + 1, updated_at=int(self.now)
            )
            if self.rnd.random() < 0.6:
                self.rows[key] = dataclasses.replace(tried, state="sent")
                self.sends[key] = self.sends.get(key, 0) + 1
                assert self.sends[key] == 1, ("sent twice", key)
            else:
                self.rows[key] = tried
                act = after_failure(tried, self.now, self._cfg())
                self.rows, skipped = apply_cas(self.rows, [act], self.now)
                assert not skipped, ("after_failure must apply to the row it was made for", act)
        self._observe()
        check_transitions(before, self.rows)

    def _observe(self):
        for (iid, kind), d in self.rows.items():
            if kind == "open" and d.state == "sent":
                self.opened.add(iid)
            if kind == "recover" and d.state != "pending":
                self.recovered.add(iid)

    # ---- planner passes -----------------------------------------------------------------
    def _apply(self, actions, fresh):
        before = dict(self.rows)
        keys = [(a.incident_id, a.kind) for a in actions]
        assert len(keys) == len(set(keys)), actions  # (h)
        for a in actions:
            self._check_action(a, fresh)
        self.rows, skipped = apply_cas(self.rows, actions, self.now, self.cfg.retention_seconds)
        assert not (fresh and skipped), ("a fresh plan must apply in full", skipped)
        self._check_cas(actions, skipped, before)
        self.seen |= {type(a).__name__ for a in actions}
        self.skips += len(skipped)
        for a in actions:
            if isinstance(a, Forget) and a not in skipped:  # only an APPLIED forget ends a life
                self.sends.pop((a.incident_id, a.kind), None)
                self.recovered.discard(a.incident_id)
                if a.kind == "open":
                    self.opened.discard(a.incident_id)
        self._observe()
        check_transitions(before, self.rows)
        if fresh:
            self._check_pending_rows()

    def _check_cas(self, actions, skipped, before):
        """Independent oracle: an action applied iff its expectation matched the row."""
        for a in actions:
            row, exp = before.get((a.incident_id, a.kind)), a.expected
            sibling = before.get((a.incident_id, "recover"))
            blocked = (
                isinstance(a, Forget)
                and a.sibling_recover is not None
                and sibling is not None
                and sibling.state == "pending"
            )
            if exp is None:
                matches = row is None
            else:
                matches = (
                    row is not None
                    and (row.state, row.attempts, row.version)
                    == (exp.state, exp.attempts, exp.version)
                    and not blocked
                )
            assert matches == (a not in skipped), ("stale action applied or fresh skipped", a, row)

    def _verdict_ok(self, a):
        """An open delivery is never (re)scheduled for a quiet incident or before a snooze ends."""
        review = self.reviews.get(a.incident_id)
        if review is None:
            return
        assert review.status not in QUIET, ("scheduled while quiet", a, review)
        until = review.snooze_until
        if review.status == "snoozed" and isinstance(until, int | float) and self.now < until:
            assert a.not_before >= math.ceil(until), ("before snooze ends", a, review)

    def _check_action(self, a, fresh):
        row = self.rows.get((a.incident_id, a.kind))
        inc = self.inc[a.incident_id]
        if not fresh:
            return
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
                assert row.state != "sent" or (rec is not None and rec.state != "pending"), (a, rec)
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
        self._apply(self.plan(), fresh=True)

    def ev_stale(self):
        actions = self.plan()
        self.rnd.choice(
            [self.ev_sender, self.ev_decision, self.ev_transition, self.ev_time, self.ev_pass]
        )()
        self._apply(actions, fresh=False)

    # ---- quiescence ---------------------------------------------------------------------
    def settle(self, limit=6):
        for _ in range(limit):
            actions = self.plan()
            if not actions:
                return
            self._apply(actions, fresh=True)
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
            if s["state"] == "resolved" and iid in self.opened:
                assert rec is not None or iid in self.recovered, ("recover owed", iid)  # (c)

    def run(self, steps=70):
        ops = [
            (self.ev_new, 2), (self.ev_transition, 6), (self.ev_decision, 8),
            (self.ev_watermark, 3), (self.ev_time, 4), (self.ev_sender, 5),
            (self.ev_pass, 6), (self.ev_stale, 6),
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
