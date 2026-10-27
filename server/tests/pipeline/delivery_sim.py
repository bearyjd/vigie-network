"""Compare-and-set applier and a seeded world simulator for the delivery planner tests."""

from __future__ import annotations

import dataclasses
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
ALLOWED = {
    "pending": {"pending", "sent", "failed", "suppressed", "expired"},
    "suppressed": {"suppressed", "pending", "failed", "expired"},
    "sent": {"sent"},
    "failed": {"failed"},
    "expired": {"expired"},
}


def _transition(a, old, t):
    if isinstance(a, Enqueue):
        return DeliveryView(a.incident_id, a.kind, "pending", 0, a.not_before, t, t)
    if isinstance(a, Suppress):
        if old is None:
            return DeliveryView(a.incident_id, a.kind, "suppressed", 0, None, t, t)
        return dataclasses.replace(old, state="suppressed", updated_at=t)
    if isinstance(a, Requeue):
        return dataclasses.replace(old, state="pending", next_attempt_at=a.not_before, updated_at=t)
    if isinstance(a, Reschedule):
        return dataclasses.replace(old, next_attempt_at=a.next_attempt_at, updated_at=t)
    if isinstance(a, Expire):
        return dataclasses.replace(old, state="expired", updated_at=t)
    if isinstance(a, Fail):
        return dataclasses.replace(old, state="failed", updated_at=t)
    if isinstance(a, Forget | Withdraw):
        return None
    raise AssertionError(a)


def apply_cas(rows, actions, now, retention=None):
    """One conditional statement per action; 0 affected rows (a stale plan) is skipped."""
    out, skipped = dict(rows), []
    for a in actions:
        key, exp = (a.incident_id, a.kind), a.expected
        old = out.get(key)
        stale = (
            old is not None
            if exp is None
            else (old is None or (old.state, old.attempts) != (exp.state, exp.attempts))
        )
        if stale:
            skipped.append(a)
            continue
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
            assert a.state in ALLOWED[b.state], (b, a)


class World:
    """Incidents, human decisions, a sender and the planner, driven by a seeded RNG."""

    def __init__(self, seed: int, cfg: DeliveryConfig | None = None):
        self.rnd = random.Random(seed)  # noqa: S311 - deterministic test data
        self.cfg = cfg or DeliveryConfig()
        self.now, self.since, self.next_id = 1_000_000, None, 0
        self.inc, self.reviews, self.rows = {}, {}, {}
        self.sends = {}
        self.seen, self.skips = set(), 0
        self.opened, self.recovered, self.exempt = set(), set(), set()

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
        iid = self.rnd.choice(sorted(self.inc))
        s = self.inc[iid]
        if not s["present"]:
            s["present"] = True
        elif s["state"] == "open":
            if self.rnd.random() < 0.25:
                s["present"] = False
            else:
                s["state"] = self.rnd.choice(["resolved", "resolved", "superseded"])
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
        steps = [1, 1, 30, 59, 60, 600, 3600, DAY - 1, DAY, DAY + 1, self.cfg.retention_seconds + 1]
        self.now += self.rnd.choice(steps) + self.rnd.choice([0, 0, 0.5])

    def ev_sender(self):
        before = dict(self.rows)
        for key, d in sorted(self.rows.items()):
            if d.state != "pending" or d.next_attempt_at > self.now or self.rnd.random() < 0.3:
                continue
            tried = dataclasses.replace(d, attempts=d.attempts + 1, updated_at=int(self.now))
            if self.rnd.random() < 0.6:
                self.rows[key] = dataclasses.replace(tried, state="sent")
                self.sends[key] = self.sends.get(key, 0) + 1
                if key[0] not in self.exempt:
                    assert self.sends[key] == 1, ("sent twice", key)
            else:
                self.rows[key] = tried  # the sender records the attempt, then the planner helper
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
        assert not (fresh and skipped), skipped
        self._check_cas(actions, skipped, before)
        self.seen |= {type(a).__name__ for a in actions}
        self.skips += len(skipped)
        for a in actions:
            if isinstance(a, Forget):  # the dedup memory is gone: a reopened id starts a new life
                self.exempt.add(a.incident_id)
                self.opened.discard(a.incident_id)
                self.recovered.discard(a.incident_id)
        self._observe()
        check_transitions(before, self.rows)

    def _check_cas(self, actions, skipped, before):
        """Independent oracle: an action applied iff its expectation matched the row."""
        for a in actions:
            row = before.get((a.incident_id, a.kind))
            exp = a.expected
            matches = (
                row is None
                if exp is None
                else (row is not None and (row.state, row.attempts) == (exp.state, exp.attempts))
            )
            assert matches == (a not in skipped), ("stale action applied or fresh skipped", a, row)

    def _check_action(self, a, fresh):
        row = self.rows.get((a.incident_id, a.kind))
        if fresh:
            if a.expected is None:
                assert row is None and isinstance(a, Enqueue | Suppress), (a, row)
            else:
                assert row is not None and (row.state, row.attempts) == (
                    a.expected.state,
                    a.expected.attempts,
                ), (a, row)
        owned = any(k[0] == a.incident_id for k in self.rows)
        inc = self.inc[a.incident_id]
        if (
            fresh
            and isinstance(a, Forget)
            and a.kind == "open"
            and row is not None
            and inc["present"]
            and inc["state"] == "resolved"
        ):
            rec = self.rows.get((a.incident_id, "recover"))  # a recover is still owed
            assert row.state != "sent" or (rec is not None and rec.state != "pending"), (a, rec)
        if isinstance(a, Requeue) and fresh:
            assert self.now - row.created_at < self.cfg.pending_ttl_seconds, ("ttl", a, row)
            if row.attempts > 0 and row.next_attempt_at is not None:
                assert a.not_before >= row.next_attempt_at, ("backoff", a, row)
        if isinstance(a, Enqueue | Suppress) and not owned and a.kind == "open":
            detected = self.inc[a.incident_id]["detected"]
            assert self.since is None or detected >= self.since, ("watermark", a)  # (j)

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
        ttl = self.cfg.pending_ttl_seconds
        for d in self.rows.values():
            if d.state == "pending":
                assert self.now - max(d.created_at, d.next_attempt_at) < ttl, d  # (e)
        for iid, s in self.inc.items():
            if not s["present"]:
                continue
            rec = self.rows.get((iid, "recover"))
            if s["state"] == "open":
                assert rec is None or rec.state != "pending", (iid, rec)  # (d)
            if s["state"] == "resolved" and iid in self.opened and iid not in self.exempt:
                assert rec is not None or iid in self.recovered, ("recover owed", iid)  # (c)

    def run(self, steps=70):
        ops = [
            (self.ev_new, 3), (self.ev_transition, 3), (self.ev_decision, 4),
            (self.ev_watermark, 1), (self.ev_time, 4), (self.ev_sender, 4),
            (self.ev_pass, 6), (self.ev_stale, 3),
        ]  # fmt: skip
        funcs = [f for f, w in ops for _ in range(w)]
        for _ in range(steps):
            self.rnd.choice(funcs)()
            if self.rnd.random() < 0.15:
                self.check_quiescent()
        self.check_quiescent()
        self.now += self.cfg.pending_ttl_seconds + 1
        self.check_quiescent()
        self.now += self.cfg.retention_seconds + 1
        self.check_quiescent()
