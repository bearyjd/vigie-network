"""APPLY phase of identity stitching (docs/stitching-design.md section 4): one short
BEGIN IMMEDIATE that re-validates every decision of the plan with indexed point lookups (the
pair's candidate state; for an attach the rule, links and group rows of overrides.db by primary
key), drops what went stale, and writes a count-bounded number of rows: at most MAX_ROWS_PER_PASS
candidate/suggestion/widen/cleanup rows and MAX_ATTACHES_PER_PASS attaches.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime

from vigie_ingest.db import immediate
from vigie_pipeline.config import (
    MAX_ATTACHES_PER_PASS,
    MAX_OPEN_SUGGESTIONS_PER_DEVICE,
    MAX_ROWS_PER_PASS,
    PipelineConfig,
)
from vigie_pipeline.logs import log
from vigie_pipeline.overrides import canonical_device
from vigie_pipeline.snapshot import MalformedRule, Snapshot, parse_rule, rule_active
from vigie_pipeline.stitch_db import (
    Attachment,
    candidate_state,
    candidate_write_needed,
    create_merge_suggestion,
    dismiss_open_candidates,
    emit_event,
    emit_once,
    find_merge_suggestion,
    open_candidates_left,
    open_suggestions_into,
    save_attachment,
    state_set,
    upsert_candidate,
    withdraw_open_suggestions,
    withdraw_orphan_suggestions,
)
from vigie_pipeline.stitch_types import (
    HASHED,
    Ambiguous,
    Attach,
    Candidate,
    Decision,
    Flag,
    Plan,
    Settle,
    StitchStats,
    Suggest,
    Veto,
    Widen,
    short_hash,
)

logger = logging.getLogger("vigie_pipeline")


class Applier:
    def __init__(
        self, inv: sqlite3.Connection, snap: Snapshot, overrides: sqlite3.Connection | None,
        cfg: PipelineConfig, now: float, at: float, stats: StitchStats,
    ) -> None:  # fmt: skip
        self.inv, self.snap, self.overrides, self.cfg = inv, snap, overrides, cfg
        self.now, self.at, self.stats = now, at, stats  # `at`: the clock read under the lock
        self.writes = 0
        self.attaches = 0
        self.day = datetime.fromtimestamp(now, tz=UTC).strftime("%Y-%m-%d")

    def apply(self, d: Decision) -> None:
        handler = {
            Attach: self._attach, Candidate: self._candidate, Veto: self._veto,
            Ambiguous: self._ambiguous, Suggest: self._suggest, Flag: self._flag,
            Widen: self._widen, Settle: self._settle,
        }[type(d)]  # fmt: skip
        handler(d)  # type: ignore[operator]

    # ---- shared preconditions and the row cap ----------------------------------------------

    def _still_self(self, mac: str, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT device_id, link_source FROM observations WHERE mac=?", (mac,)
        ).fetchone()
        return row is not None and (row[0], row[1]) == (device_id, "self")

    def _unchanged(self, a: str, b: str, expected: str | None) -> bool:
        """The pair's candidate row is as it was when the decision was computed; a human
        decision in between (dismissed, or any other change) drops the decision, which is
        recomputed against the new state on a later pass."""
        if candidate_state(self.inv, a, b) == expected:
            return True
        self.stats.stale += 1
        return False

    def _reserve(self, rows: int) -> bool:
        """Does a whole decision of `rows` writes fit under MAX_ROWS_PER_PASS? If not, nothing of
        it is written and it is recomputed on a later pass."""
        if rows and self.writes + rows > MAX_ROWS_PER_PASS:
            self.stats.capped += 1
            return False
        return True

    def _record(self, a: str, b: str, score: float, evidence: dict, state: str) -> str:
        cid, wrote = upsert_candidate(self.inv, a, b, score, evidence, state, self.now)
        self.stats.candidates += wrote
        self.writes += wrote
        return cid

    def _need(self, a: str, b: str, score: float, evidence: dict, state: str) -> int:
        return int(candidate_write_needed(self.inv, a, b, score, evidence, state))

    # ---- decisions -------------------------------------------------------------------------

    def _candidate(self, d: Candidate) -> None:
        if not self._still_self(d.mac, d.from_device):
            return
        if not self._unchanged(d.from_device, d.into, d.expected):
            return
        if d.provisional and d.expected is not None:
            return  # a provisional overlap never downgrades an existing row
        evidence = dict(d.evidence)
        if self._reserve(self._need(d.from_device, d.into, d.score, evidence, d.state)):
            self._record(d.from_device, d.into, d.score, evidence, d.state)

    def _veto(self, d: Veto) -> None:
        if not self._still_self(d.mac, d.from_device):
            return
        if not self._unchanged(d.from_device, d.into, d.expected):
            return
        evidence = dict(d.evidence)
        if not self._reserve(self._need(d.from_device, d.into, d.score, evidence, "vetoed")):
            return  # no withdrawal either: the pair is retried whole next pass
        withdraw_open_suggestions(self.inv, self.snap, d.from_device, d.into, self.now)
        self._record(d.from_device, d.into, d.score, evidence, "vetoed")
        token = "~".join(sorted((d.from_device, d.into)))
        if emit_once(self.inv, d.from_device, "identity_overlap_veto", "warn",
                     f"identity overlap veto {token}", token, self.now):  # fmt: skip
            self.stats.vetoed += 1
            log(logger, logging.INFO, "identity_overlap_veto", mac=short_hash(d.mac))

    def _ambiguous(self, d: Ambiguous) -> None:
        if not self._still_self(d.mac, d.from_device):
            return
        if not all(self._unchanged(d.from_device, t, e) for t, e in zip(d.targets, d.expected,
                                                                         strict=True)):  # fmt: skip
            return
        evidence = dict(d.evidence)
        need = sum(self._need(d.from_device, t, d.score, evidence, "ambiguous") for t in d.targets)
        if not self._reserve(need):
            return  # the whole multi-target decision waits: never a partial set of rows
        for target in d.targets:
            withdraw_open_suggestions(self.inv, self.snap, d.from_device, target, self.now)
            self._record(d.from_device, target, d.score, evidence, "ambiguous")
        if emit_once(self.inv, d.from_device, "identity_candidate_ambiguous", "warn",
                     f"identity candidate ambiguous: {len(d.targets)} devices match"
                     f" {d.from_device}", d.from_device, self.now):  # fmt: skip
            self.stats.ambiguous += 1
            log(logger, logging.INFO, "identity_candidate_ambiguous", mac=short_hash(d.mac))

    def _suggest(self, d: Suggest) -> None:
        if not self._still_self(d.mac, d.from_device):
            return
        if not self._unchanged(d.from_device, d.into, d.expected):
            return
        if self.snap.canonical(d.from_device) == self.snap.canonical(d.into):
            return  # already one identity
        known = find_merge_suggestion(self.inv, self.snap, d.from_device, d.into, self.now)
        create = known is None
        state = "dismissed" if known is not None and known.status == "rejected" else "suggested"
        if create and open_suggestions_into(self.inv, d.into, self.now) >= (
            MAX_OPEN_SUGGESTIONS_PER_DEVICE
        ):
            create, state = False, "open"  # the human already has a flood of these to decide
            self._flag(Flag("stitch_deferred", d.into, f"suggestion_cap:{self.day}",
                            "stitching deferred (suggestion_cap): too many open suggestions"
                            " into one device"))  # fmt: skip
        evidence = dict(d.evidence)
        if not self._reserve(self._need(d.from_device, d.into, d.score, evidence, state) + create):
            return
        cid = self._record(d.from_device, d.into, d.score, evidence, state)
        if not create:
            return
        summary = {
            "candidate_id": cid,
            "signals": list(d.signals),
            "hashes": {k: short_hash(str(v)) for k, v in evidence.items() if k in HASHED and v},
        }
        create_merge_suggestion(
            self.inv, self.snap, d.from_device, d.into, score=d.score, reason_code=d.reason_code,
            reason_text=d.reason_text, evidence_summary=summary, now=self.now,
            ttl_s=self.cfg.suggestion_ttl_s,
        )  # fmt: skip
        self.stats.suggestions += 1
        self.writes += 1
        token = f"{d.from_device} -> {d.into}"
        emit_once(self.inv, d.from_device, "identity_candidate", "info",
                  f"identity candidate {token} score {d.score:.2f}", token, self.now)  # fmt: skip
        log(logger, logging.INFO, "identity_suggestion", reason=d.reason_code, score=d.score)

    def _flag(self, d: Flag) -> None:
        emit_once(self.inv, d.device_id, d.kind, d.severity, d.summary, d.token, self.now)

    def _settle(self, d: Settle) -> None:
        """Finish dismissing an orphan's candidate rows under this pass's remaining row cap."""
        written = dismiss_open_candidates(self.inv, d.device_id, MAX_ROWS_PER_PASS - self.writes)
        self.writes += written
        if not open_candidates_left(self.inv, d.device_id):
            state_set(self.inv, f"settle:{d.device_id}", None)

    def _widen(self, d: Widen) -> None:
        if not self._reserve(1):
            return
        self.writes += self.inv.execute(
            "UPDATE devices SET"
            " first_seen=MIN(first_seen, (SELECT first_seen FROM devices WHERE id=?)),"
            " last_seen=MAX(last_seen, (SELECT last_seen FROM devices WHERE id=?))"
            " WHERE id=? AND EXISTS (SELECT 1 FROM devices s WHERE s.id=? AND"
            " (s.first_seen < devices.first_seen OR s.last_seen > devices.last_seen))",
            (d.src, d.src, d.dst, d.src),
        ).rowcount

    # ---- the attach: T1 re-validated under the lock ----------------------------------------

    def _authorised(self, d: Attach) -> bool:
        """T1 re-validated under the inventory lock with primary-key lookups in overrides.db (the
        rule row, the target's links, its override row, its group): the rule must still be the
        same active rule pointing at the same canonical target in the same explicit auto_inherit=1
        group, and the candidate's device must not have been merged away. Any read problem fails
        closed. Without an overrides connection (tests) the compute snapshot stands in."""
        if d.rule.expires_at is not None and d.rule.expires_at <= self.at:
            return False
        group = self.snap.overrides.get(d.target, (0, None))[1]
        if self.overrides is None:
            return (
                d.rule in self.snap.rules and self.snap.canonical(d.rule.device_id) == d.target
                and group is not None and self.snap.group_auto_inherit.get(group) == 1
            )  # fmt: skip
        try:
            return _rule_lookup(self.overrides, d, group, self.at)
        except (sqlite3.Error, MalformedRule, TypeError, ValueError) as exc:
            log(logger, logging.ERROR, "attach_revalidation_failed", error=str(exc))
            return False

    def _state_ok(self, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT identity_state FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        return bool(row) and row[0] == "ok"

    def _attach(self, d: Attach) -> None:
        if self.attaches >= MAX_ATTACHES_PER_PASS:
            self.stats.capped += 1
            return
        if not (
            self._authorised(d)
            and self._still_self(d.mac, d.from_device)
            and self._state_ok(d.target)
            and self._state_ok(d.from_device)
            and self._unchanged(d.from_device, d.target, d.expected)
            and d.expected != "vetoed"
        ):
            return  # expired, revoked, regrouped, vetoed or moved while the plan was computed
        old = self.inv.execute(
            "SELECT mac FROM observations WHERE device_id=? AND mac<>?"
            " ORDER BY last_seen DESC, mac LIMIT 1",
            (d.target, d.mac),
        ).fetchone()
        self.inv.execute(
            "UPDATE observations SET device_id=?, link_source='rule', link_rule_id=?,"
            " link_score=? WHERE mac=? AND link_source='self'",
            (d.target, d.rule.id, d.score, d.mac),
        )
        save_attachment(
            self.inv, d.mac,
            Attachment(d.rule.id, d.target, d.hostname, d.mdns_name, d.opt55, d.opt60, d.views),
            self.now,
        )  # fmt: skip
        self.inv.execute(
            "UPDATE devices SET first_seen=MIN(first_seen,(SELECT first_seen FROM devices"
            " WHERE id=?)), last_seen=MAX(last_seen,(SELECT last_seen FROM devices WHERE id=?))"
            " WHERE id=?",
            (d.from_device, d.from_device, d.target),
        )
        self.inv.execute(  # the orphaned self device is retired (never deleted)
            "UPDATE devices SET status='retired' WHERE id=? AND NOT EXISTS"
            " (SELECT 1 FROM observations WHERE device_id=?)",
            (d.from_device, d.from_device),
        )
        # settled by the rule: its suggestions become unactionable at once (two indexed
        # statements, bounded by the suggestion cap); its candidate rows are dismissed under the
        # remaining row cap, the rest on later passes (Settle)
        withdraw_orphan_suggestions(self.inv, self.snap, d.from_device, self.now)
        self.writes += dismiss_open_candidates(
            self.inv, d.from_device, MAX_ROWS_PER_PASS - self.writes
        )
        if open_candidates_left(self.inv, d.from_device):
            state_set(self.inv, f"settle:{d.from_device}", "1")
        before = short_hash(old["mac"]) if old else "none"
        emit_event(self.inv, d.target, "mac_attached", "info",
                   f"mac attached: {before} -> {short_hash(d.mac)}", self.now)  # fmt: skip
        self.stats.attached += 1
        self.attaches += 1
        log(logger, logging.INFO, "mac_attached", old=before, new=short_hash(d.mac))


def _rule_lookup(overrides: sqlite3.Connection, d: Attach, group: str | None, at: float) -> bool:
    """Primary-key reads of exactly the rows the attach depends on, in one read transaction."""
    overrides.execute("BEGIN")
    try:
        row = overrides.execute(
            "SELECT id, device_id, signature, created_by, expires_at, revoked_at FROM"
            " identity_rules WHERE id=?",
            (d.rule.id,),
        ).fetchone()
        if row is None or not rule_active(row, at) or parse_rule(row) != d.rule:
            return False
        if canonical_device(overrides, d.rule.device_id) != d.target:
            return False
        if canonical_device(overrides, d.from_device) != d.from_device:
            return False  # the candidate's device was merged away in the meantime
        over = overrides.execute(
            "SELECT group_id FROM device_overrides WHERE device_id=?", (d.target,)
        ).fetchone()
        if over is None or over[0] is None or over[0] != group:
            return False
        grp = overrides.execute("SELECT auto_inherit FROM groups WHERE id=?", (over[0],)).fetchone()
        return grp is not None and grp[0] == 1 and not isinstance(grp[0], bool)
    finally:
        if overrides.in_transaction:
            overrides.execute("COMMIT")


def apply_plan(
    inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
    clock: Callable[[], float], overrides: sqlite3.Connection | None, plan: Plan,
) -> StitchStats:  # fmt: skip
    stats = plan.stats
    with immediate(inv):
        at = clock()  # read once the lock is held: rule expiry is judged against it
        applier = Applier(inv, snap, overrides, cfg, now, at, stats)
        for decision in plan.decisions:
            applier.apply(decision)
        for key, value in plan.cursors.items():
            state_set(inv, key, value)
        if snap.malformed_rules:
            emit_once(inv, None, "rule_malformed", "warn",
                      f"{snap.malformed_rules} identity_rules rows with malformed fields ignored",
                      applier.day, now)  # fmt: skip
    return stats
