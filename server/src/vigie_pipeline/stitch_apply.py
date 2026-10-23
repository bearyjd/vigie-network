"""APPLY phase of identity stitching (docs/stitching-design.md section 4): one short
BEGIN IMMEDIATE that re-validates every decision of the plan with indexed point lookups (the
pair's candidate state, the MAC's link, both identity states) and, immediately before each attach
write, that overrides.db is unwritten since the snapshot (PRAGMA data_version on the pipeline's
own connection); drops what went stale; writes a count-bounded number of rows: at most
MAX_ROWS_PER_PASS candidate/suggestion/widen/cleanup rows and MAX_ATTACHES_PER_PASS attaches.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from vigie_ingest.db import immediate
from vigie_pipeline.config import (
    CLEANUP_ROWS_SHARE,
    MAX_ATTACHES_PER_PASS,
    MAX_OPEN_SUGGESTIONS_PER_DEVICE,
    MAX_ROWS_PER_PASS,
    PipelineConfig,
)
from vigie_pipeline.logs import log
from vigie_pipeline.snapshot import Snapshot
from vigie_pipeline.stitch_db import (
    Attachment,
    SuggestionOutcome,
    candidate_state,
    candidate_write_needed,
    create_merge_suggestion,
    dismiss_open_candidates,
    emit_event,
    emit_once,
    find_merge_suggestion,
    open_candidates_left,
    open_suggestions_into,
    prepare_merge_decisions,
    save_attachment,
    state_get,
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
        cfg: PipelineConfig, now: float, clock: Callable[[], float], stats: StitchStats,
        merge_decisions: Mapping[str, SuggestionOutcome],
    ) -> None:  # fmt: skip
        self.inv, self.snap, self.overrides, self.cfg = inv, snap, overrides, cfg
        self.now, self.clock, self.stats = now, clock, stats
        self.merge_decisions = merge_decisions
        self.at = clock()  # the clock under the lock; read again before each attach write
        self.dirty = False  # overrides.db written since the snapshot: no more attaches this pass
        self.cleanup_writes = 0  # orphan cleanup rows this pass (<= CLEANUP_ROWS_SHARE of the cap)
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
        known = find_merge_suggestion(
            self.inv, self.merge_decisions, d.from_device, d.into, self.now
        )
        create = known is None
        state = "dismissed" if known is not None and known.status == "rejected" else "suggested"
        if create and open_suggestions_into(self.inv, d.into, self.now) >= (
            MAX_OPEN_SUGGESTIONS_PER_DEVICE
        ):
            create, state = False, "open"  # the human already has a flood of these to decide
            self.stats.deferred += 1
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
        """Finish an orphan's cleanup under this pass's remaining row cap."""
        self._cleanup(d.device_id)

    def _cleanup(self, device_id: str) -> None:
        """Expire the orphan's undecided suggestions (both directions) and dismiss its candidate
        rows, each charged to the row cap; a `settle:` key keeps whatever did not fit for later."""
        allowance = min(
            int(MAX_ROWS_PER_PASS * CLEANUP_ROWS_SHARE) - self.cleanup_writes,
            MAX_ROWS_PER_PASS - self.writes,
        )
        key = f"settle:{device_id}"
        stored = state_get(self.inv, key)
        cursor = json.loads(stored) if stored and stored.startswith("{") else {}
        written, more, cursor = withdraw_orphan_suggestions(
            self.inv, self.snap, device_id, self.now, allowance, cursor
        )
        written += dismiss_open_candidates(self.inv, device_id, allowance - written)
        self.writes += written
        self.cleanup_writes += written
        left = more or open_candidates_left(self.inv, device_id)
        state_set(self.inv, key, json.dumps(cursor, sort_keys=True) if left else None)

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
        """T1 against the snapshot and the clock read under the lock; the snapshot's currency is
        checked separately, immediately before the write (`_overrides_unchanged`)."""
        if d.rule.expires_at is not None and d.rule.expires_at <= self.at:
            return False
        group = self.snap.overrides.get(d.target, (0, None))[1]
        return (
            d.rule in self.snap.rules and self.snap.canonical(d.rule.device_id) == d.target
            and group is not None and self.snap.group_auto_inherit.get(group) == 1
        )  # fmt: skip

    def _overrides_unchanged(self) -> bool:
        """overrides.db has not been written since the snapshot was read: PRAGMA data_version on
        the pipeline's own long-lived connection, read FRESH immediately before every attach write
        (never cached: a commit between two attaches of one pass ends the pass for attaches). Any
        write (a merge, a new, revoked or malformed rule, a regroup) drops the attach; it is
        recomputed against a fresh snapshot next pass. Without an overrides connection (tests)
        the compute snapshot stands in. The remaining window between this read and the write is
        the cross-database race documented in docs/stitching.md; the next pass's re-check surfaces
        an attach made in it."""
        if self.overrides is None:
            return True
        if not self.dirty:
            try:
                row = self.overrides.execute("PRAGMA data_version").fetchone()  # type: ignore[union-attr]
                current: int | None = int(row[0])
            except (sqlite3.Error, TypeError, ValueError) as exc:  # unreadable: fail closed
                log(logger, logging.ERROR, "attach_revalidation_failed", error=str(exc))
                current = None
            self.dirty = current is None or current != self.snap.data_version
        if self.dirty:
            self.stats.stale += 1
        return not self.dirty

    def _state_ok(self, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT identity_state FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        return bool(row) and row[0] == "ok"

    def _attach(self, d: Attach) -> None:
        if self.attaches >= MAX_ATTACHES_PER_PASS:
            self.stats.capped += 1
            return
        self.at = self.clock()  # expiry does not change data_version: judge it per attach
        if not (
            self._authorised(d)
            and self._still_self(d.mac, d.from_device)
            and self._state_ok(d.target)
            and self._state_ok(d.from_device)
            and self._unchanged(d.from_device, d.target, d.expected)
        ):
            return  # expired, revoked, regrouped, vetoed or moved while the plan was computed
        old = self.inv.execute(
            "SELECT mac FROM observations WHERE device_id=? AND mac<>?"
            " ORDER BY last_seen DESC, mac LIMIT 1",
            (d.target, d.mac),
        ).fetchone()
        if not self._overrides_unchanged():  # the last read before the write: nothing in between
            return
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
        # settled by the rule: its open suggestions are expired and its candidate rows dismissed
        # under the remaining row cap, the rest on later passes (Settle)
        self._cleanup(d.from_device)
        before = short_hash(old["mac"]) if old else "none"
        emit_event(self.inv, d.target, "mac_attached", "info",
                   f"mac attached: {before} -> {short_hash(d.mac)}", self.now)  # fmt: skip
        self.stats.attached += 1
        self.attaches += 1
        log(logger, logging.INFO, "mac_attached", old=before, new=short_hash(d.mac))


def apply_candidate_decisions(inv: sqlite3.Connection, snap: Snapshot) -> None:
    """Consume human clears before COMPUTE, never attaching or changing observations.

    A receipt in inventory makes each decision id one-shot, including stale decisions whose
    candidate no longer matches. A later clear requires a new API decision id. Select outside
    the writer lock, then recheck receipts and exact candidate id/pair/state under the lock.
    At most MAX_ROWS_PER_PASS rows are written in this separate bounded transaction.
    """
    pending = []
    for decision in snap.candidate_decisions:
        key = f"candidate-clear:{decision.id}"
        if state_get(inv, key) is None:
            pending.append((key, decision))
            if len(pending) >= MAX_ROWS_PER_PASS // 2:
                break
    if not pending:
        return
    with immediate(inv):
        for key, decision in pending:
            if state_get(inv, key) is not None:
                continue
            inv.execute(
                "UPDATE identity_candidates SET state='dismissed'"
                " WHERE id=? AND device_a=? AND device_b=? AND state='vetoed'",
                (decision.candidate_id, decision.device_a, decision.device_b),
            )
            state_set(inv, key, "consumed")


def apply_plan(
    inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
    clock: Callable[[], float], overrides: sqlite3.Connection | None, plan: Plan,
) -> StitchStats:  # fmt: skip
    stats = plan.stats
    merge_decisions = (
        prepare_merge_decisions(inv, snap)
        if any(isinstance(d, Suggest) for d in plan.decisions)
        else {}
    )
    with immediate(inv):
        applier = Applier(inv, snap, overrides, cfg, now, clock, stats, merge_decisions)
        for decision in plan.decisions:
            applier.apply(decision)
        for key, value in plan.cursors.items():
            state_set(inv, key, value)
        if snap.malformed_rules:
            emit_once(inv, None, "rule_malformed", "warn",
                      f"{snap.malformed_rules} identity_rules rows with malformed fields ignored",
                      applier.day, now)  # fmt: skip
    return stats
