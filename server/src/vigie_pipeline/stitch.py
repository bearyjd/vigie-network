"""Identity stitching (PRP section 8; docs/stitching.md): candidates, ambiguity, overlap veto,
immutable merge suggestions, and application of human-approved standing rules.

The pipeline never writes overrides.db and never creates trust. It applies a rule only when it
is an active, non-blank-creator rule read from overrides.db. That the creator is a human is NOT
checkable here (created_by is just a principal name): it is enforced by the API, which must be the
sole writer of identity_rules and must reject non-human principals. Everything else stays a
suggestion for a human to accept.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from vigie_ingest.db import immediate
from vigie_pipeline.activity import Interval, load_activity, merge_intervals, overlap_seconds
from vigie_pipeline.config import (
    MAX_FLOOD_EVENTS_PER_PASS,
    MAX_INTERVALS_PER_MAC,
    MAX_OVERLAP_OPS_PER_PASS,
    MAX_ROWS_PER_PASS,
    MAX_SIGNATURE_BUCKET,
    PEER_TAIL_MIN_GRACE_MULT,
    SIGNAL_WEIGHTS,
    PipelineConfig,
)
from vigie_pipeline.logs import log
from vigie_pipeline.snapshot import Rule, Snapshot
from vigie_pipeline.stitch_db import (
    emit_event,
    emit_once,
    ensure_merge_suggestion,
    upsert_candidate,
    withdraw_open_suggestions,
)

logger = logging.getLogger("vigie_pipeline")
EPSILON = 1e-9


@dataclass(frozen=True)
class Obs:
    mac: str
    device_id: str
    canon: str
    randomized: bool
    source: str
    opt55: str | None
    opt60: str | None
    hostname: str | None
    mdns: str | None
    first_seen: str


@dataclass
class StitchStats:
    candidates: int = 0
    suggestions: int = 0
    attached: int = 0
    vetoed: int = 0
    ambiguous: int = 0
    flooded: int = 0
    capped: int = 0
    suspect: int = 0


GroupKey = tuple[str, str, str, str]


class BudgetExhaustedError(Exception):
    """The per-pass overlap-computation budget is spent: stop stitching new candidates."""


def group_keys(o: Obs) -> list[GroupKey]:
    """Name groups of a MAC: (opt55, opt60, kind, casefolded name) per available name."""
    if not (o.opt55 and o.opt60):
        return []
    return [(o.opt55, o.opt60, kind, name.casefold())
            for kind, name in (("h", o.hostname), ("m", o.mdns)) if name]  # fmt: skip


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.casefold() == b.casefold()  # type: ignore[union-attr]


def signals(a: Obs, b: Obs) -> list[str]:
    out = []
    if a.opt55 and a.opt55 == b.opt55:
        out.append("opt55")
    if a.opt60 and a.opt60 == b.opt60:
        out.append("opt60")
    if _same(a.mdns, b.mdns):
        out.append("mdns_name")
    if _same(a.hostname, b.hostname):
        out.append("hostname")
    return out


def is_candidate_match(found: list[str]) -> bool:
    """opt55 AND opt60 AND (hostname OR mdns_name). Hostname alone is never enough."""
    return "opt55" in found and "opt60" in found and ("mdns_name" in found or "hostname" in found)


def score_of(found: Iterable[str]) -> float:
    return round(sum(SIGNAL_WEIGHTS[s] for s in found), 6)


def rule_matches(rule: Rule, o: Obs) -> bool:
    """Every field the rule names must be equal; opt55 and opt60 are always required."""
    return (
        o.opt55 == rule.opt55
        and o.opt60 == rule.opt60
        and (rule.hostname is None or _same(rule.hostname, o.hostname))
        and (rule.mdns_name is None or _same(rule.mdns_name, o.mdns))
    )


def rule_score(rule: Rule) -> float:
    named = [n for n, v in (("hostname", rule.hostname), ("mdns_name", rule.mdns_name)) if v]
    return score_of(["opt55", "opt60", *named])


def _load_obs(inv: sqlite3.Connection, snap: Snapshot) -> list[Obs]:
    return [
        Obs(r["mac"], r["device_id"], snap.canonical(r["device_id"]), bool(r["is_randomized"]),
            r["link_source"], r["dhcp_fingerprint"] or None, r["vendor_class"] or None,
            r["hostname"] or None, r["mdns_name"] or None, r["first_seen"])
        for r in inv.execute(
            "SELECT mac, device_id, is_randomized, dhcp_fingerprint, vendor_class, hostname,"
            " mdns_name, link_source, first_seen FROM observations ORDER BY first_seen, mac"
        )
    ]  # fmt: skip


class Stitcher:
    def __init__(self, inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float):
        self.inv, self.snap, self.cfg, self.now = inv, snap, cfg, now
        self.act = {  # only the most recent intervals of a MAC are compared
            m: ivs[-MAX_INTERVALS_PER_MAC:]
            for m, ivs in load_activity(inv, cfg.activity_gap_s).items()
        }
        self.ops = 0  # overlap-computation budget spent this pass
        self.flood_events = 0
        self.flood_suppressed = 0
        self.stats = StitchStats()
        self.handled: set[str] = set()
        self.flooded_keys: set[GroupKey] = set()
        self.writes = 0  # candidate/suggestion rows written this pass
        self.reload()

    def reload(self) -> None:
        self.obs = _load_obs(self.inv, self.snap)
        self.by_canon: dict[str, list[Obs]] = defaultdict(list)
        self.groups: dict[GroupKey, list[Obs]] = defaultdict(list)
        for o in self.obs:
            self.by_canon[o.canon].append(o)
            for key in group_keys(o):
                self.groups[key].append(o)
        self._canon_ivs: dict[str, list[Interval]] = {}
        self._bad_pairs_cache: dict[tuple[GroupKey, ...], set[frozenset[str]]] = {}
        self._live_sizes: dict[GroupKey, int] | None = None
        self._by_fp: dict[tuple[str | None, str | None], list[Obs]] | None = None

    def _charge(self, units: int = 1) -> None:
        self.ops += units
        if self.ops > MAX_OVERLAP_OPS_PER_PASS:
            raise BudgetExhaustedError

    # ---- activity helpers -------------------------------------------------------------------

    def _union(self, macs: Iterable[str], tail: int = 0) -> list[Interval]:
        """Merged activity of several MACs; `tail` extends every interval end (presence presumed
        until a full gap passes silently)."""
        ivs = [(s, e + tail) for m in set(macs) for s, e in self.act.get(m, ())]
        self._charge(1 + len(ivs) // 256)
        return merge_intervals(ivs)

    def _canon_macs(self, canons: Iterable[str]) -> set[str]:
        return {o.mac for c in canons for o in self.by_canon.get(c, [])}

    def _canon_union(self, canon: str) -> list[Interval]:
        if canon not in self._canon_ivs:
            self._canon_ivs[canon] = self._union(o.mac for o in self.by_canon.get(canon, []))
        return self._canon_ivs[canon]

    def covered(self, mac: str) -> int:
        """Seconds of observed activity (sum of the widened intervals): sparse stamps count only
        for the time they cover, not for the span between them."""
        return sum(end - start for start, end in self.act.get(mac, ()))

    def sustained(self, mac: str, others: Iterable[str]) -> bool:
        """Concurrent activity that rules out a rolling twin. Sustained = overlap longer than the
        grace window; OR any overlap covering all of this MAC's time; OR, for a MAC observed longer
        than the grace, any overlap leaving it less than half an activity gap of time of its own
        (a "tail lead" of seconds of attacker-only time must not defeat the veto; half a gap
        because a lone stamp is widened by that much on each side). An established peer interval
        (longer than PEER_TAIL_MIN_GRACE_MULT grace windows) is presumed present for one gap past
        its last stamp, since it is only gone after a full gap of silence; short bursts, like
        the minutes-long MACs of a fast roller, get no such tail."""
        grace, gap = self.cfg.overlap_grace_s, self.cfg.activity_gap_s
        ivs = [
            (s, e + (gap if e - s > PEER_TAIL_MIN_GRACE_MULT * grace else 0))
            for m in set(others) for s, e in self.act.get(m, ())
        ]  # fmt: skip
        self._charge(2 + len(ivs) // 256)
        overlap = overlap_seconds(self.act.get(mac, []), merge_intervals(ivs))
        covered = self.covered(mac)
        lead = covered - overlap
        return overlap > grace or (
            overlap > 0 and (lead <= 0 or (covered > grace and lead < gap // 2))
        )

    def _live(self, o: Obs) -> bool:
        """Still a self device and active inside the activity retention window."""
        ivs = self.act.get(o.mac)
        return (
            o.source == "self"
            and bool(ivs)
            and ivs[-1][1] >= self.now - self.cfg.activity_retention_s
        )

    def name_peers(self, c: Obs) -> list[Obs]:
        """Every other MAC with c's opt55 and opt60 and an agreeing hostname or mDNS name: the
        candidate-style match, whatever other fields a rule may additionally name."""
        found = {o.mac: o for key in group_keys(c) for o in self.groups[key] if o.mac != c.mac}
        return list(found.values())

    def _pool(self, c: Obs) -> list[Obs]:
        """Live self MACs sharing c's opt55 and opt60 (the compatible-peer pool, c included)."""
        if self._by_fp is None:
            self._by_fp = defaultdict(list)
            for o in self.obs:
                if self._live(o):
                    self._by_fp[(o.opt55, o.opt60)].append(o)
        return self._by_fp.get((c.opt55, c.opt60), [])

    def _compat_flooded(self, c: Obs, peers: set[str]) -> bool:
        """A compatible-peer set over MAX_SIGNATURE_BUCKET cannot be told apart: it is reported as
        a signature flood (same event path as name groups, once per signature per pass)."""
        key: GroupKey = (c.opt55 or "", c.opt60 or "", "p", "")
        over = [(key, len(peers))] if len(peers) > MAX_SIGNATURE_BUCKET else []
        self._report_flood(over, c.device_id)
        return bool(over)

    def _close_in_time(self, a: Obs, b: Obs) -> bool:
        """First sightings within one activity gap of each other."""
        first = [datetime.fromisoformat(o.first_seen.replace("Z", "+00:00")) for o in (a, b)]
        return abs((first[0] - first[1]).total_seconds()) <= self.cfg.activity_gap_s

    def _compat_raw(self, c: Obs) -> set[str]:
        pool = self._pool(c)
        self._charge(1 + len(pool) // 64)
        return {
            o.mac for o in pool
            if o.mac != c.mac and not (
                (o.hostname and c.hostname and not _same(o.hostname, c.hostname))
                or (o.mdns and c.mdns and not _same(o.mdns, c.mdns))
            ) and (o.hostname or o.mdns or self._close_in_time(o, c))
        }  # fmt: skip

    def compatible_peers(self, c: Obs) -> set[str]:
        """Live self MACs with c's opt55 and opt60 whose hostname and mDNS name do not contradict
        c's (a missing name cannot be told apart): the victim's new MAC that has only revealed an
        mDNS name, or no hostname yet, is still a peer of a hostname-copying twin. A MAC with no
        name at all (anyone can send the public opt55/opt60) is a peer only when first seen within
        one activity gap of c. More than MAX_SIGNATURE_BUCKET peers yield none (reported as a
        flood; a rule attach refuses it)."""
        peers = self._compat_raw(c)
        return set() if self._compat_flooded(c, peers) else peers

    def eligible(self, o: Obs) -> bool:
        return bool(
            o.source == "self" and o.randomized and o.canon == o.device_id
            and o.opt55 and o.opt60 and (o.hostname or o.mdns) and self.act.get(o.mac)
        )  # fmt: skip

    def _live_size(self, key: GroupKey) -> int:
        if self._live_sizes is None:  # once per reload, not once per member
            sizes: dict[GroupKey, int] = defaultdict(int)
            for o in self.obs:
                if self._live(o):
                    for k in group_keys(o):
                        sizes[k] += 1
            self._live_sizes = sizes
        return self._live_sizes.get(key, 0)

    def _flooded(self, o: Obs) -> bool:
        """A name group (opt55, opt60 and one hostname or mDNS name) with more than
        MAX_SIGNATURE_BUCKET live MACs is skipped: attached, retired or silent MACs do not count,
        and MACs with other names never share the group. One event per group per UTC day; at most
        MAX_FLOOD_EVENTS_PER_PASS new events per pass, the rest are counted in one daily summary."""
        over = [
            (key, size)
            for key in group_keys(o)
            if (size := self._live_size(key)) > MAX_SIGNATURE_BUCKET
        ]
        self._report_flood(over, o.device_id)
        return bool(over)

    def _report_flood(self, over: list[tuple[GroupKey, int]], device_id: str) -> None:
        fresh = [(key, size) for key, size in over if key not in self.flooded_keys]
        if fresh:  # one event for the whole flooded population, however many names it shares
            key, size = fresh[0]
            if self.flood_events >= MAX_FLOOD_EVENTS_PER_PASS:
                self.flood_suppressed += 1
            else:
                token = short_hash("|".join(key))
                if emit_once(self.inv, device_id, "signature_flood", "warn",
                             f"signature flood {token}: {size} MACs skipped",
                             f"{token}:{self._day()}", self.now):  # fmt: skip
                    self.flood_events += 1
                log(logger, logging.WARNING, "signature_flood", signature=token, macs=size)
                self.stats.flooded += 1
        self.flooded_keys.update(key for key, _ in over)

    def _day(self) -> str:
        return datetime.fromtimestamp(self.now, tz=UTC).strftime("%Y-%m-%d")

    def _eligible_sorted(self, undecided_first: bool = False) -> list[Obs]:
        """Eligible, unflooded MACs by age. With undecided_first, MACs that have no candidate row
        yet go first, so a pass that runs out of budget still makes progress on new ones."""
        decided = (
            {r[0] for r in self.inv.execute("SELECT DISTINCT device_a FROM identity_candidates")}
            if undecided_first else set()
        )  # fmt: skip
        return sorted(
            (o for o in self.obs if self.eligible(o) and not self._flooded(o)),
            key=lambda o: (o.device_id in decided, o.first_seen, o.mac),
        )

    def _full(self) -> bool:
        if self.writes < MAX_ROWS_PER_PASS:
            return False
        self.stats.capped += 1
        return True

    # ---- recording -------------------------------------------------------------------------

    def _record(self, c: Obs, into: str, score: float, evidence: dict, state: str) -> str | None:
        if self._full():
            return None
        cid, changed = upsert_candidate(
            self.inv, c.device_id, into, score, evidence, state, self.now
        )
        self.stats.candidates += changed
        self.writes += changed
        return cid

    def _withdraw(self, c: Obs, canons: Iterable[str]) -> None:
        for canon in canons:
            withdraw_open_suggestions(self.inv, self.snap, c.device_id, canon, self.now)

    def _veto(self, c: Obs, into: str, score: float, evidence: dict) -> None:
        self._withdraw(c, [into])
        if self._record(c, into, score, evidence, "vetoed") is None:
            return
        token = "~".join(sorted((c.device_id, into)))
        if emit_once(self.inv, c.device_id, "identity_overlap_veto", "warn",
                     f"identity overlap veto {token}", token, self.now):  # fmt: skip
            self.stats.vetoed += 1
            log(logger, logging.INFO, "identity_overlap_veto", mac=short_hash(c.mac))

    def _ambiguous(self, c: Obs, canons: list[str], score: float, evidence: dict) -> None:
        self._withdraw(c, canons)
        for canon in canons:
            if self._record(c, canon, score, evidence, "ambiguous") is None:
                return
        if emit_once(self.inv, c.device_id, "identity_candidate_ambiguous", "warn",
                     f"identity candidate ambiguous: {len(canons)} devices match {c.device_id}",
                     c.device_id, self.now):  # fmt: skip
            self.stats.ambiguous += 1
            log(logger, logging.INFO, "identity_candidate_ambiguous", mac=short_hash(c.mac))

    def _suggest(
        self, c: Obs, into: str, score: float, evidence: dict, reason: str, found: list[str]
    ) -> None:
        cid = self._record(c, into, score, evidence, "suggested")
        if cid is None:
            return
        summary = {
            "candidate_id": cid,
            "signals": found,
            "hashes": {k: short_hash(str(v)) for k, v in evidence.items() if k in HASHED and v},
        }
        out = ensure_merge_suggestion(
            self.inv, self.snap, c.device_id, into, score=score, reason_code=reason,
            evidence_summary=summary, now=self.now, ttl_s=self.cfg.suggestion_ttl_s,
        )  # fmt: skip
        if out.status == "rejected":
            self.inv.execute("UPDATE identity_candidates SET state='dismissed' WHERE id=?", (cid,))
        elif out.status == "created":
            self.stats.suggestions += 1
            self.writes += 1
            token = f"{c.device_id} -> {into}"
            emit_once(self.inv, c.device_id, "identity_candidate", "info",
                      f"identity candidate {token} score {score:.2f}", token, self.now)  # fmt: skip
            log(logger, logging.INFO, "identity_suggestion", reason=reason, score=score)

    # ---- pass 1: standing rules --------------------------------------------------------------

    def run(self) -> None:
        """Three phases, each with its OWN overlap budget, so a phase that runs out never starves
        the next: the post-attach re-check first (it is the only guard on trust already given),
        then standing rules, then fingerprint candidates."""
        for phase in (self._recheck_rule_attached, self.apply_rules, self.stitch_candidates):
            self.ops = 0
            try:
                phase()
            except BudgetExhaustedError:  # raised before any write of the interrupted decision
                emit_once(self.inv, None, "stitch_budget_exhausted", "warn",
                          "stitching overlap budget exhausted: remaining work resumes next"
                          " pass", self._day(), self.now)  # fmt: skip
                log(logger, logging.WARNING, "stitch_budget_exhausted",
                    phase=phase.__name__, ops=self.ops)  # fmt: skip
        self.ops = 0
        if self.flood_suppressed:
            emit_once(self.inv, None, "signature_flood_summary", "warn",
                      f"{self.flood_suppressed} further signature floods not reported this pass",
                      f"summary:{self._day()}", self.now)  # fmt: skip

    def apply_rules(self) -> None:
        if self.snap.rules:
            for c in self._eligible_sorted(undecided_first=True):
                self._apply_rule(c)

    def _recheck_rule_attached(self) -> None:
        """A rule-attached MAC found to overlap its peers beyond the veto limit is only flagged:
        the pipeline never rewrites trust (no detach). One rule_attach_suspect event per MAC."""
        for o in self.obs:
            if o.source != "rule" or not self.act.get(o.mac):
                continue
            peers = (
                self._canon_macs([o.canon]) | {p.mac for p in self.name_peers(o)}
                | self.compatible_peers(o)
            ) - {o.mac}  # fmt: skip
            if not self.sustained(o.mac, peers):
                continue
            token = f"{short_hash(o.mac)}~{o.canon}"
            if emit_once(self.inv, o.canon, "rule_attach_suspect", "warn",
                         f"rule attach suspect {short_hash(o.mac)}: sustained overlap with peers",
                         token, self.now):  # fmt: skip
                self.stats.suspect += 1
                log(logger, logging.WARNING, "rule_attach_suspect", mac=short_hash(o.mac))

    def _vetoed(self, c: Obs, into: str) -> bool:
        """A (candidate, target) pair once vetoed stays vetoed: re-evaluating it would only let
        the interval cap or fresh lone stamps launder the overlap that justified the veto."""
        return (
            self.inv.execute(
                "SELECT 1 FROM identity_candidates"
                " WHERE device_a=? AND device_b=? AND state='vetoed'",
                (c.device_id, into),
            ).fetchone()
            is not None
        )

    def _state_ok(self, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT identity_state FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        return bool(row) and row[0] == "ok"

    def _apply_rule(self, c: Obs) -> None:
        if self.covered(c.mac) <= self.cfg.overlap_grace_s:
            return  # too little observed history to rule out an overlapping twin: defer quietly
        matched = [r for r in self.snap.rules if rule_matches(r, c)]
        targets = sorted({self.snap.canonical(r.device_id) for r in matched})
        if not matched or c.canon in targets:
            return
        evidence = {"rule_ids": sorted(r.id for r in matched), **_evidence(c)}
        if len(targets) > 1:  # a signature that names two devices attaches nothing
            self.handled.add(c.mac)
            self._ambiguous(c, targets, max(map(rule_score, matched)), evidence)
            return
        target = targets[0]
        if not self.inv.execute("SELECT 1 FROM devices WHERE id=?", (target,)).fetchone():
            log(logger, logging.WARNING, "rule_device_missing", device_id=target)
            return
        self.handled.add(c.mac)
        if self._vetoed(c, target):
            return
        compat = self._compat_raw(c)
        if self._compat_flooded(c, compat):
            return  # too many look-alikes to rule out a twin: attach nothing, suggest nothing
        rule = min((r for r in matched), key=lambda r: r.id)
        score = rule_score(rule)
        # peers: the target's MACs, every MAC that agrees with c on opt55, opt60 and a name (even
        # one a stricter rule would not match) and every live MAC with the same opt55 and opt60
        # whose names do not contradict c's (the victim's own new MAC that has only an mDNS name)
        peers = (
            self._canon_macs([target]) | {o.mac for o in self.name_peers(c)} | compat
        )  # fmt: skip
        if self.sustained(c.mac, peers - {c.mac}):
            self._veto(c, target, score, evidence)
            return
        group = self.snap.overrides.get(target, (0, None))[1]
        trusted_state = self._state_ok(target) and self._state_ok(c.device_id)
        if trusted_state and group is not None and self.snap.group_auto_inherit.get(group) == 1:
            self._attach(c, target, rule, score)
        else:  # unassigned, auto_inherit=0, unknown group or identity_state != 'ok': human confirms
            found = ["opt55", "opt60", *(n for n in ("hostname", "mdns_name") if getattr(rule, n))]
            self._suggest(c, target, score, evidence, "rule_hit_needs_confirm", found)

    def _attach(self, c: Obs, target: str, rule: Rule, score: float) -> None:
        old = self.inv.execute(
            "SELECT mac FROM observations WHERE device_id=? AND mac<>?"
            " ORDER BY last_seen DESC, mac LIMIT 1",
            (target, c.mac),
        ).fetchone()
        moved = self.inv.execute(
            "UPDATE observations SET device_id=?, link_source='rule', link_rule_id=?,"
            " link_score=? WHERE mac=? AND link_source='self'",
            (target, rule.id, score, c.mac),
        ).rowcount
        if not moved:
            return
        self.inv.execute(
            "UPDATE devices SET first_seen=MIN(first_seen,(SELECT first_seen FROM devices"
            " WHERE id=?)), last_seen=MAX(last_seen,(SELECT last_seen FROM devices WHERE id=?))"
            " WHERE id=?",
            (c.device_id, c.device_id, target),
        )
        left = self.inv.execute(
            "SELECT COUNT(*) FROM observations WHERE device_id=?", (c.device_id,)
        ).fetchone()[0]
        if not left:  # the orphaned self device is retired, never deleted
            self.inv.execute("UPDATE devices SET status='retired' WHERE id=?", (c.device_id,))
        self.inv.execute(  # settled by the rule; an earlier open suggestion just expires
            "UPDATE identity_candidates SET state='dismissed' WHERE device_a=?"
            " AND state IN ('open','suggested')",
            (c.device_id,),
        )
        before = short_hash(old["mac"]) if old else "none"
        emit_event(self.inv, target, "mac_attached", "info",
                   f"mac attached: {before} -> {short_hash(c.mac)}", self.now)  # fmt: skip
        self.stats.attached += 1
        log(logger, logging.INFO, "mac_attached", old=before, new=short_hash(c.mac))
        self.reload()  # the canonical map changed: later MACs must see this attachment

    # ---- pass 2: fingerprint candidates ----------------------------------------------------------

    def stitch_candidates(self) -> None:
        for c in self._eligible_sorted(undecided_first=True):
            if self._full():
                break
            if c.mac not in self.handled:
                self._candidate(c)

    def _older(self, p: Obs, c: Obs) -> bool:
        if p.first_seen != c.first_seen:
            return p.first_seen < c.first_seen
        return not self.eligible(p) or p.mac < c.mac  # tie: only one direction per pair

    def _candidate(self, c: Obs) -> None:
        peers = [(o, f) for o in self.name_peers(c) if o.canon != c.canon
                 if is_candidate_match(f := signals(c, o))]  # fmt: skip
        older = [(o, f) for o, f in peers if self._older(o, c)]
        if not older:
            return
        by_dev: dict[str, list[tuple[Obs, list[str]]]] = defaultdict(list)
        for o, f in peers:
            by_dev[o.canon].append((o, f))
        oldest = min(older, key=lambda p: (p[0].first_seen, p[0].mac))[0]
        into = oldest.canon
        if self._vetoed(c, into):
            return
        best_o, best_f = max(by_dev[into], key=lambda p: (score_of(p[1]), len(p[1]), p[0].mac))
        score = score_of(best_f)
        evidence = {**_evidence(c), "into_mac": best_o.mac, "signals": best_f}
        canons = sorted(by_dev)
        if self._has_concurrent_pair(c, canons):
            self._ambiguous(c, canons, score, evidence)
        elif self.sustained(c.mac, self._canon_macs(canons)):
            self._veto(c, into, score, evidence)
        elif score + EPSILON >= self.cfg.suggest_threshold:
            self._suggest(c, into, score, evidence, "fingerprint_match", best_f)
        else:
            self._record(c, into, score, evidence, "open")

    def _has_concurrent_pair(self, c: Obs, canons: list[str]) -> bool:
        """Two matching devices that were active together beyond the grace window are provably
        distinct: the signature then names more than one device. The concurrent pairs of c's name
        groups are computed once per pass (a sweep) and short-circuit on the first hit."""
        bad = self._concurrent_pairs(tuple(sorted(group_keys(c))))
        have = set(canons)
        return any(pair <= have for pair in bad)

    def _concurrent_pairs(self, keys: tuple[GroupKey, ...]) -> set[frozenset[str]]:
        if keys in self._bad_pairs_cache:
            return self._bad_pairs_cache[keys]
        canons = {o.canon for k in keys for o in self.groups[k]}
        events = sorted((s, e, c) for c in canons for s, e in self._canon_union(c))
        grace, bad = self.cfg.overlap_grace_s, set()
        acc: dict[frozenset[str], int] = defaultdict(int)
        active: list[tuple[int, str]] = []  # (end, canon) of intervals still open at the sweep
        steps = 0
        for start, end, canon in events:
            active = [a for a in active if a[0] > start]
            steps += 1 + len(active)
            if steps >= 64:  # one budget unit per 64 comparisons
                self._charge(steps // 64)
                steps %= 64
            for a_end, a_canon in active:
                pair = frozenset((a_canon, canon))
                if pair not in bad:
                    acc[pair] += min(a_end, end) - start
                    if acc[pair] > grace:
                        bad.add(pair)
            active.append((end, canon))
        self._bad_pairs_cache[keys] = bad
        return bad


HASHED = ("opt55", "opt60", "hostname", "mdns_name")


def _evidence(c: Obs) -> dict:
    """Full values: stored only in identity_candidates.evidence, never logged."""
    return {"from_mac": c.mac, "opt55": c.opt55, "opt60": c.opt60, "hostname": c.hostname,
            "mdns_name": c.mdns}  # fmt: skip


def stitch(inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float) -> StitchStats:
    """One stitching pass over inventory.db (a single transaction)."""
    with immediate(inv):
        stitcher = Stitcher(inv, snap, cfg, now)
        stitcher.run()
    log(logger, logging.INFO, "stitch_complete", **stitcher.stats.__dict__)
    return stitcher.stats
