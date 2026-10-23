"""COMPUTE phase of identity stitching (docs/stitching-design.md): inside a read-only
transaction, examine at most MACS_PER_PASS rule-attached MACs (the post-attach re-check) and at
most MACS_PER_PASS self MACs (standing rules, then fingerprint candidates), round-robin from
persisted cursors, and turn each into DECISIONS that the apply phase re-validates under the lock.

Nothing here writes. Whenever the evidence of a subject is incomplete it DEGRADES (a suggestion
for a human, a provisional row, or a daily deferral event): never an attach, never a silent veto.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime

from vigie_pipeline.activity import Gaps, Interval, merge_intervals, overlap_seconds
from vigie_pipeline.config import (
    MACS_PER_PASS,
    MAX_ALIAS_IDS,
    MAX_ROWS_PER_PASS,
    MAX_SIGNATURE_BUCKET,
    PEER_TAIL_MIN_GRACE_MULT,
    STITCH_COMPUTE_BUDGET_S,
    PipelineConfig,
)
from vigie_pipeline.logs import log
from vigie_pipeline.snapshot import Rule, Snapshot
from vigie_pipeline.stitch_db import event_exists, load_attachment, state_get, vetoed_between
from vigie_pipeline.stitch_hood import Hood, load_obs
from vigie_pipeline.stitch_types import (
    EPSILON,
    Ambiguous,
    Attach,
    Candidate,
    Decision,
    Flag,
    GroupKey,
    Obs,
    Plan,
    StitchStats,
    Suggest,
    Veto,
    Widen,
    components,
    evidence_of,
    group_keys,
    is_candidate_match,
    rule_matches,
    rule_score,
    same,
    score_of,
    short_hash,
    signals,
)

logger = logging.getLogger("vigie_pipeline")
SELF_CURSOR = "cursor:self"
RECHECK_CURSOR = "cursor:recheck"
SUSPECT = "rule_attach_suspect"

SELF_SUBJECTS = (
    "SELECT DISTINCT a.mac FROM mac_activity a JOIN observations o ON o.mac = a.mac"
    " WHERE a.mac > ? AND a.\"end\" >= ? AND o.link_source = 'self' AND o.is_randomized = 1"
    " AND o.dhcp_fingerprint <> '' AND o.vendor_class <> ''"
    " AND (o.hostname <> '' OR o.mdns_name <> '') ORDER BY a.mac LIMIT ?"
)
RULE_SUBJECTS = (
    "SELECT mac FROM observations WHERE link_source='rule' AND mac > ? ORDER BY mac LIMIT ?"
)


class Compute:
    def __init__(
        self, inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:  # fmt: skip
        self.inv, self.snap, self.cfg, self.now = inv, snap, cfg, now
        self.monotonic = monotonic
        self.deadline = monotonic() + STITCH_COMPUTE_BUDGET_S
        self.components = components(snap.links)
        self.malformed_targets = frozenset(snap.canonical(d) for d in snap.malformed_devices)
        self.cutoff = int(now) - cfg.activity_retention_s
        self.gaps = Gaps(inv, self.cutoff - cfg.activity_gap_s)
        self.decisions: list[Decision] = []
        self.stats = StitchStats()
        self.flooded: set[GroupKey] = set()
        self.deferred: set[str] = set()
        self.day = datetime.fromtimestamp(now, tz=UTC).strftime("%Y-%m-%d")

    def run(self) -> Plan:
        """The re-check robin first (the only guard on trust already given), then the self robin,
        then the bounded range catch-up of merged devices."""
        cursors = {
            RECHECK_CURSOR: self._robin(RECHECK_CURSOR, self._rule_subjects, self._recheck),
            SELF_CURSOR: self._robin(SELF_CURSOR, self._self_subjects, self._examine),
        }
        self._widen()
        return Plan(tuple(self.decisions), cursors, self.stats)

    # ---- subjects --------------------------------------------------------------------------

    def _robin(
        self, key: str, fetch: Callable[[str], list[str]], handle: Callable[[str], None]
    ) -> str | None:
        """Up to MACS_PER_PASS subjects after the persisted cursor; stops between subjects when
        the compute budget is spent (the cursor then stays on the last finished one). Returns the
        new cursor, None once the robin wrapped."""
        after = state_get(self.inv, key) or ""
        macs = fetch(after)
        for i, mac in enumerate(macs):
            if self.monotonic() > self.deadline:
                self._defer("budget")
                return macs[i - 1] if i else (after or None)
            handle(mac)
        return macs[-1] if len(macs) >= MACS_PER_PASS else None

    def _self_subjects(self, after: str) -> list[str]:
        rows = self.inv.execute(SELF_SUBJECTS, (after, self.cutoff, MACS_PER_PASS))
        return [r[0] for r in rows]

    def _rule_subjects(self, after: str) -> list[str]:
        rows = self.inv.execute(RULE_SUBJECTS, (after, MACS_PER_PASS))
        return [r[0] for r in rows]

    def _hood(self) -> Hood:
        return Hood(self.inv, self.snap, self.cfg, self.components, self.cutoff)

    def _defer(self, reason: str, device_id: str | None = None) -> None:
        """One stitch_deferred event per reason per UTC day: a degrade is never silent."""
        self.stats.deferred += 1
        if reason in self.deferred:
            return
        self.deferred.add(reason)
        self.decisions.append(Flag("stitch_deferred", device_id, f"{reason}:{self.day}",
                                   f"stitching deferred ({reason}): a human decides or the work"
                                   " resumes next pass"))  # fmt: skip
        log(logger, logging.WARNING, "stitch_deferred", reason=reason)

    # ---- activity arithmetic ---------------------------------------------------------------

    def covered(self, hood: Hood, mac: str) -> int:
        return sum(end - start for start, end in hood.act.get(mac, ()))

    def maturity(self, hood: Hood, mac: str) -> str:
        """'ok' | 'young' | 'gap'. Mature = more than the grace window of covered time (widened,
        clipped intervals) AND first received by the SERVER more than the grace window ago AND
        no evidence gap overlaps the MAC's activity window (within one activity gap)."""
        grace, slack = self.cfg.overlap_grace_s, self.cfg.activity_gap_s
        first = hood.first_recv.get(mac)
        ivs = hood.act.get(mac, [])
        if not (self.covered(hood, mac) > grace and first is not None and self.now - first > grace):
            return "young"
        if ivs and self.gaps.overlaps(ivs[0][0] - slack, ivs[-1][1] + slack):
            return "gap"
        return "ok"

    def sustained(self, hood: Hood, mac: str, others: Iterable[str]) -> bool:
        """Concurrent activity that rules out a rolling twin: overlap longer than the grace window;
        OR any overlap covering all of this MAC's time; OR, for a MAC observed longer than the
        grace, any overlap leaving it less than half an activity gap of its own (a "tail lead" of
        seconds must not defeat the veto). An established peer interval (longer than
        PEER_TAIL_MIN_GRACE_MULT grace windows) is presumed present one gap past its last stamp."""
        grace, gap = self.cfg.overlap_grace_s, self.cfg.activity_gap_s
        ivs = [
            (s, e + (gap if e - s > PEER_TAIL_MIN_GRACE_MULT * grace else 0))
            for m in set(others) for s, e in hood.act.get(m, ())
        ]  # fmt: skip
        overlap = overlap_seconds(hood.act.get(mac, []), merge_intervals(ivs))
        covered = self.covered(hood, mac)
        lead = covered - overlap
        return overlap > grace or (
            overlap > 0 and (lead <= 0 or (covered > grace and 2 * lead < gap))
        )

    def _canon_union(self, hood: Hood, canon: str) -> list[Interval]:
        return merge_intervals(iv for o in hood.by_canon(canon) for iv in hood.act.get(o.mac, ()))

    def _concurrent(self, hood: Hood, canons: list[str]) -> bool:
        """Two matching devices active together beyond the grace window are provably distinct:
        the signature then names more than one device (one sweep over their interval unions)."""
        events = sorted((s, e, c) for c in canons for s, e in self._canon_union(hood, c))
        grace = self.cfg.overlap_grace_s
        acc: dict[frozenset[str], int] = defaultdict(int)
        active: list[tuple[int, str]] = []
        for start, end, canon in events:
            active = [a for a in active if a[0] > start]
            for a_end, a_canon in active:
                pair = frozenset((a_canon, canon))
                acc[pair] += min(a_end, end) - start
                if acc[pair] > grace:
                    return True
            active.append((end, canon))
        return False

    # ---- floods and peers ------------------------------------------------------------------

    def _flood(self, hood: Hood, key: GroupKey, size: int, device_id: str) -> None:
        self.stats.flooded += 1
        if key in self.flooded:
            return
        self.flooded.add(key)
        token = short_hash("|".join(key))
        self.decisions.append(Flag("signature_flood", device_id, f"{token}:{self.day}",
                                   f"signature flood {token}: {size} MACs skipped"))  # fmt: skip
        log(logger, logging.WARNING, "signature_flood", signature=token, macs=size)

    def _name_flooded(self, hood: Hood, c: Obs) -> bool:
        """A name group (opt55, opt60, one name) with more than MAX_SIGNATURE_BUCKET live MACs
        (attached, retired and silent MACs do not count) attaches nothing and is not compared."""
        groups = hood.groups()
        over = False
        for key in group_keys(c):
            size = sum(1 for o in groups.get(key, ()) if hood.counted(o))
            if size > MAX_SIGNATURE_BUCKET:
                self._flood(hood, key, size, c.device_id)
                over = True
        return over

    def _compatible(self, hood: Hood, c: Obs, known: set[str]) -> set[str]:
        """Live self MACs with c's opt55 and opt60 whose names do not contradict c's AND that share
        a name with c, carry a name the target already used, or were first seen within one gap."""
        gap = self.cfg.activity_gap_s
        return {
            o.mac for o in hood.obs.values()
            if o.mac != c.mac and hood.live(o) and (o.opt55, o.opt60) == (c.opt55, c.opt60)
            and not ((o.hostname and c.hostname and not same(o.hostname, c.hostname))
                     or (o.mdns and c.mdns and not same(o.mdns, c.mdns)))
            and (same(o.hostname, c.hostname) or same(o.mdns, c.mdns)
                 or any(n.casefold() in known for n in (o.hostname, o.mdns) if n)
                 or abs(o.first_ts - c.first_ts) <= gap)
        }  # fmt: skip

    def _gather_peers(self, hood: Hood, target: str, views: list[Obs]) -> None:
        hood.add_target(target)
        known = hood.names_of(target)
        for view in views:
            hood.add_keys(view)
            if view.opt55 and view.opt60:
                hood.add_close(view.opt55, view.opt60, view.first_ts)
                for name in known:
                    hood.add_name(view.opt55, view.opt60, "h", name)
                    hood.add_name(view.opt55, view.opt60, "m", name)
        hood.load()

    def _safety_peers(self, hood: Hood, target: str, views: list[Obs]) -> tuple[set[str], bool]:
        """MACs whose concurrent activity vetoes an attach (or flags an attached MAC), derived
        from the RULE and the target identity, never from names the applicant adds: the target's
        MACs, every MAC sharing a name with any of them, and per rule view its name peers and
        compatible peers. Returns (peers, compatible_pool_flooded)."""
        self._gather_peers(hood, target, views)
        peers, flooded = hood.canon_macs([target]), False
        known = hood.names_of(target)
        for t in hood.by_canon(target):
            peers |= {p.mac for p in hood.name_peers(t)}
        for view in views:
            peers |= {p.mac for p in hood.name_peers(view)}
            compat = self._compatible(hood, view, known)
            size = sum(1 for m in compat if hood.counted(hood.obs[m]))
            if size > MAX_SIGNATURE_BUCKET:
                self._flood(
                    hood, (view.opt55 or "", view.opt60 or "", "p", ""), size, view.device_id
                )
                flooded = True
            else:
                peers |= compat
        return peers, flooded

    def _veto_state(self, hood: Hood, a: str, b: str) -> str | None:
        """'vetoed' (a sticky veto joins the two identities), 'oversize' (a merge component too
        large to look up: a human decides) or None."""
        a_ids, b_ids = hood.alias_ids(a), hood.alias_ids(b)
        if min(len(a_ids), len(b_ids)) > MAX_ALIAS_IDS:
            self._defer("component_oversize", b)
            return "oversize"
        return "vetoed" if vetoed_between(self.inv, a_ids, b_ids) else None

    # ---- self subjects: standing rules, then fingerprint candidates ------------------------

    def _examine(self, mac: str) -> None:
        c = load_obs(self.inv, self.snap, mac)
        if c is None or c.source != "self" or c.canon != c.device_id:
            return
        hood = self._hood()
        hood.add_keys(c)
        hood.load(mac)
        if not hood.act.get(mac):
            return
        self.stats.examined += 1
        if self._name_flooded(hood, c):
            return
        if not self._rule_path(hood, c):
            self._candidate_path(hood, c)

    def _rule_live(self, rule: Rule) -> bool:
        return rule.expires_at is None or rule.expires_at > self.now

    def _rule_path(self, hood: Hood, c: Obs) -> bool:
        """Standing rules (docs/stitching.md section 6). True when the MAC is settled here."""
        matched = [r for r in self.snap.rules if rule_matches(r, c) and self._rule_live(r)]
        targets = sorted({self.snap.canonical(r.device_id) for r in matched})
        if not matched or c.canon in targets:
            return False
        maturity = self.maturity(hood, c.mac)
        if maturity == "young":
            return False  # too little trusted history yet: resolves itself, no noise
        evidence = {"rule_ids": sorted(r.id for r in matched), **evidence_of(c)}
        if len(targets) > 1:  # a signature that names two devices attaches nothing
            self.decisions.append(
                Ambiguous(
                    c.mac, c.device_id, tuple(targets), max(map(rule_score, matched)), evidence
                )
            )
            return True
        target = targets[0]
        if not self.inv.execute("SELECT 1 FROM devices WHERE id=?", (target,)).fetchone():
            log(logger, logging.WARNING, "rule_device_missing", device_id=target)
            return False
        veto = self._veto_state(hood, c.device_id, target)
        if veto == "vetoed":
            return True
        rule = min(matched, key=lambda r: r.id)
        masks = tuple(sorted({(bool(r.hostname), bool(r.mdns_name)) for r in matched}))
        views = [replace(c, hostname=c.hostname if h else None, mdns=c.mdns if m else None)
                 for h, m in masks]  # fmt: skip
        peers, flooded = self._safety_peers(hood, target, views)
        if flooded:
            return True  # too many look-alikes to rule out a twin: attach nothing, suggest nothing
        score = rule_score(rule)
        if self.sustained(hood, c.mac, peers - {c.mac}):
            if maturity == "gap":  # provisional: a gap means the overlap cannot be judged
                self._defer("evidence_gap", target)
                self.decisions.append(
                    Candidate(c.mac, c.device_id, target, score, evidence, "open")
                )
            else:
                self.decisions.append(Veto(c.mac, c.device_id, target, score, evidence))
            return True
        reason = self._incomplete(hood, veto, maturity, target)
        found = ("opt55", "opt60", *(n for n in ("hostname", "mdns_name") if getattr(rule, n)))
        if reason == "component_oversize":
            self.decisions.append(Candidate(c.mac, c.device_id, target, score, evidence, "open"))
        elif reason is not None or not self._gate(c, target):
            if reason:
                self._defer(reason, target)
            self.decisions.append(Suggest(c.mac, c.device_id, target, score, evidence,
                                          "rule_hit_needs_confirm", reason, found))  # fmt: skip
        else:
            self.decisions.append(Attach(
                c.mac, c.device_id, target, rule, score,
                c.hostname if any(r.hostname for r in matched) else None,
                c.mdns if any(r.mdns_name for r in matched) else None, c.opt55, c.opt60, masks,
            ))  # fmt: skip
        return True

    def _incomplete(self, hood: Hood, veto: str | None, maturity: str, target: str) -> str | None:
        """The one reason (if any) the evidence for an attach is incomplete."""
        if hood.truncated:
            return "truncated" if "truncated" in hood.truncated else sorted(hood.truncated)[0]
        if veto == "oversize":
            return "component_oversize"
        if maturity == "gap":
            return "evidence_gap"
        if target in self.malformed_targets:
            return "malformed_target"
        return None

    def _state_ok(self, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT identity_state FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        return bool(row) and row[0] == "ok"

    def _gate(self, c: Obs, target: str) -> bool:
        """Both devices identity_state='ok' and the target in an EXPLICIT auto_inherit=1 group."""
        group = self.snap.overrides.get(target, (0, None))[1]
        return (
            self._state_ok(target) and self._state_ok(c.device_id)
            and group is not None and self.snap.group_auto_inherit.get(group) == 1
        )  # fmt: skip

    def _older(self, hood: Hood, p: Obs, c: Obs) -> bool:
        if p.first_seen != c.first_seen:
            return p.first_seen < c.first_seen
        eligible = (
            p.source == "self"
            and p.randomized
            and p.canon == p.device_id
            and bool(p.opt55 and p.opt60 and (p.hostname or p.mdns) and hood.act.get(p.mac))
        )
        return not eligible or p.mac < c.mac  # tie: only one direction per pair

    def _candidate_path(self, hood: Hood, c: Obs) -> None:
        """Fingerprint candidates (docs/stitching.md sections 2-5)."""
        peers = [(o, f) for o in hood.name_peers(c) if o.canon != c.canon
                 if is_candidate_match(f := signals(c, o))]  # fmt: skip
        older = [(o, f) for o, f in peers if self._older(hood, o, c)]
        if not older:
            return
        if hood.truncated:  # the oldest identity, or a concurrent one, may be hidden
            self._defer("truncated", c.device_id)
            return
        by_dev: dict[str, list[tuple[Obs, list[str]]]] = defaultdict(list)
        for o, f in peers:
            by_dev[o.canon].append((o, f))
        into = min(older, key=lambda p: (p[0].first_seen, p[0].mac))[0].canon
        veto = self._veto_state(hood, c.device_id, into)
        if veto is not None:
            return
        best_o, best_f = max(by_dev[into], key=lambda p: (score_of(p[1]), len(p[1]), p[0].mac))
        score = score_of(best_f)
        evidence = {**evidence_of(c), "into_mac": best_o.mac, "signals": best_f}
        canons = sorted(by_dev)
        if self._concurrent(hood, canons):
            self.decisions.append(Ambiguous(c.mac, c.device_id, tuple(canons), score, evidence))
        elif self.sustained(hood, c.mac, hood.canon_macs(canons)):
            if self.maturity(hood, c.mac) == "ok":
                self.decisions.append(Veto(c.mac, c.device_id, into, score, evidence))
            else:  # provisional evidence, never a permanent veto: written only once
                self.decisions.append(
                    Candidate(c.mac, c.device_id, into, score, evidence, "open", provisional=True)
                )
        elif score + EPSILON >= self.cfg.suggest_threshold:
            self.decisions.append(Suggest(c.mac, c.device_id, into, score, evidence,
                                          "fingerprint_match", None, tuple(best_f)))  # fmt: skip
        else:
            self.decisions.append(Candidate(c.mac, c.device_id, into, score, evidence, "open"))

    # ---- rule-attached subjects: the post-attach re-check ----------------------------------

    def _recheck(self, mac: str) -> None:
        """A rule-attached MAC that overlaps its peers beyond the veto limit, or whose evidence
        cannot be gathered completely, is FLAGGED once (rule_attach_suspect): never detached."""
        o = load_obs(self.inv, self.snap, mac)
        if o is None or o.source != "rule":
            return
        token = f"{short_hash(mac)}~{o.canon}"
        if event_exists(self.inv, SUSPECT, token) or not self._has_activity(mac):
            return
        self.stats.examined += 1
        att = load_attachment(self.inv, mac)
        if att is None:
            self._suspect(o, token, "attach evidence missing")
            return
        base = replace(o, opt55=att.opt55 or o.opt55, opt60=att.opt60 or o.opt60)
        views = [replace(base, hostname=att.hostname if h else None,
                         mdns=att.mdns_name if m else None) for h, m in att.views]  # fmt: skip
        hood = self._hood()
        hood.load(mac)
        peers, _ = self._safety_peers(hood, o.canon, views)
        if self.sustained(hood, mac, peers - {mac}):
            self._suspect(o, token, "sustained overlap with peers")
        elif hood.truncated:
            self._suspect(o, token, "evidence incomplete, " + sorted(hood.truncated)[0])

    def _has_activity(self, mac: str) -> bool:
        return self.inv.execute(
            'SELECT 1 FROM mac_activity WHERE mac=? AND "end">=? LIMIT 1', (mac, self.cutoff)
        ).fetchone() is not None  # fmt: skip

    def _suspect(self, o: Obs, token: str, why: str) -> None:
        self.stats.suspect += 1
        self.decisions.append(Flag(SUSPECT, o.canon, token,
                                   f"rule attach suspect {short_hash(o.mac)}: {why}"))  # fmt: skip
        log(logger, logging.WARNING, SUSPECT, mac=short_hash(o.mac), why=why)

    # ---- merged device ranges --------------------------------------------------------------

    def _widen(self) -> None:
        """Catch-up for the first/last seen widening of merged devices that a run with an
        unreadable overrides.db could not do, at most MAX_ROWS_PER_PASS links per pass."""
        links = sorted(self.snap.links.items())
        todo: list[Widen] = []
        for i in range(0, len(links), 200):
            chunk = links[i : i + 200]
            ids = sorted({d for pair in chunk for d in pair})
            ranges = {
                r[0]: (r[1], r[2])
                for r in self.inv.execute(
                    "SELECT id, first_seen, last_seen FROM devices"  # noqa: S608
                    f" WHERE id IN ({','.join('?' * len(ids))})",
                    ids,
                )
            }
            for src, dst in chunk:
                s, d = ranges.get(src), ranges.get(dst)
                if s and d and (s[0] < d[0] or s[1] > d[1]):
                    todo.append(Widen(src, dst))
                    if len(todo) >= MAX_ROWS_PER_PASS:
                        self.decisions.extend(todo)
                        return
        self.decisions.extend(todo)


def compute_plan(
    inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> Plan:  # fmt: skip
    """One read-only transaction (a WAL reader never blocks writers)."""
    inv.execute("BEGIN")
    try:
        return Compute(inv, snap, cfg, now, monotonic).run()
    finally:
        inv.execute("COMMIT")
