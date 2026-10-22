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
import time
from bisect import bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from vigie_ingest.db import immediate
from vigie_pipeline.activity import (
    Interval,
    load_activity,
    load_first_received,
    load_gaps,
    merge_intervals,
    overlap_seconds,
)
from vigie_pipeline.config import (
    ACTIVITY_MAX_REPORT_LAG_S,
    MAX_ALIAS_IDS,
    MAX_FLOOD_EVENTS_PER_PASS,
    MAX_INTERVALS_PER_MAC,
    MAX_OVERLAP_OPS_PER_PASS,
    MAX_ROWS_PER_PASS,
    MAX_SIGNATURE_BUCKET,
    PEER_TAIL_MIN_GRACE_MULT,
    SIGNAL_WEIGHTS,
    STITCH_MAX_TXN_SECONDS,
    STITCH_SETUP_MAX_SECONDS,
    PipelineConfig,
)
from vigie_pipeline.logs import log
from vigie_pipeline.snapshot import OverridesUnreadable, Rule, Snapshot, load_snapshot
from vigie_pipeline.stitch_db import (
    Attachment,
    candidate_state,
    candidate_write_needed,
    create_merge_suggestion,
    emit_event,
    emit_once,
    event_exists,
    find_merge_suggestion,
    has_open_orphan_suggestions,
    load_attachments,
    save_attachment,
    state_get,
    state_set,
    upsert_candidate,
    vetoed_between,
    widen_linked_devices,
    withdraw_open_suggestions,
    withdraw_orphan_suggestions,
)

logger = logging.getLogger("vigie_pipeline")
EPSILON = 1e-9
RECHECK_CURSOR = "recheck_after_mac"


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
    first_ts: float = 0.0  # first_seen as epoch seconds, parsed once at load
    retired: bool = False  # the MAC's own device is retired
    rule_id: str | None = None  # observations.link_rule_id (rule-attached MACs)


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
    """The per-pass work budget or the transaction time-box is spent: stop at a safe point."""


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


def _components(links: Mapping[str, str]) -> dict[str, frozenset[str]]:
    """Connected components of the merge links (undirected, iterative, any chain length): the
    set of device ids that are one identity."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:  # path compression
            parent[x], x = root, parent[x]
        return root

    for src, dst in links.items():
        parent[find(src)] = find(dst)
    groups: dict[str, set[str]] = defaultdict(set)
    for device in list(parent):
        groups[find(device)].add(device)
    return {d: frozenset(g) for g in groups.values() for d in g}


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _chunked(items: list[str], size: int = 400) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _load_obs(
    inv: sqlite3.Connection, snap: Snapshot, tick: Callable[[], None], devices: Iterable[str]
) -> list[Obs]:
    """The observations of the given devices (index seeks by device), ordered by age. `tick` runs
    between chunks, so loading is interruptible and proportional to the devices asked for."""
    out = []
    for chunk in _chunked(sorted(set(devices))):
        tick()
        for r in inv.execute(
            "SELECT o.mac, o.device_id, o.is_randomized, o.dhcp_fingerprint, o.vendor_class,"  # noqa: S608
            " o.hostname, o.mdns_name, o.link_source, o.first_seen, o.link_rule_id, d.status"
            " FROM observations o JOIN devices d ON d.id = o.device_id"
            f" WHERE o.device_id IN ({','.join('?' * len(chunk))})",
            chunk,
        ):
            out.append(
                Obs(r["mac"], r["device_id"], snap.canonical(r["device_id"]),
                    bool(r["is_randomized"]), r["link_source"], r["dhcp_fingerprint"] or None,
                    r["vendor_class"] or None, r["hostname"] or None, r["mdns_name"] or None,
                    r["first_seen"], _epoch(r["first_seen"]),
                    r["status"] == "retired", r["link_rule_id"])
            )  # fmt: skip
    out.sort(key=lambda o: (o.first_seen, o.mac))
    return out


class Stitcher:
    def __init__(
        self, inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
        clock: Callable[[], float] | None = None, overrides: sqlite3.Connection | None = None,
    ):  # fmt: skip
        self.inv, self.snap, self.cfg, self.now = inv, snap, cfg, now
        self.clock = clock or (lambda: now)  # rule expiry is re-checked against this
        self.overrides = overrides  # re-read under the lock before an attach
        self.deadline = time.monotonic() + STITCH_SETUP_MAX_SECONDS  # setup only; see run()
        self.components = _components(snap.links)
        self.first_recv = load_first_received(inv, self._check_time)  # SERVER first receipt
        self.act = {  # only active MACs; only the most recent intervals of a MAC are compared
            m: ivs[-MAX_INTERVALS_PER_MAC:]
            for m, ivs in load_activity(
                inv, cfg.activity_gap_s, per_mac_limit=MAX_INTERVALS_PER_MAC,
                first_received=self.first_recv, max_lag_s=ACTIVITY_MAX_REPORT_LAG_S,
                min_end=int(now) - cfg.activity_retention_s, tick=self._check_time,
            ).items()
        }  # fmt: skip
        self.gaps = load_gaps(inv, int(now) - cfg.activity_retention_s)  # missing evidence
        self.ops = 0  # overlap-computation budget spent this pass
        self.flood_events = 0
        self.flood_suppressed = 0
        self.stats = StitchStats()
        self.handled: set[str] = set()
        self.flooded_keys: set[GroupKey] = set()
        self.writes = 0  # candidate/suggestion rows written this pass
        self.attachments = load_attachments(inv)  # immutable evidence of each rule attach
        self.obs = _load_obs(inv, snap, self._check_time, self._relevant_devices())
        self._index()

    def _relevant_devices(self) -> set[str]:
        """Every device the decisions can depend on: devices with an active MAC (all their MACs),
        the rule targets, and everything merged with them (the target of an attach that is still
        active is loaded through the attached MAC's own device).
        A device with no active MAC that is none of these cannot overlap anything and is not a
        peer; it is not loaded."""
        devices: set[str] = set()
        active = sorted(self.act)
        for chunk in _chunked(active):
            self._check_time()
            marks = ",".join("?" * len(chunk))
            devices.update(
                r[0] for r in self.inv.execute(
                    f"SELECT DISTINCT device_id FROM observations WHERE mac IN ({marks})",  # noqa: S608
                    chunk,
                )
            )  # fmt: skip
        devices.update(r.device_id for r in self.snap.rules)
        for device in list(devices):
            devices |= self.alias_ids(device)
        return devices

    def alias_ids(self, device_id: str) -> frozenset[str]:
        """Every device id of the same identity (the connected component of the merge links)."""
        return self.components.get(device_id) or frozenset({device_id})

    def _index(self) -> None:
        self.by_mac = {o.mac: o for o in self.obs}
        self.by_canon: dict[str, list[Obs]] = defaultdict(list)
        self.groups: dict[GroupKey, list[Obs]] = defaultdict(list)
        for o in self.obs:
            self.by_canon[o.canon].append(o)
            for key in group_keys(o):
                self.groups[key].append(o)
        self._reset_caches()

    def _reset_caches(self) -> None:
        self._canon_ivs: dict[str, list[Interval]] = {}
        self._bad_pairs_cache: dict[tuple[GroupKey, ...], set[frozenset[str]]] = {}
        self._live_sizes: dict[GroupKey, int] | None = None
        self._by_fp: dict[tuple[str | None, str | None], list[Obs]] | None = None

    def _moved(self, old: Obs, new: Obs) -> None:
        """Swap one observation in the in-memory maps after a committed attach: no reload, so
        no deadline can interrupt it halfway and leave the maps stale."""
        self.obs = [new if o.mac == old.mac else o for o in self.obs]
        self.by_mac[new.mac] = new
        self.by_canon[old.canon].remove(old)
        self.by_canon[new.canon].append(new)
        for key in group_keys(old):
            self.groups[key] = [new if o.mac == old.mac else o for o in self.groups[key]]
        self._reset_caches()

    def _check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise BudgetExhaustedError

    def _charge(self, units: int = 1) -> None:
        """Spend work units; raises (before the decision in flight writes anything) when the
        phase budget is spent or the transaction has held the write lock for too long."""
        self.ops += units
        if self.ops > MAX_OVERLAP_OPS_PER_PASS or time.monotonic() > self.deadline:
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

    def mature(self, mac: str) -> bool:
        """Enough TRUSTED history to rule out an overlapping twin: more than the grace window of
        covered time (stamps back-filled earlier than the report lag are already clipped away) AND
        first received by the server more than the grace window ago (the server clock, not a
        collector stamp)."""
        grace = self.cfg.overlap_grace_s
        first = self.first_recv.get(mac)  # no anchor: unknown age, so not mature (fail closed)
        return (
            self.covered(mac) > grace
            and first is not None
            and self.now - first > grace
            and not self._in_gap(mac)
        )

    def _in_gap(self, mac: str) -> bool:
        """Does the MAC's activity window overlap a span in which some collector's evidence is
        known to be missing (stamps dropped for the report lag, or a long silence)?"""
        ivs = self.act.get(mac)
        if not ivs:
            return False
        lo, hi = ivs[0][0], ivs[-1][1]
        return any(start < hi and end > lo for start, end in self.gaps)

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
            overlap > 0 and (lead <= 0 or (covered > grace and 2 * lead < gap))
        )

    def _live(self, o: Obs) -> bool:
        """Still a self MAC and active inside the activity retention window (retired or not: a
        retired MAC's intervals still count for overlap checks, see _counted)."""
        ivs = self.act.get(o.mac)
        return (
            o.source == "self"
            and bool(ivs)
            and ivs[-1][1] >= self.now - self.cfg.activity_retention_s
        )

    def _counted(self, o: Obs) -> bool:
        """Counts toward flood populations: live and not on a retired device."""
        return self._live(o) and not o.retired

    def name_peers(self, c: Obs) -> list[Obs]:
        """Every other MAC with c's opt55 and opt60 and an agreeing hostname or mDNS name: the
        candidate-style match, whatever other fields a rule may additionally name."""
        found = {o.mac: o for key in group_keys(c) for o in self.groups[key] if o.mac != c.mac}
        return list(found.values())

    def _restrict(self, o: Obs, hostname: bool, mdns: bool) -> Obs:
        """o as the rule sees it: only the name fields the rule requires. A name the applicant
        merely supplies in addition must never exclude a peer."""
        return replace(o, hostname=o.hostname if hostname else None, mdns=o.mdns if mdns else None)

    def _safety_peers(self, target: str, views: Iterable[Obs]) -> tuple[set[str], bool]:
        """MACs whose concurrent activity vetoes an attach (or flags an attached MAC), derived
        from the RULE and the target identity, not from the applicant's extra names: the target's
        MACs, every MAC sharing a name with any of them, and for each rule view (the applicant
        restricted to the rule's name fields) its name peers and compatible peers. Returns
        (peers, compat_flooded)."""
        peers = self._canon_macs([target])
        flooded = False
        known = self._names_of(target)
        for t in self.by_canon.get(target, []):
            peers |= {p.mac for p in self.name_peers(t)}
        for view in views:
            peers |= {p.mac for p in self.name_peers(view)}
            compat = self._compat_raw(view, known)
            if self._compat_flooded(view, compat):
                flooded = True
            else:
                peers |= compat
        return peers, flooded

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
        size = sum(1 for m in peers if self._counted(self.by_mac[m]))
        over = [(key, size)] if size > MAX_SIGNATURE_BUCKET else []
        self._report_flood(over, c.device_id)
        return bool(over)

    def _close_in_time(self, a: Obs, b: Obs) -> bool:
        """First sightings within one activity gap of each other."""
        return abs(a.first_ts - b.first_ts) <= self.cfg.activity_gap_s

    def _names_of(self, canon: str) -> set[str]:
        """Casefolded hostnames and mDNS names seen on any MAC of a device."""
        return {
            n.casefold() for o in self.by_canon.get(canon, []) for n in (o.hostname, o.mdns) if n
        }

    def _compat_raw(self, c: Obs, known: set[str] | None = None) -> set[str]:
        """The filtered compatible set (see compatible_peers); `known` = names of the target
        device (default: c's own device). Only the filtered set is charged to the budget."""
        known = self._names_of(c.canon) if known is None else known
        pool = self._pool(c)
        self._charge(len(pool) // 1024)  # the scan itself, cheap per MAC
        out = {
            o.mac for o in pool
            if o.mac != c.mac and not (
                (o.hostname and c.hostname and not _same(o.hostname, c.hostname))
                or (o.mdns and c.mdns and not _same(o.mdns, c.mdns))
            ) and (
                _same(o.hostname, c.hostname) or _same(o.mdns, c.mdns)
                or any(n.casefold() in known for n in (o.hostname, o.mdns) if n)
                or self._close_in_time(o, c)
            )
        }  # fmt: skip
        self._charge(1 + len(out) // 64)
        return out

    def compatible_peers(self, c: Obs) -> set[str]:
        """Live self MACs with c's opt55 and opt60 whose hostname and mDNS name do not contradict
        c's (a missing name cannot be told apart) AND that either share a name with c, carry a name
        already seen on the target device, or were first seen within one activity gap of c. The
        victim's new MAC that has only revealed an mDNS name the target already used is a peer of
        a hostname-copying twin; junk names and nameless MACs (anyone can send the public
        opt55/opt60) are peers only when they appear within a gap of c. More than
        MAX_SIGNATURE_BUCKET peers yield none (reported as a flood; a rule attach refuses it)."""
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
                if self._counted(o):
                    for k in group_keys(o):
                        sizes[k] += 1
            self._live_sizes = sizes
        return self._live_sizes.get(key, 0)

    def _flooded(self, o: Obs) -> bool:
        """A name group (opt55, opt60 and one hostname or mDNS name) with more than
        MAX_SIGNATURE_BUCKET live MACs is skipped: attached, retired or silent MACs do not count
        (their intervals still serve overlap checks),
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
                             f"{token}:{self.day()}", self.now):  # fmt: skip
                    self.flood_events += 1
                log(logger, logging.WARNING, "signature_flood", signature=token, macs=size)
                self.stats.flooded += 1
        self.flooded_keys.update(key for key, _ in over)

    def day(self) -> str:
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

    def _reserve(self, rows: int) -> bool:
        """Does a whole decision of `rows` row writes fit under MAX_ROWS_PER_PASS? If not, nothing
        of it is written (counted as capped) and it waits for the next pass."""
        if rows and self.writes + rows > MAX_ROWS_PER_PASS:
            self.stats.capped += 1
            return False
        return True

    def _record(
        self, c: Obs, into: str, score: float, evidence: dict, state: str, extra: int = 0
    ) -> str | None:
        """Write the candidate row. `extra` rows the caller will write on top (a suggestion) are
        reserved too: the whole decision fits under MAX_ROWS_PER_PASS or none of it is written. An
        identical or sticky row needs no write and is never refused."""
        need = int(candidate_write_needed(self.inv, c.device_id, into, score, evidence, state))
        if not self._reserve(need + extra):
            return None
        cid, wrote = upsert_candidate(self.inv, c.device_id, into, score, evidence, state, self.now)
        self.stats.candidates += wrote
        self.writes += wrote
        return cid

    def _withdraw(self, c: Obs, canons: Iterable[str]) -> None:
        """Safety update of existing suggestion rows: bounded by the open suggestions of the pairs
        evaluated. The whole work is charged BEFORE the first update, so a stop never leaves a
        decision half-withdrawn; it is charged to the work budget, not to the row cap."""
        canons = list(canons)
        self._charge(len(canons))
        for canon in canons:
            withdraw_open_suggestions(self.inv, self.snap, c.device_id, canon, self.now)

    def _veto(self, c: Obs, into: str, score: float, evidence: dict) -> None:
        need = int(candidate_write_needed(self.inv, c.device_id, into, score, evidence, "vetoed"))
        self._charge(1)
        if not self._reserve(need):
            return  # no withdrawal either: the pair is retried whole next pass
        self._withdraw(c, [into])
        self._record(c, into, score, evidence, "vetoed")
        token = "~".join(sorted((c.device_id, into)))
        if emit_once(self.inv, c.device_id, "identity_overlap_veto", "warn",
                     f"identity overlap veto {token}", token, self.now):  # fmt: skip
            self.stats.vetoed += 1
            log(logger, logging.INFO, "identity_overlap_veto", mac=short_hash(c.mac))

    def _ambiguous(self, c: Obs, canons: list[str], score: float, evidence: dict) -> None:
        need = sum(
            candidate_write_needed(self.inv, c.device_id, canon, score, evidence, "ambiguous")
            for canon in canons
        )
        self._charge(len(canons))
        if not self._reserve(need):
            return  # the whole multi-target decision waits: never a partial set of rows
        self._withdraw(c, canons)
        for canon in canons:
            self._record(c, canon, score, evidence, "ambiguous")
        if emit_once(self.inv, c.device_id, "identity_candidate_ambiguous", "warn",
                     f"identity candidate ambiguous: {len(canons)} devices match {c.device_id}",
                     c.device_id, self.now):  # fmt: skip
            self.stats.ambiguous += 1
            log(logger, logging.INFO, "identity_candidate_ambiguous", mac=short_hash(c.mac))

    def _suggest(
        self, c: Obs, into: str, score: float, evidence: dict, reason: str, found: list[str]
    ) -> None:
        self._charge(1)  # the suggestion look-up is work inside the write lock
        known = find_merge_suggestion(self.inv, self.snap, c.device_id, into, self.now)
        create = known is None
        rejected = known is not None and known.status == "rejected"
        cid = self._record(c, into, score, evidence, "dismissed" if rejected else "suggested",
                           extra=int(create))  # fmt: skip
        if cid is None or not create:
            return
        summary = {
            "candidate_id": cid,
            "signals": found,
            "hashes": {k: short_hash(str(v)) for k, v in evidence.items() if k in HASHED and v},
        }
        create_merge_suggestion(
            self.inv, self.snap, c.device_id, into, score=score, reason_code=reason,
            evidence_summary=summary, now=self.now, ttl_s=self.cfg.suggestion_ttl_s,
        )  # fmt: skip
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
            self.ops = 0  # each phase also gets an equal slice of the transaction time-box,
            self.deadline = time.monotonic() + STITCH_MAX_TXN_SECONDS / 3  # after setup
            try:
                phase()
            except BudgetExhaustedError:  # raised before any write of the interrupted decision
                emit_once(self.inv, None, "stitch_budget_exhausted", "warn",
                          "stitching work budget or time-box exhausted in "
                          f"{phase.__name__.strip('_')}: remaining work resumes next pass",
                          self.day(), self.now)  # fmt: skip
                log(logger, logging.WARNING, "stitch_budget_exhausted",
                    phase=phase.__name__, ops=self.ops)  # fmt: skip
        self.ops = 0
        if self.flood_suppressed:
            emit_once(self.inv, None, "signature_flood_summary", "warn",
                      f"{self.flood_suppressed} further signature floods not reported this pass",
                      f"summary:{self.day()}", self.now)  # fmt: skip

    def apply_rules(self) -> None:
        self._settle_attached()
        if self.snap.rules:
            for c in self._eligible_sorted(undecided_first=True):
                self._charge(0)  # time-box check
                self._apply_rule(c)

    def _recheck_rule_attached(self) -> None:
        """A rule-attached MAC found to overlap its peers beyond the veto limit is only flagged:
        the pipeline never rewrites trust (no detach). One rule_attach_suspect event per MAC.
        MACs are checked in mac order starting after a persisted cursor (written only when the
        phase runs out of budget, cleared when it completes), so every rule-attached MAC is
        eventually checked however often the budget runs out. If the phase stops before finishing
        even one MAC the cursor moves past that head MAC, so a single slow one cannot pin it."""
        macs = sorted(o.mac for o in self.obs if o.source == "rule" and self.act.get(o.mac))
        cursor = state_get(self.inv, RECHECK_CURSOR)
        start = bisect_right(macs, cursor) if cursor else 0
        order = macs[start:] + macs[:start]
        done = None
        try:
            for mac in order:
                self._charge(0)
                self._recheck(self.by_mac[mac])
                done = mac
        except BudgetExhaustedError:
            moved = done or (order[0] if order else None)
            if moved is not None:
                state_set(self.inv, RECHECK_CURSOR, moved)
            raise
        if cursor:
            state_set(self.inv, RECHECK_CURSOR, None)

    def _recheck(self, o: Obs) -> None:
        token = f"{short_hash(o.mac)}~{o.canon}"
        if event_exists(self.inv, "rule_attach_suspect", token):
            return  # already flagged: costs the budget nothing
        att = self.attachments.get(o.mac)
        if att:  # the values and rule fields that justified the attach, immune to renames
            view = replace(
                o, hostname=att.hostname, mdns=att.mdns_name,
                opt55=att.opt55 or o.opt55, opt60=att.opt60 or o.opt60,
            )  # fmt: skip
        else:  # attached before attachments were recorded: the names shared with the target
            others = [t for t in self.by_canon.get(o.canon, []) if t.mac != o.mac]
            view = self._restrict(
                o,
                any(_same(t.hostname, o.hostname) for t in others),
                any(_same(t.mdns, o.mdns) for t in others),
            )
        peers, _ = self._safety_peers(o.canon, [view])
        if not self.sustained(o.mac, peers - {o.mac}):
            return
        if emit_once(self.inv, o.canon, "rule_attach_suspect", "warn",
                     f"rule attach suspect {short_hash(o.mac)}: sustained overlap with peers",
                     token, self.now):  # fmt: skip
            self.stats.suspect += 1
            log(logger, logging.WARNING, "rule_attach_suspect", mac=short_hash(o.mac))

    def _vetoed(self, c: Obs, into: str) -> bool:
        """A (candidate, target) pair once vetoed stays vetoed: re-evaluating it would only let
        the interval cap or fresh lone stamps launder the overlap that justified the veto. Only a
        human dismissal (the state `dismissed`, written through the API) clears it. Both endpoints
        are resolved through the current merges, so a veto survives its target being merged."""
        a, b = self.alias_ids(c.device_id), self.alias_ids(into)
        if len(a) > MAX_ALIAS_IDS or len(b) > MAX_ALIAS_IDS:
            return True  # an absurd merge component cannot be checked: fail closed
        return vetoed_between(self.inv, a, b)

    def _rule_live(self, rule: Rule) -> bool:
        """Not expired NOW (the snapshot's own check is as old as the snapshot)."""
        return rule.expires_at is None or rule.expires_at > self.clock()

    def _state_ok(self, device_id: str) -> bool:
        row = self.inv.execute(
            "SELECT identity_state FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        return bool(row) and row[0] == "ok"

    def _apply_rule(self, c: Obs) -> None:
        if not self.mature(c.mac):
            return  # too little trusted history to rule out an overlapping twin: defer quietly
        matched = [r for r in self.snap.rules if rule_matches(r, c) and self._rule_live(r)]
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
        rule = min((r for r in matched), key=lambda r: r.id)
        score = rule_score(rule)
        # peers come from the RULE(s) and the target identity, never from names the applicant
        # supplies beyond what the rule requires (see _safety_peers)
        views = [self._restrict(c, h, m) for h, m in sorted({(bool(r.hostname), bool(r.mdns_name))
                                                              for r in matched})]  # fmt: skip
        peers, flooded = self._safety_peers(target, views)
        if flooded:
            return  # too many look-alikes to rule out a twin: attach nothing, suggest nothing
        if self.sustained(c.mac, peers - {c.mac}):
            self._veto(c, target, score, evidence)
            return
        group = self.snap.overrides.get(target, (0, None))[1]
        trusted_state = self._state_ok(target) and self._state_ok(c.device_id)
        if trusted_state and group is not None and self.snap.group_auto_inherit.get(group) == 1:
            self._attach(c, target, rule, score, matched)
        else:  # unassigned, auto_inherit=0, unknown group or identity_state != 'ok': human confirms
            found = ["opt55", "opt60", *(n for n in ("hostname", "mdns_name") if getattr(rule, n))]
            self._suggest(c, target, score, evidence, "rule_hit_needs_confirm", found)

    def _still_authorised(self, rule: Rule, target: str) -> bool:
        """Re-read overrides.db (read-only) under the inventory lock: the rule must still be
        active and unchanged and the target's group must still be an explicit auto_inherit=1
        group, exactly as when the snapshot was taken."""
        if self.overrides is None:
            return True
        try:
            fresh = load_snapshot(self.overrides, self.clock())
        except OverridesUnreadable:
            return False
        group = fresh.overrides.get(target, (0, None))[1]
        return (
            rule in fresh.rules
            and group is not None
            and group == self.snap.overrides.get(target, (0, None))[1]
            and fresh.group_auto_inherit.get(group) == 1
        )

    def _dismiss_open_candidates(self, device_id: str, room: int) -> int:
        """Settle the candidate rows of a device that a rule attach orphaned: at most `room`
        rows now, the rest in later passes (see _settle_attached). Returns rows written."""
        ids = [
            r[0]
            for r in self.inv.execute(
                "SELECT id FROM identity_candidates WHERE device_a=? AND state IN"
                " ('open','suggested') LIMIT ?",
                (device_id, max(room, 0)),
            )
        ]
        self.inv.executemany(
            "UPDATE identity_candidates SET state='dismissed' WHERE id=?", [(i,) for i in ids]
        )
        return len(ids)

    def _settle_attached(self) -> None:
        """Finish the dismissal and the suggestion withdrawal that an attach could not fit under
        the row cap. Stops at once when the allowance is spent or the time-box is."""
        keys = [
            r[0] for r in self.inv.execute("SELECT key FROM stitch_state WHERE key LIKE 'settle:%'")
        ]
        for key in keys:
            self._charge(0)
            if MAX_ROWS_PER_PASS - self.writes <= 0:
                return
            device_id = key[len("settle:") :]
            self._settle_device(device_id)

    def _settle_device(self, device_id: str) -> None:
        """Expire the orphan's open suggestions, then dismiss its open candidate rows, within the
        row allowance of this pass; the settle marker stays until nothing is left."""
        self.writes += withdraw_orphan_suggestions(
            self.inv, self.snap, device_id, self.now, MAX_ROWS_PER_PASS - self.writes
        )
        self.writes += self._dismiss_open_candidates(device_id, MAX_ROWS_PER_PASS - self.writes)
        left = self.inv.execute(
            "SELECT 1 FROM identity_candidates WHERE device_a=? AND state IN"
            " ('open','suggested') LIMIT 1", (device_id,),
        ).fetchone()  # fmt: skip
        if left is None and not has_open_orphan_suggestions(
            self.inv, self.snap, device_id, self.now
        ):
            state_set(self.inv, f"settle:{device_id}", None)
        else:
            state_set(self.inv, f"settle:{device_id}", "1")

    def _attach(self, c: Obs, target: str, rule: Rule, score: float, matched: list[Rule]) -> None:
        if not self._rule_live(rule) or not self._still_authorised(rule, target):
            return  # expired, revoked or regrouped while this pass waited for the lock or worked
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
        save_attachment(
            self.inv, c.mac,
            Attachment(rule.id, target,
                       c.hostname if any(r.hostname for r in matched) else None,
                       c.mdns if any(r.mdns_name for r in matched) else None,
                       c.opt55, c.opt60), self.now,
        )  # fmt: skip
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
        # settled by the rule: the orphan's open suggestions expire at once (a human must not be
        # able to accept one after this) and its candidate rows are dismissed, both under the
        # row cap; what does not fit is finished by the following passes (_settle_device).
        self._settle_device(c.device_id)
        before = short_hash(old["mac"]) if old else "none"
        emit_event(self.inv, target, "mac_attached", "info",
                   f"mac attached: {before} -> {short_hash(c.mac)}", self.now)  # fmt: skip
        self.stats.attached += 1
        log(logger, logging.INFO, "mac_attached", old=before, new=short_hash(c.mac))
        status = self.inv.execute("SELECT status FROM devices WHERE id=?", (target,)).fetchone()
        self._moved(  # the canonical map changed: later MACs must see this attachment
            c,
            replace(
                c, device_id=target, canon=self.snap.canonical(target), source="rule",
                rule_id=rule.id, retired=bool(status) and status[0] == "retired",
            ),
        )  # fmt: skip

    # ---- pass 2: fingerprint candidates ----------------------------------------------------------

    def stitch_candidates(self) -> None:
        for c in self._eligible_sorted(undecided_first=True):
            self._charge(0)  # time-box check
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
            if self.mature(c.mac):
                self._veto(c, into, score, evidence)
            elif candidate_state(self.inv, c.device_id, into) is None:
                # not enough trusted history to tell a hand-over from a twin: the overlap is
                # provisional evidence, never a permanent veto (and no suggestion)
                self._record(c, into, score, evidence, "open")
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


def stitch(
    inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig, now: float,
    clock: Callable[[], float] | None = None, overrides: sqlite3.Connection | None = None,
) -> StitchStats:  # fmt: skip
    """One stitching pass over inventory.db (a single transaction). With a live `clock`, `now` is
    re-read once the inventory write lock is held and rule expiry is checked against the clock.
    `overrides` (read-only) is re-read under the lock before every attach."""
    with immediate(inv):
        stamp = clock() if clock else now
        try:
            stitcher = Stitcher(inv, snap, cfg, stamp, clock, overrides)
        except BudgetExhaustedError:  # loading alone outlasted the setup cap: release the lock
            day = datetime.fromtimestamp(stamp, tz=UTC).strftime("%Y-%m-%d")
            emit_once(inv, None, "stitch_budget_exhausted", "warn",
                      "stitching setup exceeded its time cap: nothing stitched this pass",
                      day, stamp)  # fmt: skip
            log(logger, logging.WARNING, "stitch_budget_exhausted", phase="setup")
            return StitchStats()
        widen_linked_devices(inv, snap.links)
        if snap.malformed_rules:
            emit_once(inv, None, "rule_malformed", "warn",
                      f"{snap.malformed_rules} identity_rules rows with malformed fields ignored",
                      stitcher.day(), stamp)  # fmt: skip
        stitcher.run()
    log(logger, logging.INFO, "stitch_complete", **stitcher.stats.__dict__)
    return stitcher.stats
