"""Value types of identity stitching: the per-MAC observation view, the signal arithmetic, and
the DECISIONS the read-only compute phase hands to the apply phase (docs/stitching-design.md)."""

from __future__ import annotations

import hashlib
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from vigie_pipeline.config import SIGNAL_WEIGHTS
from vigie_pipeline.snapshot import Rule

GroupKey = tuple[str, str, str, str]
HASHED = ("opt55", "opt60", "hostname", "mdns_name")
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
    first_ts: float  # first_seen as epoch seconds
    retired: bool  # the MAC's own device is retired
    rule_id: str | None = None  # observations.link_rule_id (rule-attached MACs)


def epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def long_hash(value: str) -> str:
    """128 bits: for dedup tokens, where a chosen value must not be able to collide."""
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def fold(name: str) -> str:
    """THE name fold, used identically in Python and as the stored indexed column: NFKC (full-width
    and compatibility forms, NFD vs NFC), Unicode casefold (ß -> ss, final sigma, dotless i), then
    NFKC again so the result is a FIXPOINT (casefold can expand a letter in front of a combining
    mark into a sequence NFKC recomposes: without the second pass fold(fold(x)) != fold(x) for
    about 900 two-character sequences). A bounded loop guards the property; a stored fold is
    therefore equal to the fold of the fold. SQLite's NOCASE folds ASCII only and is never used."""
    out = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", name).casefold())
    for _ in range(3):
        again = unicodedata.normalize("NFKC", out.casefold())
        if again == out:
            break
        out = again
    return out


def same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and fold(a) == fold(b)  # type: ignore[arg-type]


def group_keys(o: Obs) -> list[GroupKey]:
    """Name groups of a MAC: (opt55, opt60, kind, folded name) per available name."""
    if not (o.opt55 and o.opt60):
        return []
    return [(o.opt55, o.opt60, kind, fold(name))
            for kind, name in (("h", o.hostname), ("m", o.mdns)) if name]  # fmt: skip


def signals(a: Obs, b: Obs) -> list[str]:
    out = []
    if a.opt55 and a.opt55 == b.opt55:
        out.append("opt55")
    if a.opt60 and a.opt60 == b.opt60:
        out.append("opt60")
    if same(a.mdns, b.mdns):
        out.append("mdns_name")
    if same(a.hostname, b.hostname):
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
        and (rule.hostname is None or same(rule.hostname, o.hostname))
        and (rule.mdns_name is None or same(rule.mdns_name, o.mdns))
    )


def rule_score(rule: Rule) -> float:
    named = [n for n, v in (("hostname", rule.hostname), ("mdns_name", rule.mdns_name)) if v]
    return score_of(["opt55", "opt60", *named])


def evidence_of(c: Obs) -> dict:
    """Full values: stored only in identity_candidates.evidence, never logged."""
    return {"from_mac": c.mac, "opt55": c.opt55, "opt60": c.opt60, "hostname": c.hostname,
            "mdns_name": c.mdns}  # fmt: skip


def components(links: Mapping[str, str]) -> dict[str, frozenset[str]]:
    """Connected components of the merge links (undirected, iterative, any chain length): the
    set of device ids that are one identity. All members of a component share ONE frozenset."""
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
    out: dict[str, frozenset[str]] = {}
    for group in groups.values():
        shared = frozenset(group)
        out.update(dict.fromkeys(group, shared))
    return out


# ---- decisions: the whole output of the compute phase ------------------------------------------


@dataclass(frozen=True)
class Attach:
    """Attach `mac` (now a self MAC of `from_device`) to `target` under `rule`. Re-validated under
    the lock: still self, both devices ok, the pair's candidate state unchanged, the rule unexpired
    at the clock read under the lock, and overrides.db unwritten since the snapshot (data_version,
    read fresh immediately before the write)."""

    mac: str
    from_device: str
    target: str
    rule: Rule
    score: float
    hostname: str | None
    mdns_name: str | None
    opt55: str | None
    opt60: str | None
    views: tuple[tuple[bool, bool], ...]
    expected: str | None = None  # the pair's candidate state when computed (None: no row)


@dataclass(frozen=True)
class Candidate:
    """One candidate row (open | suggested | dismissed). `mac` is the from device's self MAC."""

    mac: str
    from_device: str
    into: str
    score: float
    evidence: Mapping[str, object]
    state: str
    provisional: bool = False  # written only when the pair has no row yet (immature overlap)
    expected: str | None = None


@dataclass(frozen=True)
class Veto:
    mac: str
    from_device: str
    into: str
    score: float
    evidence: Mapping[str, object]
    expected: str | None = None


@dataclass(frozen=True)
class Ambiguous:
    mac: str
    from_device: str
    targets: tuple[str, ...]
    score: float
    evidence: Mapping[str, object]
    expected: tuple[str | None, ...] = ()


@dataclass(frozen=True)
class Suggest:
    """A candidate row plus one immutable merge suggestion (reserved as a whole)."""

    mac: str
    from_device: str
    into: str
    score: float
    evidence: Mapping[str, object]
    reason_code: str  # fingerprint_match | rule_hit_needs_confirm
    reason_text: str | None  # the deferral reason when the rule hit needs a human
    signals: tuple[str, ...]
    expected: str | None = None


@dataclass(frozen=True)
class Flag:
    """An event written once per token (floods, suspects, deferrals)."""

    kind: str
    device_id: str | None
    token: str
    summary: str
    severity: str = "warn"


@dataclass(frozen=True)
class Settle:
    """Dismiss (under the row cap) the undecided candidate rows of a device a rule attach orphaned;
    the `settle:<device>` state key stays until none is left."""

    device_id: str


@dataclass(frozen=True)
class Widen:
    """Catch-up of a merged device's first/last seen range from one of its sources."""

    src: str
    dst: str


Decision = Attach | Candidate | Veto | Ambiguous | Suggest | Flag | Widen | Settle


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
    deferred: int = 0
    examined: int = 0
    stale: int = 0  # decisions dropped by APPLY because their preconditions changed


@dataclass(frozen=True)
class Plan:
    """Output of the compute phase: decisions in application order plus the robin cursors."""

    decisions: tuple[Decision, ...] = ()
    cursors: Mapping[str, str | None] = field(default_factory=dict)
    stats: StitchStats = field(default_factory=StitchStats)
