"""The bounded NEIGHBOURHOOD of one stitching subject: the observations that can matter to its
decision, gathered by a fixed set of indexed lookups each limited to BUCKET_ROWS rows, plus their
activity. A lookup that overflows marks the neighbourhood `truncated`: the evidence is incomplete
and the subject degrades (docs/stitching-design.md section 2). Nothing here writes."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from collections.abc import Callable, Iterable

from vigie_ingest.db import iso_utc
from vigie_pipeline.activity import Interval, load_activity, load_first_received
from vigie_pipeline.config import BUCKET_ROWS, MAX_ALIAS_IDS, TARGET_KEYS, PipelineConfig
from vigie_pipeline.snapshot import Snapshot
from vigie_pipeline.stitch_types import GroupKey, Obs, epoch, fold, group_keys

OBS_COLUMNS = (
    "o.mac, o.device_id, o.is_randomized, o.dhcp_fingerprint, o.vendor_class, o.hostname,"
    " o.mdns_name, o.link_source, o.first_seen, o.link_rule_id, d.status"
)
OBS_FROM = "FROM observations o JOIN devices d ON d.id = o.device_id"
FOLD_COLUMNS = {"h": "hostname_fold", "m": "mdns_fold"}


def obs_from_row(snap: Snapshot, r: sqlite3.Row) -> Obs:
    return Obs(
        r["mac"], r["device_id"], snap.canonical(r["device_id"]), bool(r["is_randomized"]),
        r["link_source"], r["dhcp_fingerprint"] or None, r["vendor_class"] or None,
        r["hostname"] or None, r["mdns_name"] or None, r["first_seen"], epoch(r["first_seen"]),
        r["status"] == "retired", r["link_rule_id"],
    )  # fmt: skip


def load_obs(inv: sqlite3.Connection, snap: Snapshot, mac: str) -> Obs | None:
    row = inv.execute(f"SELECT {OBS_COLUMNS} {OBS_FROM} WHERE o.mac=?", (mac,)).fetchone()  # noqa: S608
    return None if row is None else obs_from_row(snap, row)


class Hood:
    def __init__(
        self, inv: sqlite3.Connection, snap: Snapshot, cfg: PipelineConfig,
        components: dict[str, frozenset[str]], cutoff: int,
        tick: Callable[[], None] = lambda: None,
    ) -> None:  # fmt: skip
        self.inv, self.snap, self.cfg = inv, snap, cfg
        self.components, self.cutoff, self.tick = components, cutoff, tick
        self.obs: dict[str, Obs] = {}
        self.act: dict[str, list[Interval]] = {}
        self.first_recv: dict[str, int] = {}
        self.truncated: set[str] = set()  # reasons
        self._done: set[tuple] = set()  # lookups already run
        self._loaded: set[str] = set()  # MACs whose activity is loaded

    # ---- lookups (each at most BUCKET_ROWS rows, newest last_seen first) --------------------

    def _rows(self, key: tuple, sql: str, params: tuple) -> None:
        if key in self._done:
            return
        self.tick()  # the compute budget is charged per lookup, inside a subject
        self._done.add(key)
        rows = self.inv.execute(sql, (*params, BUCKET_ROWS + 1)).fetchall()
        if len(rows) > BUCKET_ROWS:
            self.truncated.add("truncated")
        for r in rows[:BUCKET_ROWS]:
            self.obs.setdefault(r["mac"], obs_from_row(self.snap, r))

    def add_name(self, opt55: str, opt60: str, kind: str, folded_key: str) -> None:
        """Every MAC with this fingerprint and this hostname ('h') or mDNS name ('m'). The key is
        ALREADY the fold (group_keys / known_names produce folds) and is compared as is against
        the stored fold column: never folded again here."""
        column = FOLD_COLUMNS[kind]
        self._rows(
            ("name", opt55, opt60, kind, folded_key),
            f"SELECT {OBS_COLUMNS} {OBS_FROM} WHERE o.dhcp_fingerprint=? AND o.vendor_class=?"  # noqa: S608
            f" AND o.{column} = ? ORDER BY o.last_seen DESC LIMIT ?",
            (opt55, opt60, folded_key),
        )

    def add_keys(self, o: Obs) -> None:
        for opt55, opt60, kind, name in group_keys(o):
            self.add_name(opt55, opt60, kind, name)

    def add_close(self, opt55: str, opt60: str, first_ts: float) -> None:
        """Every MAC with this fingerprint first seen within one activity gap of `first_ts`."""
        gap = self.cfg.activity_gap_s
        self._rows(
            ("close", opt55, opt60, int(first_ts)),
            f"SELECT {OBS_COLUMNS} {OBS_FROM} WHERE o.dhcp_fingerprint=? AND o.vendor_class=?"  # noqa: S608
            " AND o.first_seen BETWEEN ? AND ? ORDER BY o.first_seen LIMIT ?",
            (opt55, opt60, iso_utc(first_ts - gap), iso_utc(first_ts + gap)),
        )

    def alias_ids(self, device_id: str) -> frozenset[str]:
        return self.components.get(device_id) or frozenset({device_id})

    def add_components(self, canons: Iterable[str]) -> None:
        """Every MAC of the given identities (their whole merge components), chunked by device id
        so a long list of singleton devices costs one lookup per 400 of them. A component over
        MAX_ALIAS_IDS is not expanded (incomplete evidence)."""
        ids: set[str] = set()
        for canon in canons:
            members = self.alias_ids(canon)
            if len(members) > MAX_ALIAS_IDS:
                self.truncated.add("component_oversize")
                members = frozenset({canon})
            ids |= members
        chunks = sorted(ids)
        for i in range(0, len(chunks), 400):
            chunk = chunks[i : i + 400]
            self._rows(
                ("devices", tuple(chunk)),
                f"SELECT {OBS_COLUMNS} {OBS_FROM}"  # noqa: S608
                f" WHERE o.device_id IN ({','.join('?' * len(chunk))}) LIMIT ?",
                tuple(chunk),
            )

    def add_target(self, canon: str) -> None:
        """The MACs of a target identity and the MACs sharing a fingerprint and a name with any
        of them (its known signatures, at most TARGET_KEYS)."""
        self.add_components([canon])
        keys = {k for o in self.by_canon(canon) for k in group_keys(o)}
        if len(keys) > TARGET_KEYS:
            self.truncated.add("target_keys")
        for opt55, opt60, kind, name in sorted(keys)[:TARGET_KEYS]:
            self.add_name(opt55, opt60, kind, name)

    def known_names(self, canon: str) -> set[str]:
        """The folded names of a target identity, at most TARGET_KEYS of them (more is incomplete
        evidence): what bounds the per-view known-name lookups."""
        names = self.names_of(canon)
        if len(names) > TARGET_KEYS:
            self.truncated.add("target_keys")
        return set(sorted(names)[:TARGET_KEYS])

    def load(self, *extra: str) -> None:
        """Activity (widened, clipped, inside retention) and first receipts of every MAC gathered
        so far plus `extra`: primary-key reads, at most INTERVALS_PER_MAC rows each."""
        macs = sorted((set(self.obs) | set(extra)) - self._loaded)
        if not macs:
            return
        self.tick()
        self._loaded.update(macs)
        first = load_first_received(self.inv, macs)
        self.first_recv.update(first)
        self.act.update(
            load_activity(
                self.inv,
                macs,
                min_width_s=self.cfg.activity_gap_s,
                min_end=self.cutoff,
                first_received=first,
            )  # fmt: skip
        )

    # ---- views -----------------------------------------------------------------------------

    def by_canon(self, canon: str) -> list[Obs]:
        return [o for o in self.obs.values() if o.canon == canon]

    def canon_macs(self, canons: Iterable[str]) -> set[str]:
        wanted = set(canons)
        return {o.mac for o in self.obs.values() if o.canon in wanted}

    def names_of(self, canon: str) -> set[str]:
        """Folded hostnames and mDNS names seen on any MAC of a device."""
        return {fold(n) for o in self.by_canon(canon) for n in (o.hostname, o.mdns) if n}

    def groups(self) -> dict[GroupKey, list[Obs]]:
        out: dict[GroupKey, list[Obs]] = defaultdict(list)
        for o in self.obs.values():
            for key in group_keys(o):
                out[key].append(o)
        return out

    def name_peers(self, c: Obs, groups: dict[GroupKey, list[Obs]] | None = None) -> list[Obs]:
        """Every other MAC with c's opt55 and opt60 and an agreeing hostname or mDNS name (through
        a precomputed `groups()` map when a caller has one: linear, not quadratic)."""
        groups = self.groups() if groups is None else groups
        return [o for k in group_keys(c) for o in groups.get(k, ()) if o.mac != c.mac]

    def live(self, o: Obs) -> bool:
        """Still a self MAC with activity inside the retention window."""
        return o.source == "self" and bool(self.act.get(o.mac))

    def counted(self, o: Obs) -> bool:
        """Counts toward flood populations: live and not on a retired device."""
        return self.live(o) and not o.retired
