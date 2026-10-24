"""Per-MAC activity intervals (inventory.db `mac_activity`), derived from raw-shard row timestamps.

A MAC's row timestamps are folded into closed intervals [start, end]; silence longer than the
gap (default 5 min) starts a new interval. At most INTERVALS_PER_MAC rows are kept per MAC (the
closest intervals are coalesced, which only ADDS presence: conservative for every veto). The table
is derived and disposable (7 d retention, like raw).
"""

from __future__ import annotations

import json
import sqlite3
from bisect import bisect_left
from collections.abc import Iterable, Mapping, Sequence

from vigie_ingest.db import immediate
from vigie_pipeline.config import (
    ACTIVITY_MAX_REPORT_LAG_S,
    ACTIVITY_SKEW_S,
    INTERVALS_PER_MAC,
    PRUNE_BATCH_ROWS,
)
from vigie_pipeline.sources import MacActivity

Interval = tuple[int, int]


def merge_intervals(intervals: Iterable[Interval], gap_s: int = 0) -> list[Interval]:
    """Sort and coalesce intervals whose separation is at most gap_s."""
    merged: list[Interval] = []
    for start, end in sorted(intervals):
        if merged and start - merged[-1][1] <= gap_s:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def coalesce_to(intervals: list[Interval], limit: int) -> list[Interval]:
    """At most `limit` intervals: exactly the smallest silences are bridged (earliest first on a
    tie). Bridging a MAC's own silence only adds presence."""
    if len(intervals) <= limit:
        return intervals
    by_size = sorted(
        range(len(intervals) - 1), key=lambda i: (intervals[i + 1][0] - intervals[i][1], i)
    )
    bridged = set(by_size[: len(intervals) - limit])
    out = [intervals[0]]
    for i in range(1, len(intervals)):
        if i - 1 in bridged:
            out[-1] = (out[-1][0], max(out[-1][1], intervals[i][1]))
        else:
            out.append(intervals[i])
    return out


def overlap_seconds(a: list[Interval], b: list[Interval]) -> int:
    """Total length of the intersection of two merged (sorted, disjoint) interval lists."""
    total, i, j = 0, 0, 0
    while i < len(a) and j < len(b):
        total += max(0, min(a[i][1], b[j][1]) - max(a[i][0], b[j][0]))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def record_activity(
    inv: sqlite3.Connection,
    acts: Mapping[str, MacActivity],
    gap_s: int,
    received_ts: float,
    retention_s: int,
) -> None:
    """Fold a batch's row timestamps into mac_activity. Idempotent: re-folding the same stamps
    changes nothing, and out-of-order batches coalesce with neighbouring intervals.

    Row timestamps are collector-supplied and untrusted: a stamp outside
    [received - min(retention, ACTIVITY_MAX_REPORT_LAG_S), received + ACTIVITY_SKEW_S] is ignored
    (epoch-zero from a clock without an RTC, far in the future, or back-filled older than the
    report lag of THIS batch), because it could otherwise fake observed history. The rule is the
    same for a new and a known MAC and for every batch, so a later batch cannot back-fill the
    absence of a peer either. Stamps dropped for the lag are MISSING evidence, not safe evidence:
    their span is recorded in `evidence_gaps` (section 1 of docs/stitching.md)."""
    # Cleanup is paged: an expired anchor can outlive its activity rows. Check the
    # retained evidence before adding fresh rows, including rows awaiting pruning.
    inv.executemany(
        "DELETE FROM mac_first_received WHERE mac=? AND NOT EXISTS ("
        'SELECT 1 FROM mac_activity WHERE mac=? AND "end">=?)',
        [(mac, mac, int(received_ts) - retention_s) for mac in acts],
    )
    inv.executemany(  # server-clock anchor, stable while retained activity survives
        "INSERT OR IGNORE INTO mac_first_received (mac, received) VALUES (?,?)",
        [(mac, int(received_ts)) for mac in acts],
    )
    hi_ok = int(received_ts) + ACTIVITY_SKEW_S
    lo_ok = int(received_ts) - min(retention_s, ACTIVITY_MAX_REPORT_LAG_S)
    _record_gap(inv, acts, int(received_ts), lo_ok, retention_s, gap_s)
    for mac, act in acts.items():
        stamps = sorted(t for t in act.stamps if lo_ok <= t <= hi_ok)
        if stamps:
            _fold(inv, mac, merge_intervals(((t, t) for t in stamps), gap_s), gap_s)


def _fold(inv: sqlite3.Connection, mac: str, fresh: list[Interval], gap_s: int) -> None:
    """Rewrite the MAC's rows that touch the fresh intervals; when the MAC would exceed
    INTERVALS_PER_MAC rows, every row of the MAC is coalesced down to the cap."""
    lo, hi = fresh[0][0] - gap_s, fresh[-1][1] + gap_s
    where = 'mac=? AND "end">=? AND start<=?'
    select = f'SELECT start, "end" FROM mac_activity WHERE {where}'  # noqa: S608
    old = inv.execute(select, (mac, lo, hi)).fetchall()
    merged = merge_intervals([*((r[0], r[1]) for r in old), *fresh], gap_s)
    others = inv.execute(
        'SELECT COUNT(*) FROM mac_activity WHERE mac=? AND NOT ("end">=? AND start<=?)',
        (mac, lo, hi),
    ).fetchone()[0]
    if others + len(merged) > INTERVALS_PER_MAC:
        rows = inv.execute('SELECT start, "end" FROM mac_activity WHERE mac=?', (mac,)).fetchall()
        merged = coalesce_to(
            merge_intervals([*((r[0], r[1]) for r in rows), *fresh], gap_s), INTERVALS_PER_MAC
        )
        inv.execute("DELETE FROM mac_activity WHERE mac=?", (mac,))
    else:
        inv.execute(f"DELETE FROM mac_activity WHERE {where}", (mac, lo, hi))  # noqa: S608
    inv.executemany(
        'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
        [(mac, s, e) for s, e in merged],
    )


def _record_gap(
    inv: sqlite3.Connection, acts: Mapping[str, MacActivity], received: int, lo_ok: int,
    retention_s: int, gap_s: int,
) -> None:  # fmt: skip
    """The span of the stamps dropped for being older than the report lag (inside retention),
    merged into the existing gaps within one activity gap of it, so the table holds at most
    retention / gap_s rows whatever a collector sends."""
    late = [t for act in acts.values() for t in act.stamps if received - retention_s <= t < lo_ok]
    if not late:
        return
    start, end = min(late), lo_ok
    for row in inv.execute(
        'SELECT start, "end" FROM evidence_gaps WHERE "end" >= ? AND start <= ?',
        (start - gap_s, end + gap_s),
    ).fetchall():
        start, end = min(start, row[0]), max(end, row[1])
    inv.execute(
        'DELETE FROM evidence_gaps WHERE "end" >= ? AND start <= ?', (start - gap_s, end + gap_s)
    )
    inv.execute('INSERT INTO evidence_gaps (start, "end") VALUES (?,?)', (start, end))


class Gaps:
    """The merged evidence gaps ending no earlier than `since` (all of them: bounded by
    retention / gap at write time), with a binary-search overlap test."""

    def __init__(self, inv: sqlite3.Connection, since: int) -> None:
        rows = inv.execute(
            'SELECT start, "end" FROM evidence_gaps WHERE "end" >= ? ORDER BY start', (since,)
        ).fetchall()
        self.spans = merge_intervals((r[0], r[1]) for r in rows)
        self._ends = [e for _, e in self.spans]

    def overlaps(self, lo: int, hi: int) -> bool:
        i = bisect_left(self._ends, lo)
        return i < len(self.spans) and self.spans[i][0] <= hi


def load_first_received(inv: sqlite3.Connection, macs: Sequence[str]) -> dict[str, int]:
    """SERVER time (batch receipt, epoch s) each MAC was first folded (primary-key seeks)."""
    out: dict[str, int] = {}
    for i in range(0, len(macs), 400):
        chunk = list(macs[i : i + 400])
        for r in inv.execute(
            "SELECT mac, received FROM mac_first_received"  # noqa: S608
            f" WHERE mac IN ({','.join('?' * len(chunk))})",
            chunk,
        ):
            out[r[0]] = r[1]
    return out


def load_activity(
    inv: sqlite3.Connection,
    macs: Sequence[str],
    *,
    min_width_s: int,
    min_end: int,
    first_received: Mapping[str, int],
    max_lag_s: int = ACTIVITY_MAX_REPORT_LAG_S,
) -> dict[str, list[Interval]]:
    """Per-MAC merged intervals ending at or after `min_end` (primary-key range per MAC, at most
    INTERVALS_PER_MAC rows each). An interval shorter than min_width_s is widened symmetrically to
    that width: a stamp means "present around then", so a lone stamp must still be able to
    overlap. Activity earlier than the MAC's first server receipt minus max_lag_s is clipped
    away: collector stamps are untrusted and back-filled history must not establish maturity or
    time apart. A MAC with no receipt row is not clipped (it stays evidence about its peers) but
    can never be mature (see Stitcher.maturity)."""
    raw: dict[str, list[Interval]] = {}
    for i in range(0, len(macs), 400):
        chunk = list(macs[i : i + 400])
        rows = inv.execute(
            'SELECT mac, start, "end" FROM mac_activity'  # noqa: S608
            f' WHERE mac IN ({",".join("?" * len(chunk))}) AND "end" >= ?',
            [*chunk, min_end],
        ).fetchall()
        for mac, start, end in rows:
            short = min_width_s - (end - start)
            if short > 0:
                start, end = start - short // 2, end + short - short // 2
            horizon = first_received.get(mac, start) - max_lag_s
            if end >= horizon:
                raw.setdefault(mac, []).append((max(start, horizon), end))
    return {mac: merge_intervals(ivs) for mac, ivs in raw.items()}


def purge_activity(inv: sqlite3.Connection, now: float, retention_s: int) -> int:
    """Prune one indexed, count-limited batch per table, each in its own transaction.

    Further expired rows wait for later passes. Anchor candidates advance in received/MAC
    order so old anchors with surviving activity cannot starve orphaned anchors behind them.
    The cursor persists across connections and wraps after the last expired candidate.
    """
    cutoff = int(now) - retention_s
    with immediate(inv):
        purged = inv.execute(
            "DELETE FROM mac_activity WHERE rowid IN ("
            'SELECT rowid FROM mac_activity WHERE "end" < ? ORDER BY "end" LIMIT ?)',
            (cutoff, PRUNE_BATCH_ROWS),
        ).rowcount
    with immediate(inv):
        inv.execute(
            "DELETE FROM evidence_gaps WHERE rowid IN ("
            'SELECT rowid FROM evidence_gaps WHERE "end" < ? ORDER BY "end" LIMIT ?)',
            (cutoff, PRUNE_BATCH_ROWS),
        )
    with immediate(inv):
        key = "activity_prune_anchor_cursor"
        saved = inv.execute("SELECT value FROM pipeline_meta WHERE key=?", (key,)).fetchone()
        after = " AND (received, mac) > (?, ?)" if saved else ""
        params = [cutoff, *json.loads(saved[0])] if saved else [cutoff]
        rows = inv.execute(
            "SELECT received, mac FROM mac_first_received WHERE received < ?"  # noqa: S608
            f"{after} ORDER BY received, mac LIMIT ?",
            [*params, PRUNE_BATCH_ROWS],
        ).fetchall()
        # A MAC with no activity left starts over (like a new one) if it returns.
        inv.executemany(
            "DELETE FROM mac_first_received WHERE mac=? AND NOT EXISTS ("
            "SELECT 1 FROM mac_activity WHERE mac=?)",
            [(row[1], row[1]) for row in rows],
        )
        if len(rows) == PRUNE_BATCH_ROWS:
            inv.execute(
                "INSERT OR REPLACE INTO pipeline_meta (key, value) VALUES (?, ?)",
                (key, json.dumps(tuple(rows[-1]))),
            )
        else:
            inv.execute("DELETE FROM pipeline_meta WHERE key=?", (key,))
    return purged
