"""Per-MAC activity intervals (inventory.db `mac_activity`), derived from raw-shard row timestamps.

A MAC's row timestamps are folded into closed intervals [start, end]; silence longer than the
gap (default 5 min) starts a new interval. The table is derived and disposable (7 d retention,
like raw).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping

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


def record_activity(inv: sqlite3.Connection, acts: Mapping[str, MacActivity], gap_s: int) -> None:
    """Fold a batch's row timestamps into mac_activity. Idempotent: re-folding the same stamps
    changes nothing, and out-of-order batches coalesce with neighbouring intervals."""
    for mac, act in acts.items():
        stamps = sorted(t for t in act.stamps if t >= 0)
        if not stamps:
            continue
        fresh = merge_intervals(((t, t) for t in stamps), gap_s)
        lo, hi = fresh[0][0] - gap_s, fresh[-1][1] + gap_s
        where = 'mac=? AND "end">=? AND start<=?'
        old = [
            (r[0], r[1])
            for r in inv.execute(
                f'SELECT start, "end" FROM mac_activity WHERE {where}',  # noqa: S608
                (mac, lo, hi),
            )
        ]
        inv.execute(f"DELETE FROM mac_activity WHERE {where}", (mac, lo, hi))  # noqa: S608
        inv.executemany(
            'INSERT INTO mac_activity (mac, start, "end") VALUES (?,?,?)',
            [(mac, s, e) for s, e in merge_intervals([*old, *fresh], gap_s)],
        )


def load_activity(inv: sqlite3.Connection, min_width_s: int = 0) -> dict[str, list[Interval]]:
    """Per-MAC merged intervals. An interval shorter than min_width_s is widened symmetrically to
    that width: a stamp means "present around then", so a single-stamp or zero-length interval
    must still be able to overlap (otherwise sparse stamps dodge the overlap veto)."""
    raw: dict[str, list[Interval]] = {}
    for row in inv.execute('SELECT mac, start, "end" FROM mac_activity ORDER BY mac, start'):
        start, end = row[1], row[2]
        short = min_width_s - (end - start)
        if short > 0:
            start, end = start - short // 2, end + short - short // 2
        raw.setdefault(row[0], []).append((start, end))
    return {mac: merge_intervals(ivs) for mac, ivs in raw.items()}


def purge_activity(inv: sqlite3.Connection, now: float, retention_s: int) -> int:
    return inv.execute(
        'DELETE FROM mac_activity WHERE "end" < ?', (int(now) - retention_s,)
    ).rowcount
