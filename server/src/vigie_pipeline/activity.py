"""Per-MAC activity intervals (inventory.db `mac_activity`), derived from raw-shard row timestamps.

A MAC's row timestamps are folded into closed intervals [start, end]; silence longer than the
gap (default 5 min) starts a new interval. The table is derived and disposable (7 d retention,
like raw).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping

from vigie_pipeline.config import ACTIVITY_NEW_MAC_LOOKBACK_S, ACTIVITY_SKEW_S
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
    [received - retention, received + ACTIVITY_SKEW_S] (epoch-zero from a clock without an RTC, or
    far in the future) is ignored, because it could otherwise fake observed history. For a MAC
    with no stored activity the lower bound is tighter (ACTIVITY_NEW_MAC_LOOKBACK_S, 24 h): a MAC
    that is new to us cannot have a week of back-filled history to hide an overlap in."""
    inv.executemany(  # the server-clock maturity anchor: set once, never moved
        "INSERT OR IGNORE INTO mac_first_received (mac, received) VALUES (?,?)",
        [(mac, int(received_ts)) for mac in acts],
    )
    hi_ok = int(received_ts) + ACTIVITY_SKEW_S
    lo_known = int(received_ts) - retention_s
    lo_new = max(lo_known, int(received_ts) - ACTIVITY_NEW_MAC_LOOKBACK_S)
    for mac, act in acts.items():
        known = inv.execute("SELECT 1 FROM mac_activity WHERE mac=? LIMIT 1", (mac,)).fetchone()
        lo_ok = lo_known if known else lo_new
        stamps = sorted(t for t in act.stamps if lo_ok <= t <= hi_ok)
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


def load_first_received(inv: sqlite3.Connection) -> dict[str, int]:
    """SERVER time (batch receipt, epoch s) each MAC was first folded into mac_activity."""
    return {r[0]: r[1] for r in inv.execute("SELECT mac, received FROM mac_first_received")}


def load_activity(
    inv: sqlite3.Connection,
    min_width_s: int = 0,
    *,
    per_mac_limit: int | None = None,
    first_received: Mapping[str, int] | None = None,
    max_lag_s: int = 0,
) -> dict[str, list[Interval]]:
    """Per-MAC merged intervals. An interval shorter than min_width_s is widened symmetrically to
    that width: a stamp means "present around then", so a single-stamp or zero-length interval
    must still be able to overlap (otherwise sparse stamps dodge the overlap veto).

    per_mac_limit reads only each observed MAC's newest raw intervals (index seeks, so the rows
    loaded are bounded; raw intervals more than a gap apart never merge after widening, so this is
    the same set as the newest merged ones). With first_received, a MAC's activity earlier than
    its first server receipt minus max_lag_s is clipped away: collector stamps are untrusted and
    back-filled history must not establish maturity or time apart."""
    if per_mac_limit is None:
        rows = inv.execute('SELECT mac, start, "end" FROM mac_activity ORDER BY mac, start')
    else:
        rows = (
            row
            for (mac,) in inv.execute("SELECT mac FROM observations").fetchall()
            for row in inv.execute(
                'SELECT mac, start, "end" FROM (SELECT mac, start, "end" FROM mac_activity'
                " WHERE mac=? ORDER BY start DESC LIMIT ?) ORDER BY start",
                (mac, per_mac_limit),
            ).fetchall()
        )
    raw: dict[str, list[Interval]] = {}
    for row in rows:
        start, end = row[1], row[2]
        short = min_width_s - (end - start)
        if short > 0:
            start, end = start - short // 2, end + short - short // 2
        if first_received is not None and row[0] in first_received:
            horizon = first_received[row[0]] - max_lag_s
            if end < horizon:
                continue  # wholly before the trusted horizon
            start = max(start, horizon)
        raw.setdefault(row[0], []).append((start, end))
    return {mac: merge_intervals(ivs) for mac, ivs in raw.items()}


def purge_activity(inv: sqlite3.Connection, now: float, retention_s: int) -> int:
    purged = inv.execute(
        'DELETE FROM mac_activity WHERE "end" < ?', (int(now) - retention_s,)
    ).rowcount
    inv.execute(  # a MAC with no activity left starts over (like a new one) if it returns
        "DELETE FROM mac_first_received WHERE received < ?"
        " AND mac NOT IN (SELECT mac FROM mac_activity)",
        (int(now) - retention_s,),
    )
    return purged
