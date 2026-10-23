"""Per-MAC activity intervals (inventory.db `mac_activity`), derived from raw-shard row timestamps.

A MAC's row timestamps are folded into closed intervals [start, end]; silence longer than the
gap (default 5 min) starts a new interval. The table is derived and disposable (7 d retention,
like raw).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence

from vigie_pipeline.config import ACTIVITY_MAX_REPORT_LAG_S, ACTIVITY_SKEW_S
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
    collector: str | None = None,
) -> None:
    """Fold a batch's row timestamps into mac_activity. Idempotent: re-folding the same stamps
    changes nothing, and out-of-order batches coalesce with neighbouring intervals.

    Row timestamps are collector-supplied and untrusted: a stamp outside
    [received - min(retention, ACTIVITY_MAX_REPORT_LAG_S), received + ACTIVITY_SKEW_S] is ignored
    (epoch-zero from a clock without an RTC, far in the future, or back-filled older than the
    report lag of THIS batch), because it could otherwise fake observed history. The rule is the
    same for a new and a known MAC and for every batch, so a later batch cannot back-fill the
    absence of a peer either. A collector offline for longer than the lag loses the older part of
    its backlog. That is MISSING evidence, not safe evidence: with a `collector`, the span of the
    dropped stamps is recorded in `collector_gaps`; the stitcher refuses to mature a MAC whose
    activity window overlaps a gap. (A collector that is simply silent delivers no stamps and
    leaves no trace: that absence of evidence cannot be told from an idle network.)"""
    inv.executemany(  # the server-clock maturity anchor: set once, never moved
        "INSERT OR IGNORE INTO mac_first_received (mac, received) VALUES (?,?)",
        [(mac, int(received_ts)) for mac in acts],
    )
    hi_ok = int(received_ts) + ACTIVITY_SKEW_S
    lo_ok = int(received_ts) - min(retention_s, ACTIVITY_MAX_REPORT_LAG_S)
    if collector is not None:
        _record_gaps(inv, acts, collector, int(received_ts), lo_ok, retention_s)
        inv.executemany(
            "INSERT OR IGNORE INTO mac_collectors (mac, collector_id) VALUES (?,?)",
            [(mac, collector) for mac in acts],
        )
    for mac, act in acts.items():
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


def _record_gaps(
    inv: sqlite3.Connection, acts: Mapping[str, MacActivity], collector: str, received: int,
    lo_ok: int, retention_s: int,
) -> None:  # fmt: skip
    """Evidence this collector could not deliver in time: the span of the stamps dropped for being
    older than the report lag (but inside retention)."""
    late = [t for act in acts.values() for t in act.stamps if received - retention_s <= t < lo_ok]
    if not late:
        return
    start, end = min(late), lo_ok
    for (
        row
    ) in inv.execute(  # merge into the collector's overlapping gaps: few rows, not one per batch
        'SELECT start, "end" FROM collector_gaps'
        ' WHERE collector_id=? AND "end" >= ? AND start <= ?',
        (collector, start, end),
    ).fetchall():
        start, end = min(start, row[0]), max(end, row[1])
    inv.execute(
        'DELETE FROM collector_gaps WHERE collector_id=? AND "end" >= ? AND start <= ?',
        (collector, start, end),
    )
    inv.execute(
        'INSERT INTO collector_gaps (collector_id, start, "end", recorded) VALUES (?,?,?,?)',
        (collector, start, end, received),
    )


def load_gaps(
    inv: sqlite3.Connection, since: int, tick: Callable[[], None] = lambda: None
) -> dict[str, list[Interval]]:
    """Evidence gaps that end no earlier than `since`, per collector, merged (overlapping gaps
    become one) and sorted, at most MAX_GAPS_PER_COLLECTOR newest per collector."""
    raw: dict[str, list[Interval]] = {}
    for i, r in enumerate(
        inv.execute(
            'SELECT collector_id, start, "end" FROM collector_gaps WHERE "end" >= ?'
            " ORDER BY collector_id, start",
            (since,),
        )
    ):
        if not i % 4096:
            tick()
        raw.setdefault(r[0], []).append((r[1], r[2]))
    return {c: merge_intervals(g)[-MAX_GAPS_PER_COLLECTOR:] for c, g in raw.items()}


def load_collectors(
    inv: sqlite3.Connection, macs: Sequence[str], tick: Callable[[], None] = lambda: None
) -> dict[str, frozenset[str]]:
    """The collectors that saw each of the given MACs (primary-key seeks, in chunks)."""
    out: dict[str, set[str]] = {}
    for i in range(0, len(macs), 400):
        tick()
        chunk = list(macs[i : i + 400])
        for r in inv.execute(
            "SELECT mac, collector_id FROM mac_collectors"  # noqa: S608
            f" WHERE mac IN ({','.join('?' * len(chunk))})",
            chunk,
        ):
            out.setdefault(r[0], set()).add(r[1])
    return {m: frozenset(c) for m, c in out.items()}


MAX_GAPS_PER_COLLECTOR = 1000


def load_first_received(
    inv: sqlite3.Connection,
    macs: Sequence[str],
    tick: Callable[[], None] = lambda: None,
    legacy: set[str] | None = None,
) -> dict[str, int]:
    """SERVER time (batch receipt, epoch s) each of the given MACs was first folded into
    mac_activity (primary-key seeks, in chunks, with a time check between chunks)."""
    out: dict[str, int] = {}
    for i in range(0, len(macs), 400):
        tick()
        chunk = list(macs[i : i + 400])
        for r in inv.execute(
            "SELECT mac, received, legacy FROM mac_first_received"  # noqa: S608
            f" WHERE mac IN ({','.join('?' * len(chunk))})",
            chunk,
        ):
            out[r[0]] = r[1]
            if legacy is not None and r[2]:
                legacy.add(r[0])
    return out


PAGE = 1000


def active_macs(
    inv: sqlite3.Connection, min_end: int, tick: Callable[[], None], limit: int | None = None
) -> tuple[list[str], bool]:
    """MACs with activity ending no earlier than `min_end`, NEWEST first, from the small
    `mac_last_seen` summary (kept by a trigger on mac_activity) through its `last_end` index in
    keyset pages: only ACTIVE MACs are ever examined, never stale rows, and `tick` runs between
    pages. With `limit`, stops after that many MACs and reports that the set was capped."""
    macs: list[str] = []
    last_end, last_mac = 2**62, "\U0010ffff"
    while True:
        tick()
        rows = inv.execute(
            "SELECT mac, last_end FROM mac_last_seen WHERE last_end >= ?"
            " AND (last_end < ? OR (last_end = ? AND mac < ?)) ORDER BY last_end DESC, mac DESC"
            " LIMIT ?",
            (min_end, last_end, last_end, last_mac, PAGE),
        ).fetchall()
        if not rows:
            return macs, False
        macs.extend(r[0] for r in rows)
        if limit is not None and len(macs) >= limit:
            capped = (
                len(macs) > limit
                or inv.execute(
                    "SELECT 1 FROM mac_last_seen WHERE last_end >= ? AND (last_end < ?"
                    " OR (last_end = ? AND mac < ?)) LIMIT 1",
                    (min_end, rows[-1][1], rows[-1][1], rows[-1][0]),
                ).fetchone()
                is not None
            )
            return macs[:limit], capped
        last_mac, last_end = rows[-1][0], rows[-1][1]


def _ticked(macs: Iterable[str], tick: Callable[[], None]) -> Iterable[str]:
    for mac in macs:
        tick()
        yield mac


def load_activity(
    inv: sqlite3.Connection,
    min_width_s: int = 0,
    *,
    per_mac_limit: int | None = None,
    first_received: Mapping[str, int] | None = None,
    max_lag_s: int = 0,
    min_end: int = 0,
    tick: Callable[[], None] = lambda: None,
    macs: Sequence[str] | None = None,
    clip_exempt: Collection[str] = (),
) -> dict[str, list[Interval]]:
    """Per-MAC merged intervals. An interval shorter than min_width_s is widened symmetrically to
    that width: a stamp means "present around then", so a single-stamp or zero-length interval
    must still be able to overlap (otherwise sparse stamps dodge the overlap veto).

    per_mac_limit reads only the newest raw intervals of each MAC with activity ending at or
    after `min_end` (the retention cutoff): the MACs are `macs` or, by default, `active_macs`, and
    `tick` runs between MACs, so the rows loaded are bounded by the ACTIVE MACs, not by every MAC
    ever observed. Raw intervals more than a gap apart never merge after widening, so this is the
    same set as the newest merged ones. With first_received, a MAC's activity earlier than its
    first server receipt minus max_lag_s is clipped away: collector stamps are untrusted and
    back-filled history must not establish maturity or time apart."""
    if per_mac_limit is None:
        rows = inv.execute('SELECT mac, start, "end" FROM mac_activity ORDER BY mac, start')
    else:
        rows = (
            row
            for mac in _ticked(
                macs if macs is not None else active_macs(inv, min_end, tick)[0], tick
            )
            for row in inv.execute(
                'SELECT mac, start, "end" FROM (SELECT mac, start, "end" FROM mac_activity'
                ' WHERE mac=? AND "end" >= ? ORDER BY start DESC LIMIT ?) ORDER BY start',
                (mac, min_end, per_mac_limit),
            ).fetchall()
        )
    raw: dict[str, list[Interval]] = {}
    for row in rows:
        start, end = row[1], row[2]
        short = min_width_s - (end - start)
        if short > 0:
            start, end = start - short // 2, end + short - short // 2
        if first_received is not None and row[0] in first_received and row[0] not in clip_exempt:
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
    inv.execute('DELETE FROM collector_gaps WHERE "end" < ?', (int(now) - retention_s,))
    inv.execute("DELETE FROM mac_last_seen WHERE last_end < ?", (int(now) - retention_s,))
    inv.execute(  # a MAC with no activity left starts over (like a new one) if it returns
        "DELETE FROM mac_first_received WHERE received < ?"
        " AND mac NOT IN (SELECT mac FROM mac_activity)",
        (int(now) - retention_s,),
    )
    return purged
