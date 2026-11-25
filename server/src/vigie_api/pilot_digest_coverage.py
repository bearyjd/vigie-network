"""Observation completeness of one UTC day per collector, for the pilot digest.

Same rule as the pilot report and the engine: an hour is qualified when it has at least
QUALIFIED_SECONDS and no degradation reason. Reason codes are counted; free text never leaves.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter

from vigie_api.pilot_report import QUALIFIED_SECONDS, _reasons_clear

HOURS = 24
MAX_REASON_CODES = 16
_REASON = re.compile(r"[a-z0-9_]{1,32}")


def _hour_reasons(qualified: int, text: object) -> list[str]:
    """Reason codes for one non-qualified hour; free text never leaves as such."""
    try:
        parsed = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        parsed = None
    if not isinstance(parsed, list):
        return ["other"]
    codes = sorted({c if isinstance(c, str) and _REASON.fullmatch(c) else "other" for c in parsed})
    if codes:
        return codes
    return ["short_observation"] if qualified < QUALIFIED_SECONDS else ["other"]


def coverage(inv: sqlite3.Connection, lo: int, hi: int, networks: int) -> tuple[dict, bool]:
    """Per raw collector id: qualified hours of the day and counted reasons for the others;
    truncated (True) when more than `networks` collectors have rows."""
    rows = inv.execute(
        "SELECT collector_id,hour,qualified_seconds,reasons FROM coverage_hourly "
        "WHERE hour>=? AND hour<? ORDER BY collector_id,hour LIMIT ?",
        (lo, hi, HOURS * networks + 1),
    ).fetchall()
    seen: dict[str, set[int]] = {}
    good: Counter[str] = Counter()
    why: dict[str, Counter[str]] = {}
    for row in rows[: HOURS * networks]:
        cid = row["collector_id"]
        seen.setdefault(cid, set()).add(row["hour"])
        why.setdefault(cid, Counter())
        if row["qualified_seconds"] >= QUALIFIED_SECONDS and _reasons_clear(row["reasons"]):
            good[cid] += 1
        else:
            why[cid].update(_hour_reasons(row["qualified_seconds"], row["reasons"]))
    out = {cid: coverage_entry(good[cid], len(hours), why[cid]) for cid, hours in seen.items()}
    return out, len(rows) > HOURS * networks


def coverage_entry(qualified: int, rows: int, why: Counter[str]) -> dict:
    reasons = Counter(why)
    if rows < HOURS:
        reasons["no_row"] += HOURS - rows
    kept = dict(sorted(reasons.items())[:MAX_REASON_CODES])
    if len(reasons) > MAX_REASON_CODES:
        kept["other"] = kept.get("other", 0) + sum(sorted(reasons.values())[MAX_REASON_CODES:])
    return {
        "qualified_hours": qualified,
        "hours": HOURS,
        "complete": qualified == HOURS,
        "reasons": kept,
    }
