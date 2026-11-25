"""Read-only per-UTC-day pilot digest (roadmap L2): what the owner has to label for one day.

Run it on a checkpointed COPY (a backup that `vigie-backup verify` accepted), never on the live
files: `vigie_api.ro_snapshot` opens it immutable and refuses what an immutable open would misread.

The digest reuses the pilot report's definitions (`vigie_api.pilot_report`): qualified hours, the
delivery watermark, the upload-only budget (sent `open` rows by UTC day of completion, unwanted =
the owner's CURRENT decision is `expected`, network = collector) and the evidence-gap rule. It
never infers a label: a decision is shown as the owner recorded it and the label template leaves
`owner_label` empty. A `sent` row proves only a durable local append; nothing in the databases
proves that a notification reached the owner, so every sent item is "receipt unverified".

Output holds only incident, device, lineage and collector ids, detector names, states and UTC
times: no MAC, IP, hostname, device name, evidence JSON or delivery error text. Ids that are not
plain tokens are masked. Everything is bounded (MAX_ITEMS, MAX_NETWORKS) and a truncated digest
makes every verdict unknown.
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from vigie_api.pilot_digest_coverage import coverage, coverage_entry
from vigie_api.pilot_report import (
    _NON_UPLOAD_DETECTORS,
    DELIVERY_RETENTION_S,
    LIVE_LAG_S,
    TARGET_UNWANTED_PER_NETWORK_DAY,
    _has_table,
    _lookup,
    beyond_coverage_retention,
    beyond_incident_retention,
    delivery_watermark,
    engine_lo,
    evidence_gap,
    liveness,
    stale_reason,
)
from vigie_api.ro_snapshot import InputRefused, reading
from vigie_ingest.db import iso_utc

SCHEMA = "vigie-pilot-digest/1"
MAX_ITEMS = 2000
MAX_NETWORKS = 64
MASKED = "invalid-id#"  # "#" is outside _SAFE_ID: no real id can equal a masked label
_SAFE_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_INV_TABLES = ("coverage_hourly", "monitoring_incidents", "incident_deliveries")
DELIVERY = {
    "sent": "appended_locally",
    "pending": "pending",
    "sending": "pending",
    "suppressed": "suppressed",
    "failed": "not_delivered",
    "expired": "not_delivered",
    "withdrawn": "not_delivered",
}
NOTES = (
    "appended_locally means the pipeline wrote the notification to its local delivery file; "
    "actual receipt is never proven by the databases (receipt unverified)",
    "the budget counts open notifications of upload detectors RECORDED as sent that UTC day; "
    "unwanted = the owner's current decision is expected",
    "unknown means the evidence is incomplete or unreviewed; it is never read as healthy",
)

Item = dict[str, Any]


def safe_id(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and _SAFE_ID.fullmatch(value) else MASKED


def _safe_time(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and _ISO.fullmatch(value) else "invalid-time"


def _item_ids(inv: sqlite3.Connection, lo: int, hi: int) -> tuple[list[str], bool]:
    """Incidents detected in the day, then incidents whose open notification was sent in it."""
    detected = inv.execute(
        "SELECT id FROM monitoring_incidents WHERE last_hour>=? AND detected_at>=? "
        "AND detected_at<? ORDER BY seq LIMIT ?",
        (engine_lo(lo), iso_utc(lo), iso_utc(hi), MAX_ITEMS + 1),
    ).fetchall()
    sent = inv.execute(
        "SELECT incident_id FROM incident_deliveries WHERE kind='open' AND state='sent' "
        "AND updated_at>=? AND updated_at<? ORDER BY updated_at,row_id LIMIT ?",
        (lo, hi, MAX_ITEMS + 1),
    ).fetchall()
    ids = list(dict.fromkeys([r[0] for r in detected] + [r[0] for r in sent]))
    truncated = len(detected) > MAX_ITEMS or len(sent) > MAX_ITEMS or len(ids) > MAX_ITEMS
    return sorted(ids[:MAX_ITEMS]), truncated


def _delivery(found: tuple | None, detected: str | None, watermark: int | None) -> str:
    if found is None:
        eligible = watermark is None or detected is None or detected >= iso_utc(watermark)
        return "no_open_row" if eligible else "not_eligible"
    return DELIVERY.get(found[0], "unrecognised")


_DELIVERY_UNKNOWN = {
    "no_open_row": "no open delivery row",
    "pending": "delivery pending",
    "unrecognised": "unrecognised delivery state",
}


def make_item(  # noqa: PLR0913
    iid: str,
    inc: tuple | None,
    dlv: tuple | None,
    dec: tuple | None,
    window: tuple[int, int],
    watermark: int | None,
) -> Item:
    collector, device, lineage, detector, state, detected = inc or (None,) * 6
    status, decision_network = dec or (None, None)
    delivery = _delivery(dlv, detected, watermark)
    appended = delivery == "appended_locally"
    reasons = []
    if inc is None:
        reasons.append("incident row missing")
    if status is None:
        reasons.append("unreviewed")
    if delivery in _DELIVERY_UNKNOWN:
        reasons.append(_DELIVERY_UNKNOWN[delivery])
    if appended:
        reasons.append("receipt unverified")
    budgeted = detector not in _NON_UPLOAD_DETECTORS
    sent_in_day = appended and dlv is not None and window[0] <= dlv[1] < window[1]
    return {
        "incident_id": safe_id(iid),
        # the decision's collector first, as pilot_report.unwanted_section attributes it
        "network": decision_network or collector,  # raw: named by network_names()
        "device_id": safe_id(device),
        "lineage": safe_id(lineage),
        "detector": safe_id(detector),
        "incident_state": safe_id(state),
        "opened_at": _safe_time(detected),
        "decision": safe_id(status),
        "labeled": status is not None,
        "delivery": delivery,
        "delivered_at": iso_utc(dlv[1]) if appended and dlv is not None else None,
        "receipt": "unverified" if appended else "not_sent",
        "budgeted_detector": budgeted,
        "sent_in_day": sent_in_day,
        "counts_toward_budget": budgeted and sent_in_day,
        "unknown_reasons": reasons,
    }


_INCIDENT_SQL = (
    "SELECT id,collector_id,device_id,lineage,detector,state,detected_at FROM monitoring_incidents "
    "WHERE id IN ({})"
)
_OPEN_SQL = "SELECT incident_id,state,updated_at FROM incident_deliveries WHERE kind='open' AND incident_id IN ({})"  # noqa: E501
_DECISION_SQL = (
    "SELECT incident_id,status,collector_id FROM incident_decisions WHERE incident_id IN ({})"  # noqa: E501
)


def collect_items(
    inv: sqlite3.Connection, ov: sqlite3.Connection | None, lo: int, hi: int, mark: int | None
) -> tuple[list[Item], bool]:
    ids, truncated = _item_ids(inv, lo, hi)
    incidents = _lookup(inv, _INCIDENT_SQL, ids)
    opens = _lookup(inv, _OPEN_SQL, ids)
    decisions = _lookup(ov, _DECISION_SQL, ids) if ov is not None else {}
    made = [
        make_item(i, incidents.get(i), opens.get(i), decisions.get(i), (lo, hi), mark) for i in ids
    ]
    return made, truncated


_EVIDENCE_REASONS = frozenset(  # a pending/sending row may already have reached the owner
    {
        "incident row missing",
        "no open delivery row",
        "unrecognised delivery state",
        "delivery pending",
    }
)


def budget(network: str, items: list[Item], inherited: list[str]) -> dict:
    """Unwanted opens of one network-day against the budget. `over` is a proven lower bound and
    stands despite unknowns; `within` needs every piece of evidence complete and reviewed."""
    counted = [i for i in items if i["network"] == network and i["counts_toward_budget"]]
    unwanted = sum(i["decision"] == "expected" for i in counted)
    undecided = sum(i["decision"] is None for i in counted)
    mine = [i for i in items if i["network"] == network]
    reasons = list(inherited)
    if undecided:
        reasons.append("unreviewed opens")
    if any(i["budgeted_detector"] and _EVIDENCE_REASONS & set(i["unknown_reasons"]) for i in mine):
        reasons.append("incomplete delivery evidence")
    if unwanted > TARGET_UNWANTED_PER_NETWORK_DAY:
        verdict = "over"
    else:
        verdict = "unknown" if reasons else "within"
    sent_other = sum(i["sent_in_day"] and not i["budgeted_detector"] for i in mine)
    return {
        "budget": TARGET_UNWANTED_PER_NETWORK_DAY,
        "counted_by": "opens recorded as sent that UTC day (local append); receipt unverified",
        "opens_sent": len(counted),
        "opens_not_budgeted": sent_other,
        "unwanted": unwanted,
        "undecided": undecided,
        "verdict": verdict,
        "unknown_reasons": reasons,
    }


def day_reasons(  # noqa: PLR0913
    inv: sqlite3.Connection, lo: int, hi: int, now: int, retention: int, mark: int | None
) -> list[str]:
    """Why no network-day verdict of this day can be trusted, whatever its own evidence."""
    why = []
    if now < hi + LIVE_LAG_S:
        why.append("day not complete as of --now")
    if mark is None or mark > lo:  # an incident before the watermark is never announced
        why.append("delivery not enabled for the whole day")
    if lo < now - retention:
        why.append("beyond delivery retention")
    if beyond_incident_retention(lo, now):
        why.append("beyond incident retention")
    if beyond_coverage_retention(lo, now):
        why.append("beyond coverage retention")
    gap = evidence_gap(inv, lo, hi)
    if gap:
        why.append(gap)
    engine, ingest = liveness(inv)
    stale = stale_reason(engine, ingest, hi)  # stopped before the day ended: zeros are not real
    if stale:
        why.append(stale)
    if max(engine or 0, ingest or 0) > now:  # --now is not when the copy was taken
        why.append("copy holds data newer than --now")
    return why


def _collectors(inv: sqlite3.Connection) -> tuple[set, set, bool]:
    """(active ids, revoked ids, truncated) of the collectors table, raw."""
    if not _has_table(inv, "collectors"):
        return set(), set(), False
    rows = inv.execute(
        "SELECT id,revoked FROM collectors ORDER BY id LIMIT ?", (4 * MAX_NETWORKS + 1,)
    ).fetchall()
    kept = rows[: 4 * MAX_NETWORKS]
    active = {r[0] for r in kept if not r[1]}
    return active, {r[0] for r in kept} - active, len(rows) > len(kept)


def network_names(raw: set) -> dict:
    """Display name per raw collector id: itself when it is a plain token, otherwise a distinct
    `invalid-id#N` in a stable order (never a valid id), so unsafe ids never merge into one budget
    and never collide with a real collector."""
    out = {r: r for r in raw if safe_id(r) != MASKED}
    unsafe = sorted(set(raw) - set(out), key=lambda r: (type(r).__name__, repr(r)))
    return {**out, **{r: f"{MASKED}{n}" for n, r in enumerate(unsafe, 1)}}


def build_digest(
    inv_path: Path, ov_path: Path | None, lo: int, now: int, retention: int = DELIVERY_RETENTION_S
) -> dict[str, Any]:
    """The digest of UTC day [lo, lo + 1 day) as of `now` (both from the caller, never a clock)."""
    hi = lo + 86400
    with ExitStack() as stack:
        inv = stack.enter_context(reading(inv_path))
        ov = stack.enter_context(reading(ov_path)) if ov_path is not None else None
        if not all(_has_table(inv, t) for t in _INV_TABLES) or (
            ov is not None and not _has_table(ov, "incident_decisions")
        ):
            raise InputRefused("database is not a supported Vigie inventory or overrides")
        mark = delivery_watermark(inv)
        cover, cover_cut = coverage(inv, lo, hi, MAX_NETWORKS)
        raw_items, items_cut = collect_items(inv, ov, lo, hi, mark)
        active, revoked, coll_cut = _collectors(inv)
        reasons = day_reasons(inv, lo, hi, now, retention, mark)
    seen = set(cover) | {i["network"] for i in raw_items if i["network"] is not None}
    names = network_names(seen | active)
    items = [{**i, "network": names.get(i["network"])} for i in raw_items]
    shown = sorted(names.items(), key=lambda kv: kv[1])
    if ov is None:
        reasons.append("no overrides database: decisions unavailable")
    if cover_cut or items_cut or coll_cut or len(shown) > MAX_NETWORKS:
        reasons.append("truncated")
    if any(i["network"] is None for i in items):
        reasons.append("item without a network")
    networks = {}
    for raw, name in shown[:MAX_NETWORKS]:
        entry = cover.get(raw) or coverage_entry(0, 0, Counter())
        own = [] if entry["complete"] else ["observation incomplete"]
        networks[name] = {"coverage": entry, "budget": budget(name, items, reasons + own)}
    unknown = [{"kind": "day", "id": iso_utc(lo)[:10], "reasons": reasons}] if reasons else []
    unknown += [
        {"kind": "network", "id": n, "reasons": v["budget"]["unknown_reasons"]}
        for n, v in networks.items()
        if v["budget"]["unknown_reasons"]
    ]
    unknown += [
        {"kind": "item", "id": i["incident_id"], "reasons": i["unknown_reasons"]}
        for i in items
        if i["unknown_reasons"]
    ]
    counts = Counter(i["delivery"] for i in items)
    return {
        "schema": SCHEMA,
        "day": iso_utc(lo)[:10],
        "as_of": iso_utc(now),
        "day_complete": now >= hi + LIVE_LAG_S,
        "assumed_delivery_retention_s": retention,
        "truncated": "truncated" in reasons,
        "revoked_hidden": len(revoked - seen),
        "notes": list(NOTES),
        "networks": networks,
        "items": items,
        "counts": {
            "items": len(items),
            "unlabeled": sum(not i["labeled"] for i in items),
            "unknown_items": sum(bool(i["unknown_reasons"]) for i in items),
            **{
                k: counts.get(k, 0)
                for k in (
                    *sorted(set(DELIVERY.values())),
                    "no_open_row",
                    "not_eligible",
                    "unrecognised",
                )
            },  # fmt: skip
        },
        "unknown": unknown,
    }
