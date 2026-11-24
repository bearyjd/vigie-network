"""Read-only, bounded loading of accepted batch bounds (inventory) and raw_flow rows (shards).

Raw rows join to batches by (collector_id, batch_id) only; `raw_flow.ts` is the batch's
window_end (server/src/vigie_ingest/store.py rows_by_day), so the window comes from the batch.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from . import netutil
from .inputs import InputError
from .model import Batch, Flow, RouterData, Scope

MAX_BATCHES = 20_000  # a 7-day period holds 10,080 one-minute windows
MAX_FLOW_ROWS = 1_000_000
MAX_COUNTER = 1 << 62
# Source of truth: server/src/vigie_pipeline/measurements.py:18-50 and :92-128 (read_measurements).
# raw_missing is not re-derived here; missing shard days are reported instead. The
# ct_lan_unmapped_bytes threshold needs collector-wide totals and is left to the pipeline.
INFORMATIONAL_TRUNCATED_KEYS = frozenset(
    {"ct_unmapped_bytes", "ct_unmapped_flows", "ct_lan_unmapped_flows"}
)
ALWAYS_DEGRADING_TRUNCATED_KEYS = frozenset({"truncated_other"})
LAN_UNMAPPED_BYTES_KEY = "ct_lan_unmapped_bytes"
HOUR_S = 3600
_BATCH_COLS = (
    "collector_id,batch_id,window_start,window_end,observation_kind,health,truncated,"
    "dropped_batches"
)
_FLOW_COLS = "collector_id,batch_id,ts,device_mac,dst_ip,dst_port,proto,bytes_up,bytes_down,flows"


def _flow_degraded(truncated_text: object, dropped: object) -> bool:
    if truncated_text is not None and not isinstance(truncated_text, str):
        return True
    try:
        truncated = json.loads(truncated_text or "{}")
    except ValueError:
        return True  # fail closed on anything the pipeline could not read either
    if not isinstance(truncated, dict):
        return True
    flags = truncated.get("source_flags", 0)
    if not isinstance(flags, int) or flags & ~8 or dropped:
        return True
    return any(
        value
        for key, value in truncated.items()
        if key in ALWAYS_DEGRADING_TRUNCATED_KEYS
        or (
            key != "source_flags"
            and key not in INFORMATIONAL_TRUNCATED_KEYS
            and key != LAN_UNMAPPED_BYTES_KEY
            and key.lower().startswith(("ct_", "conntrack"))
        )
    )


def batch_reasons(row) -> tuple[str, ...]:
    """Why a batch window cannot carry match keys; empty for a clean observation window."""
    start, end = row["window_start"], row["window_end"]
    if row["observation_kind"] == "probe":
        return ("probe",)
    if start is None or end is None:
        return ("legacy_window",)
    reasons = []
    if row["observation_kind"] != "observation":
        reasons.append("legacy_kind")
    if start >= end:
        reasons.append("empty_window")
    elif start // HOUR_S != (end - 1) // HOUR_S:
        reasons.append("cross_hour")
    if row["health"] is None:
        reasons.append("health_missing")
    if _flow_degraded(row["truncated"], row["dropped_batches"]):
        reasons.append("flow_degraded")
    return tuple(reasons)


def _open_ro(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=2)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def _load_batches(path: Path, sc: Scope) -> dict[tuple[str, str], Batch]:
    if not path.is_file():
        raise InputError("inventory database not found")
    with closing(_open_ro(path)) as db:
        rows = db.execute(
            f"SELECT {_BATCH_COLS} FROM batches WHERE window_start IS NULL OR window_end IS NULL "  # noqa: S608
            "OR (window_end > ? AND window_end <= ?) ORDER BY collector_id, batch_id LIMIT ?",
            (sc.period_start, sc.period_end, MAX_BATCHES + 1),
        ).fetchall()
    if len(rows) > MAX_BATCHES:
        raise InputError(f"more than {MAX_BATCHES} batches in the period")
    out = {}
    for row in rows:
        for key in ("window_start", "window_end"):
            if row[key] is not None and not isinstance(row[key], int):
                raise InputError("batch window bound is not an integer")
        cid, bid = str(row["collector_id"]), str(row["batch_id"])
        out[(cid, bid)] = Batch(
            cid, bid, row["window_start"], row["window_end"], batch_reasons(row)
        )
    return out


def shard_names(sc: Scope) -> tuple[str, ...]:
    first, last = (sc.period_start + 1) // 86400, sc.period_end // 86400
    days = (datetime.fromtimestamp(d * 86400, UTC) for d in range(first, last + 1))
    return tuple(f"raw-{d:%Y%m%d}.db" for d in days)


def _flow(row) -> Flow:
    counters = (row["bytes_up"], row["bytes_down"], row["flows"], row["ts"])
    if any(
        isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= MAX_COUNTER for v in counters
    ):
        raise InputError("raw_flow counter out of range")
    port, mac, proto = row["dst_port"], row["device_mac"], row["proto"]
    if (port is not None and not isinstance(port, int)) or not isinstance(mac, str):
        raise InputError("raw_flow row has invalid columns")
    dst = row["dst_ip"]
    dst = None if dst is None else (netutil.norm_ip(str(dst)) or str(dst))
    return Flow(
        collector_id=str(row["collector_id"]),
        batch_id="" if row["batch_id"] is None else str(row["batch_id"]),
        ts=row["ts"],
        mac=mac.lower(),
        dst_ip=dst,
        dst_port=port,
        proto=netutil.norm_proto(str(proto)),
        bytes_up=row["bytes_up"],
        bytes_down=row["bytes_down"],
        flows=row["flows"],
    )


def _load_flows(raw_dir: Path, sc: Scope) -> tuple[tuple[Flow, ...], tuple[str, ...]]:
    flows: list[Flow] = []
    missing = []
    for name in shard_names(sc):
        path = raw_dir / name
        if not path.is_file():
            missing.append(name)
            continue
        with closing(_open_ro(path)) as db:
            rows = db.execute(
                f"SELECT {_FLOW_COLS} FROM raw_flow WHERE ts > ? AND ts <= ? ORDER BY rowid "  # noqa: S608
                "LIMIT ?",
                (sc.period_start, sc.period_end, MAX_FLOW_ROWS - len(flows) + 1),
            ).fetchall()
        flows.extend(_flow(row) for row in rows)
        if len(flows) > MAX_FLOW_ROWS:
            raise InputError(f"more than {MAX_FLOW_ROWS} raw_flow rows in the period")
    return tuple(flows), tuple(missing)


def load_router(inventory: Path, raw_dir: Path, sc: Scope) -> RouterData:
    try:
        batches = _load_batches(inventory, sc)
        flows, missing = _load_flows(raw_dir, sc)
    except sqlite3.Error as exc:
        raise InputError(f"sqlite read failed: {exc}") from None
    return RouterData(batches=batches, flows=flows, missing_shards=missing)
