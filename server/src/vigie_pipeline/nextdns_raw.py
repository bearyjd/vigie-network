"""Read qualifying accepted observation batches and their raw DNS rows."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import ExitStack, closing
from datetime import timedelta
from pathlib import Path

from vigie_ingest.db import shard_name, utc_day
from vigie_ingest.models import FUTURE_WINDOW_SLACK, MAX_WINDOW_SECONDS
from vigie_pipeline.nextdns import LocalQuery, ReportError, canonical_name
from vigie_pipeline.sources import normalize_mac

MAX_BATCHES = 512
MAX_BATCH_DNS = 5000  # ingest Batch.dns maximum
MAX_RAW_DNS = 30_000
# The known source flags and these counters concern conntrack or multicast, not dnsmasq.
# Future flags and counters can signal DNS loss and must fail closed.
NON_DNS_SOURCE_FLAGS = 0b1111
NON_DNS_LOSS_COUNTERS = frozenset(
    {
        "conntrack",
        "conntrack_lost",
        "ct_errors",
        "ct_recounted",
        "ct_dropped_keys",
        "ct_unmapped_bytes",
        "ct_unmapped_flows",
        "ct_lan_unmapped_bytes",
        "ct_lan_unmapped_flows",
        "mcast_unmapped",
        "mcast_dropped",
    }
)


class CoverageError(ReportError):
    def __init__(self) -> None:
        super().__init__(
            "accepted router DNS coverage is missing, degraded, or exceeds read limits"
        )


def _open_ro(path: Path) -> sqlite3.Connection:
    info = path.stat()
    # A mode=ro SQLite open can still create a shared-memory sidecar for an owned WAL.
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise CoverageError()
    conn = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, timeout=1)
    conn.row_factory = sqlite3.Row
    return conn


def _check_quality(batch: sqlite3.Row) -> None:
    if (
        batch["observation_kind"] != "observation"
        or type(batch["dns_queries"]) is not int
        or not 0 <= batch["dns_queries"] <= MAX_BATCH_DNS
        or batch["dropped_batches"] != 0
    ):
        raise CoverageError()
    health = json.loads(batch["health"] or "null")
    lost = json.loads(batch["truncated"] or "null")
    if (
        not isinstance(health, dict)
        or health.get("dns_log_quiet") is not False
        or health.get("dns_evidence_reported") is not True
        or type(health.get("spool_batches")) is not int
        or health["spool_batches"] != 0
        or type(health.get("uptime_s")) is not int
        or health["uptime_s"] < 0
        or not isinstance(lost, dict)
        or any(type(value) is not int or value < 0 for value in lost.values())
        or lost.get("source_flags", 0) & ~NON_DNS_SOURCE_FLAGS
        or any(
            value
            for key, value in lost.items()
            if key != "source_flags" and key not in NON_DNS_LOSS_COUNTERS
        )
    ):
        raise CoverageError()


def _batch_rows(
    dbs: dict[Path, sqlite3.Connection],
    resources: ExitStack,
    raw_dir: Path,
    batch: sqlite3.Row,
    collector: str,
) -> list[LocalQuery]:
    low, high = batch["window_start"], batch["window_end"]
    day, last_day = utc_day(low), utc_day(high)
    result = []
    while day <= last_day:
        path = raw_dir / shard_name(day)
        # No DNS rows on a day is possible. The accepted full-row count below verifies that
        # skipping an absent shard did not remove a row from this batch.
        if path.exists():
            if path not in dbs:
                dbs[path] = resources.enter_context(closing(_open_ro(path)))
                dbs[path].execute("BEGIN")
            rows = dbs[path].execute(
                "SELECT ts,device_mac,qname FROM raw_dns "
                "WHERE collector_id=? AND batch_id=? LIMIT ?",
                (collector, batch["batch_id"], MAX_BATCH_DNS + 1),
            )
            for row in rows:
                ts = row["ts"]
                name = canonical_name(row["qname"])
                if (
                    len(result) >= MAX_BATCH_DNS
                    or type(ts) is not int
                    or not low <= ts <= high
                    or utc_day(ts) != day
                    or name is None
                ):
                    raise CoverageError()
                raw_mac = row["device_mac"]
                mac = normalize_mac(raw_mac) if isinstance(raw_mac, str) else None
                result.append(LocalQuery(ts, name, mac, ts in (low, high)))
        day += timedelta(days=1)
    if len(result) != batch["dns_queries"]:
        raise CoverageError()
    return result


def read_local(
    inventory: Path,
    raw_dir: Path,
    collector: str,
    start: int,
    end: int,
) -> list[LocalQuery]:
    try:
        return _read_local(inventory, raw_dir, collector, start, end)
    except (OSError, sqlite3.Error, ValueError, OverflowError, RecursionError) as exc:
        raise CoverageError() from exc


def _read_local(
    inventory: Path,
    raw_dir: Path,
    collector: str,
    start: int,
    end: int,
) -> list[LocalQuery]:
    result: list[LocalQuery] = []
    # Ingest can clamp an input timestamp to a batch boundary. The surrounding accepted
    # windows must be complete even though only their boundary rows compete for matches.
    coverage_start = start - FUTURE_WINDOW_SLACK
    coverage_end = end + FUTURE_WINDOW_SLACK
    with ExitStack() as resources:
        inv = resources.enter_context(closing(_open_ro(inventory)))
        inv.execute("BEGIN")
        # Accepted receipts without event bounds can overlap any window because spool age is
        # configurable. The original receipt time cannot prove that they are irrelevant.
        legacy = inv.execute(
            "SELECT 1 FROM batches WHERE collector_id=? "
            "AND (window_start IS NULL OR window_end IS NULL) LIMIT 1",
            (collector,),
        ).fetchone()
        if legacy is not None:
            raise ReportError(
                "accepted router DNS coverage includes legacy batches without observation "
                "timestamps. Retry after they age out"
            )
        batches = inv.execute(
            "SELECT batch_id,window_start,window_end,observation_kind,health,truncated,"
            "dropped_batches,dns_queries FROM batches WHERE collector_id=? "
            "AND window_start <= ? AND window_end >= ? "
            "ORDER BY window_start,window_end LIMIT ?",
            (collector, coverage_end, coverage_start, MAX_BATCHES + 1),
        ).fetchall()
        if len(batches) > MAX_BATCHES:
            raise CoverageError()
        # A missing day inside the coverage interval cannot establish retained raw coverage.
        first_day, last_day = utc_day(coverage_start), utc_day(coverage_end - 1)
        for offset in range((last_day - first_day).days + 1):
            if not (raw_dir / shard_name(first_day + timedelta(days=offset))).is_file():
                raise CoverageError()
        dbs: dict[Path, sqlite3.Connection] = {}
        covered_until = coverage_start
        raw_rows_read = 0
        for batch in batches:
            low, high = batch["window_start"], batch["window_end"]
            if (
                type(low) is not int
                or type(high) is not int
                or not 0 <= high - low <= MAX_WINDOW_SECONDS
            ):
                raise CoverageError()
            # Signed transport probes carry no observations and provide no coverage.
            if batch["observation_kind"] == "probe" and batch["dns_queries"] == 0:
                _batch_rows(dbs, resources, raw_dir, batch, collector)
                continue
            _check_quality(batch)
            if low > covered_until:
                raise CoverageError()
            covered_until = max(covered_until, high)
            rows = _batch_rows(dbs, resources, raw_dir, batch, collector)
            raw_rows_read += len(rows)
            if raw_rows_read > MAX_RAW_DNS:
                raise CoverageError()
            result.extend(row for row in rows if row.boundary or start <= row.ts < end)
        if covered_until < coverage_end:
            raise CoverageError()
    return result
