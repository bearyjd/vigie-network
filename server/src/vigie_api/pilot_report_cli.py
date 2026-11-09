"""`vigie-api pilot-report --since T [--json]`: read-only pilot gate report.

Run as the service user that owns the databases; any other user is refused (exit 2). Database
errors exit 3 with a fixed message.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from vigie_api.config import Settings
from vigie_api.pilot_report import (
    DELIVERY_RETENTION_S,
    BaselineConflict,
    NotDatabaseOwner,
    build_report,
)

MAX_LOOKBACK_S = 366 * 86400
_RELATIVE = re.compile(r"([1-9][0-9]{0,3})([dh])")
MIN_RETENTION_S = 3600
MAX_RETENTION_S = 366 * 86400


def parse_since(text: str, now: float) -> float:
    """`7d`, `36h`, an ISO date or an ISO datetime (UTC when naive); within the last 366 days."""
    match = _RELATIVE.fullmatch(text)
    if match:
        value = float(now - int(match.group(1)) * (86400 if match.group(2) == "d" else 3600))
    else:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError(f"invalid --since {text!r}: use 7d, 36h or an ISO date/time") from None
        value = (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    if not now - MAX_LOOKBACK_S <= value < now:
        raise ValueError("--since must be in the past and at most 366 days ago")
    return value


def _retention(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid seconds: {text!r}") from None
    if not MIN_RETENTION_S <= value <= MAX_RETENTION_S:
        raise argparse.ArgumentTypeError(f"must be {MIN_RETENTION_S}..{MAX_RETENTION_S} seconds")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigie-api pilot-report",
        description="Read-only pilot gate report. Run as the service user that owns the "
        "databases. Collector date counts are an upper bound; --since 7d can never reach 14 dates. "
        "Unwanted notifications count by the current decision, not the one at send time. Windows "
        "beyond delivery (30d) or incident (90d) retention report unknown. Delivery retention is "
        "assumed to be the pipeline default (see --delivery-retention). Sections whose evidence "
        "is truncated or whose baseline family is unknown print PARTIAL, never ok.",
    )
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    parser.add_argument("--since", required=True, help="7d, 36h, ISO date or ISO datetime (UTC)")
    parser.add_argument(
        "--baseline",
        choices=("pooled", "tod"),
        default=None,
        help="baseline family; default: read from the stored profiles (never from the "
        "environment). Without evidence the pooled gate is reported as not_derivable.",
    )
    parser.add_argument(
        "--delivery-retention",
        type=_retention,
        default=DELIVERY_RETENTION_S,
        metavar="SECONDS",
        help="the pipeline's VIGIE_DELIVERY_RETENTION_S (this process cannot see its env); "
        f"default {DELIVERY_RETENTION_S}",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def _section_lines(name: str, section: dict) -> list[str]:
    status = section.get("status", "unknown")
    head = (
        f"{name}: ok"
        if status == "ok"
        else (f"{name}: {status.upper()} ({section.get('reason', 'no detail')})")
    )
    # evidence fields are always shown; an unknown section simply carries no verdict field
    body = {k: v for k, v in section.items() if k not in ("status", "reason")}
    return [head, *(f"  {k}: {json.dumps(v, sort_keys=True)}" for k, v in body.items())]


def render_text(report: dict) -> str:
    lines = [
        f"pilot report {report['since']} .. {report['generated_at']}",
        f"gate: {report['gate']['min_distinct_dates']} distinct UTC dates, "
        f"pooled {report['gate']['pooled_min_hours']} eligible hours",
        f"inventory: {report['inventory']}",
        f"assumed delivery retention: {report['assumed_delivery_retention_s']}s",
        f"engine_last_hour: {report['engine_last_hour']}",
        f"ingest_last_hour: {report['ingest_last_hour']}",
        f"liveness_note: {report['liveness_note']}",
    ]
    for name in ("incidents", "decisions", "deliveries", "coverage", "profiles"):
        lines += _section_lines(name, report[name])
    lines += _section_lines("unwanted_notifications", report["unwanted_notifications"])
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    now = time.time()
    try:
        since = parse_since(args.since, now)
    except ValueError as exc:
        print(f"vigie-api: {exc}", file=sys.stderr)
        return 2
    settings = Settings.from_env()
    if args.data_dir:
        settings = Settings(data_dir=Path(args.data_dir))
    try:
        report = build_report(
            settings.inventory_path,
            settings.overrides_path,
            since,
            now,
            args.baseline,
            args.delivery_retention,
        )
    except BaselineConflict as exc:
        print(f"vigie-api: {exc}", file=sys.stderr)
        return 2
    except NotDatabaseOwner:
        print("vigie-api: pilot report must run as the database owner", file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError):
        print("vigie-api: pilot report failed: database unreadable", file=sys.stderr)
        return 3
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_text(report))
    return 0
