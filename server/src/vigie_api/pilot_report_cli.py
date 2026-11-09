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
from vigie_api.pilot_report import NotDatabaseOwner, build_report
from vigie_pipeline.config import PipelineConfig

MAX_LOOKBACK_S = 366 * 86400
_RELATIVE = re.compile(r"([1-9][0-9]{0,3})([dh])")


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigie-api pilot-report",
        description="Read-only pilot gate report. Run as the service user that owns the "
        "databases. Collector date counts are an upper bound; --since 7d can never reach 14 dates.",
    )
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    parser.add_argument("--since", required=True, help="7d, 36h, ISO date or ISO datetime (UTC)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def _section_lines(name: str, section: dict) -> list[str]:
    status = section.get("status", "unknown")
    if status != "ok":
        return [f"{name}: {status.upper()} ({section.get('reason', 'no detail')})"]
    body = {k: v for k, v in section.items() if k != "status"}
    return [f"{name}: ok", *(f"  {k}: {json.dumps(v, sort_keys=True)}" for k, v in body.items())]


def render_text(report: dict) -> str:
    lines = [
        f"pilot report {report['since']} .. {report['generated_at']}",
        f"gate: {report['gate']['min_distinct_dates']} distinct UTC dates, "
        f"pooled {report['gate']['pooled_min_hours']} eligible hours",
        f"inventory: {report['inventory']}",
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
        baseline = PipelineConfig.from_env().monitoring_baseline
    except ValueError:
        baseline = "unknown"  # unreadable config: the gate is reported as not derivable
    try:
        report = build_report(
            settings.inventory_path, settings.overrides_path, since, now, baseline
        )
    except NotDatabaseOwner:
        print("vigie-api: pilot report must run as the database owner", file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError):
        print("vigie-api: pilot report failed: database unreadable", file=sys.stderr)
        return 3
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_text(report))
    return 0
