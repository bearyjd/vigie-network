"""`vigie-api pilot-digest --inventory F [--overrides F] --day D --now T`: L2 per-day digest.

Read-only and offline; run it on a verified backup copy (see docs/monitoring-pilot-acceptance.md).
The clock comes only from --now, so the same copy and arguments always print the same bytes.
Refused input exits 2, an unreadable database 3; both with fixed messages.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from vigie_api.pilot_digest import build_digest
from vigie_api.pilot_report import DELIVERY_RETENTION_S, TARGET_UNWANTED_PER_NETWORK_DAY
from vigie_api.pilot_report_cli import _retention
from vigie_api.ro_snapshot import InputRefused

_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_NOW = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
TEMPLATE_FIELDS = (
    "incident_id",
    "network",
    "device_id",
    "detector",
    "opened_at",
    "delivery",
    "delivered_at",
    "decision",
    "owner_label",
    "owner_received",
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # noqa: ARG002 (fixed text: never echo the input)
        self.exit(2, "vigie-api: pilot digest: invalid arguments (see --help)\n")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="vigie-api pilot-digest",
        description="Read-only per-UTC-day pilot digest for owner labelling. Run it on a "
        "checkpointed copy (a verified backup), never on the live databases.",
    )
    parser.add_argument("--inventory", required=True, type=Path, help="copy of inventory.db")
    parser.add_argument("--overrides", type=Path, default=None, help="copy of overrides.db")
    parser.add_argument("--day", required=True, help="UTC day, YYYY-MM-DD")
    parser.add_argument("--now", required=True, help="as-of time, YYYY-MM-DDTHH:MM:SSZ (UTC)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--labels-template",
        choices=("json", "csv"),
        default=None,
        help="print an owner label skeleton (owner_label left empty) instead of the digest",
    )
    parser.add_argument(
        "--delivery-retention",
        type=_retention,
        default=DELIVERY_RETENTION_S,
        metavar="SECONDS",
        help=f"the pipeline's VIGIE_DELIVERY_RETENTION_S; default {DELIVERY_RETENTION_S}",
    )
    return parser


def _times(day: str, now: str) -> tuple[int, int]:
    if not (_DAY.fullmatch(day) and _NOW.fullmatch(now)):
        raise InputRefused("--day must be YYYY-MM-DD and --now YYYY-MM-DDTHH:MM:SSZ")
    try:
        lo = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC).timestamp()
        at = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        raise InputRefused("--day or --now is not a valid date") from None
    if at < lo + 86400:
        raise InputRefused("--now must be at or after the end of --day")
    return int(lo), int(at)


def template_rows(digest: dict) -> list[dict]:
    """One row per item; the owner fills owner_label and owner_received, the tool never does."""
    rows = []
    for item in digest["items"]:
        row = {k: item.get(k) for k in TEMPLATE_FIELDS}
        rows.append({**row, "owner_label": None, "owner_received": None})
    return rows


def render_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=TEMPLATE_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows({k: "" if v is None else v for k, v in r.items()} for r in rows)
    return buf.getvalue().rstrip("\n")


def _reasons(values: list[str]) -> str:
    return "; ".join(values) if values else "-"


def render_text(d: dict) -> str:
    lines = [
        f"pilot digest {d['day']} (UTC) as of {d['as_of']}",
        f"day complete: {'yes' if d['day_complete'] else 'no'}",
        f"budget: at most {TARGET_UNWANTED_PER_NETWORK_DAY} unwanted open per network per UTC day",
        *(f"note: {n}" for n in d["notes"]),
    ]
    for name, net in d["networks"].items():
        cov, bud = net["coverage"], net["budget"]
        why = ", ".join(f"{k}={v}" for k, v in cov["reasons"].items()) or "-"
        lines += [
            f"network {name}: qualified hours {cov['qualified_hours']}/{cov['hours']} ({why})",
            f"  opens sent {bud['opens_sent']} (not budgeted {bud['opens_not_budgeted']}), "
            f"unwanted {bud['unwanted']}, undecided {bud['undecided']} -> "
            f"{bud['verdict'].upper()}",
        ]
    lines.append(f"items: {len(d['items'])}")
    for i in d["items"]:
        lines.append(
            f"  {i['incident_id']} network={i['network']} detector={i['detector']} "
            f"opened={i['opened_at']} state={i['incident_state']} decision={i['decision']} "
            f"delivery={i['delivery']} delivered={i['delivered_at']} receipt={i['receipt']} "
            f"budget={'yes' if i['counts_toward_budget'] else 'no'} "
            f"unknown={_reasons(i['unknown_reasons'])}"
        )
    lines.append("counts: " + ", ".join(f"{k}={v}" for k, v in d["counts"].items()))
    lines.append(f"unknown: {len(d['unknown'])}")
    lines += [f"  {u['kind']} {u['id']}: {_reasons(u['reasons'])}" for u in d["unknown"]]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        lo, now = _times(args.day, args.now)
        digest = build_digest(args.inventory, args.overrides, lo, now, args.delivery_retention)
    except InputRefused as exc:
        print(f"vigie-api: pilot digest: {exc}", file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError):
        print("vigie-api: pilot digest failed: database unreadable", file=sys.stderr)
        return 3
    if args.labels_template == "json":
        print(json.dumps(template_rows(digest), indent=2))
    elif args.labels_template == "csv":
        print(render_csv(template_rows(digest)))
    elif args.format == "json":
        print(json.dumps(digest, indent=2, sort_keys=True))
    else:
        print(render_text(digest))
    return 0
