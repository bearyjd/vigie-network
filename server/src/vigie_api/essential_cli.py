"""`vigie-api essential list|set DEVICE SECONDS|clear DEVICE`: mark essential devices locally.

Runs the same essential.set_essential as the endpoint (same bounds, 32 cap, audit row) as
principal `cli:local`, with the current version as the precondition.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from vigie_api import essential
from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.schema import open_inventory_ro, open_overrides
from vigie_ingest.db import iso_utc

CLI_PRINCIPAL = "cli:local"
MIN_S, MAX_S = 3600, 604800


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-api essential")
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list the essential devices")
    mark = sub.add_parser("set", help="mark a device essential")
    mark.add_argument("device")
    mark.add_argument("seconds", type=int, help=f"absence threshold, {MIN_S} to {MAX_S}")
    unmark = sub.add_parser("clear", help="unmark a device")
    unmark.add_argument("device")
    return parser


def _fail(message: str, code: int) -> int:
    print(f"vigie-api: {message}", file=sys.stderr)
    return code


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if args.command == "set" and not MIN_S <= args.seconds <= MAX_S:
        return _fail(f"seconds must be between {MIN_S} and {MAX_S}", 2)
    settings = Settings.from_env()
    if args.data_dir:  # an explicit --data-dir wins over VIGIE_*_PATH
        settings = Settings(data_dir=Path(args.data_dir))
    ov = open_overrides(settings.overrides_path)
    try:
        if args.command == "list":
            for item in essential.list_essential(ov):
                print(f"{item['device_id']}\t{item['absent_after_s']}")
            return 0
        inv = open_inventory_ro(settings.inventory_path)
        if inv is None:
            return _fail("inventory is not available yet", 1)
        try:
            return _write(inv, ov, args)
        finally:
            inv.close()
    finally:
        ov.close()


def _write(inv, ov, args) -> int:  # noqa: ANN001
    try:
        state = essential.get_state(inv, ov, args.device)
        essential.set_essential(
            inv,
            ov,
            device_id=args.device,
            expected_version=state["version"],
            absent_after_s=args.seconds if args.command == "set" else None,
            principal=CLI_PRINCIPAL,
            now_iso=iso_utc(time.time()),
        )
    except ApiError as err:
        return _fail(f"{err.code}: {err.message}", 1)
    return 0
