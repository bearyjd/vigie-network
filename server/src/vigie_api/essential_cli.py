"""`vigie-api essential list|set DEVICE SECONDS|clear DEVICE`: mark essential devices locally.

Runs the same essential.set_essential as the endpoint (same bounds, cap, audit row) as principal
`cli:local`, with the current version as the precondition. Unlike the API it never creates or
migrates overrides.db: a mistyped --data-dir creates nothing, and a database older than this
build is refused (run the API image once to migrate it), so this command cannot silently migrate
a live volume.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import quote

from vigie_api import essential
from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.schema import BUSY_TIMEOUT_MS, OVERRIDES_MIGRATIONS, open_inventory_ro
from vigie_ingest.db import iso_utc

CLI_PRINCIPAL = "cli:local"
BUSY_TIMEOUT_S = BUSY_TIMEOUT_MS / 1000


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-api essential")
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list the essential devices")
    mark = sub.add_parser("set", help="mark a device essential")
    mark.add_argument("device")
    mark.add_argument(
        "seconds", type=int, help=f"absence threshold, {essential.MIN_S} to {essential.MAX_S}"
    )
    unmark = sub.add_parser("clear", help="unmark a device")
    unmark.add_argument("device")
    return parser


def _fail(message: str, code: int) -> int:
    print(f"vigie-api: {message}", file=sys.stderr)
    return code


def _open_existing(path: Path) -> sqlite3.Connection:
    """Open overrides.db read-write without creating or migrating it."""
    if not path.is_file():
        raise RuntimeError(f"{path} does not exist (check --data-dir); nothing was created")
    conn = sqlite3.connect(
        f"file:{quote(str(path.resolve()))}?mode=rw",
        uri=True,
        timeout=BUSY_TIMEOUT_S,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > len(OVERRIDES_MIGRATIONS):
            raise RuntimeError(f"overrides schema v{version} is newer than this build")
        if version < len(OVERRIDES_MIGRATIONS):
            raise RuntimeError(
                f"overrides schema v{version} is older than this build; "
                "run the API image once to migrate it, then retry"
            )
    except BaseException:
        conn.close()
        raise
    return conn


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if args.command == "set" and not essential.MIN_S <= args.seconds <= essential.MAX_S:
        return _fail(f"seconds must be between {essential.MIN_S} and {essential.MAX_S}", 2)
    settings = Settings.from_env()
    if args.data_dir:  # an explicit --data-dir wins over VIGIE_*_PATH
        settings = Settings(data_dir=Path(args.data_dir))
    try:
        return _run(settings, args)
    except ApiError as err:
        return _fail(f"{err.code}: {err.message}", 1)
    except (RuntimeError, OSError, sqlite3.Error) as exc:
        return _fail(str(exc), 1)


def _run(settings: Settings, args: argparse.Namespace) -> int:
    ov = _open_existing(settings.overrides_path)
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


def _write(inv: sqlite3.Connection, ov: sqlite3.Connection, args: argparse.Namespace) -> int:
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
    return 0
