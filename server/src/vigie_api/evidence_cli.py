"""`vigie-api evidence export DEVICE -o FILE`: the evidence pack, built locally and audited.

Runs the same build_export/record_export as the endpoint, as principal `cli:local`. The output
file is created exclusively (never overwritten, never through a symlink) with mode 0600, before
the audit row is written, and removed again if the audit write fails.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import sqlite3
import sys
import time
import uuid
from pathlib import Path

from vigie_api import evidence_export, evidence_writes
from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.evidence_redact import LEVELS
from vigie_api.schema import open_inventory_ro, open_overrides
from vigie_ingest.db import iso_utc

CLI_PRINCIPAL = "cli:local"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-api evidence")
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="write a device evidence pack to a new file")
    export.add_argument("device")
    export.add_argument("--redaction", choices=LEVELS, default="pseudonymized")
    export.add_argument("--format", choices=sorted(evidence_export.FORMATS), default="json")
    export.add_argument("--confirm-full", action="store_true", help="required for --redaction full")
    export.add_argument("-o", "--output", required=True, help="new file; never overwritten")
    return parser


def _fail(message: str, code: int) -> int:
    print(f"vigie-api: {message}", file=sys.stderr)
    return code


def _create(path: Path) -> int | None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags, 0o600)
    except FileExistsError:
        return None


def main(argv: list[str], version: str) -> int:
    args = _parser().parse_args(argv)
    settings = Settings.from_env()
    if args.data_dir:  # an explicit --data-dir wins over VIGIE_*_PATH
        settings = Settings(data_dir=Path(args.data_dir))
    inv = open_inventory_ro(settings.inventory_path)
    if inv is None:
        return _fail("inventory is not available yet", 1)
    ov = open_overrides(settings.overrides_path)
    try:
        return _export(inv, ov, args, version)
    finally:
        inv.close()
        ov.close()


def _export(inv: sqlite3.Connection, ov: sqlite3.Connection, args, version: str) -> int:
    now = time.time()
    try:
        export = evidence_export.build_export(
            inv, ov, args.device, level=args.redaction, fmt=args.format,
            confirm_full=args.confirm_full, now=now, vigie_version=version,
            rng=secrets.token_bytes,
        )  # fmt: skip
    except ApiError as err:
        return _fail(f"{err.code}: {err.message}", 2 if err.status == 422 else 1)
    path = Path(args.output)
    try:
        fd = _create(path)
    except OSError as exc:
        return _fail(f"cannot create {path}: {exc.strerror or exc}", 2)
    if fd is None:
        return _fail(f"{path} already exists; refusing to overwrite it", 2)
    try:
        evidence_writes.record_export(
            ov,
            principal=CLI_PRINCIPAL,
            now_iso=iso_utc(now),
            detail={**export.detail, "request_id": str(uuid.uuid4())},
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(export.data)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.close(fd)
        path.unlink(missing_ok=True)
        if isinstance(exc, (sqlite3.Error, OSError)):
            return _fail(f"export failed, nothing written: {exc}", 3)
        raise
    print(f"wrote {path} ({len(export.data)} bytes, {args.redaction})", file=sys.stderr)
    return 0
