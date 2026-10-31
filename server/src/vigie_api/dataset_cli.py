"""`vigie-api dataset stage|list|accept|reject`: offline known-issue datasets, principal cli:local.

The file is read bounded (never more than the source's input cap), through O_NOFOLLOW and only
if it is a regular file. Nothing is fetched or applied: staging writes the import, its entries
and one audit row; `accept`/`reject` decide a staged import; `list` shows all imports.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

from vigie_api import dataset_parse, dataset_writes
from vigie_api.config import Settings
from vigie_api.errors import ApiError
from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc

CLI_PRINCIPAL = "cli:local"
CHUNK = 1 << 20
SHA_PREFIX = 12


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    parser = argparse.ArgumentParser(prog="vigie-api dataset")
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("stage", parents=[common], help="stage a dataset file for review")
    stage.add_argument("--source", required=True, choices=sorted(dataset_writes.PARSERS))
    stage.add_argument("--file", required=True, help="regular file, read bounded")
    stage.add_argument("--version", required=True, help="dataset version or release label")
    stage.add_argument("--licence", required=True, help="licence the dataset is published under")
    sub.add_parser("list", parents=[common], help="list imports and their status")
    accept = sub.add_parser("accept", parents=[common], help="accept a staged import")
    reject = sub.add_parser("reject", parents=[common], help="reject a staged import (terminal)")
    for cmd in (accept, reject):
        cmd.add_argument("import_id")
        cmd.add_argument("--by", default=CLI_PRINCIPAL, help="operator identity to record")
    accept.add_argument(
        "--force", action="store_true", help="accept despite an entry-count change over the limit"
    )
    reject.add_argument("--reason", default=None, help="why (max 200 characters)")
    return parser


def _fail(message: str, code: int) -> int:
    print(f"vigie-api: {message}", file=sys.stderr)
    return code


def _read_bounded(path: Path, limit: int) -> bytes:
    # NONBLOCK: a FIFO must not hang open; NOCTTY: a tty must not become our controlling tty
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        chunks, total = [], 0
        while chunk := os.read(fd, min(CHUNK, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise OSError(f"file too large (max {limit} bytes)")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _stage(ov, args) -> int:
    path = Path(args.file)
    try:
        data = _read_bounded(path, dataset_parse.input_limit(args.source))
    except OSError as exc:
        return _fail(f"cannot read {path}: {exc.strerror or exc}", 2)
    try:
        import_id = dataset_writes.stage(
            ov, args.source, data, args.version, args.licence, CLI_PRINCIPAL, iso_utc(time.time())
        )
    except ApiError as err:
        return _fail(f"{err.code}: {err.message}", 2 if err.status == 422 else 1)
    except sqlite3.Error as exc:
        return _fail(f"staging failed, nothing stored: {exc}", 3)
    print(f"staged {import_id} ({args.source}, {args.version})", file=sys.stderr)
    return 0


def _decide(ov, args) -> int:
    now = iso_utc(time.time())
    try:
        if args.command == "accept":
            dataset_writes.accept(ov, args.import_id, CLI_PRINCIPAL, args.by, now, force=args.force)
        else:
            dataset_writes.reject(ov, args.import_id, CLI_PRINCIPAL, args.by, now, args.reason)
    except ApiError as err:
        return _fail(f"{err.code}: {err.message}", 2 if err.status == 422 else 1)
    except sqlite3.Error as exc:
        return _fail(f"{args.command} failed, nothing changed: {exc}", 3)
    print(f"{args.command}ed {args.import_id}", file=sys.stderr)
    return 0


def _list(ov) -> int:
    query = (
        "SELECT id,source,version,status,entry_count,sha256 FROM dataset_imports"
        " ORDER BY created_at,id"
    )
    for row in ov.execute(query):
        cells = (row["id"], row["source"], row["version"], row["status"], row["entry_count"])
        print("\t".join(str(c) for c in (*cells, row["sha256"][:SHA_PREFIX])))
    return 0


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    settings = Settings.from_env()
    if args.data_dir:  # an explicit --data-dir wins over VIGIE_*_PATH
        settings = Settings(data_dir=Path(args.data_dir))
    ov = open_overrides(settings.overrides_path)
    try:
        if args.command == "stage":
            return _stage(ov, args)
        return _list(ov) if args.command == "list" else _decide(ov, args)
    finally:
        ov.close()
