"""`vigie-api dataset stage|list`: stage an offline known-issue dataset, as principal cli:local.

The file is read bounded (never more than the parser's input cap), through O_NOFOLLOW and only
if it is a regular file. Nothing is fetched or applied: staging writes the import, its entries
and one audit row, and `list` shows what is staged.
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
    sub.add_parser("list", parents=[common], help="list staged imports")
    return parser


def _fail(message: str, code: int) -> int:
    print(f"vigie-api: {message}", file=sys.stderr)
    return code


def _read_bounded(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK  # NONBLOCK: a FIFO must not hang open
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        limit, chunks, total = dataset_parse.MAX_INPUT_BYTES, [], 0
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
        data = _read_bounded(path)
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
        return _stage(ov, args) if args.command == "stage" else _list(ov)
    finally:
        ov.close()
