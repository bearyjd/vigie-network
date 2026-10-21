"""Entrypoint: `python -m vigie_ingest`. Refuses to start without TLS unless --insecure-dev."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import uvicorn

from vigie_ingest.app import create_app
from vigie_ingest.config import Settings

DEFAULT_LIMIT_CONCURRENCY = 64
DEFAULT_KEEPALIVE_S = 5
LOCK_NAME = ".ingest.lock"


class LockHeld(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-ingest")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--tls-cert", default=os.environ.get("VIGIE_TLS_CERT"))
    parser.add_argument("--tls-key", default=os.environ.get("VIGIE_TLS_KEY"))
    parser.add_argument(
        "--insecure-dev",
        action="store_true",
        default=os.environ.get("VIGIE_INSECURE_DEV") == "1",
        help="serve plain HTTP (development only)",
    )
    parser.add_argument("--limit-concurrency", type=int, default=DEFAULT_LIMIT_CONCURRENCY)
    parser.add_argument("--timeout-keep-alive", type=int, default=DEFAULT_KEEPALIVE_S)
    parser.add_argument("--workers", type=int, default=1, help="must be 1 (state is per process)")
    return parser


@contextlib.contextmanager
def _exclusive_data_dir(data_dir: Path) -> Iterator[None]:
    """Hold an exclusive flock on <data_dir>/.ingest.lock for the life of the process."""
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        handle = (data_dir / LOCK_NAME).open("a")
    except OSError as exc:
        raise LockHeld(f"cannot open {data_dir / LOCK_NAME}: {exc}") from exc
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockHeld(
                f"{data_dir / LOCK_NAME} is held: another vigie-ingest uses this data dir"
            ) from exc
        yield
    finally:
        handle.close()  # also releases the flock


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.tls_cert or args.tls_key:
        if not (args.tls_cert and args.tls_key):
            return _refuse("--tls-cert and --tls-key must be given together")
        missing = [p for p in (args.tls_cert, args.tls_key) if not Path(p).is_file()]
        if missing:
            return _refuse(f"TLS file(s) not found: {missing}")
    elif not args.insecure_dev:
        return _refuse("TLS is required: pass --tls-cert/--tls-key (or --insecure-dev for dev)")
    if args.workers != 1:
        return _refuse("--workers must be 1: the shard lock and rate limits are per process")
    settings = Settings.from_env()
    try:
        with _exclusive_data_dir(settings.data_dir):
            uvicorn.run(
                create_app(settings),
                host=args.host,
                port=args.port,
                limit_concurrency=args.limit_concurrency,
                timeout_keep_alive=args.timeout_keep_alive,
                ssl_certfile=args.tls_cert,
                ssl_keyfile=args.tls_key,
                workers=1,
            )
    except LockHeld as exc:
        return _refuse(str(exc))
    return 0


def _refuse(reason: str) -> int:
    print(f"vigie-ingest: refusing to start: {reason}", file=sys.stderr)
    return 2
