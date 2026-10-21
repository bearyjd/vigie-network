"""Entrypoint: `python -m vigie_ingest`. Refuses to start without TLS unless --insecure-dev."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from vigie_ingest.app import create_app
from vigie_ingest.config import Settings

DEFAULT_LIMIT_CONCURRENCY = 64
DEFAULT_KEEPALIVE_S = 5


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
    return parser


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
    uvicorn.run(
        create_app(Settings.from_env()),
        host=args.host,
        port=args.port,
        limit_concurrency=args.limit_concurrency,
        timeout_keep_alive=args.timeout_keep_alive,
        ssl_certfile=args.tls_cert,
        ssl_keyfile=args.tls_key,
    )
    return 0


def _refuse(reason: str) -> int:
    print(f"vigie-ingest: refusing to start: {reason}", file=sys.stderr)
    return 2
