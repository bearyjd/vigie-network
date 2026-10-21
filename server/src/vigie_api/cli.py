"""Entrypoint: `python -m vigie_api [serve opts]` and `python -m vigie_api tokens create|revoke`.

Serving refuses to start without TLS unless --insecure-dev (same rule as vigie_ingest).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

import uvicorn

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides

DEFAULT_LIMIT_CONCURRENCY = 64
DEFAULT_KEEPALIVE_S = 5


def _serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-api")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
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


def _tokens_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-api tokens")
    parser.add_argument("--data-dir", default=None, help="default: $VIGIE_DATA_DIR")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="create an app token (printed once)")
    create.add_argument("--id", dest="token_id", default=None, help="label [A-Za-z0-9_-]{1,32}")
    revoke = sub.add_parser("revoke", help="revoke a token by id")
    revoke.add_argument("token_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if args_list[:1] == ["tokens"]:
        return _tokens_main(args_list[1:])
    return _serve_main(args_list)


def _serve_main(argv: list[str]) -> int:
    args = _serve_parser().parse_args(argv)
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


def _tokens_main(argv: list[str]) -> int:
    args = _tokens_parser().parse_args(argv)
    data_dir = Path(args.data_dir or os.environ.get("VIGIE_DATA_DIR", "/var/lib/vigie"))
    conn = open_overrides(data_dir / "overrides.db")
    try:
        if args.command == "create":
            try:
                token_id, token = tokens.create_token(conn, args.token_id)
            except ValueError as exc:
                print(f"vigie-api: {exc}", file=sys.stderr)
                return 2
            except sqlite3.IntegrityError:
                print("vigie-api: a token with that id already exists", file=sys.stderr)
                return 2
            print(f"token id: {token_id}", file=sys.stderr)
            print(token)
            return 0
        if not tokens.revoke_token(conn, args.token_id):
            print("vigie-api: no such token id", file=sys.stderr)
            return 1
        return 0
    finally:
        conn.close()


def _refuse(reason: str) -> int:
    print(f"vigie-api: refusing to start: {reason}", file=sys.stderr)
    return 2
