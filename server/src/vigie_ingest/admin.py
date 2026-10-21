"""Minimal operator CLI: provision / revoke a collector row (keys live in the secrets dir)."""

from __future__ import annotations

import argparse
import sys

from vigie_ingest import store
from vigie_ingest.config import Settings
from vigie_ingest.db import open_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vigie-ingest-admin")
    sub = parser.add_subparsers(dest="cmd", required=True)
    prov = sub.add_parser("provision", help="register a collector id with a key id")
    prov.add_argument("collector_id")
    prov.add_argument("key_id")
    rev = sub.add_parser("revoke", help="revoke a collector")
    rev.add_argument("collector_id")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    conn = open_inventory(settings.inventory_path)
    try:
        if args.cmd == "provision":
            store.provision_collector(conn, args.collector_id, args.key_id)
        elif not store.revoke_collector(conn, args.collector_id):
            print("unknown collector", file=sys.stderr)
            return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
