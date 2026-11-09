"""vigie-backup: consistent SQLite backup and restore-verify (logic in vigie_pipeline.backup)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from vigie_pipeline import backup


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-backup")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup", help="online-backup inventory.db / overrides.db into a directory")
    b.add_argument("--dest", type=Path, required=True,
                   help="existing directory, owned by you, not group/world-writable")  # fmt: skip
    b.add_argument("--inventory", type=Path, help="path of inventory.db")
    b.add_argument("--overrides", type=Path, help="path of overrides.db")
    v = sub.add_parser("verify", help="check a backup directory (schema version, integrity)")
    v.add_argument("directory", type=Path)
    v.add_argument("--no-manifest", action="store_true",
                   help="accept a manual copy that has no manifest.json")  # fmt: skip
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "backup" and not (args.inventory or args.overrides):
        parser.error("give --inventory and/or --overrides")
    try:
        if args.command == "backup":
            result = backup.backup(args.dest, inventory=args.inventory, overrides=args.overrides)
        else:
            result = backup.verify(args.directory, require_manifest=not args.no_manifest)
    except (backup.BackupError, backup.VerifyError) as exc:
        print(f"vigie-backup: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("vigie-backup: interrupted; partial files were removed", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - fixed message, never a traceback or a path
        print(f"vigie-backup: unexpected error ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0
