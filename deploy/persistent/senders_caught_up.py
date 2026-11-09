#!/usr/bin/env python3
"""Read-only check for the two-sender truncate rule (PRP-004, H4).

The shared delivery file may be truncated or rotated only when BOTH senders (ntfy and Home
Assistant) have a cursor offset equal to the file size. This reads each sender config ONLY for
`cursor_file` and `delivery_file`, then the cursor and the delivery file's size, and prints one
line per sender: `<name>: offset=<n> size=<m> caught_up|behind`. It never writes, creates or locks
anything, and never prints a path, host, token or config content.

Exit codes: 0 every named sender is caught up, 1 at least one is behind, 2 a config, cursor or
delivery file is missing, unreadable or invalid (or bad arguments). The cursor format and the
private-file reads are those of ha_sender.py (the ntfy sender writes the same format).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

EXIT_OK, EXIT_BEHIND, EXIT_ERROR = 0, 1, 2


def _load_ha_sender() -> Any:
    """ha_sender.py from beside this file; failure exits 2 with a fixed message (never a path
    or a traceback, so a wrapper like `helper && truncate` cannot see exit 0 or 1)."""
    try:
        spec = importlib.util.spec_from_file_location(
            "_ha_sender_for_caught_up", Path(__file__).resolve().parent / "ha_sender.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError("no loader")
        module: Any = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except Exception:  # noqa: BLE001 -- any load failure is the same fixed answer
        sys.stderr.write("error: cannot load ha_sender.py beside this script\n")
        raise SystemExit(EXIT_ERROR) from None
    return module


ha: Any = _load_ha_sender()


@dataclass(frozen=True)
class Status:
    offset: int
    size: int
    caught_up: bool


def _paths(config_path: str) -> tuple[str, str]:
    """(cursor_file, delivery_file) from a sender config; every other key is ignored."""
    data = ha.read_private_bytes(config_path, "config file", ha.MAX_CONFIG)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ha.ConfigError("config file is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ha.ConfigError("configuration must be a JSON object")
    for key in ("cursor_file", "delivery_file"):
        if key not in raw:
            raise ha.ConfigError(f"missing configuration key: {key}")
    return ha._abs_path(raw["cursor_file"], "cursor_file"), ha._abs_path(
        raw["delivery_file"], "delivery_file"
    )


def _open_delivery(path: str) -> int:
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise ha.ConfigError(f"cannot open delivery file: {exc.strerror}") from exc


def _check(config_path: str) -> Status:
    """Caught up means offset == size AND the cursor still names this file: the sender restarts
    at 0 when the inode or the first-line hash differ, so matching numbers alone prove nothing."""
    cursor_file, delivery_file = _paths(config_path)
    cursor = ha.load_cursor(cursor_file)  # a missing cursor is an error, never a seed
    fd = _open_delivery(delivery_file)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ha.ConfigError("delivery file is not a regular file")
        same_file = cursor.offset == 0 or (
            cursor.ino == info.st_ino and cursor.head == ha._first_line_hash(fd)
        )
    finally:
        os.close(fd)
    return Status(cursor.offset, info.st_size, cursor.offset == info.st_size and same_file)


def check(config_path: str) -> Status:
    """_check with any OSError (open, fstat, pread, ...) turned into a ConfigError, so it exits 2
    with the OS reason only (no path)."""
    try:
        return _check(config_path)
    except OSError as exc:
        raise ha.ConfigError(f"cannot read: {exc.strerror or 'I/O error'}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        """argparse's own text can echo argument values, so it is never shown."""
        self.print_usage(sys.stderr)
        sys.stderr.write("error: bad arguments (values not shown)\n")
        raise SystemExit(EXIT_ERROR)


def _usage_error(parser: argparse.ArgumentParser, message: str) -> NoReturn:
    parser.print_usage(sys.stderr)
    sys.stderr.write(f"error: {message}\n")
    raise SystemExit(EXIT_ERROR)


def _parser() -> argparse.ArgumentParser:
    # No -h/--help: it would exit 0, and `helper --help && truncate` must never truncate.
    parser = _Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--ntfy-config", metavar="PATH", help="ntfy sender config")
    parser.add_argument("--ha-config", metavar="PATH", help="Home Assistant sender config")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    named = [(n, p) for n, p in (("ntfy", args.ntfy_config), ("ha", args.ha_config)) if p]
    if not named:
        _usage_error(parser, "at least one of --ntfy-config / --ha-config is required")
    results: list[Status | None] = []
    for name, path in named:
        try:
            status = check(path)
        except ha.ConfigError as exc:
            sys.stderr.write(f"{name}: error: {exc}\n")
            results.append(None)
            continue
        except Exception:  # noqa: BLE001 -- fixed message: no traceback, no path; exit 2
            sys.stderr.write(f"{name}: error: unexpected internal error\n")
            results.append(None)
            continue
        word = "caught_up" if status.caught_up else "behind"
        sys.stdout.write(f"{name}: offset={status.offset} size={status.size} {word}\n")
        results.append(status)
    if any(r is None for r in results):
        return EXIT_ERROR
    return EXIT_OK if all(r is not None and r.caught_up for r in results) else EXIT_BEHIND


if __name__ == "__main__":
    sys.exit(main())
