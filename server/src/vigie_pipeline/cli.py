"""Entrypoint: `python -m vigie_pipeline run --once | --loop SECONDS`."""

from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import select
import signal
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from vigie_ingest.keeper import Keeper
from vigie_pipeline.config import TRANSIENT_WINDOW_DEFAULT_S, PipelineConfig
from vigie_pipeline.logs import configure_logging, log
from vigie_pipeline.processor import run_once
from vigie_pipeline.schema import SchemaVersionError
from vigie_pipeline.sources import ShardReadError

logger = logging.getLogger("vigie_pipeline")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigie-pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="process new batches")
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="one pass, then exit")
    mode.add_argument("--loop", type=int, metavar="SECONDS", help="repeat every SECONDS")
    run.add_argument("--data-dir", type=Path, help="default: $VIGIE_DATA_DIR or /var/lib/vigie")
    run.add_argument("--transient-window-s", type=int, default=None,
                     help=f"default {TRANSIENT_WINDOW_DEFAULT_S}")  # fmt: skip
    run.add_argument("--min-dwell-s", type=int, default=None, help="min first-to-last-seen dwell")
    run.add_argument("--promotion-cap", type=int, default=None, help="max promotions per hour")
    run.add_argument("--migrate", action="store_true",
                     help="apply ingest-owned schema migrations (bootstrap/upgrade)")  # fmt: skip
    return parser


def _pick(flag: int | None, fallback: int) -> int:
    return fallback if flag is None else flag


def _config(args: argparse.Namespace) -> PipelineConfig:
    base = PipelineConfig.from_env()
    return dataclasses.replace(
        base,
        data_dir=args.data_dir or base.data_dir,
        transient_window_s=_pick(args.transient_window_s, base.transient_window_s),
        transient_min_dwell_s=_pick(args.min_dwell_s, base.transient_min_dwell_s),
        promotion_cap_per_hour=_pick(args.promotion_cap, base.promotion_cap_per_hour),
        migrate=args.migrate,
    )


def _touch_health_file() -> None:
    """Mark a successful pass for the container healthcheck (deploy/healthcheck.py fresh).
    Only set in the container (VIGIE_HEALTH_FILE, on tmpfs); a failure here never stops the loop."""
    target = os.environ.get("VIGIE_HEALTH_FILE")
    if not target:
        return
    try:
        Path(target).touch()
    except OSError as exc:
        log(logger, logging.WARNING, "health_file_failed", error=str(exc))


class _StopFlag:
    """Signal-safe stop request: a self-pipe plus a plain bool, no locks.

    threading.Event.set() takes the Event's non-reentrant lock, so a handler that interrupts the
    main thread inside Event.wait() deadlocks. os.write() on a non-blocking pipe is
    async-signal-safe, and select() on the read end is the idle wait. The Python-level handler
    runs only at the next eval-loop check, so a signal landing between that check and select()
    would otherwise wait out the loop interval: signal.set_wakeup_fd(write end) makes the C-level
    handler write the byte immediately, which closes that window (main thread only)."""

    def __init__(self) -> None:
        self._r, self._w = os.pipe()
        for fd in (self._r, self._w):
            os.set_blocking(fd, False)
        self.requested = False
        self._previous_wakeup: int | None = None

    def install_wakeup(self) -> None:
        self._previous_wakeup = signal.set_wakeup_fd(self._w)

    def restore_wakeup(self) -> None:
        if self._previous_wakeup is not None:  # install may have failed off the main thread
            signal.set_wakeup_fd(self._previous_wakeup)

    def is_set(self) -> bool:
        return self.requested

    def request(self, signum: int) -> None:
        """Signal handler body. The second request forces exit so a hung pass can be interrupted."""
        if self.requested:
            raise SystemExit(128 + signum)
        self.requested = True
        try:
            os.write(self._w, b"x")
        except OSError:  # pipe full or closed: the bool is already set, the next tick sees it
            pass

    def wait(self, timeout: float) -> bool:
        select.select([self._r], [], [], timeout)
        return self.requested

    def close(self) -> None:
        os.close(self._r)
        os.close(self._w)


def _install_stop_handlers(stop: _StopFlag) -> dict[int, object]:
    """SIGTERM/SIGINT ask the loop to stop after the current pass; a second one forces exit.

    Python as PID 1 receives SIGTERM only because a handler is installed, which is why
    `podman stop` works without STOPSIGNAL."""

    def handler(signum: int, frame: object) -> None:
        stop.request(signum)

    return {sig: signal.signal(sig, handler) for sig in (signal.SIGTERM, signal.SIGINT)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.loop is not None and args.loop < 1:
        parser.error("--loop SECONDS must be >= 1")
    configure_logging()
    try:
        config = _config(args)
    except ValueError as exc:
        parser.error(str(exc))
    if args.once:
        try:
            run_once(config)
        except (sqlite3.Error, ShardReadError, SchemaVersionError) as exc:
            log(logger, logging.ERROR, "run_failed", error=str(exc))
            return 1
        return 0
    held = Keeper()
    stop = _StopFlag()
    previous = _install_stop_handlers(stop)
    try:
        stop.install_wakeup()
        while not stop.is_set():
            # Keep inventory.db attached for the api's read-only mount; retried every tick until
            # ingest has created the file (never created from here).
            held.hold(config.inventory_path)
            try:
                run_once(config, should_stop=stop.is_set)
                _touch_health_file()
            except (sqlite3.Error, ShardReadError) as exc:  # log, retry next tick
                log(logger, logging.ERROR, "run_failed", error=str(exc))
            stop.wait(args.loop)
        log(logger, logging.INFO, "stopped")
        return 0
    finally:
        stop.restore_wakeup()
        for sig, old in previous.items():
            signal.signal(sig, old)
        stop.close()
        held.close()
