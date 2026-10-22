"""Entrypoint: `python -m vigie_pipeline run --once | --loop SECONDS`."""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import time
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
    return PipelineConfig(
        data_dir=args.data_dir or base.data_dir,
        transient_window_s=_pick(args.transient_window_s, base.transient_window_s),
        transient_min_dwell_s=_pick(args.min_dwell_s, base.transient_min_dwell_s),
        promotion_cap_per_hour=_pick(args.promotion_cap, base.promotion_cap_per_hour),
        migrate=args.migrate,
        inventory_db=base.inventory_db,
        overrides_db=base.overrides_db,
        suggest_threshold=base.suggest_threshold,
        overlap_grace_s=base.overlap_grace_s,
        activity_gap_s=base.activity_gap_s,
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
    try:
        while True:
            # Keep inventory.db attached for the api's read-only mount; retried every tick until
            # ingest has created the file (never created from here).
            held.hold(config.inventory_path)
            try:
                run_once(config)
                _touch_health_file()
            except (sqlite3.Error, ShardReadError) as exc:  # log, retry next tick
                log(logger, logging.ERROR, "run_failed", error=str(exc))
            time.sleep(args.loop)
    except KeyboardInterrupt:
        log(logger, logging.INFO, "stopped")
        return 0
    finally:
        held.close()
