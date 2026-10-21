"""Entrypoint: `python -m vigie_pipeline run --once | --loop SECONDS`."""

from __future__ import annotations

import argparse
import logging
import sqlite3
import time
from collections.abc import Sequence
from pathlib import Path

from vigie_pipeline.config import TRANSIENT_WINDOW_DEFAULT_S, PipelineConfig
from vigie_pipeline.logs import configure_logging, log
from vigie_pipeline.processor import run_once
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
    return parser


def _config(args: argparse.Namespace) -> PipelineConfig:
    base = PipelineConfig.from_env()
    return PipelineConfig(
        data_dir=args.data_dir or base.data_dir,
        transient_window_s=args.transient_window_s or base.transient_window_s,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.loop is not None and args.loop < 1:
        parser.error("--loop SECONDS must be >= 1")
    configure_logging()
    config = _config(args)
    if args.once:
        try:
            run_once(config)
        except (sqlite3.Error, ShardReadError) as exc:
            log(logger, logging.ERROR, "run_failed", error=str(exc))
            return 1
        return 0
    try:
        while True:
            try:
                run_once(config)
            except (sqlite3.Error, ShardReadError) as exc:  # transient lock/IO trouble: log and retry next tick
                log(logger, logging.ERROR, "run_failed", error=str(exc))
            time.sleep(args.loop)
    except KeyboardInterrupt:
        log(logger, logging.INFO, "stopped")
        return 0
