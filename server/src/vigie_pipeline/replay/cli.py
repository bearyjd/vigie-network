"""`python -m vigie_pipeline.replay --series FILE --labels FILE [--strategy pooled|tod]`.

Read-only: input files are opened for reading only, the report goes to stdout, and nothing else is
written (the engine runs against a throwaway database in a private temp directory). Errors print one
fixed message without paths or input values and exit 2.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from vigie_pipeline.baselines import BaselineConfig
from vigie_pipeline.baselines_tod import TodConfig
from vigie_pipeline.monitoring_strategy import strategy_for
from vigie_pipeline.replay._json import MAX_BYTES
from vigie_pipeline.replay.errors import ReplayInputError
from vigie_pipeline.replay.labels import load_labels
from vigie_pipeline.replay.report import build_report
from vigie_pipeline.replay.runner import replay
from vigie_pipeline.replay.series import load_series


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vigie_pipeline.replay",
        description="Offline chronological replay of owner-labelled hours; prints a JSON report.",
    )
    parser.add_argument("--series", type=Path, required=True, help="hourly measurement fixture")
    parser.add_argument("--labels", type=Path, required=True, help="owner label file")
    parser.add_argument("--strategy", choices=("pooled", "tod"), default="pooled")
    parser.add_argument("--minimum-hours", type=int, help="pooled cold-start floor (default 20)")
    parser.add_argument("--minimum-days", type=int, help="pooled distinct-day floor (default 14)")
    parser.add_argument("--min-samples-per-cohort", type=int, help="tod floor (default 20)")
    parser.add_argument("--min-days-per-cohort", type=int, help="tod day floor (default 7)")
    return parser


def read_input(path: Path) -> bytes:
    "Read a regular file for reading only, at most MAX_BYTES + 1 bytes; fixed error otherwise."
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ReplayInputError("replay: cannot read an input file") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReplayInputError("replay: cannot read an input file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise ReplayInputError("replay: cannot read an input file") from exc
    finally:
        os.close(fd)


def _policy(args: argparse.Namespace):
    pick = {
        "pooled": {"minimum_hours": args.minimum_hours, "minimum_days": args.minimum_days},
        "tod": {
            "min_samples_per_cohort": args.min_samples_per_cohort,
            "min_days_per_cohort": args.min_days_per_cohort,
        },
    }[args.strategy]
    given = {k: v for k, v in pick.items() if v is not None}
    try:
        return (TodConfig if args.strategy == "tod" else BaselineConfig)(**given)
    except (ValueError, TypeError) as exc:
        raise ReplayInputError("replay: policy option outside supported bounds") from exc


def run(args: argparse.Namespace) -> dict:
    policy = _policy(args)
    series = load_series(read_input(args.series))
    labels = load_labels(read_input(args.labels))
    outcomes = replay(series, policy, extra_hours=[(x.device, x.hour) for x in labels])
    return build_report(outcomes, labels, strategy_for(policy).algorithm, policy.version)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = run(args)
    except ReplayInputError as exc:
        print(str(exc), file=sys.stderr)  # noqa: T201 - CLI output
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))  # noqa: T201 - CLI output
    return 0
