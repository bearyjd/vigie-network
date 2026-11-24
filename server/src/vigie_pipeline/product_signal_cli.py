"""`python -m vigie_pipeline.product_signal_cli --inventory FILE [--threshold T]`.

Offline M2b-I product-signal coverage report over an exported, synthetic or owner-approved
inventory document. Writes canonical JSON to stdout. Exit codes: 0 report, 2 arguments or
threshold, 3 unreadable inventory, 4 invalid inventory. Error text is fixed and never echoes
inventory content. The report is evidence only and never authorizes known-issue notes.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from vigie_pipeline import product_signal_input as psi
from vigie_pipeline.product_signal import build_report, parse_threshold, render

PROGRAM = "vigie-product-signal"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        super().error("invalid or missing report arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=PROGRAM, allow_abbrev=False, description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True, help="inventory JSON document")
    parser.add_argument(
        "--threshold",
        default=None,
        help="owner usefulness threshold, 0 < T <= 1 (no default; omitted = not evaluated)",
    )
    return parser


def _fail(code: int, message: str) -> int:
    sys.stderr.buffer.write(f"{PROGRAM}: {message}\n".encode())
    sys.stderr.buffer.flush()
    return code


def _read(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(psi.MAX_INPUT_BYTES + 1)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.threshold is not None:
        try:
            parse_threshold(args.threshold)
        except ValueError:
            return _fail(2, "invalid threshold")
    try:
        data = _read(args.inventory)
    except OSError:
        return _fail(3, "cannot read inventory")
    try:
        inventory = psi.load_inventory(data)
    except psi.InventoryError as exc:
        return _fail(4, f"invalid inventory: {exc}")
    sys.stdout.buffer.write(render(build_report(inventory, args.threshold)))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
