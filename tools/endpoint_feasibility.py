#!/usr/bin/env python3
"""PRP-003 phase E0 feasibility report for one device (docs/prp/003-endpoint-events.md).

Offline and read-only: an exported endpoint JSONL log (one opensnitch remote-logger event per
line), the owner's scope JSON (host, device MAC spans, LAN prefixes, router IPs, period, optional
skew_s and export_start), the inventory database (`batches`) and the raw shard directory.
Prints a sorted-key JSON report with the `other` byte share, the key match ratio (direct
+-120 s and 24 h carryover, explicit denominators), explanations and the go/no-go gate.

Exit codes: 0 go, 1 no_go or no_result, 2 input/usage error. Run as `python3 -I`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from endpoint_e0 import inputs, report, router  # noqa: E402


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        sys.stderr.write(f"error: {message}\n")
        sys.exit(2)


def main(argv: list[str]) -> int:
    parser = _Parser(description=__doc__.splitlines()[0])
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        sc = inputs.read_scope(args.scope)
        log = inputs.read_events(args.events, sc)
        data = router.load_router(args.inventory, args.raw_dir, sc)
    except inputs.InputError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    out = report.build_report(sc, data, log)
    sys.stdout.write(report.render(out))
    return 0 if out["gate"]["verdict"] == "go" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
