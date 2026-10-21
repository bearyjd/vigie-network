"""CLI: `generate` writes fixtures + manifest; `post` signs and POSTs to a running ingest."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from .generator import generate
from .model import DEFAULT_START, PRP_BATCH_CAP_BYTES, Emission, shift_emission
from .model import emissions_to_jsonl as to_jsonl
from .roster import PROFILES
from .transport import http_post, run

# Committed fixtures under tests/fixtures/synthetic/ are regenerated from exactly these.
FIXTURE_SPECS: dict[str, dict[str, Any]] = {
    "baseline": {"profile": "baseline", "kwargs": {"seed": 1, "windows": 5}},
    "rolling_mac": {
        "profile": "rolling_mac",
        "kwargs": {"seed": 1, "windows": 12, "roll_interval_s": 180},
    },
    "hostname_spoof": {"profile": "hostname_spoof", "kwargs": {"seed": 1, "windows": 6}},
    "mac_clone": {"profile": "mac_clone", "kwargs": {"seed": 1, "windows": 6}},
    "ip_flap": {"profile": "ip_flap", "kwargs": {"seed": 1, "windows": 8}},
    "doh_user": {"profile": "doh_user", "kwargs": {"seed": 1, "windows": 5}},
    "replay": {"profile": "replay", "kwargs": {"seed": 1, "windows": 4}},
    "out_of_order": {"profile": "out_of_order", "kwargs": {"seed": 1, "windows": 5}},
    "stale_ts": {"profile": "stale_ts", "kwargs": {"seed": 1, "windows": 4}},
    # 256 KB would exceed the 200 KB fixture budget, so the committed flood uses a 64 KB cap.
    "flood": {"profile": "flood", "kwargs": {"seed": 1, "windows": 4, "batch_cap_bytes": 64_000}},
}


def _write(out: Path, name: str, emissions: list[Emission], manifest: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.jsonl").write_text(to_jsonl(emissions))
    (out / f"{name}.manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")


def _read_key(args: argparse.Namespace) -> bytes:
    raw = args.key_hex or Path(args.key_file).read_text().strip()
    return bytes.fromhex(raw)


def _cmd_generate(args: argparse.Namespace) -> int:
    sc = generate(
        args.profile,
        seed=args.seed,
        windows=args.windows,
        start=args.start,
        roll_interval_s=args.roll_interval,
        batch_cap_bytes=args.batch_cap_bytes,
    )
    _write(Path(args.out), args.profile, sc.emissions, sc.manifest)
    print(f"wrote {len(sc.emissions)} batches + manifest for {args.profile} to {args.out}")
    return 0


def _cmd_fixtures(args: argparse.Namespace) -> int:
    for name, spec in FIXTURE_SPECS.items():
        sc = generate(spec["profile"], **spec["kwargs"])
        _write(Path(args.out), name, sc.emissions, sc.manifest)
    print(f"wrote {len(FIXTURE_SPECS)} fixtures to {args.out}")
    return 0


def _cmd_post(args: argparse.Namespace) -> int:
    key = _read_key(args)
    sc = generate(
        args.profile,
        seed=args.seed,
        windows=args.windows,
        start=args.start,
        roll_interval_s=args.roll_interval,
        batch_cap_bytes=args.batch_cap_bytes,
    )
    now = int(time.time())
    first, last = sc.emissions[0].arrival_ts, sc.emissions[-1].arrival_ts
    # Map the synthetic timeline onto wall clock: the server judges sent_ts against its own clock.
    delta = (now - first) if args.pace else (now - last)
    emissions = [shift_emission(e, delta) for e in sc.emissions]
    if not args.pace and last - first > 240:
        print(
            "warning: span > 4 min without --pace; early batches may be rejected as stale",
            file=sys.stderr,
        )

    def wait(ts: int) -> None:
        if args.pace:
            time.sleep(max(0.0, ts - time.time()))

    post, client = http_post(args.url)
    try:
        results = run(emissions, key, post, on_arrival=wait)
    except httpx.HTTPError as exc:
        print(f"error: cannot reach {args.url}: {exc}", file=sys.stderr)
        return 2
    finally:
        client.close()
    for r in results:
        print(
            f"{r.emission.label}: {r.status} {json.dumps(r.payload)} "
            f"{'ok' if r.ok else 'UNEXPECTED (wanted ' + str(r.emission.expect_status) + ')'}"
        )
    return 0 if all(r.ok for r in results) else 1


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", required=True, choices=PROFILES)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--windows", type=int, default=10)
    p.add_argument("--start", type=int, default=DEFAULT_START)
    p.add_argument("--roll-interval", type=int, default=None, help="seconds between MAC rolls")
    p.add_argument("--batch-cap-bytes", type=int, default=PRP_BATCH_CAP_BYTES)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trafficgen")
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate", help="write <profile>.jsonl and <profile>.manifest.json")
    _common(gen)
    gen.add_argument("--out", required=True)
    gen.set_defaults(fn=_cmd_generate)
    fx = sub.add_parser("fixtures", help="regenerate the committed fixture set")
    fx.add_argument("--out", required=True)
    fx.set_defaults(fn=_cmd_fixtures)
    post = sub.add_parser("post", help="sign and POST to a running vigie-ingest")
    _common(post)
    post.add_argument("--url", required=True)
    post.add_argument("--key-file", help="file holding the collector key as hex")
    post.add_argument("--key-hex")
    post.add_argument("--pace", action="store_true", help="sleep to real time between batches")
    post.set_defaults(fn=_cmd_post)
    args = parser.parse_args(argv)
    if args.cmd == "post" and not (args.key_file or args.key_hex):
        parser.error("post requires --key-file or --key-hex")
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
