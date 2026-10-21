"""CLI: `generate` writes fixtures + manifest; `post` signs and POSTs to a running ingest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from .generator import generate
from .model import DEFAULT_START, PRP_BATCH_CAP_BYTES, Emission, shift_emission
from .model import emissions_to_jsonl as to_jsonl
from .roster import PROFILES
from .tls import PIN_RE, TlsError
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


KEY_ENV = "VIGIE_TRAFFICGEN_KEY"
_MIN_KEY_BYTES = 32  # same floor as vigie_ingest.auth
_MAX_KEY_CHARS = 1024


class KeyInputError(Exception):
    """The key could not be read or is malformed. Messages never contain key material."""


def _read_key(args: argparse.Namespace) -> bytes:
    """Key from --key-file, --key-stdin or $VIGIE_TRAFFICGEN_KEY (never from argv)."""
    if args.key_file:
        try:
            with Path(args.key_file).open("rb") as fh:
                raw = fh.read(_MAX_KEY_CHARS + 1).decode("ascii")
        except OSError as exc:
            raise KeyInputError(f"cannot read key file {args.key_file}: {exc.strerror}") from exc
        except UnicodeDecodeError as exc:
            raise KeyInputError("invalid key: key file is not ASCII hex") from exc
    elif args.key_stdin:
        raw = sys.stdin.readline(_MAX_KEY_CHARS + 1)
    else:
        raw = os.environ.get(KEY_ENV, "")
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError:
        raise KeyInputError("invalid key: not valid hex") from None
    if len(key) < _MIN_KEY_BYTES:
        raise KeyInputError(f"invalid key: need at least {_MIN_KEY_BYTES} bytes (64 hex chars)")
    return key


def _cmd_generate(args: argparse.Namespace) -> int:
    sc = generate(
        args.profile,
        seed=args.seed,
        windows=args.windows,
        start=args.start,
        roll_interval_s=args.roll_interval,
        batch_cap_bytes=args.batch_cap_bytes,
        variant=args.variant,
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
    try:
        key = _read_key(args)
    except KeyInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    sc = generate(
        args.profile,
        seed=args.seed,
        windows=args.windows,
        start=args.start,
        roll_interval_s=args.roll_interval,
        batch_cap_bytes=args.batch_cap_bytes,
        variant=args.variant,
    )
    now = int(time.time())
    first, last = sc.emissions[0].arrival_ts, sc.emissions[-1].arrival_ts
    span = last - first
    if not args.pace and span > args.max_skew_s and not args.no_pace_check:
        print(
            f"error: unpaced span is {span} s, over --max-skew-s {args.max_skew_s}: the server "
            "rejects batches whose sent_ts is far from its clock. Use the default real-time "
            "pacing, raise --max-skew-s, or pass --no-pace-check to send anyway.",
            file=sys.stderr,
        )
        return 2
    # Map the synthetic timeline onto wall clock: the server judges sent_ts against its own clock.
    delta = (now - first) if args.pace else (now - last)
    emissions = [shift_emission(e, delta) for e in sc.emissions]

    def wait(ts: int) -> None:
        if args.pace:
            time.sleep(max(0.0, ts - time.time()))

    try:
        post, client = http_post(args.url, ca_file=args.ca_file, pin_sha256=args.pin_sha256)
    except TlsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        results = run(emissions, key, post, on_arrival=wait)
    except TlsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
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
    p.add_argument("--variant", default=None, help="profile variant (see README); default varies")


def _check_post_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.key_file and args.key_stdin:
        parser.error("give the key by exactly one of --key-file / --key-stdin / $" + KEY_ENV)
    if not (args.key_file or args.key_stdin or os.environ.get(KEY_ENV)):
        parser.error(f"post needs a key: --key-file, --key-stdin or ${KEY_ENV}")
    if args.pin_sha256 and not PIN_RE.fullmatch(args.pin_sha256):
        parser.error("--pin-sha256 must be 64 hex characters")
    if (args.ca_file or args.pin_sha256) and not args.url.lower().startswith("https://"):
        parser.error("--ca-file/--pin-sha256 need an https:// --url")


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
    post.add_argument("--key-stdin", action="store_true", help="read the hex key from stdin")
    post.add_argument(
        "--pace",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="replay on a real-time schedule (default); --no-pace sends back to back",
    )
    post.add_argument(
        "--max-skew-s", type=int, default=240, help="unpaced span limit (default 240)"
    )
    post.add_argument("--no-pace-check", action="store_true", help="skip the unpaced span check")
    post.add_argument("--ca-file", help="PEM CA or self-signed server cert to trust (https)")
    post.add_argument("--pin-sha256", help="SPKI SHA-256 pin, 64 hex chars (gen-certs.sh output)")
    post.set_defaults(fn=_cmd_post)
    args = parser.parse_args(argv)
    if args.cmd == "post":
        _check_post_args(parser, args)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
