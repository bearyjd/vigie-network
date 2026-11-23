"""Operator-only NextDNS report from an explicit resolver and observed-device binding."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from threading import current_thread, main_thread
from time import time

from vigie_ingest.config import BATCH_RETENTION_DAYS, SHARD_RETENTION_DEFAULT_DAYS
from vigie_ingest.db import iso_utc
from vigie_ingest.models import FUTURE_WINDOW_SLACK
from vigie_pipeline import nextdns, nextdns_raw
from vigie_pipeline.sources import normalize_mac

PROGRAM = "vigie-nextdns"
RUN_TIMEOUT_S = 25
MAX_KEY_BYTES = 512
MIN_SETTLING_S = 300
MAX_WINDOW_S = 3600
MAX_AGE_S = min(BATCH_RETENTION_DAYS, SHARD_RETENTION_DEFAULT_DAYS) * 86400
_IDENT = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_PROFILE = re.compile(r"[A-Za-z0-9]{1,64}", re.ASCII)
_KEY = re.compile(rb"[!-~]{1,512}")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        super().error("invalid or missing report arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=PROGRAM, allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--raw-dir", type=Path, required=True, help="directory holding ingest shards"
    )
    parser.add_argument("--inventory", type=Path, required=True, help="ingest inventory.db")
    parser.add_argument("--key-file", type=Path, required=True, help="private NextDNS API key file")
    parser.add_argument(
        "--profile", required=True, help="NextDNS profile ID receiving forwarded DNS"
    )
    parser.add_argument("--device", required=True, help="NextDNS device.id of the forwarded device")
    parser.add_argument("--collector", required=True, help="native router dnsmasq collector ID")
    parser.add_argument("--mac", required=True, help="local observed MAC bound to the provider ID")
    parser.add_argument(
        "--confirm-exclusive-binding",
        action="store_true",
        required=True,
        help="attest that the profile/device ID identifies only forwarded DNS from this MAC",
    )
    parser.add_argument(
        "--from", dest="start", required=True, help="UTC start YYYY-MM-DDTHH:MM:SSZ"
    )
    parser.add_argument("--to", dest="end", required=True, help="UTC end YYYY-MM-DDTHH:MM:SSZ")
    return parser


def _key_file(path: Path) -> str:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    error = nextdns.ReportError("NextDNS key file must be private, owned, regular, and valid")
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as key_file:
            info = os.fstat(key_file.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise error
            raw = key_file.read(MAX_KEY_BYTES + 1)
            if len(raw) > MAX_KEY_BYTES or not _KEY.fullmatch(raw.rstrip(b"\r\n")):
                raise error
            return raw.rstrip(b"\r\n").decode("ascii")
    except OSError as exc:
        raise error from exc


def _validate(args: argparse.Namespace) -> tuple[int, int, str]:
    mac = normalize_mac(args.mac)
    if (
        not _PROFILE.fullmatch(args.profile)
        or not _IDENT.fullmatch(args.device)
        or args.device == "__UNIDENTIFIED__"
        or not _IDENT.fullmatch(args.collector)
        or mac is None
        or mac != args.mac
    ):
        raise nextdns.ReportError("invalid NextDNS binding identifiers")
    try:
        start = nextdns.timestamp_us(args.start) // nextdns.MICROSECONDS
        end = nextdns.timestamp_us(args.end) // nextdns.MICROSECONDS
    except ValueError as exc:
        raise nextdns.ReportError("invalid report UTC interval") from exc
    now = time()
    if (
        args.start != iso_utc(start)
        or args.end != iso_utc(end)
        or not 0 < end - start <= MAX_WINDOW_S
        or start - nextdns.PADDING_S - FUTURE_WINDOW_SLACK < now - MAX_AGE_S
        or end + nextdns.PADDING_S + FUTURE_WINDOW_SLACK > now - MIN_SETTLING_S
    ):
        raise nextdns.ReportError("report interval is too long or outside settled raw retention")
    return start, end, mac


def _deadline(signum: int, frame: object) -> None:
    raise nextdns.ReportError("report time limit exceeded")


@contextmanager
def _report_deadline() -> Iterator[None]:
    previous = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, _deadline)
        try:
            signal.setitimer(signal.ITIMER_REAL, RUN_TIMEOUT_S)
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        # An alarm delivered while cancelling must still leave the previous handler installed.
        signal.signal(signal.SIGALRM, previous)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if (
            os.name != "posix"
            or current_thread() is not main_thread()
            or not all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer"))
        ):
            raise nextdns.ReportError("report requires POSIX interval timers and the main thread")
        if "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ:
            raise nextdns.ReportError("custom TLS trust environment is unsupported")
        with _report_deadline():
            start, end, mac = _validate(args)
            key = _key_file(args.key_file)
            low = start - nextdns.PADDING_S
            high = end + nextdns.PADDING_S
            # Check coverage before contacting NextDNS, then use a fresh local snapshot so batches
            # accepted during the fetch still compete for attribution.
            nextdns_raw.read_local(args.inventory, args.raw_dir, args.collector, low, high)
            provider = nextdns.read_logs(args.profile, args.device, key, low, high)
            local = nextdns_raw.read_local(args.inventory, args.raw_dir, args.collector, low, high)
            count, ambiguity_withheld = nextdns.summarize_matches(local, provider, mac, start, end)
            report = {
                "source": "nextdns",
                "provider_coverage": "unverified",
                "ambiguity_withheld": ambiguity_withheld,
                "window": {"from": args.start, "to": args.end},
                "devices": [{"mac": mac, "threat_intelligence_blocks": count}] if count else [],
            }
    except nextdns.ReportError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"{PROGRAM}: interrupted", file=sys.stderr)
        return 130
    except Exception:  # noqa: BLE001 - suppress exception data from database, TLS, or provider
        print(f"{PROGRAM}: report unavailable", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
