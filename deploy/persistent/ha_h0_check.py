#!/usr/bin/env python3
"""H0 connectivity check for the Home Assistant webhook (PRP-004, H0).

Sends ONE harmless dummy POST to the secret webhook URL through the same validation, TLS and
send code as ha_sender.py (`ha_sender.send_once`), then reports only the target host and a status
class. The URL, the webhook id and the response body are never printed. One attempt, no retries
(so Retry-After is ignored), no redirects.

The dummy payload may still trigger the automation that listens on that webhook. A 2xx does NOT
prove that an automation ran (PRP-004, H0).

Usage: ha_h0_check.py CONFIG.json [--url-file PATH]

CONFIG.json is the ha_sender configuration (allowed_hosts, http_hosts, ca_file, timeout_seconds,
url_file). The URL comes from, in order: --url-file, the HA_H0_WEBHOOK_URL environment variable,
then the config's url_file. Files must be mode 0600/0400; the environment variable skips that
check and is readable by the same user in /proc/PID/environ. Standard library plus ha_sender.py
(same directory, loaded by path).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

_SPEC = importlib.util.spec_from_file_location(
    "_ha_sender_for_h0", Path(__file__).resolve().parent / "ha_sender.py"
)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("ha_sender.py not found beside ha_h0_check.py")
ha: Any = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = ha
_SPEC.loader.exec_module(ha)

ENV_URL = "HA_H0_WEBHOOK_URL"
EXIT_OK, EXIT_CONFIG, EXIT_CLIENT, EXIT_RETRY, EXIT_TLS, EXIT_DNS = 0, 2, 3, 4, 5, 6
RETRY_CODES = "/".join(str(c) for c in sorted(ha.RETRY_STATUS))

EPILOG = f"""\
exit codes:
  0 ok: any 2xx (not proof an automation ran)
  2 configuration, secret-file or URL-validation error (nothing was sent)
  3 client error: 4xx other than {RETRY_CODES}, or a redirect/unexpected status;
    auth or webhook-id problem, never retry
  4 retry class: 5xx, {RETRY_CODES}, timeout, connection error
  5 TLS certificate verification failed, including not yet valid or expired
    (stricter than the sender, which retries those; verification is never disabled)
  6 DNS failure: the host name did not resolve
"""


@dataclass(frozen=True)
class Verdict:
    code: int
    label: str
    status: int | None = None
    note: str = ""


class _Recorder:
    """Opener wrapper that remembers the status of a successful response (Outcome has none)."""

    def __init__(self, inner: urllib.request.OpenerDirector) -> None:
        self.inner = inner
        self.status: int | None = None

    def open(self, req: urllib.request.Request, timeout: float) -> Any:
        response = self.inner.open(req, timeout=timeout)
        self.status = response.status
        return response


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # noqa: ARG002 -- may echo a pasted URL
        self.print_usage(sys.stderr)
        print("ha_h0_check: invalid arguments (values not shown)", file=sys.stderr)
        sys.exit(EXIT_CONFIG)


def classify(outcome: Any, ok_status: int | None) -> Verdict:
    """Map ha_sender's Outcome (kind, detail) to a verdict; the detail strings are its own."""
    detail = outcome.detail or ""
    if outcome.kind == "ok":
        return Verdict(EXIT_OK, "ok", ok_status)
    if detail.startswith("HTTP "):
        code = int(detail[5:])
        if outcome.kind == "retry":
            return Verdict(EXIT_RETRY, "retry", code, "retry class")
        note = (
            "auth or webhook-id problem; never retry"
            if 400 <= code < 500
            else "unexpected status; never retry"
        )
        return Verdict(EXIT_CLIENT, "client-error", code, note)
    if detail == "redirect refused":
        return Verdict(
            EXIT_CLIENT, "client-error", note="redirect refused; never retry"
        )
    if detail.startswith("certificate"):
        return Verdict(EXIT_TLS, "tls-verify", note=detail)
    if detail == "gaierror":
        return Verdict(EXIT_DNS, "dns", note="host name did not resolve")
    if detail == "TimeoutError":
        return Verdict(EXIT_RETRY, "retry", note="timeout")
    return Verdict(EXIT_RETRY, "retry", note=f"transport error: {detail}")


def probe(
    opener: urllib.request.OpenerDirector, req: urllib.request.Request, timeout: float
):
    """One POST via ha.send_once, classified. Only an exception TYPE name is ever reported."""
    recorder = _Recorder(opener)
    try:
        outcome = ha.send_once(recorder, req, timeout)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 -- last resort; class name only, never the message
        return Verdict(
            EXIT_RETRY, "retry", note=f"transport error: {type(exc).__name__}"
        )
    return classify(outcome, recorder.status)


def load_url(cfg: Any, url_file: str | None) -> str:
    """Precedence: --url-file, then the environment variable, then the config's url_file."""
    if url_file is None:
        env_value = os.environ.get(ENV_URL)
        if env_value is not None:
            text = env_value.strip()
            if not text:
                raise ha.ConfigError(f"{ENV_URL} is empty")
            return text
        url_file = cfg.url_file
    return ha.read_secret(url_file, "webhook URL file")


def dummy_request(url: str) -> urllib.request.Request:
    payload = {
        "delivery_id": "0" * 32,
        "sent_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "kind": "h0check",
        "title": "Vigie H0 check",
        "body": "Connectivity check. No action needed.",
    }
    return urllib.request.Request(  # noqa: S310 -- validated by ha.validate_webhook_url
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        description="Send one dummy POST to the HA webhook and classify the answer (PRP-004 H0).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("config", help="ha_sender JSON configuration")
    parser.add_argument(
        "--url-file",
        help=f"private file holding the webhook URL (wins over env {ENV_URL}, then config url_file)",
    )
    args = parser.parse_args(argv)
    try:
        cfg = ha.load_config(args.config)
        url = ha.validate_webhook_url(
            load_url(cfg, args.url_file), cfg.allowed_hosts, cfg.http_hosts
        )
        opener = ha.build_opener(ha.build_ssl_context(cfg.ca_file))
    except ha.ConfigError as exc:
        print(f"ha_h0_check configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    host = ha.normalize_host(urlsplit(url).hostname or "") or "?"
    verdict = probe(opener, dummy_request(url), cfg.timeout_seconds)
    status = f" status={verdict.status}" if verdict.status is not None else ""
    note = f" ({verdict.note})" if verdict.note else ""
    print(
        f"ha_h0_check host={host} class={verdict.label}{status} exit={verdict.code}{note}"
    )
    return verdict.code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
