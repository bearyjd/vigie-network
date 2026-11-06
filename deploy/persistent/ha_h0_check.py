#!/usr/bin/env python3
"""H0 connectivity check for the Home Assistant webhook (PRP-004, H0).

Sends ONE harmless dummy POST to the secret webhook URL through the same validation, TLS and
opener code as ha_sender.py, then reports only the target host and a status class. The URL, the
webhook id and the response body are never printed. One attempt, no retries, no redirects.

The dummy payload may still trigger the automation that listens on that webhook. A 2xx does NOT
prove that an automation ran (PRP-004, H0).

Usage: ha_h0_check.py CONFIG.json [--url-file PATH]

CONFIG.json is the ha_sender configuration (allowed_hosts, http_hosts, ca_file, timeout_seconds,
url_file). The URL comes from, in order: the HA_H0_WEBHOOK_URL environment variable, --url-file,
then the config's url_file. Files must be mode 0600/0400. Standard library plus ha_sender.py
(same directory).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(
    0, str(Path(__file__).resolve().parent)
)  # also works under `python3 -I`
import ha_sender as ha  # noqa: E402

ENV_URL = "HA_H0_WEBHOOK_URL"
EXIT_OK, EXIT_CONFIG, EXIT_CLIENT, EXIT_RETRY, EXIT_TLS, EXIT_DNS = 0, 2, 3, 4, 5, 6

EPILOG = """\
exit codes:
  0 ok: any 2xx (not proof an automation ran)
  2 configuration, secret-file or URL-validation error (nothing was sent)
  3 client error: 4xx other than 408/429, or a redirect/unexpected status;
    auth or webhook-id problem, never retry
  4 retry class: 5xx, 408, 429, timeout, connection error
  5 TLS certificate verification failed (verification is never disabled)
  6 DNS failure: the host name did not resolve
"""


@dataclass(frozen=True)
class Verdict:
    code: int
    label: str
    status: int | None = None
    note: str = ""


def probe(
    opener: urllib.request.OpenerDirector, req: urllib.request.Request, timeout: float
) -> Verdict:
    """One POST, classified. Reuses ha.classify_status for HTTP codes; no exception text leaks."""
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 -- validated URL
            return from_status(response.status)
    except urllib.error.HTTPError as exc:
        return from_status(exc.code)
    except ha.RedirectRefused:
        return Verdict(
            EXIT_CLIENT, "client-error", note="redirect refused; never retry"
        )
    except urllib.error.URLError as exc:
        return from_transport(exc.reason)
    except (OSError, http.client.HTTPException) as exc:
        return from_transport(exc)


def from_status(code: int) -> Verdict:
    kind = ha.classify_status(code, None).kind
    if kind == "ok":
        return Verdict(EXIT_OK, "ok", code)
    if kind == "retry":
        return Verdict(EXIT_RETRY, "retry", code, "retry class")
    if 400 <= code < 500:
        return Verdict(
            EXIT_CLIENT, "client-error", code, "auth or webhook-id problem; never retry"
        )
    return Verdict(EXIT_CLIENT, "client-error", code, "unexpected status; never retry")


def from_transport(reason: object) -> Verdict:
    if isinstance(reason, ssl.SSLCertVerificationError):
        return Verdict(EXIT_TLS, "tls-verify", note="certificate verification failed")
    if isinstance(reason, socket.gaierror):
        return Verdict(EXIT_DNS, "dns", note="host name did not resolve")
    if isinstance(reason, TimeoutError):  # socket.timeout is an alias
        return Verdict(EXIT_RETRY, "retry", note="timeout")
    return Verdict(
        EXIT_RETRY, "retry", note=f"transport error: {type(reason).__name__}"
    )


def load_url(cfg: ha.Config, url_file: str | None) -> str:
    env_value = os.environ.get(ENV_URL)
    if env_value is not None:
        text = env_value.strip()
        if not text:
            raise ha.ConfigError(f"{ENV_URL} is empty")
        return text
    path = url_file or cfg.url_file
    return ha.read_secret(path, "webhook URL file")


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
    parser = argparse.ArgumentParser(
        description="Send one dummy POST to the HA webhook and classify the answer (PRP-004 H0).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("config", help="ha_sender JSON configuration")
    parser.add_argument(
        "--url-file", help=f"private file holding the webhook URL (env {ENV_URL} wins)"
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
    sys.exit(main())
