"""Container healthchecks (the slim image has no curl).

  healthcheck.py http PORT PATH [--any-status]   HTTPS GET on 127.0.0.1 (self-signed, so the
                                                 certificate is not verified: this only proves
                                                 the listener and TLS stack are up)
  healthcheck.py proc NEEDLE                     PID 1's command line contains NEEDLE
                                                 (liveness only: the pipeline has no endpoint)

Exit 0 healthy, 1 unhealthy.
"""

from __future__ import annotations

import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT_S = 3


def check_http(port: int, path: str, any_status: bool) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # noqa: S501 - loopback liveness probe of our own listener
    url = f"https://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=TIMEOUT_S) as resp:  # noqa: S310
            return resp.status == 200 or any_status
    except urllib.error.HTTPError:
        return any_status  # the server answered; ingest has no GET endpoint (405 is healthy)
    except (urllib.error.URLError, OSError):
        return False


def check_proc(needle: str) -> bool:
    try:
        return needle.encode() in Path("/proc/1/cmdline").read_bytes()
    except OSError:
        return False


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "http":
        return 0 if check_http(int(argv[1]), argv[2], "--any-status" in argv[3:]) else 1
    if len(argv) == 2 and argv[0] == "proc":
        return 0 if check_proc(argv[1]) else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
