"""Container healthchecks (the slim image has no curl).

  healthcheck.py http PORT PATH [--accept-4xx]   HTTPS GET on 127.0.0.1 (self-signed, so the
                                                 certificate is not verified: this only proves
                                                 the listener and TLS stack are up). 200 is
                                                 healthy; with --accept-4xx any 4xx is too (ingest
                                                 has no GET route: 405 means it answered). 5xx is
                                                 NEVER healthy.
  healthcheck.py fresh PATH                      PATH was touched within 3 x
                                                 $VIGIE_PIPELINE_INTERVAL_S seconds (default 30):
                                                 the pipeline touches it after every successful
                                                 pass, so a wedged or failing loop goes unhealthy
  healthcheck.py proc NEEDLE                     PID 1's command line contains NEEDLE (liveness)

Exit 0 healthy, 1 unhealthy.
"""

from __future__ import annotations

import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT_S = 3


def check_http(port: int, path: str, accept_4xx: bool) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # noqa: S501 - loopback liveness probe of our own listener
    url = f"https://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=TIMEOUT_S) as resp:  # noqa: S310
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        # The server answered. Ingest has no GET endpoint, so its 405 is healthy; a 5xx never is.
        return accept_4xx and 400 <= exc.code < 500
    except (urllib.error.URLError, OSError):
        return False


def check_proc(needle: str) -> bool:
    try:
        return needle.encode() in Path("/proc/1/cmdline").read_bytes()
    except OSError:
        return False


FRESH_FACTOR = 3
DEFAULT_INTERVAL_S = 30


def check_fresh(path: str) -> bool:
    try:
        interval = int(os.environ.get("VIGIE_PIPELINE_INTERVAL_S", DEFAULT_INTERVAL_S))
        age = time.time() - Path(path).stat().st_mtime
    except (OSError, ValueError):
        return False
    return interval >= 1 and age <= FRESH_FACTOR * interval


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "http":
        return 0 if check_http(int(argv[1]), argv[2], "--accept-4xx" in argv[3:]) else 1
    if len(argv) == 2 and argv[0] == "fresh":
        return 0 if check_fresh(argv[1]) else 1
    if len(argv) == 2 and argv[0] == "proc":
        return 0 if check_proc(argv[1]) else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
