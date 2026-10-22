#!/usr/bin/env python3
"""Fake conntrack helper socket (stdlib only; never needs root).

Snapshots come from the REAL helper in `--once --file` mode, re-stamped (seq, ts, interval_s)
the way the daemon would. Serves ONE connection at a time: snapshot 1 at once, snapshot 2 after
DELAY seconds, then keeps the connection open and re-sends snapshot 2 (seq+1) every DELAY
seconds until killed. The socket is 0600 inside a 0700 directory, as the agent requires.

Usage: fake_conntrack.py SOCKET HELPER_BIN FIXTURE1 FIXTURE2 DELAY_S
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time


def snapshot(helper: str, fixture: str, seq: int) -> bytes:
    out = subprocess.run(
        [helper, "--once", "--file", fixture, "--lan-cidr", "192.168.1.0/24"],
        check=True, capture_output=True, text=True,
    ).stdout
    snap = json.loads(out)
    snap.update(seq=seq, ts=int(time.time()), interval_s=60)
    return (json.dumps(snap, separators=(",", ":")) + "\n").encode()


def main() -> int:
    path, helper, fx1, fx2, delay = sys.argv[1:6]
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(1)
    print("fake-conntrack: listening", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            seq = 1
            conn.sendall(snapshot(helper, fx1, seq))
            while True:
                time.sleep(float(delay))
                seq += 1
                conn.sendall(snapshot(helper, fx2, seq))
                print(f"fake-conntrack: sent seq {seq}", flush=True)
        except (BrokenPipeError, ConnectionResetError):
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
