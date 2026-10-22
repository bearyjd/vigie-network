#!/usr/bin/env python3
"""Stage (d): what did ingest record? Usage: assert_ingest.py DATA_DIR

Hard assertions cover the chain working, including the DHCP fingerprints (opt55 for every device,
opt60 for the phones and the camera). VIGIE_E2E_NO_TAGS=1 is the control run without dnsmasq's
`tags:` line (docs/e2e.md finding F1); it must pass the same assertions.
"""

from __future__ import annotations

import glob
import sqlite3
import sys
from pathlib import Path

LAPTOP, CAMERA = "3c:22:fb:11:22:33", "ec:71:db:aa:bb:cc"
PHONE = ("c2:11:22:33:44:01", "c2:11:22:33:44:02", "c2:11:22:33:44:03")
FAILS: list[str] = []


def check(ok: bool, what: str) -> None:
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


def ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def main() -> int:
    data = Path(sys.argv[1])
    inv = ro(str(data / "inventory.db"))
    q = inv.execute
    n_batches = q("select count(*) from batches").fetchone()[0]
    coll = q("select last_seq, parse_failures, revoked from collectors where id='rtr-1'").fetchone()
    print(f"batches={n_batches} collector(last_seq, parse_failures, revoked)={coll}")
    check(n_batches >= 1, "ingest recorded >= 1 batch")
    check(coll is not None and coll[0] == n_batches, "last_seq equals batch count (no gaps)")
    check(coll is not None and coll[1] == 0, "no parse failures counted")
    check(q("select count(*) from batches where dropped_batches>0").fetchone()[0] == 0,
          "no dropped_batches")
    shards = sorted(glob.glob(str(data / "raw-*.db")))
    check(bool(shards), "at least one raw shard")
    rows: dict[str, list[tuple]] = {}
    for table in ("raw_dns", "raw_flow", "raw_lease", "raw_neigh", "raw_health"):
        rows[table] = []
        for shard in shards:
            rows[table] += ro(shard).execute(f"select * from {table}").fetchall()
    print({t: len(r) for t, r in rows.items()})
    dns_macs = {}
    for r in rows["raw_dns"]:
        dns_macs[r[2]] = dns_macs.get(r[2], 0) + 1
    print("dns rows per mac:", dns_macs)
    check(dns_macs.get(CAMERA, 0) >= 10, "camera: >= 10 periodic DNS rows")
    check(dns_macs.get(LAPTOP, 0) >= 1 and dns_macs.get(PHONE[0], 0) >= 1, "laptop and phone DNS rows")
    check(all(r[3] == "cam.vendor.example" for r in rows["raw_dns"] if r[2] == CAMERA),
          "camera DNS qname")
    check(all(r[5] == "203.0.113.5" for r in rows["raw_dns"] if r[2] == CAMERA),
          "camera DNS answer attributed")
    lease_macs = {r[3]: r for r in rows["raw_lease"]}
    check({LAPTOP, CAMERA, *PHONE} <= set(lease_macs), "lease rows for all 5 MACs")
    check({r[5] for r in rows["raw_lease"] if r[3] in PHONE} == {"Pixel-8"}, "phone hostname Pixel-8")
    neigh = {(r[3], r[4]) for r in rows["raw_neigh"]}
    check(all(("192.168.1.50", m) in neigh for m in PHONE), "neighbor rows: IP .50 under each phone MAC")
    check(("192.168.1.20", LAPTOP) in neigh and ("192.168.1.30", CAMERA) in neigh, "neighbor rows: laptop, camera")
    flow_macs = {r[2] for r in rows["raw_flow"]}
    check({LAPTOP, CAMERA} <= flow_macs and flow_macs & set(PHONE), "conntrack flow rows attributed")
    check(len(rows["raw_health"]) == n_batches, "one health row per batch")
    check(all(r[3] == 0 for r in rows["raw_health"]), "dns_log_quiet false on every batch (F4)")
    people = [(LAPTOP, "laptop", False), (CAMERA, "camera", True)]
    people += [(m, "phone " + m[-2:], True) for m in PHONE]
    for mac, label, want_class in people:
        mine = [r for r in rows["raw_lease"] if r[3] == mac]
        check(any(r[6] not in ("[]", None, "") for r in mine), f"{label}: non-empty opt55 in raw_lease")
        if want_class:
            check(any(r[7] not in (None, "") for r in mine), f"{label}: non-empty opt60 in raw_lease")
    check(any(r[7] == "android-dhcp-14" for r in rows["raw_lease"] if r[3] in PHONE),
          "phone vendor class android-dhcp-14")
    check(any(r[7] == "udhcp 1.31.1" for r in rows["raw_lease"] if r[3] == CAMERA),
          "camera vendor class udhcp 1.31.1")
    ct = [r[3] for r in q("select * from batches where truncated != '{}'")]
    print("batches with truncated/drops:", ct)
    print("FAILURES:", FAILS or "none")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
