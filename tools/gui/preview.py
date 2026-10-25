#!/usr/bin/env python3
"""Isolated synthetic GUI preview; never loads environment-selected production DBs.

Seed writes only a NEW /tmp/vigie-gui-preview-* directory. Serve binds loopback18745,
uses explicit own DB paths and automatically exits after8hours. No live collector.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import threading
import time
import uuid
from pathlib import Path

import uvicorn

from vigie_api import tokens
from vigie_api.app import create_app
from vigie_api.config import Settings
from vigie_api.schema import open_overrides
from vigie_ingest.db import iso_utc
from vigie_pipeline.schema import open_pipeline_inventory

COLLECTOR = "synthetic-preview"
ATTACK_DEVICE = str(uuid.UUID(int=1))
INCIDENT = "synthetic-incident-1"
PREVIEW_SECONDS = 8 * 3600
PREVIEW_PARENT = Path("/tmp")  # noqa: S108 -- absent owned0700 child required; never shared files.


def directory(value: str) -> Path:
    root = Path(value)
    if (
        not root.is_absolute()
        or root.parent != PREVIEW_PARENT
        or not root.name.startswith("vigie-gui-preview-")
        or root.resolve() != root
    ):
        raise ValueError("use a new direct /tmp/vigie-gui-preview-* directory without symlinks")
    return root


def seed(root: Path) -> dict:
    previous = os.umask(0o077)
    try:
        return _seed(root)
    finally:
        os.umask(previous)


def _seed(root: Path) -> dict:
    root.mkdir(mode=0o700)
    now = time.time()
    hour = int(now) // 3600 * 3600
    stamp = iso_utc(now)
    inv = open_pipeline_inventory(root / "inventory.db", migrate=True)
    ov = open_overrides(root / "overrides.db")
    try:
        inv.execute(
            "INSERT INTO collectors(id,key_id,boot_id,last_seq) VALUES (?,?,?,?)",
            (COLLECTOR, "synthetic-key", "synthetic-boot", 3),
        )
        for number in range(1, 56):
            device = str(uuid.UUID(int=number))
            mac = f"02:00:00:00:00:{number:02x}"
            inv.execute(
                "INSERT INTO devices(id,first_seen,last_seen,identity_state,status) "
                "VALUES (?,?,?,'ok','active')",
                (device, iso_utc(now - 86400), stamp),
            )
            inv.execute(
                "INSERT INTO observations(mac,device_id,is_randomized,hostname,link_source,"
                "first_seen,last_seen) VALUES (?,?,0,?,'self',?,?)",
                (mac, device, f"synthetic-host-{number:02d}", iso_utc(now - 86400), stamp),
            )
            name = (
                '<img src=x onerror="window.__guiInjected=1">'
                if number == 1
                else f"Synthetic device {number:02d}"
            )
            ov.execute(
                "INSERT INTO device_overrides(device_id,name,updated_at,updated_by) "
                "VALUES (?,?,?,'synthetic-preview')",
                (device, name, stamp),
            )
            if number % 3:
                address = f"192.0.2.{number}" if number % 3 == 1 else f"2001:db8::{number:x}"
                inv.execute(
                    "INSERT INTO mac_last_ip VALUES (?,?,?,'lease')", (mac, address, int(now))
                )
            for offset in range(1, 6):
                if offset == 3:
                    continue  # Actual missing hour, never zero-filled.
                inv.execute(
                    "INSERT INTO measurements_hourly VALUES (?,?,?,?,?,?,?)",
                    (
                        COLLECTOR,
                        mac,
                        hour - offset * 3600,
                        number * 1024 * offset,
                        number * 2048,
                        number,
                        number * 2,
                    ),
                )
        for offset in (1, 2, 4, 5):
            qualified = 1200 if offset == 2 else 3600
            reasons = '["synthetic_partial"]' if offset == 2 else "[]"
            inv.execute(
                "INSERT INTO coverage_hourly VALUES (?,?,?,?,?)",
                (COLLECTOR, hour - offset * 3600, qualified, qualified, reasons),
            )
        inv.execute(
            "INSERT INTO batches(collector_id,batch_id,received_at,window_start,window_end,"
            "observation_kind,dns_queries,health,truncated,dropped_batches) "
            "VALUES (?,?,?,?,?,'observation',3,?,?,0)",
            (
                COLLECTOR,
                "synthetic-batch",
                stamp,
                int(now) - 60,
                int(now),
                '{"rss_kb":2048,"uptime_s":600,"dns_log_quiet":false}',
                '{"source_flags":8}',
            ),
        )
        inv.execute(
            "INSERT INTO measurement_batches VALUES (?,?,?,?,?,?,?)",
            (
                COLLECTOR,
                "synthetic-batch",
                int(now) - 60,
                int(now),
                stamp,
                hour,
                '["synthetic_degraded_coverage"]',
            ),
        )
        evidence = {
            "reason_code": "large_upload_threshold",
            "hour": hour - 3600,
            "previous_hour": None,
            "observed_bytes": 1073741824,
            "threshold_bytes": 1073741824,
            "baseline_id": None,
            "algorithm": "pooled-median-v1",
            "config_version": "synthetic",
            "coverage_required_seconds": 3420,
            "lineage": "synthetic-lineage",
            "unusual_is_not_malicious": True,
        }
        inv.execute(
            "INSERT INTO monitoring_incidents(id,collector_id,device_id,lineage,detector,state,"
            "episode_start,last_hour,detected_at,baseline_id,observed_bytes,threshold_bytes,"
            "evidence) VALUES (?,?,?,'synthetic-lineage','large_upload','open',?,?,?,NULL,?,?,?)",
            (
                INCIDENT,
                COLLECTOR,
                ATTACK_DEVICE,
                hour - 3600,
                hour - 3600,
                stamp,
                1073741824,
                1073741824,
                json.dumps(evidence),
            ),
        )
        _, token = tokens.create_token(ov, "synthetic-gui", scope="read-only")
        with (root / "read-token.private").open("x", encoding="utf-8") as stream:
            stream.write(token + "\n")
        manifest = {
            "synthetic": True,
            "collector_id": COLLECTOR,
            "devices": 55,
            "attack_device_id": ATTACK_DEVICE,
            "incident_id": INCIDENT,
            "seeded_at": stamp,
            "url": "http://127.0.0.1:18745/ui/?preview=synthetic",
            "token_file": str(root / "read-token.private"),
            "expires_after_server_seconds": PREVIEW_SECONDS,
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    finally:
        inv.close()
        ov.close()


def serve(root: Path) -> None:
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o777 != 0o700:
        raise ValueError("preview directory must be privately owned0700")
    for name in ("inventory.db", "overrides.db", "manifest.json", "read-token.private"):
        path = root / name
        st = path.lstat()
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o777 != 0o600
            or st.st_nlink != 1
        ):
            raise ValueError("preview files must be owned0600 regular single-link files")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("synthetic") is not True or manifest.get("collector_id") != COLLECTOR:
        raise ValueError("explicit synthetic seed manifest required")
    settings = Settings(
        data_dir=root,
        inventory_db=root / "inventory.db",
        overrides_db=root / "overrides.db",
    )  # No environment DB/config paths are loaded.
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host="127.0.0.1",
            port=18745,
            access_log=False,
            log_level="warning",
            limit_concurrency=64,
            timeout_keep_alive=5,
            timeout_graceful_shutdown=5,
        )
    )
    timer = threading.Timer(PREVIEW_SECONDS, lambda: setattr(server, "should_exit", True))
    timer.daemon = True
    timer.start()
    try:
        server.run()
    finally:
        timer.cancel()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seed", "serve"))
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = directory(args.directory)
    if args.action == "seed":
        print(json.dumps(seed(root)))  # Safe manifest only, never token material.
    else:
        serve(root)


if __name__ == "__main__":
    main()
