#!/usr/bin/env python3
"""Render reviewed rootless Quadlets and an inert installation/rollback manifest.

Never executes Podman/systemctl, creates secrets/volumes, or installs into unit search paths.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path

_FIELDS = {
    "namespace",
    "image",
    "ingest_address",
    "ingest_port",
    "api_port",
    "collector_key_id",
}
_MOUNTS = {
    "ingest": (("raw", "rw"), ("inv", "rw")),
    "pipeline": (("raw", "ro"), ("inv", "rw"), ("overrides", "ro")),
    "api": (("inv", "ro"), ("overrides", "rw")),
}


def render(config: dict) -> dict[str, str]:
    if (
        not isinstance(config, dict)
        or not _FIELDS <= set(config)
        or set(config)
        - (_FIELDS | {"monitoring_large_upload_bytes", "monitoring_baseline"})
    ):
        raise ValueError("configuration must contain only the documented fields")
    threshold = config.get("monitoring_large_upload_bytes", 1073741824)
    if type(threshold) is not int or not 1 <= threshold <= 2**50:
        raise ValueError("monitoring_large_upload_bytes must be an integer in 1..2**50")
    baseline = config.get("monitoring_baseline", "pooled")
    if baseline not in ("pooled", "tod"):
        raise ValueError("monitoring_baseline must be exactly 'pooled' or 'tod'")
    ns, image, key = (config[k] for k in ("namespace", "image", "collector_key_id"))
    if not isinstance(ns, str) or not re.fullmatch(r"vigie_[a-z0-9_]{1,32}", ns):
        raise ValueError("a dedicated vigie_ namespace is required")
    if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("image must be a reviewed immutable local sha256 image ID")
    if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9]{1,32}", key):
        raise ValueError("invalid collector key id")
    if not isinstance(config["ingest_address"], str):
        raise ValueError("ingest address must be a literal string")  # noqa: TRY004 -- configuration contract
    try:
        address = ipaddress.IPv4Address(config["ingest_address"])
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise ValueError(
            "ingest requires an explicit literal IPv4 LAN address"
        ) from exc
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or int(address) == 0xFFFFFFFF
    ):
        raise ValueError(
            "wildcard/loopback/multicast/broadcast ingest binds are forbidden"
        )
    ports = [config[k] for k in ("ingest_port", "api_port")]
    if (
        any(type(p) is not int or not 1024 <= p <= 65535 for p in ports)
        or ports[0] == ports[1]
    ):
        raise ValueError("two distinct unprivileged ports are required")
    result = {}
    for volume in ("raw", "inv", "overrides"):
        result[f"{ns}-{volume}.volume"] = f"[Volume]\nVolumeName={ns}_{volume}\n"
    for role, mounts in _MOUNTS.items():
        lines = [
            "[Unit]",
            f"Description=Vigie owned {role}",
            "StartLimitIntervalSec=3600",
            "StartLimitBurst=5",
        ]
        deps = (
            [f"{ns}-ingest.service"]
            if role == "api"
            else (
                [f"{ns}-ingest.service", f"{ns}-api.service"]
                if role == "pipeline"
                else []
            )
        )
        if deps:
            lines += ["After=" + " ".join(deps), "Wants=" + " ".join(deps)]
        lines += [
            "[Container]",
            f"Image={image}",
            "Pull=never",
            f"ContainerName={ns}_{role}",
            "User=10001",
            "Group=10001",
            "ReadOnly=true",
            "DropCapability=all",
            "NoNewPrivileges=true",
            "PidsLimit=256",
            # Memory= needs a newer Podman than 4.9; PodmanArgs works on both.
            "PodmanArgs=--memory=512m --cpus=1",
            "Tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
            "LogDriver=journald",
        ]
        lines += [f"Volume={ns}-{name}.volume:/{name}:{mode}" for name, mode in mounts]
        lines += ["Environment=VIGIE_INVENTORY_PATH=/inv/inventory.db"]
        if role != "api":
            lines += ["Environment=VIGIE_DATA_DIR=/raw"]
        if role != "ingest":
            lines += [
                "Environment=VIGIE_OVERRIDES_PATH=/overrides/overrides.db",
                "Environment=VIGIE_GUARD_OVERRIDES=1",
            ]
        if role == "pipeline":
            lines += [f"Environment=VIGIE_MONITORING_LARGE_UPLOAD_BYTES={threshold}"]
            lines += [f"Environment=VIGIE_MONITORING_BASELINE={baseline}"]
            lines += [
                "Environment=VIGIE_PIPELINE_INTERVAL_S=30",
                "Environment=VIGIE_HEALTH_FILE=/tmp/vigie-pipeline.ok",
                "Network=none",
                "Exec=python -m vigie_pipeline run --loop 30",
                "HealthCmd=python /usr/local/bin/healthcheck.py fresh /tmp/vigie-pipeline.ok",
                "HealthStartPeriod=120s",
            ]
        else:
            port = 8443 if role == "ingest" else 8444
            prefix = "vigie_tls" if role == "ingest" else "vigie_api_tls"
            for suffix in ("cert", "key"):
                lines += [
                    f"Secret={ns}_{role}_{suffix},target={prefix}_{suffix},uid=10001,gid=10001,mode=0400"
                ]
            command = f"Exec=python -m vigie_{role} --host 0.0.0.0 --port {port} --tls-cert /run/secrets/{prefix}_cert --tls-key /run/secrets/{prefix}_key"
            if role == "ingest":
                command += " --workers 1"
                lines += [
                    "Environment=VIGIE_SECRETS_DIR=/run/secrets",
                    f"Secret={ns}_collector_key_{key},target=collector_key_{key},uid=10001,gid=10001,mode=0400",
                ]
            lines += [
                command,
                f"PublishPort={address if role == 'ingest' else '127.0.0.1'}:{config[role + '_port']}: {port}".replace(
                    ": ", ":"
                ),
                f"HealthCmd=python /usr/local/bin/healthcheck.py http {port} {'/v1/batch --accept-4xx' if role == 'ingest' else '/healthz'}",
                "HealthStartPeriod=15s",
            ]
        lines += [
            "HealthInterval=30s",
            "HealthTimeout=5s",
            "HealthRetries=3",
            "HealthOnFailure=kill",
            "[Service]",
            "Restart=on-failure",
            "RestartSec=5s",
            "TimeoutStartSec=180",
            "TimeoutStopSec=45",
            "[Install]",
            "WantedBy=default.target",
        ]
        result[f"{ns}-{role}.container"] = "\n".join(lines) + "\n"
    return result


def write_bundle(config: dict, output: Path) -> None:
    files = render(config)
    # Refuse existing output, including symlinks; no clobber or privileged target writes.
    output.mkdir(mode=0o700)
    hashes = {}
    for name, text in files.items():
        with (output / name).open("x", encoding="utf-8") as stream:
            os.chmod(output / name, 0o600)
            stream.write(text)
        hashes[name] = hashlib.sha256(text.encode()).hexdigest()
    plan = {
        "version": 1,
        "namespace": config["namespace"],
        "image": config["image"],
        "files": hashes,
        "apply": "NOT IMPLEMENTED: independently review and collision-check before installing",
        "preconditions": [
            "cgroup v2, rootless Quadlet supported and user linger enabled",
            "exact image ID present; no pull/build",
            "namespace unit/container/volume names absent or proven owned",
            "five unique secrets provisioned, collector enrollment and database bootstrap complete",
            "ingest address reserved, DNS/certificate pins and free loopback/API ports verified",
            "validate with QUADLET_UNIT_DIRS isolated generator --user --dryrun before copying",
        ],
        "rollback": [
            "stop only generated pipeline/api/ingest units",
            "compare installed file hashes with this manifest; refuse drift",
            "restore only exact pre-install snapshots or remove exact newly created owned unit files",
            "daemon-reload after reviewed restoration",
            "retain all named volumes, secrets, network and private evidence",
        ],
        "router": "separate reviewed transaction; no router commands are executed",
    }
    with (output / "plan.json").open("x", encoding="utf-8") as stream:
        os.chmod(output / "plan.json", 0o600)
        json.dump(plan, stream, indent=2)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    write_bundle(config, args.output)


if __name__ == "__main__":
    main()
