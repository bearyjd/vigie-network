#!/usr/bin/env python3
"""Check real `podman inspect` evidence against the deployment volume ownership matrix.

Usage: check_image_mounts.py SERVICE INSPECT_JSON --project-prefix PREFIX
The caller creates isolated containers first; this checker only reads captured evidence.
"""

import argparse
import json
from pathlib import Path, PurePosixPath

EXPECTED = {
    "ingest": {"/raw": ("vigie-raw", True), "/inv": ("vigie-inv", True)},
    "pipeline": {
        "/raw": ("vigie-raw", False),
        "/inv": ("vigie-inv", True),
        "/overrides": ("vigie-overrides", False),
    },
    "api": {"/inv": ("vigie-inv", False), "/overrides": ("vigie-overrides", True)},
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=EXPECTED)
    parser.add_argument("inspect_json", type=Path)
    parser.add_argument("--project-prefix", required=True)
    args = parser.parse_args()
    container = json.loads(args.inspect_json.read_text())[0]
    protected = {PurePosixPath(path) for path in ("/raw", "/inv", "/overrides")}
    mounts = {}
    for mount in container["Mounts"]:
        destination = PurePosixPath(mount["Destination"])
        if any(
            destination == root or destination in root.parents or root in destination.parents
            for root in protected
        ):
            path = str(destination)
            if path in mounts:
                raise SystemExit(f"FAIL {args.service}: duplicate protected mount at {path}")
            mounts[path] = mount
    expected = EXPECTED[args.service]
    if set(mounts) != set(expected):
        raise SystemExit(
            f"FAIL {args.service}: expected volumes {sorted(expected)}, got {sorted(mounts)}"
        )
    for path, (volume, writable) in expected.items():
        mount = mounts[path]
        if (
            mount["Type"] != "volume"
            or mount.get("Name") != f"{args.project_prefix}_{volume}"
            or mount["RW"] != writable
        ):
            raise SystemExit(f"FAIL {args.service}: incorrect ownership/mode of {path}")
    if (
        not container["HostConfig"]["ReadonlyRootfs"]
        or container["Config"]["User"] != "10001:10001"
    ):
        raise SystemExit(f"FAIL {args.service}: root filesystem or runtime user changed")
    print(
        f"PASS {args.service}: exact named volumes, mount modes, read-only rootfs and runtime user"
    )


if __name__ == "__main__":
    main()
