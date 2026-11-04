#!/usr/bin/env bash
# Build deploy/Containerfile and assert the image: Python 3.12, packages import, non-root uid.
# Extra args are passed to `podman build` (e.g. --build-arg PYTHON_IMAGE=... for the negative test).
# PODMAN overrides the binary (default: podman).
set -euo pipefail
cd "$(dirname "$0")/.."
podman=${PODMAN:-podman}
img=localhost/vigie-server:ci
$podman build -f deploy/Containerfile -t "$img" "$@" .
run() { $podman run --rm --entrypoint "" "$img" "$@"; }
ver=$(run python --version)
case $ver in "Python 3.12."*) ;; *) echo "image smoke: expected Python 3.12.x, got: $ver" >&2; exit 1 ;; esac
run python -c 'import vigie_api, vigie_ingest, vigie_pipeline'
uid=$(run id -u)
[ "$uid" = 10001 ] || { echo "image smoke: expected uid 10001, got: $uid" >&2; exit 1; }
echo "image smoke: ok ($ver, uid $uid)"
