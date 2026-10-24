#!/usr/bin/env bash
# Full local/hosted gate. Each stage stops on failure; logs retain the complete output.
set -euo pipefail
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"
stages=(server trafficgen rust deploy contracts e2e)
usage() {
    echo 'Usage: scripts/ci.sh [--list | --help | STAGE ...]'
    echo "Stages (default: all): ${stages[*]}"
}
if [[ ${1:-} == --help ]]; then usage; exit 0; fi
if [[ ${1:-} == --list ]]; then printf '%s\n' "${stages[@]}"; exit 0; fi
selected=("${@:-}")
if (($# == 0)); then selected=("${stages[@]}"); fi
# Validate all input before running anything.
for stage in "${selected[@]}"; do
    valid=0
    for known in "${stages[@]}"; do [[ $stage != "$known" ]] || valid=1; done
    if ((valid == 0)); then usage >&2; exit 2; fi
done
for tool in uv cargo openssl python3; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 2; }
done
export VIGIE_INGEST_SRC="$REPO/server/src"
SERVER_ENV=${VIGIE_CI_SERVER_ENV:-$REPO/server/.venv}
TRAFFIC_ENV=${VIGIE_CI_TRAFFICGEN_ENV:-$REPO/tools/trafficgen/.venv}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$REPO/collector/target}
# Resolve paths before entering project directories.
SERVER_ENV=$(realpath -m "$SERVER_ENV")
TRAFFIC_ENV=$(realpath -m "$TRAFFIC_ENV")
CARGO_TARGET_DIR=$(realpath -m "$CARGO_TARGET_DIR")
export CARGO_TARGET_DIR
LOG_DIR=${VIGIE_CI_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vigie-ci.XXXXXX")}
mkdir -p "$LOG_DIR"
LOG_DIR=$(realpath "$LOG_DIR")
echo "CI logs: $LOG_DIR"
server() { (cd server && UV_PROJECT_ENVIRONMENT="$SERVER_ENV" uv run --frozen "$@"); }
trafficgen() { (cd tools/trafficgen && UV_PROJECT_ENVIRONMENT="$TRAFFIC_ENV" uv run --frozen "$@"); }
stage_server() {
    server pytest -q &&
        server ruff check . &&
        server ruff format --check .
}
stage_trafficgen() {
    trafficgen pytest -q &&
        trafficgen ruff check . &&
        trafficgen ruff format --check .
}
stage_rust() { (cd collector && cargo test --locked --workspace); }
stage_deploy() {
    bash deploy/tests/test_scripts.sh &&
    python3 -I deploy/tests/test_check_image_mounts.py &&
    python3 -I deploy/tests/test_persistent.py &&
    python3 -I deploy/tests/test_soak.py &&
    python3 -I deploy/tests/test_soak_adapters.py &&
    python3 -I deploy/tests/test_router_logfs.py &&
    UV_PROJECT_ENVIRONMENT="$TRAFFIC_ENV" uv run --frozen --project tools/trafficgen \
        --with PyYAML==6.0.3 python -I deploy/tests/check_refs.py --release &&
    bash tests/p0/test_mac_roll_report.sh
}
stage_contracts() {
    # Schema/OpenAPI drift and committed signing vectors are also checked by the suites.
    # Require jsonschema here: test_rust_batches otherwise treats it as optional.
    trafficgen python -c 'import jsonschema' &&
    trafficgen python "$REPO/tests/vectors/test_rust_batches.py" &&
    server python "$REPO/tests/vectors/test_https_against_ingest.py"
}
stage_e2e() {
    # Explicitly reuse this checkout's server environment and cargo output, never stale binaries.
    UV_PROJECT_ENVIRONMENT="$SERVER_ENV" bash tests/e2e/run_e2e.sh
}
for stage in "${selected[@]}"; do
    echo "RUN  $stage"
    if ("stage_$stage") >"$LOG_DIR/$stage.log" 2>&1; then
        echo "PASS $stage"
    else
        status=$?
        echo "FAIL $stage (exit $status): $LOG_DIR/$stage.log" >&2
        tail -n 60 "$LOG_DIR/$stage.log" >&2
        exit "$status"
    fi
done
echo 'All selected CI stages passed.'
