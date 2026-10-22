#!/usr/bin/env bash
# Whole-chain smoke test: real collector -> real ingest (TLS, pinned, HMAC) -> real pipeline ->
# real API. See docs/e2e.md. Never needs root, podman or the router; binds 127.0.0.1 only.
#
#   tests/e2e/run_e2e.sh [--skip-build]
#
# All output lives under $VIGIE_E2E_BASE (default $HOME/.cache/vigie-e2e). Each run makes a fresh
# run-<pid> directory there; the script never deletes anything (remove old runs yourself).
set -u
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH='' cd -- "$HERE/../.." && pwd)
BASE=${VIGIE_E2E_BASE:-$HOME/.cache/vigie-e2e}
export TMPDIR=${VIGIE_E2E_TMP:-$HOME/.cache/vigie-e2e-tmp}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/.cache/vigie-e2e-target}
export UV_CACHE_DIR=${UV_CACHE_DIR:-$HOME/.cache/vigie-e2e-uv}
export UV_PROJECT_ENVIRONMENT=${UV_PROJECT_ENVIRONMENT:-$HOME/.cache/vigie-e2e-venv}
WINDOW_S=${VIGIE_E2E_WINDOW_S:-6}
STEP_S=${VIGIE_E2E_STEP_S:-10}
mkdir -p "$BASE" "$TMPDIR" "$CARGO_TARGET_DIR" "$UV_CACHE_DIR"
RUN="$BASE/run-$$"
mkdir -p "$RUN"
chmod 700 "$RUN"
PY="$UV_PROJECT_ENVIRONMENT/bin/python"
PIDS=()
RESULTS=()
FAILED=0

cleanup() {
	local p
	for p in "${PIDS[@]:-}"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null
	done
	wait 2>/dev/null
}
trap cleanup EXIT

stage() { # stage NAME CMD...  -> PASS/FAIL line, output in $RUN/logs/NAME.out
	local name=$1
	shift
	if "$@" >"$RUN/logs/$name.out" 2>&1; then
		RESULTS+=("PASS  $name")
	else
		RESULTS+=("FAIL  $name   (see $RUN/logs/$name.out)")
		FAILED=1
		tail -n 15 "$RUN/logs/$name.out" | sed 's/^/    | /'
		return 1
	fi
}

free_port() { "$PY" -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

wait_port() { # wait_port PORT SECONDS
	local i
	for ((i = 0; i < $2 * 10; i++)); do
		(exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

mkdir -p "$RUN/logs" "$RUN/data" "$RUN/secrets" "$RUN/agentkey" "$RUN/ct" "$RUN/bin" "$RUN/certs1" "$RUN/certs2" "$RUN/apicerts"
chmod 700 "$RUN"/{data,secrets,agentkey,ct,bin,certs1,certs2,apicerts}
echo "run dir: $RUN"

s_build() {
	if [ "${1:-}" != "--skip-build" ]; then
		(cd "$REPO/collector" && cargo build --release -p vigie-collector -p vigie-conntrack) || return 1
		(cd "$REPO/server" && uv sync) || return 1
	fi
	test -x "$CARGO_TARGET_DIR/release/vigie-collector" && test -x "$CARGO_TARGET_DIR/release/vigie-conntrack" && test -x "$PY"
}

s_provision() {
	# (a) two ingest certs (pin1/pin2 must differ), SPKI pins, collector key, registration.
	VIGIE_CERT_SAN="IP:127.0.0.1,DNS:localhost" "$REPO/deploy/gen-certs.sh" --role ingest --out "$RUN/certs1" || return 1
	VIGIE_CERT_SAN="IP:127.0.0.1,DNS:localhost" "$REPO/deploy/gen-certs.sh" --role ingest --out "$RUN/certs2" || return 1
	VIGIE_CERT_SAN="IP:127.0.0.1,DNS:localhost" "$REPO/deploy/gen-certs.sh" --role api --out "$RUN/apicerts" || return 1
	PIN1=$(sed -n 's/^pin_sha256_hex=//p' "$RUN/certs1/pins.txt")
	PIN2=$(sed -n 's/^pin_sha256_hex=//p' "$RUN/certs2/pins.txt")
	[ ${#PIN1} -eq 64 ] && [ ${#PIN2} -eq 64 ] || return 1
	umask 077
	openssl rand -hex 32 >"$RUN/secrets/collector_key_k1"
	cp "$RUN/secrets/collector_key_k1" "$RUN/agentkey/key"
	chmod 600 "$RUN/agentkey/key" "$RUN/secrets/collector_key_k1"
	VIGIE_DATA_DIR="$RUN/data" VIGIE_SECRETS_DIR="$RUN/secrets" "$PY" -m vigie_ingest.admin provision rtr-1 k1 || return 1
	echo "$PIN1" >"$RUN/pin1"
	echo "$PIN2" >"$RUN/pin2"
}

s_ingest_up() {
	INGEST_PORT=$(free_port)
	echo "$INGEST_PORT" >"$RUN/ingest_port"
	VIGIE_DATA_DIR="$RUN/data" VIGIE_SECRETS_DIR="$RUN/secrets" \
		"$PY" -m vigie_ingest --host 127.0.0.1 --port "$INGEST_PORT" \
		--tls-cert "$RUN/certs1/server.crt" --tls-key "$RUN/certs1/server.key" \
		>"$RUN/logs/ingest.log" 2>&1 &
	PIDS+=($!)
	wait_port "$INGEST_PORT" 20
}

write_agent_inputs() {
	: >"$RUN/dnsmasq.log"
	: >"$RUN/dhcp.leases"
	: >"$RUN/neigh.txt"
	cat >"$RUN/bin/ip" <<'EOF'
#!/bin/sh
# Test double for `ip`: the agent runs `ip -4 neigh show` / `ip -6 neigh show`.
case "$1" in
-4) cat "$VIGIE_E2E_NEIGH_FILE" ;;
esac
exit 0
EOF
	chmod 755 "$RUN/bin/ip"
	cat >"$RUN/collector.conf" <<EOF
server_url=https://127.0.0.1:$(cat "$RUN/ingest_port")/v1/batch
collector_id=rtr-1
key_id=k1
pin1=$(cat "$RUN/pin1")
pin2=$(cat "$RUN/pin2")
key_file=$RUN/agentkey/key
dnsmasq_log=$RUN/dnsmasq.log
leases_file=$RUN/dhcp.leases
conntrack_socket=$RUN/ct/conntrack.sock
lan_addr=127.0.0.1
lan_prefix=8
lan_iface=lo
EOF
}

s_collector_check() {
	PATH="$RUN/bin:$PATH" "$CARGO_TARGET_DIR/release/vigie-collector" --config "$RUN/collector.conf" --check
}

s_collect() {
	# (c) fake conntrack socket + real agent, then timed fixture feed; ends when shipped.
	"$PY" "$HERE/fake_conntrack.py" "$RUN/ct/conntrack.sock" "$CARGO_TARGET_DIR/release/vigie-conntrack" \
		"$HERE/conntrack1.txt" "$HERE/conntrack2.txt" 12 >"$RUN/logs/fake-conntrack.log" 2>&1 &
	PIDS+=($!)
	sleep 1
	PATH="$RUN/bin:$PATH" VIGIE_E2E_NEIGH_FILE="$RUN/neigh.txt" \
		"$CARGO_TARGET_DIR/release/vigie-collector" --config "$RUN/collector.conf" --window-s "$WINDOW_S" \
		>"$RUN/logs/collector.log" 2>&1 &
	AGENT_PID=$!
	PIDS+=($AGENT_PID)
	sleep 3 # the tail starts at the END of the log on its first poll: append only after that
	"$PY" "$HERE/feed.py" "$RUN" "$STEP_S" || return 1
	sleep $((WINDOW_S * 3))
	kill -0 "$AGENT_PID" 2>/dev/null || {
		echo "agent died"
		return 1
	}
	kill "$AGENT_PID"
	wait "$AGENT_PID" 2>/dev/null
	return 0
}

s_ingest_assert() {
	"$PY" "$HERE/assert_ingest.py" "$RUN/data" || return 1
}

s_ingest_down() {
	local p=${PIDS[0]}
	kill "$p" 2>/dev/null
	wait "$p" 2>/dev/null
	return 0
}

s_token() {
	export VIGIE_DATA_DIR="$RUN/data"
	"$PY" -m vigie_api tokens create --id e2e >"$RUN/token.out" || return 1
	grep -o 'vgt_[A-Za-z0-9_.-]*' "$RUN/token.out" | head -n 1 >"$RUN/token"
	chmod 600 "$RUN/token"
	test -s "$RUN/token" && test -f "$RUN/data/overrides.db"
}

s_pipeline() {
	VIGIE_DATA_DIR="$RUN/data" VIGIE_TRANSIENT_MIN_DWELL_S="${VIGIE_E2E_MIN_DWELL_S:-0}" \
		"$PY" -m vigie_pipeline run --once "$@"
}

s_api_up() {
	API_PORT=$(free_port)
	echo "$API_PORT" >"$RUN/api_port"
	VIGIE_DATA_DIR="$RUN/data" "$PY" -m vigie_api --host 127.0.0.1 --port "$API_PORT" \
		--tls-cert "$RUN/apicerts/server.crt" --tls-key "$RUN/apicerts/server.key" \
		>"$RUN/logs/api.log" 2>&1 &
	PIDS+=($!)
	wait_port "$API_PORT" 20
}

s_api_assert() {
	"$PY" "$HERE/assert_api.py" "$1" "$RUN"
}

stage build s_build "${1:-}" || exit 1
stage provision s_provision || exit 1
stage ingest_up s_ingest_up || exit 1
write_agent_inputs
stage collector_check s_collector_check || exit 1
stage collect s_collect
stage ingest_assert s_ingest_assert
stage ingest_down s_ingest_down
stage api_token s_token || { printf '%s\n' "${RESULTS[@]}"; exit 1; }
stage pipeline_1 s_pipeline
stage api_up s_api_up || { printf '%s\n' "${RESULTS[@]}"; exit 1; }
stage api_assert s_api_assert phase1
stage pipeline_2 s_pipeline
stage api_assert_after_rerun s_api_assert phase2

echo
echo "==== e2e results ===="
printf '%s\n' "${RESULTS[@]}"
exit "$FAILED"
