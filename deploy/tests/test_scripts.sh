#!/bin/sh
# shellcheck disable=SC2016 # the sh -c bodies are intentionally single-quoted
# Plain-sh tests for gen-certs.sh, provision-collector.sh and entrypoint.sh (no bats).
# Uses a temp dir, the real openssl, and a stub `podman` that records argv and stdin.
#   sh deploy/tests/test_scripts.sh
set -u

# Safety: these tests must never reach a real podman (a reviewer's run once created and removed the
# real secrets vigie_tls_cert/vigie_tls_key through distrobox-host-exec). An inherited PODMAN is
# refused outright; the script then points PODMAN at its own stub and verifies it (guard_podman).
if [ -n "${PODMAN+x}" ]; then
	echo "test_scripts: refusing to run with PODMAN already set ('$PODMAN'); this script supplies its own stub" >&2
	exit 2
fi

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
DEPLOY=$(dirname "$HERE")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILS=0
PASSES=0

pass() { PASSES=$((PASSES + 1)); }
fail() {
	FAILS=$((FAILS + 1))
	echo "FAIL: $1" >&2
}
check() { # check DESCRIPTION COMMAND...
	d=$1
	shift
	if "$@" >/dev/null 2>&1; then pass; else fail "$d"; fi
}
mode_of() { stat -c %a "$1"; }
is_mode() { [ "$(mode_of "$1")" = "$2" ]; }

# ---- stub podman -----------------------------------------------------------------------------
STUB_MARK='# VIGIE-TEST-STUB'
# guard_podman CMD: succeeds only for ONE path (no whitespace, so never "distrobox-host-exec
# podman"), inside this test's temp dir, that is executable and carries the stub marker.
guard_podman() {
	case $1 in '' | *[[:space:]]*) return 1 ;; esac
	case $1 in "$T"/*) ;; *) return 1 ;; esac
	[ -x "$1" ] && [ "$(sed -n 2p "$1")" = "$STUB_MARK" ]
}
mkdir "$T/bin" "$T/state"
cat >"$T/bin/podman" <<'STUB'
#!/bin/sh
# VIGIE-TEST-STUB
# argv log (this is what a process listing would show) and stdin capture
printf '%s\n' "$*" >>"$STUB_STATE/argv.log"
case "$1 $2" in
"secret inspect") [ -e "$STUB_STATE/secret.$3" ] ;;
"secret rm") shift 2; for n in "$@"; do rm -f "$STUB_STATE/secret.$n"; done ;;
"secret create")
	if [ "$4" = "-" ]; then cat >"$STUB_STATE/secret.$3"; else cp "$4" "$STUB_STATE/secret.$3"; fi
	;;
*) exit 1 ;;
esac
STUB
chmod +x "$T/bin/podman"
cat >"$T/bin/fake-admin" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_STATE/admin.log"
STUB
chmod +x "$T/bin/fake-admin"
# Failing, logging stand-ins for every way to reach a real container runtime; first on PATH.
for tool in podman-compose distrobox-host-exec; do
	printf '#!/bin/sh\necho "REAL-TOOL-INVOKED: %s $*" >>"$STUB_STATE/real-tool.log"\nexit 99\n' "$tool" >"$T/bin/$tool"
	chmod +x "$T/bin/$tool"
done
PATH="$T/bin:$PATH"
export STUB_STATE="$T/state"
export PODMAN="$T/bin/podman"
guard_podman "$PODMAN" || {
	echo "test_scripts: internal error: PODMAN is not the verified stub" >&2
	exit 2
}

# ---- stub-podman guard self-test --------------------------------------------------------------
check "guard accepts the stub" guard_podman "$T/bin/podman"
for bad in podman "distrobox-host-exec podman" "$T/bin/podman extra" /usr/bin/podman "" "$T/bin/fake-admin" "$T/bin/podman-compose"; do
	if guard_podman "$bad"; then fail "guard accepted '$bad'"; else pass; fi
done
inherited=$(PODMAN=podman sh "$0" 2>&1)
check "script refuses an inherited PODMAN (exit 2)" test $? -eq 2
check "refusal names PODMAN" sh -c 'printf %s "$1" | grep -q "refusing to run with PODMAN"' _ "$inherited"
check "guard self-test touched no tool" test ! -e "$T/state/argv.log" -a ! -e "$T/state/real-tool.log"

# ---- gen-certs.sh ----------------------------------------------------------------------------
G="$DEPLOY/gen-certs.sh"
CD="$T/certs"
out=$(VIGIE_CERT_SAN="DNS:vigie.lan,IP:192.168.1.10" sh "$G" --out "$CD" 2>&1)
check "gen-certs succeeds" test -f "$CD/server.crt"
check "key is 0600" is_mode "$CD/server.key" 600
check "out dir is 0700" is_mode "$CD" 700
check "pins.txt is 0600" is_mode "$CD/pins.txt" 600
check "key is not printed" sh -c '! printf %s "$1" | grep -q "PRIVATE KEY"' _ "$out"
check "curve is P-256" sh -c 'openssl pkey -in "$1" -text -noout | grep -q prime256v1' _ "$CD/server.key"
check "SAN has DNS" sh -c 'openssl x509 -in "$1" -noout -ext subjectAltName | grep -q "DNS:vigie.lan"' _ "$CD/server.crt"
check "SAN has IP" sh -c 'openssl x509 -in "$1" -noout -ext subjectAltName | grep -q "IP Address:192.168.1.10"' _ "$CD/server.crt"
want_hex=$(openssl x509 -in "$CD/server.crt" -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
check "printed hex pin matches independent computation" sh -c 'printf %s "$1" | grep -q "$2"' _ "$out" "$want_hex"
want_b64=$(python3 -I -c 'import base64,sys;print(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' "$want_hex")
check "printed base64 pin matches" sh -c 'printf %s "$1" | grep -qF "$2"' _ "$out" "$want_b64"

sh "$G" --out "$CD" >/dev/null 2>&1
check "refuses without SAN" test $? -ne 0
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --out "$CD" >/dev/null 2>&1
rc=$?
check "refuses to overwrite (exit 73)" test "$rc" = 73
check "key unchanged after refusal" sh -c 'openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | grep -q "$2"' _ "$CD/server.crt" "$want_hex"
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --out "$CD" --force >/dev/null 2>&1
check "--force overwrites" sh -c '! openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | grep -q "$2"' _ "$CD/server.crt" "$want_hex"
check "key still 0600 after --force" is_mode "$CD/server.key" 600
VIGIE_CERT_SAN='DNS:a;rm' sh "$G" --out "$T/bad" >/dev/null 2>&1
check "rejects shell metacharacters in SAN" test $? -ne 0
VIGIE_CERT_SAN='host.lan' sh "$G" --out "$T/bad" >/dev/null 2>&1
check "rejects SAN without DNS:/IP: prefix" test $? -ne 0
check "failed runs leave no output dir content" sh -c '[ ! -e "$1/server.key" ]' _ "$T/bad"
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --out "$T/c2" --create-secrets >/dev/null 2>&1
check "--create-secrets creates both secrets" test -s "$T/state/secret.vigie_tls_key" -a -s "$T/state/secret.vigie_tls_cert"

# ---- provision-collector.sh ------------------------------------------------------------------
P="$DEPLOY/provision-collector.sh"
rm -f "$T/state/argv.log"
cat >"$T/compose-no.yaml" <<'Y'
secrets:
  - source: vigie_tls_cert
Y
cat >"$T/compose-yes.yaml" <<'Y'
secrets:
  - source: collector_key_k1
    uid: "10001"
Y
export VIGIE_ADMIN_CMD="$T/bin/fake-admin"

# compose lacks the secret: key + secret are made, registration is NOT attempted, ordering printed
PO="$T/rtr-1"
out=$(VIGIE_COMPOSE_FILE="$T/compose-no.yaml" sh "$P" --out "$PO" rtr-1 k1 2>&1)
check "key file written" test -f "$PO/key-k1"
check "key file is 0600" is_mode "$PO/key-k1" 600
check "key dir is 0700" is_mode "$PO" 700
check "key is 64 hex chars" sh -c 'grep -Eq "^[0-9a-f]{64}$" "$1"' _ "$PO/key-k1"
KEY=$(cat "$PO/key-k1")
check "secret holds the same key" test "$(cat "$T/state/secret.collector_key_k1")" = "$KEY"
check "key never in podman argv" sh -c '! grep -q "$1" "$2"' _ "$KEY" "$T/state/argv.log"
check "key never printed" sh -c '! printf %s "$1" | grep -q "$2"' _ "$out" "$KEY"
check "unlisted secret: admin not called" test ! -e "$T/state/admin.log"
check "ordering instructions printed" sh -c 'printf %s "$1" | grep -q "Register the collector"' _ "$out"
check "router snippet has scp -O" sh -c 'printf %s "$1" | grep -q "scp -O"' _ "$out"
check "router snippet has collector_id" sh -c 'printf %s "$1" | grep -q "collector_id=rtr-1"' _ "$out"

VIGIE_COMPOSE_FILE="$T/compose-no.yaml" sh "$P" --out "$PO" rtr-1 k1 >/dev/null 2>&1
rc=$?
check "second run refuses without --force (73)" test "$rc" = 73
check "key unchanged after refusal" test "$(cat "$PO/key-k1")" = "$KEY"

VIGIE_COMPOSE_FILE="$T/compose-yes.yaml" sh "$P" --force --out "$PO" rtr-1 k1 >/dev/null 2>&1
check "--force rotates the key" test "$(cat "$PO/key-k1")" != "$KEY"
check "--force with listed secret registers" grep -q "provision rtr-1 k1" "$T/state/admin.log"
check "rotated key file still 0600" is_mode "$PO/key-k1" 600

sh "$P" --out "$T/x" 'bad id' >/dev/null 2>&1
check "rejects id with a space" test $? -ne 0
sh "$P" --out "$T/x" 'a/../b' >/dev/null 2>&1
check "rejects id with slashes" test $? -ne 0
sh "$P" --out "$T/x" >/dev/null 2>&1
check "needs a collector id" test $? -ne 0

# ---- entrypoint.sh ---------------------------------------------------------------------------
E="$DEPLOY/entrypoint.sh"
ep() { # ep DATA_DIR INVENTORY_PATH OVERRIDES_PATH CMD... ; guard on
	d=$1 i=$2 o=$3
	shift 3
	VIGIE_GUARD_OVERRIDES=1 VIGIE_DATA_DIR="$d" VIGIE_INVENTORY_PATH="$i" VIGIE_OVERRIDES_PATH="$o" sh "$E" "$@"
}
mkdir -p "$T/raw" "$T/inv" "$T/ovr"
ep "$T/raw" "$T/inv/inventory.db" "$T/ovr/overrides.db" true >/dev/null 2>&1
check "entrypoint passes on clean volumes" test $? -eq 0
check "entrypoint execs its command" test "$(ep "$T/raw" "$T/inv/inventory.db" "$T/ovr/overrides.db" echo hi)" = hi
check "entrypoint creates nothing" test ! -e "$T/raw/overrides.db" -a ! -L "$T/raw/overrides.db"
echo human-labels >"$T/raw/overrides.db"
ep "$T/raw" "$T/inv/inventory.db" "$T/ovr/overrides.db" true >/dev/null 2>&1
check "refuses a regular overrides.db in the data dir (70)" test $? -eq 70
check "regular file left untouched" test "$(cat "$T/raw/overrides.db")" = human-labels
rm -f "$T/raw/overrides.db"
ln -s /overrides/overrides.db "$T/raw/overrides.db"
ep "$T/raw" "$T/inv/inventory.db" "$T/ovr/overrides.db" true >/dev/null 2>&1
check "refuses a (dangling) symlink in the data dir (70)" test $? -eq 70
check "symlink left untouched" test -L "$T/raw/overrides.db"
rm -f "$T/raw/overrides.db"
ln -s /nonexistent/x "$T/inv/overrides.db"
ep "$T/raw" "$T/inv/inventory.db" "$T/ovr/overrides.db" true >/dev/null 2>&1
check "refuses a stale link in the inventory dir (70)" test $? -eq 70
rm -f "$T/inv/overrides.db"
ep "$T/raw" "$T/inv/inventory.db" "" true >/dev/null 2>&1
check "refuses when VIGIE_OVERRIDES_PATH is unset (70)" test $? -eq 70
ep "$T/raw" "$T/inv/inventory.db" "$T/raw/sub/overrides.db" true >/dev/null 2>&1
check "refuses an overrides path inside the data dir (70)" test $? -eq 70
ep "$T/raw" "$T/inv/inventory.db" "$T/inv/overrides.db" true >/dev/null 2>&1
check "refuses an overrides path inside the inventory dir (70)" test $? -eq 70
echo planted >"$T/raw/overrides.db"
VIGIE_DATA_DIR="$T/raw" sh "$E" true >/dev/null 2>&1
check "guard is off without VIGIE_GUARD_OVERRIDES (ingest)" test $? -eq 0
rm -f "$T/raw/overrides.db"

# ---- healthcheck.py (argument dispatch; the live TLS probe was run by hand against real servers)
H="$DEPLOY/healthcheck.py"
python3 -I "$H" http 1 /healthz >/dev/null 2>&1
check "healthcheck: closed port is unhealthy (1)" test $? -eq 1
python3 -I "$H" proc definitely-not-a-process-name >/dev/null 2>&1
check "healthcheck: proc mismatch is unhealthy (1)" test $? -eq 1
python3 -I "$H" bogus >/dev/null 2>&1
check "healthcheck: bad usage is 2" test $? -eq 2

check "no real container tool was invoked" test ! -e "$T/state/real-tool.log"
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" = 0 ]
