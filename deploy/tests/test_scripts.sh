#!/bin/sh
# shellcheck disable=SC2016 # the sh -c bodies are intentionally single-quoted
# Plain-sh tests for gen-certs.sh, provision-collector.sh and entrypoint.sh (no bats).
# Uses a temp dir, the real openssl, and a stub `podman` that records argv and stdin.
#   sh deploy/tests/test_scripts.sh
set -u

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
mkdir "$T/bin" "$T/state"
cat >"$T/bin/podman" <<'STUB'
#!/bin/sh
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
export STUB_STATE="$T/state"
export PODMAN="$T/bin/podman"

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
D="$T/data"
mkdir "$D"
VIGIE_LINK_OVERRIDES=1 VIGIE_DATA_DIR="$D" VIGIE_OVERRIDES_TARGET=/overrides/overrides.db sh "$E" true
check "entrypoint creates symlink" test "$(readlink "$D/overrides.db")" = /overrides/overrides.db
VIGIE_LINK_OVERRIDES=1 VIGIE_DATA_DIR="$D" VIGIE_OVERRIDES_TARGET=/overrides/overrides.db sh "$E" true
check "entrypoint is idempotent" test "$(readlink "$D/overrides.db")" = /overrides/overrides.db
D2="$T/data2"
mkdir "$D2"
echo human-labels >"$D2/overrides.db"
VIGIE_LINK_OVERRIDES=1 VIGIE_DATA_DIR="$D2" sh "$E" true >/dev/null 2>&1
check "entrypoint refuses a regular overrides.db (70)" test $? -eq 70
check "regular file untouched" test "$(cat "$D2/overrides.db")" = human-labels
D3="$T/data3"
mkdir "$D3"
ln -s /elsewhere/overrides.db "$D3/overrides.db"
VIGIE_LINK_OVERRIDES=1 VIGIE_DATA_DIR="$D3" sh "$E" true >/dev/null 2>&1
check "entrypoint refuses a symlink to the wrong target" test $? -eq 70
D4="$T/data4"
mkdir "$D4"
VIGIE_DATA_DIR="$D4" sh "$E" true
check "no link without VIGIE_LINK_OVERRIDES" test ! -e "$D4/overrides.db" -a ! -L "$D4/overrides.db"
check "entrypoint execs its command" test "$(VIGIE_DATA_DIR="$D4" sh "$E" echo hi)" = hi

# ---- healthcheck.py (argument dispatch; the live TLS probe was run by hand against real servers)
H="$DEPLOY/healthcheck.py"
python3 -I "$H" http 1 /healthz >/dev/null 2>&1
check "healthcheck: closed port is unhealthy (1)" test $? -eq 1
python3 -I "$H" proc definitely-not-a-process-name >/dev/null 2>&1
check "healthcheck: proc mismatch is unhealthy (1)" test $? -eq 1
python3 -I "$H" bogus >/dev/null 2>&1
check "healthcheck: bad usage is 2" test $? -eq 2

echo "$PASSES passed, $FAILS failed"
[ "$FAILS" = 0 ]
