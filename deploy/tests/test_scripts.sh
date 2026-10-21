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
	[ -e "$STUB_STATE/fail.create" ] && exit 1
	if [ "$4" = "-" ]; then cat >"$STUB_STATE/secret.$3"; else cp "$4" "$STUB_STATE/secret.$3"; fi
	;;
*) exit 1 ;;
esac
STUB
chmod +x "$T/bin/podman"
cat >"$T/bin/fake-admin" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_STATE/admin.log"
[ -e "$STUB_STATE/admin.fail" ] && { echo "collector is revoked" >&2; exit 1; }
exit 0
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
check "ingest role does not create api secrets" test ! -e "$T/state/secret.vigie_api_tls_key" -a ! -e "$T/state/secret.vigie_api_tls_cert"
ingest_key_before=$(cat "$T/state/secret.vigie_tls_key")
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --role api --out "$T/c-api" --create-secrets >/dev/null 2>&1
check "--role api creates its own secrets" test -s "$T/state/secret.vigie_api_tls_key" -a -s "$T/state/secret.vigie_api_tls_cert"
check "--role api leaves the ingest secrets alone" test "$(cat "$T/state/secret.vigie_tls_key")" = "$ingest_key_before"
check "api key differs from the ingest key" test "$(cat "$T/state/secret.vigie_api_tls_key")" != "$ingest_key_before"
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --role bogus --out "$T/c-bogus" >/dev/null 2>&1
check "rejects an unknown role (64)" test $? -eq 64
check "unknown role writes nothing" test ! -e "$T/c-bogus"
# default --out is next to the script, not the current directory
mkdir "$T/here" "$T/elsewhere"
cp "$G" "$T/here/gen-certs.sh"
(cd "$T/elsewhere" && VIGIE_CERT_SAN="DNS:vigie.lan" sh "$T/here/gen-certs.sh" >/dev/null 2>&1)
check "default out is <script dir>/certs" test -f "$T/here/certs/server.key"
check "nothing is written in the cwd" test -z "$(ls -A "$T/elsewhere")"
(cd "$T/elsewhere" && VIGIE_CERT_SAN="DNS:vigie.lan" sh "$T/here/gen-certs.sh" --role api >/dev/null 2>&1)
check "default api out is <script dir>/certs-api" test -f "$T/here/certs-api/server.key"
# an existing --out directory is not chmodded
mkdir "$T/shared"
chmod 0755 "$T/shared"
VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --out "$T/shared" >/dev/null 2>&1
check "existing out dir keeps its mode" is_mode "$T/shared" 755
check "key in an existing dir is still 0600" is_mode "$T/shared/server.key" 600
# an openssl failure is shown, not swallowed
mkdir "$T/failbin"
printf '#!/bin/sh\necho "openssl-said-boom" >&2\nexit 1\n' >"$T/failbin/openssl"
chmod +x "$T/failbin/openssl"
fail_out=$(PATH="$T/failbin:$PATH" VIGIE_CERT_SAN="DNS:vigie.lan" sh "$G" --out "$T/c-fail" 2>&1)
check "openssl failure exits non-zero" test $? -ne 0
check "openssl stderr is shown" sh -c 'printf %s "$1" | grep -q openssl-said-boom' _ "$fail_out"
check "failed run leaves no key" test ! -e "$T/c-fail/server.key"

# ---- provision-collector.sh ------------------------------------------------------------------
P="$DEPLOY/provision-collector.sh"
rm -f "$T/state/argv.log"
cat >"$T/compose-no.yaml" <<'Y'
secrets:
  - source: vigie_tls_cert
Y
cat >"$T/compose-yes.yaml" <<'Y'
services:
  ingest:
    secrets:
      - source: collector_key_k1
        uid: "10001"
secrets:
  collector_key_k1:
    external: true
Y
# decoys: substring / prefix matches must NOT count as listing collector_key_k1
cat >"$T/compose-decoy.yaml" <<'Y'
services:
  ingest:
    secrets:
      - source: collector_key_k10
      - source: xcollector_key_k1
      # - source: collector_key_k1
secrets:
  collector_key_k10:
    external: true
Y
cat >"$T/compose-nodef.yaml" <<'Y'
services:
  ingest:
    secrets:
      - source: collector_key_k1
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

rm -f "$T/state/admin.log"
VIGIE_COMPOSE_FILE="$T/compose-decoy.yaml" sh "$P" --force --out "$PO" rtr-1 k1 >/dev/null 2>&1
check "decoy secret names do not count as listed" test ! -e "$T/state/admin.log"
VIGIE_COMPOSE_FILE="$T/compose-nodef.yaml" sh "$P" --force --out "$PO" rtr-1 k1 >/dev/null 2>&1
check "a secret not defined at top level does not count" test ! -e "$T/state/admin.log"
reg_out=$(VIGIE_COMPOSE_FILE="$T/compose-yes.yaml" sh "$P" --force --out "$PO" rtr-1 k1 2>&1)
check "exact match registers" grep -q "provision rtr-1 k1" "$T/state/admin.log"
check "registration warns about immediate key_id switch" sh -c 'printf %s "$1" | grep -q "WARNING: ingest now expects key id k1"' _ "$reg_out"
check "no temporary secret is left behind" sh -c '! ls "$1" | grep -q "\.tmp"' _ "$T/state"
# registration failure (revoked collector): honest message, non-zero exit
: >"$T/state/admin.fail"
fail_reg=$(VIGIE_COMPOSE_FILE="$T/compose-yes.yaml" sh "$P" --force --out "$PO" rtr-1 k1 2>&1)
check "failed registration exits 1" test $? -eq 1
check "failed registration mentions a revoked collector" sh -c 'printf %s "$1" | grep -q REVOKED' _ "$fail_reg"
check "failed registration does not claim ingest has no row" sh -c '! printf %s "$1" | grep -q "no row"' _ "$fail_reg"
rm -f "$T/state/admin.fail"
# a failing podman: nothing is written, the old key file survives
OLD_KEY=$(cat "$PO/key-k1")
: >"$T/state/fail.create"
VIGIE_COMPOSE_FILE="$T/compose-yes.yaml" sh "$P" --force --out "$PO" rtr-1 k1 >/dev/null 2>&1
check "podman failure exits non-zero" test $? -ne 0
check "podman failure leaves the old key file" test "$(cat "$PO/key-k1")" = "$OLD_KEY"
VIGIE_COMPOSE_FILE="$T/compose-yes.yaml" sh "$P" --out "$T/fresh" rtr-9 >/dev/null 2>&1
check "podman failure writes no key file for a new collector" test ! -e "$T/fresh/key-k1"
rm -f "$T/state/fail.create"
mkdir "$T/preexisting"
chmod 0755 "$T/preexisting"
VIGIE_COMPOSE_FILE="$T/compose-no.yaml" sh "$P" --out "$T/preexisting" rtr-2 >/dev/null 2>&1
check "existing --out directory keeps its mode" is_mode "$T/preexisting" 755

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

# ---- .gitignore ------------------------------------------------------------------------------
REPO=$(dirname "$DEPLOY")
ign() { git -C "$REPO" check-ignore --no-index -q "$1"; }
if command -v git >/dev/null 2>&1 && git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
	for f in deploy/certs-next/server.key collector-rtr-1/key-k2 certs-next/server.key \
		deploy/collector-rtr-1/key-k2 deploy/certs/pins.txt deploy/certs-api/server.crt \
		some/dir/token.secret deploy/other.key; do
		check ".gitignore ignores $f" ign "$f"
	done
	for f in deploy/compose.yaml deploy/gen-certs.sh deploy/tests/test_scripts.sh .gitignore; do
		check ".gitignore does not ignore $f" sh -c '! git -C "$1" check-ignore --no-index -q "$2"' _ "$REPO" "$f"
	done
	check "no tracked file is ignored" test -z "$(git -C "$REPO" ls-files | git -C "$REPO" check-ignore --no-index --stdin)"
fi

# ---- healthcheck.py (argument dispatch; the live TLS probe was run by hand against real servers)
H="$DEPLOY/healthcheck.py"
python3 -I "$H" http 1 /healthz >/dev/null 2>&1
check "healthcheck: closed port is unhealthy (1)" test $? -eq 1
python3 -I "$H" proc definitely-not-a-process-name >/dev/null 2>&1
check "healthcheck: proc mismatch is unhealthy (1)" test $? -eq 1
python3 -I "$H" fresh "$T/no-such-heartbeat" >/dev/null 2>&1
check "healthcheck: missing heartbeat is unhealthy (1)" test $? -eq 1
: >"$T/heartbeat"
python3 -I "$H" fresh "$T/heartbeat" >/dev/null 2>&1
check "healthcheck: fresh heartbeat is healthy (0)" test $? -eq 0
python3 -I "$H" bogus >/dev/null 2>&1
check "healthcheck: bad usage is 2" test $? -eq 2

check "no real container tool was invoked" test ! -e "$T/state/real-tool.log"
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" = 0 ]
