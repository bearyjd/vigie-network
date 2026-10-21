#!/bin/sh
# Create a collector: generate its 256-bit HMAC key, store it as the podman secret
# collector_key_<key_id>, register the collector id + key id in ingest's database, and write the
# key to a 0600 file to copy to the router with `scp -O`.
#
#   ./provision-collector.sh [--force] [--no-register] [--out DIR] COLLECTOR_ID [KEY_ID]
#
#   COLLECTOR_ID  [A-Za-z0-9_.-]{1,64}, e.g. rtr-1
#   KEY_ID        same alphabet, default k1. The secret name is collector_key_<KEY_ID>.
#   --out DIR     where the router-side key file goes (default: collector-<COLLECTOR_ID> next to
#                 this script, 0700; an existing directory is not chmodded)
#   --force       replace an existing secret / key file of the same name. Not atomic (podman
#                 cannot swap a secret in place): the new key is first stored under a temporary
#                 secret name, then the old secret is removed and the final one created. For a
#                 real rotation prefer a NEW KEY_ID (k2): old and new coexist (docs/deploy.md).
#                 A REVOKED collector additionally needs `admin provision --force` by hand.
#                 WARNING: registering switches the collector's key_id in ingest's database
#                 immediately; batches signed with the old key get 401 until the router has the new
#                 key AND ingest was recreated (it mounts secrets at start).
#   --no-register create the key and secret only; print the registration command instead
#
#   PODMAN             podman command (default podman; e.g. "distrobox-host-exec podman")
#   VIGIE_ADMIN_CMD    command that runs `python -m vigie_ingest.admin ARGS...` (split on spaces,
#                      so no spaces inside one argument; default:
#                      podman-compose -f <compose.yaml> run --rm --no-deps ingest python -m vigie_ingest.admin)
#   VIGIE_PIN_HEX1/2   the two SPKI pins (hex) to print in the router config (default: read
#                      certs/pins.txt next to this script, else placeholders)
#   VIGIE_SERVER_URL   URL printed in the router config (default https://<set-me>:8443/v1/batch)
#
# ORDER MATTERS: ingest refuses to start while a non-revoked collector has no readable key file.
# So the secret must exist and be listed under ingest's `secrets:` in compose.yaml BEFORE the
# collector row is registered and ingest is (re)started. This script checks compose.yaml for the
# secret and, when it is not listed yet, prints the lines to add and does not register.
#
# The key is held only in this shell's memory and passed on stdin (printf is a shell builtin, so
# it is never in a process argument list). It is never printed.
set -eu
umask 077

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
FORCE=0
REGISTER=1
OUT=
while [ $# -gt 0 ]; do
	case $1 in
	--force) FORCE=1 ;;
	--no-register) REGISTER=0 ;;
	--out)
		[ $# -ge 2 ] || {
			echo "provision-collector: --out needs a directory" >&2
			exit 64
		}
		OUT=$2
		shift
		;;
	-h | --help)
		sed -n '2,25p' "$0"
		exit 0
		;;
	--) shift; break ;;
	-*)
		echo "provision-collector: unknown option: $1" >&2
		exit 64
		;;
	*) break ;;
	esac
	shift
done
[ $# -ge 1 ] && [ $# -le 2 ] || {
	echo "usage: provision-collector.sh [--force] [--no-register] [--out DIR] COLLECTOR_ID [KEY_ID]" >&2
	exit 64
}
COLLECTOR_ID=$1
KEY_ID=${2:-k1}
for v in "$COLLECTOR_ID" "$KEY_ID"; do
	case $v in
	'' | *[!A-Za-z0-9_.-]*)
		echo "provision-collector: ids may only contain A-Z a-z 0-9 _ . - (got '$v')" >&2
		exit 64
		;;
	esac
	[ "${#v}" -le 64 ] || {
		echo "provision-collector: ids are at most 64 characters" >&2
		exit 64
	}
done

PODMAN=${PODMAN:-podman}
SECRET=collector_key_$KEY_ID
OUT=${OUT:-$HERE/collector-$COLLECTOR_ID}
KEYFILE=$OUT/key-$KEY_ID
COMPOSE=${VIGIE_COMPOSE_FILE:-$HERE/compose.yaml}

# shellcheck disable=SC2086 # PODMAN may be a multi-word command
secret_exists() { $PODMAN secret inspect "${1:-$SECRET}" >/dev/null 2>&1; }

# Exact match, not a substring: the secret must be listed under a `- source: NAME` line (whole
# line) AND defined as a top-level `  NAME:` key in compose.yaml.
compose_lists_secret() {
	[ -r "$COMPOSE" ] || return 1
	awk -v s="$SECRET" '
		$1 == "-" && $2 == "source:" && $3 == s && NF == 3 { listed = 1 }
		$0 == "  " s ":" { defined = 1 }
		END { exit !(listed && defined) }' "$COMPOSE"
}

# shellcheck disable=SC2086 # VIGIE_ADMIN_CMD is a multi-word command
run_admin() {
	if [ -n "${VIGIE_ADMIN_CMD:-}" ]; then
		$VIGIE_ADMIN_CMD "$@"
	else
		podman-compose -f "$COMPOSE" run --rm --no-deps ingest python -m vigie_ingest.admin "$@"
	fi
}

if [ "$FORCE" != 1 ]; then
	if secret_exists; then
		echo "provision-collector: podman secret $SECRET exists; use --force to rotate it" >&2
		exit 73
	fi
	if [ -e "$KEYFILE" ]; then
		echo "provision-collector: $KEYFILE exists; use --force to replace it" >&2
		exit 73
	fi
fi

if [ ! -d "$OUT" ]; then # only a directory created here is chmodded
	mkdir -p "$OUT"
	chmod 0700 "$OUT"
fi

KEY=$(openssl rand -hex 32)
case $KEY in
'' | *[!0-9a-f]*)
	echo "provision-collector: openssl rand failed" >&2
	exit 70
	;;
esac
[ "${#KEY}" = 64 ] || {
	echo "provision-collector: unexpected key length" >&2
	exit 70
}

# Order: the secret first (it is what can fail), the router-side key file only once the secret
# holds the new key, so a failure never leaves a key file that matches no secret.
TMP_SECRET=$SECRET.tmp$$
# shellcheck disable=SC2086
printf '%s\n' "$KEY" | $PODMAN secret create "$TMP_SECRET" - >/dev/null || {
	echo "provision-collector: podman secret create failed; nothing was changed" >&2
	exit 1
}
if secret_exists; then
	# shellcheck disable=SC2086
	$PODMAN secret rm "$SECRET" >/dev/null || {
		# shellcheck disable=SC2086
		$PODMAN secret rm "$TMP_SECRET" >/dev/null 2>&1 || true
		echo "provision-collector: could not remove the old secret $SECRET; nothing was changed" >&2
		exit 1
	}
fi
# shellcheck disable=SC2086
printf '%s\n' "$KEY" | $PODMAN secret create "$SECRET" - >/dev/null || {
	echo "provision-collector: creating $SECRET failed; the new key is kept in secret $TMP_SECRET" >&2
	exit 1
}
# shellcheck disable=SC2086
$PODMAN secret rm "$TMP_SECRET" >/dev/null 2>&1 || true
printf '%s\n' "$KEY" >"$KEYFILE.tmp"
chmod 0600 "$KEYFILE.tmp"
mv -f "$KEYFILE.tmp" "$KEYFILE"
KEY=
echo "created podman secret $SECRET and $KEYFILE (0600)"

if [ "$REGISTER" = 1 ] && ! compose_lists_secret; then
	REGISTER=0
	echo "NOT registering yet: $COMPOSE does not list $SECRET under ingest's secrets (and top-level secrets)." >&2
fi
if [ "$REGISTER" = 1 ]; then
	if run_admin provision "$COLLECTOR_ID" "$KEY_ID"; then
		echo "registered collector $COLLECTOR_ID with key id $KEY_ID"
		echo "WARNING: ingest now expects key id $KEY_ID for $COLLECTOR_ID. Batches signed with any other" >&2
		echo "  key get 401 until the router has $KEYFILE and ingest was recreated to mount the secret:" >&2
		echo "  podman-compose up -d --force-recreate ingest" >&2
	else
		echo "provision-collector: registration failed (see the message above). The secret and $KEYFILE" >&2
		echo "  exist and ingest's collector table is unchanged. A REVOKED collector needs" >&2
		echo "  'admin provision --force $COLLECTOR_ID $KEY_ID' run by hand." >&2
		exit 1
	fi
else
	cat <<EOF

Do these in order (ingest refuses to start if a registered collector's key file is missing):
  1. In $COMPOSE add under services.ingest.secrets:
         - source: $SECRET
           uid: "10001"
           gid: "10001"
           mode: "0400"
     and under the top-level secrets:
         $SECRET:
           external: true
  2. Register the collector (this switches its key id immediately; the old key stops working):
         podman-compose -f '$COMPOSE' run --rm --no-deps ingest python -m vigie_ingest.admin provision '$COLLECTOR_ID' '$KEY_ID'
  3. Recreate ingest so it mounts the new secret:  podman-compose up -d --force-recreate ingest
EOF
fi

PIN1=${VIGIE_PIN_HEX1:-}
PIN2=${VIGIE_PIN_HEX2:-}
if [ -z "$PIN1" ] && [ -r "$HERE/certs/pins.txt" ]; then
	PIN1=$(sed -n 's/^pin_sha256_hex=//p' "$HERE/certs/pins.txt")
fi
PIN1=${PIN1:-<pin1: 64 lowercase hex from gen-certs.sh>}
PIN2=${PIN2:-<pin2: pin of the NEXT certificate, must differ from pin1>}
URL=${VIGIE_SERVER_URL:-https://<server-address>:8443/v1/batch}

cat <<EOF

--- Router side (GL-XE3000) ---
Copy the key with scp -O (legacy protocol; OpenWrt has no sftp-server) and delete the local file
once it is installed and verified:
  scp -O $KEYFILE root@<router>:/etc/vigie/key
On the router (as root; the vigie user must exist first, see README.md):
  chown vigie:vigie /etc/vigie/key && chmod 0600 /etc/vigie/key

/etc/vigie/collector.conf (mode 0644, no secrets):
  server_url=$URL
  collector_id=$COLLECTOR_ID
  key_id=$KEY_ID
  pin1=$PIN1
  pin2=$PIN2
EOF
