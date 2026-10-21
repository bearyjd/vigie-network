#!/bin/sh
# Create a collector: generate its 256-bit HMAC key, store it as the podman secret
# collector_key_<key_id>, register the collector id + key id in ingest's database, and write the
# key to a 0600 file to copy to the router with `scp -O`.
#
#   ./provision-collector.sh [--force] [--no-register] [--out DIR] COLLECTOR_ID [KEY_ID]
#
#   COLLECTOR_ID  [A-Za-z0-9_.-]{1,64}, e.g. rtr-1
#   KEY_ID        same alphabet, default k1. The secret name is collector_key_<KEY_ID>.
#   --out DIR     where the router-side key file goes (default ./collector-<COLLECTOR_ID>, 0700)
#   --force       replace an existing secret / key file of the same name (key rotation).
#                 A REVOKED collector additionally needs `admin provision --force` by hand.
#   --no-register create the key and secret only; print the registration command instead
#
#   PODMAN             podman command (default podman; e.g. "distrobox-host-exec podman")
#   VIGIE_ADMIN_CMD    command that runs `python -m vigie_ingest.admin ARGS...` (default:
#                      podman-compose -f compose.yaml run --rm --no-deps ingest python -m vigie_ingest.admin)
#   VIGIE_PIN_HEX1/2   the two SPKI pins (hex) to print in the router config (default: read
#                      ./certs/pins.txt, else placeholders)
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
OUT=${OUT:-./collector-$COLLECTOR_ID}
KEYFILE=$OUT/key-$KEY_ID
COMPOSE=${VIGIE_COMPOSE_FILE:-$HERE/compose.yaml}

# shellcheck disable=SC2086 # PODMAN may be a multi-word command
secret_exists() { $PODMAN secret inspect "$SECRET" >/dev/null 2>&1; }

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

mkdir -p "$OUT"
chmod 0700 "$OUT"

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

# Router-side key file first (0600, via umask), then the secret, both from stdin/builtin printf.
printf '%s\n' "$KEY" >"$KEYFILE.tmp"
chmod 0600 "$KEYFILE.tmp"
mv -f "$KEYFILE.tmp" "$KEYFILE"

# shellcheck disable=SC2086
if secret_exists; then
	# shellcheck disable=SC2086
	$PODMAN secret rm "$SECRET" >/dev/null
fi
# shellcheck disable=SC2086
printf '%s\n' "$KEY" | $PODMAN secret create "$SECRET" - >/dev/null
KEY=
echo "created podman secret $SECRET and $KEYFILE (0600)"

ADMIN=${VIGIE_ADMIN_CMD:-podman-compose -f $COMPOSE run --rm --no-deps ingest python -m vigie_ingest.admin}

if [ "$REGISTER" = 1 ] && ! grep -q "source: $SECRET\$" "$COMPOSE" 2>/dev/null; then
	REGISTER=0
	echo "NOT registering yet: $COMPOSE does not list $SECRET under ingest's secrets." >&2
fi
if [ "$REGISTER" = 1 ]; then
	# shellcheck disable=SC2086 # ADMIN is a multi-word command
	if $ADMIN provision "$COLLECTOR_ID" "$KEY_ID"; then
		echo "registered collector $COLLECTOR_ID with key id $KEY_ID"
	else
		echo "provision-collector: registration failed; the secret exists but ingest has no row" >&2
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
  2. Register the collector:
         $ADMIN provision $COLLECTOR_ID $KEY_ID
  3. Recreate ingest so it mounts the new secret:  podman-compose up -d --force-recreate ingest
EOF
fi

PIN1=${VIGIE_PIN_HEX1:-}
PIN2=${VIGIE_PIN_HEX2:-}
if [ -z "$PIN1" ] && [ -r ./certs/pins.txt ]; then
	PIN1=$(sed -n 's/^pin_sha256_hex=//p' ./certs/pins.txt)
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
