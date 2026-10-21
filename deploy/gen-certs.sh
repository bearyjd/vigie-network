#!/bin/sh
# Generate a self-signed server certificate and print its SPKI SHA-256 pin. Ingest (collector ->
# server) and the API (control app -> server) have SEPARATE certificates and keys, so a compromised
# ingest never holds the API's key: run this once per role.
#
#   VIGIE_CERT_SAN="DNS:vigie.lan,IP:192.168.1.10" ./gen-certs.sh [--role ingest|api] [--force] [--out DIR] [--create-secrets]
#
#   VIGIE_CERT_SAN    REQUIRED, comma-separated subjectAltName entries: DNS:name or IP:address.
#                     The client connects to a name/address in this list.
#   VIGIE_CERT_DAYS   validity in days (default 825)
#   --role ROLE       ingest (default; secrets vigie_tls_cert/vigie_tls_key, out dir certs) or
#                     api (secrets vigie_api_tls_cert/vigie_api_tls_key, out dir certs-api)
#   --out DIR         output directory (default: certs / certs-api next to this script, NOT the
#                     current directory), created 0700. An existing directory is left as it is.
#   --force           overwrite existing server.key / server.crt (otherwise refuse)
#   --create-secrets  also create the role's podman secrets
#                     (PODMAN overrides the command, e.g. PODMAN="distrobox-host-exec podman")
#
# ECDSA P-256. Everything is created under umask 077; the key is 0600 and never printed.
set -eu
umask 077

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OUT=
ROLE=ingest
FORCE=0
SECRETS=0
while [ $# -gt 0 ]; do
	case $1 in
	--force) FORCE=1 ;;
	--create-secrets) SECRETS=1 ;;
	--role)
		[ $# -ge 2 ] || {
			echo "gen-certs: --role needs ingest or api" >&2
			exit 64
		}
		ROLE=$2
		shift
		;;
	--out)
		[ $# -ge 2 ] || {
			echo "gen-certs: --out needs a directory" >&2
			exit 64
		}
		OUT=$2
		shift
		;;
	-h | --help)
		sed -n '2,21p' "$0"
		exit 0
		;;
	*)
		echo "gen-certs: unknown argument: $1" >&2
		exit 64
		;;
	esac
	shift
done

case $ROLE in
ingest)
	SECRET_PREFIX=vigie_tls
	OUT=${OUT:-$HERE/certs}
	;;
api)
	SECRET_PREFIX=vigie_api_tls
	OUT=${OUT:-$HERE/certs-api}
	;;
*)
	echo "gen-certs: --role must be ingest or api (got '$ROLE')" >&2
	exit 64
	;;
esac
SAN=${VIGIE_CERT_SAN:-}
DAYS=${VIGIE_CERT_DAYS:-825}
[ -n "$SAN" ] || {
	echo "gen-certs: set VIGIE_CERT_SAN, e.g. VIGIE_CERT_SAN='DNS:vigie.lan,IP:192.168.1.10'" >&2
	exit 64
}
case $DAYS in '' | *[!0-9]*)
	echo "gen-certs: VIGIE_CERT_DAYS must be a number" >&2
	exit 64
	;;
esac
# Every entry must be DNS:<host chars> or IP:<address chars>; nothing else reaches openssl.
case $SAN in
*[!A-Za-z0-9.:,_-]*)
	echo "gen-certs: VIGIE_CERT_SAN may only contain letters, digits and . : , _ -" >&2
	exit 64
	;;
esac
OLD_IFS=$IFS
IFS=,
for entry in $SAN; do
	case $entry in
	DNS:?* | IP:?*) ;;
	*)
		IFS=$OLD_IFS
		echo "gen-certs: bad SAN entry '$entry' (use DNS:name or IP:address)" >&2
		exit 64
		;;
	esac
done
IFS=$OLD_IFS
CN=${SAN%%,*}
CN=${CN#*:}

KEY=$OUT/server.key
CRT=$OUT/server.crt
if [ "$FORCE" != 1 ] && { [ -e "$KEY" ] || [ -e "$CRT" ]; }; then
	echo "gen-certs: $KEY or $CRT exists; refusing to overwrite (use --force)" >&2
	exit 73
fi

# Only a directory this script creates is chmodded; an existing one (maybe shared) is left alone.
if [ ! -d "$OUT" ]; then
	mkdir -p "$OUT"
	chmod 0700 "$OUT"
elif [ -n "$(find "$OUT" -maxdepth 0 -perm /077)" ]; then
	echo "gen-certs: warning: existing $OUT is accessible to group/others; the key inside is 0600" >&2
fi

# Write to temporary names inside the 0700 directory, then rename: a failure never leaves a
# half-written key in place of a good one.
TMP_KEY=$OUT/.server.key.$$
TMP_CRT=$OUT/.server.crt.$$
trap 'rm -f "$TMP_KEY" "$TMP_CRT"' EXIT INT TERM
if ! OPENSSL_OUT=$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$TMP_KEY" -out "$TMP_CRT" -days "$DAYS" \
	-subj "/CN=$CN" -addext "subjectAltName=$SAN" \
	-addext "basicConstraints=critical,CA:FALSE" \
	-addext "keyUsage=critical,digitalSignature" \
	-addext "extendedKeyUsage=serverAuth" 2>&1); then
	echo "gen-certs: openssl failed:" >&2
	printf '%s\n' "$OPENSSL_OUT" >&2
	exit 70
fi
chmod 0600 "$TMP_KEY"
chmod 0644 "$TMP_CRT"
mv -f "$TMP_KEY" "$KEY"
mv -f "$TMP_CRT" "$CRT"

spki_digest() {
	openssl x509 -in "$CRT" -pubkey -noout | openssl pkey -pubin -outform der |
		openssl dgst -sha256 -binary
}
PIN_B64=$(spki_digest | openssl enc -base64)
PIN_HEX=$(spki_digest | od -An -tx1 | tr -d ' \n')
printf 'pin_sha256_base64=%s\npin_sha256_hex=%s\n' "$PIN_B64" "$PIN_HEX" >"$OUT/pins.txt"

if [ "$SECRETS" = 1 ]; then
	PODMAN=${PODMAN:-podman}
	# shellcheck disable=SC2086 # PODMAN may be a multi-word command
	if [ "$FORCE" = 1 ]; then
		$PODMAN secret rm "${SECRET_PREFIX}_cert" "${SECRET_PREFIX}_key" >/dev/null 2>&1 || true
	fi
	# shellcheck disable=SC2086
	$PODMAN secret create "${SECRET_PREFIX}_cert" "$CRT" >/dev/null
	# shellcheck disable=SC2086
	$PODMAN secret create "${SECRET_PREFIX}_key" "$KEY" >/dev/null
	echo "created podman secrets ${SECRET_PREFIX}_cert and ${SECRET_PREFIX}_key"
fi

cat <<EOF
certificate: $CRT
private key: $KEY (0600; never copy it off this host)
valid for $DAYS days; SAN: $SAN

SPKI SHA-256 pin of this certificate (clients pin the public key, not the cert):
  hex    (collector.conf pin1= / pin2=, 64 lowercase hex): $PIN_HEX
  base64 (other tooling):                                  $PIN_B64
Both are also in $OUT/pins.txt.

Role: $ROLE. Only the ingest certificate is pinned by the collector, which takes TWO different pins
(pin1 and pin2 must differ). Before the first rotation, generate the NEXT certificate with
--out <other dir>, publish its pin as pin2 on the router first, then switch the server to it
(docs/deploy.md). The API certificate is trusted by the control app (--cacert or its pin).
EOF
