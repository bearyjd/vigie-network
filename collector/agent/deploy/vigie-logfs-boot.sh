#!/bin/sh
# Pre-DNS boot preparation only: no reload/restart, no successful-apply confirmation.
set -u
[ "$#" -eq 0 ] || exit 64
. "$(dirname "$0")/vigie-lib.sh"
HELPERS=/usr/libexec/vigie
if vtest; then HELPERS=$(dirname "$0"); fi
"$HELPERS/vigie-logfs.sh" prepare || exit $?
"$HELPERS/vigie-dnsmasq-dropin.sh" prepare
