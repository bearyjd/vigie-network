#!/bin/sh
# Prepare only the new collector failure-counter namespace. Never touch the legacy
# /var/run/vigie-collector directory or recursively remove user-controlled contents.
set -u
. "$(dirname "$0")/vigie-lib.sh"
[ "$#" -eq 0 ] || refuse "state preparation takes no arguments"
STATE_ROOT=/var/run/vigie-collector-root
if vtest; then
	STATE_ROOT="${VIGIE_STATE_ROOT:-$STATE_ROOT}"
fi
if ! UID_N=$(id -u vigie) || ! GID_N=$(id -g vigie); then
	refuse "dedicated vigie account missing"
fi
case "$UID_N:$GID_N" in *[!0-9:]*) refuse "invalid dedicated uid/gid" ;; esac
if ! [ "$UID_N" -ge 1000 ] || ! [ "$UID_N" -le 4294967294 ] || [ "$UID_N" -eq 65534 ] ||
   ! [ "$GID_N" -ge 1000 ] || ! [ "$GID_N" -le 4294967294 ] || [ "$GID_N" -eq 65534 ]; then
	refuse "unsafe dedicated uid/gid"
fi

# ensure_dir only sets attributes when this invocation created the directory; pre-existing
# paths must already be trusted. The root-owned parent prevents the child being swapped.
ensure_dir "$STATE_ROOT" 0711
[ "$(stat -c %a "$STATE_ROOT")" = 711 ] || refuse "$STATE_ROOT must have mode 0711"
STATE="$STATE_ROOT/state"
if (umask 077 && mkdir "$STATE") 2>/dev/null; then
	if ! chown "$UID_N:$GID_N" "$STATE" || ! chmod 0700 "$STATE"; then
		refuse "cannot initialize collector state"
	fi
fi
[ ! -L "$STATE" ] && [ -d "$STATE" ] || refuse "$STATE is not a real directory"
[ "$(stat -c %u:%g:%a "$STATE")" = "$UID_N:$GID_N:700" ] || refuse "$STATE has unsafe owner/group/mode"
# Unlink exactly one known leaf. rm -f never follows a leaf symlink and refuses a directory;
# unknown files and any pre-existing legacy state remain untouched.
rm -f "$STATE/fails" || refuse "cannot reset the known failure leaf"
