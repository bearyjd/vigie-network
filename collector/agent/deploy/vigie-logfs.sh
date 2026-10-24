#!/bin/sh
# Fixed private log tmpfs; never cover existing contents, adopt a foreign mount or fall back.
set -u
. "$(dirname "$0")/vigie-lib.sh"
case "${1:-}" in
check)
	[ "$#" -eq 1 ] || exit 64
	require_logfs
	;;
prepare)
	[ "$#" -eq 1 ] || exit 64
	# Root-owned lock geometry; an FD lock has no crash-stale directory state.
	ensure_dir "$LOGFS_LOCK_DIR" 0700
	[ "$(stat -c %a "$LOGFS_LOCK_DIR")" = 700 ] || refuse "unsafe logfs lock directory mode"
	LOCK="$LOGFS_LOCK_DIR/prepare.lock"
	if [ ! -e "$LOCK" ] && [ ! -L "$LOCK" ]; then
		(umask 077 && set -C && : >"$LOCK") 2>/dev/null || true
	fi
	require_file "$LOCK" "$VIGIE_TRUSTED_UID"
	[ -f "$LOCK" ] && [ "$(stat -c %a:%h "$LOCK")" = 600:1 ] || refuse "unsafe logfs lock file"
	exec 9<>"$LOCK" || refuse "cannot open logfs lock"
	flock -n 9 || refuse "logfs preparation already running"
	if logfs_mount_present; then
		require_logfs
		exit 0
	else
		rc=$?
		[ "$rc" -eq 1 ] || refuse "cannot inspect mount table"
	fi
	_gid=$(logfs_gid) || refuse "dedicated vigie group missing"
	case "$_gid" in '' | *[!0-9]*) refuse "invalid vigie group" ;; esac
	ensure_dir "$LOGFS_DIR" 0751
	[ "$(stat -c %u:%g:%a "$LOGFS_DIR")" = "$VIGIE_TRUSTED_UID:$_gid:751" ] || refuse "unsafe backing directory"
	for entry in "$LOGFS_DIR"/* "$LOGFS_DIR"/.[!.]* "$LOGFS_DIR"/..?*; do
		[ ! -e "$entry" ] && [ ! -L "$entry" ] || refuse "refusing to cover nonempty log directory"
	done
	"$LOGFS_MOUNT_BIN" -t tmpfs -o "size=20971520,mode=0751,uid=$VIGIE_TRUSTED_UID,gid=$_gid,nosuid,nodev,noexec" vigie-logfs "$LOGFS_DIR" || exit $?
	require_logfs
	;;
*) echo "usage: $0 prepare|check" >&2; exit 64 ;;
esac
