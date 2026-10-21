# Shared checks for the root-run Vigie scripts (sourced, not executed). POSIX sh / busybox ash.
#
# /tmp is world-writable, so everything the scripts touch there is verified first: no symlinks,
# owned by the trusted uid (root), and directories not writable by group/other.
#
# The VIGIE_* overrides below (and the path/command overrides in the scripts that source this)
# exist for the unprivileged test suite and are honoured ONLY when VIGIE_TEST=1. Production
# (cron, procd) never sets it, so an environment cannot redirect what root touches.
#
#   VIGIE_TRUSTED_UID        uid that must own directories and the drop-in   (default 0)
#   VIGIE_OWNER              user:group given to directories we create       (default root:vigie)
#   VIGIE_LOG_ALLOWED_UIDS   uids allowed to own the log file                (default: 0 and the
#                            dnsmasq/nobody uids, because dnsmasq may chown its log to its run user)

vtest() { [ "${VIGIE_TEST:-}" = 1 ]; }

if vtest; then
	VIGIE_TRUSTED_UID="${VIGIE_TRUSTED_UID:-0}"
	VIGIE_OWNER="${VIGIE_OWNER:-root:vigie}"
else
	PATH=/usr/sbin:/usr/bin:/sbin:/bin
	VIGIE_TRUSTED_UID=0
	VIGIE_OWNER=root:vigie
	VIGIE_LOG_ALLOWED_UIDS=
fi

if [ -z "${VIGIE_LOG_ALLOWED_UIDS:-}" ]; then
	VIGIE_LOG_ALLOWED_UIDS="$VIGIE_TRUSTED_UID"
	for _u in dnsmasq nobody; do
		_id=$(id -u "$_u" 2>/dev/null) && VIGIE_LOG_ALLOWED_UIDS="$VIGIE_LOG_ALLOWED_UIDS $_id"
	done
fi

# Fail closed and loud: stderr for the operator, syslog for the router's log.
refuse() {
	echo "vigie: refusing: $*" >&2
	logger -t vigie -p daemon.crit "refusing: $*" 2>/dev/null || true
	exit 70
}

# require_dir DIR: an existing real directory, owned by the trusted uid, not group/other writable.
require_dir() {
	[ -L "$1" ] && refuse "$1 is a symlink"
	[ -d "$1" ] || refuse "$1 is not a directory"
	[ "$(stat -c %u "$1")" = "$VIGIE_TRUSTED_UID" ] || refuse "$1 is not owned by uid $VIGIE_TRUSTED_UID"
	_m=$(stat -c %a "$1")
	_m=${_m#"${_m%???}"}
	case "${_m#?}" in
	*[2367]*) refuse "$1 is group/other writable (mode $_m)" ;;
	esac
}

# ensure_dir DIR MODE: create DIR privately; owner and mode are set ONLY on a directory this very
# mkdir created (no -p, so it fails on any existing name, symlinks included). A directory that
# already exists, or that someone else created between our check and our mkdir, is never
# chown'ed or chmod'ed by path: it must already pass require_dir, or we refuse.
ensure_dir() {
	if (umask 077 && mkdir "$1") 2>/dev/null; then
		chown "$VIGIE_OWNER" "$1" && chmod "$2" "$1" || refuse "cannot set owner/mode on $1"
	fi
	require_dir "$1"
}

# require_file FILE "UIDS": if FILE exists it is a regular file, not a symlink, owned by one of UIDS.
require_file() {
	[ -L "$1" ] && refuse "$1 is a symlink"
	[ -e "$1" ] || return 0
	[ -f "$1" ] || refuse "$1 is not a regular file"
	_o=$(stat -c %u "$1")
	for _a in $2; do
		[ "$_o" = "$_a" ] && return 0
	done
	refuse "$1 is owned by uid $_o (allowed: $2)"
}
