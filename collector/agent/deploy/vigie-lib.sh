# Shared checks for the root-run Vigie scripts (sourced, not executed). POSIX sh / busybox ash.
#
# /tmp is world-writable, so everything the scripts touch there is verified first: no symlinks,
# owned by the trusted uid (root), and directories not writable by group/other. The env hooks
# exist for tests (they run unprivileged); cron and procd start these scripts with a clean env.
#
#   VIGIE_TRUSTED_UID        uid that must own directories and the drop-in   (default 0)
#   VIGIE_OWNER              user:group given to directories we create       (default root:vigie)
#   VIGIE_LOG_ALLOWED_UIDS   uids allowed to own the log file                (default: 0 and the
#                            dnsmasq/nobody uids, because dnsmasq may chown its log to its run user)

VIGIE_TRUSTED_UID="${VIGIE_TRUSTED_UID:-0}"
VIGIE_OWNER="${VIGIE_OWNER:-root:vigie}"

if [ -z "${VIGIE_LOG_ALLOWED_UIDS:-}" ]; then
	VIGIE_LOG_ALLOWED_UIDS="$VIGIE_TRUSTED_UID"
	for _u in dnsmasq nobody; do
		_id=$(id -u "$_u" 2>/dev/null) && VIGIE_LOG_ALLOWED_UIDS="$VIGIE_LOG_ALLOWED_UIDS $_id"
	done
fi

refuse() {
	echo "vigie: refusing: $*" >&2
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

# ensure_dir DIR MODE: create DIR privately if absent (mkdir fails on any existing name,
# including a symlink), then verify it, whoever made it.
ensure_dir() {
	if [ ! -e "$1" ] && [ ! -L "$1" ]; then
		(umask 077 && mkdir "$1") 2>/dev/null || true
		if [ -d "$1" ] && [ ! -L "$1" ]; then
			chown "$VIGIE_OWNER" "$1" && chmod "$2" "$1" || refuse "cannot set owner/mode on $1"
		fi
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
