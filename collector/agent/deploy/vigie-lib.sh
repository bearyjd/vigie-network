# Shared checks for the root-run Vigie scripts (sourced, not executed). POSIX sh / busybox ash.
#
# /tmp is world-writable, so everything the scripts touch there is verified first: no symlinks,
# owned by the trusted uid (root), and directories not writable by group/other.
#
# The VIGIE_* overrides below (and the path/command overrides in the scripts that source this)
# exist for the unprivileged test suite and are honoured ONLY when VIGIE_TEST=1. Production
# (cron, procd) never sets it, so an environment cannot redirect what root touches. As a second
# guard, VIGIE_TEST=1 is itself refused for euid 0 on a machine that has the collector's init
# script, unless the harness also sets VIGIE_TEST_FORCE_ROOT=1.
#
#   VIGIE_TRUSTED_UID        uid that must own directories and the drop-in   (default 0)
#   VIGIE_OWNER              user:group given to directories we create       (default root:vigie)
#   VIGIE_PROC_DIR, VIGIE_RUN_DIR, VIGIE_INITD_FILE, VIGIE_TMP_ROOT   paths replacing /proc,
#                            /var/run/dnsmasq, /etc/init.d/vigie-collector and /tmp (tests only)
#
# Who may own the dnsmasq log: root (the trusted uid) and the uid the running dnsmasq has
# (resolve_dnsmasq_uid), nothing else; `nobody` is not implied.

# Fail closed and loud: stderr for the operator, syslog for the router's log.
refuse() {
	echo "vigie: refusing: $*" >&2
	logger -t vigie -p daemon.crit "refusing: $*" 2>/dev/null || true
	exit 70
}

vtest() {
	[ "${VIGIE_TEST:-}" = 1 ] || return 1
	if [ "${VIGIE_TEST_FORCE_ROOT:-}" != 1 ] && [ "$(id -u)" = 0 ] &&
		[ -e "${VIGIE_INITD_FILE:-/etc/init.d/vigie-collector}" ]; then
		refuse "VIGIE_TEST=1 as root on a machine with the collector installed (set VIGIE_TEST_FORCE_ROOT=1 in a test harness)"
	fi
	return 0
}

PROC_DIR=/proc
RUN_DIR=/var/run/dnsmasq
TMP_ROOT=/tmp
if vtest; then
	VIGIE_TRUSTED_UID="${VIGIE_TRUSTED_UID:-0}"
	VIGIE_OWNER="${VIGIE_OWNER:-root:vigie}"
	PROC_DIR="${VIGIE_PROC_DIR:-$PROC_DIR}"
	RUN_DIR="${VIGIE_RUN_DIR:-$RUN_DIR}"
	TMP_ROOT="${VIGIE_TMP_ROOT:-$TMP_ROOT}"
else
	PATH=/usr/sbin:/usr/bin:/sbin:/bin
	VIGIE_TRUSTED_UID=0
	VIGIE_OWNER=root:vigie
fi

# Everything below lives under the world-writable TMP_ROOT: without the sticky bit anyone could
# rename the verified directories away and swap them.
[ -k "$TMP_ROOT" ] || refuse "$TMP_ROOT is not sticky (mode lacks +t): other users could rename what was verified"

# dnsmasq pids from one source, one per line (stdout empty when the source has none).
_pids_ubus() { ubus call service list '{"name":"dnsmasq"}' 2>/dev/null | grep -o '"pid": *[0-9][0-9]*' | grep -o '[0-9][0-9]*$'; }
_pids_files() {
	for _f in "$RUN_DIR"/dnsmasq.*.pid; do
		[ -f "$_f" ] && [ ! -L "$_f" ] && { read -r _p <"$_f" && echo "$_p"; }
	done
}
_pids_pidof() { pidof dnsmasq 2>/dev/null | tr ' ' '\n'; }

# dnsmasq_pid: print the pid of the one running dnsmasq. Preference: the procd instance
# (ubus), then pidfiles, then pidof. The first source that finds any decides; more than one
# distinct pid there is ambiguous and fails (exit 1, reason on stderr).
dnsmasq_pid() {
	for _src in _pids_ubus _pids_files _pids_pidof; do
		_found=$($_src | grep -E '^[0-9]+$' | sort -u)
		[ -n "$_found" ] || continue
		if [ "$(printf '%s\n' "$_found" | wc -l)" -ne 1 ]; then
			echo "several dnsmasq pids from $_src" >&2
			return 1
		fi
		printf '%s\n' "$_found"
		return 0
	done
	echo "no dnsmasq pid found" >&2
	return 1
}

# resolve_dnsmasq_uid: sets DNSMASQ_UID and DNSMASQ_PID (empty when unresolved) and DNSMASQ_WHY. The real and
# effective uid in /proc/<pid>/status must agree; anything else is treated as unresolved.
resolve_dnsmasq_uid() {
	DNSMASQ_UID=
	DNSMASQ_PID=
	DNSMASQ_WHY=
	_pid=$(dnsmasq_pid 2>&1) || { DNSMASQ_WHY="$_pid"; return 1; }
	_line=$(grep '^Uid:' "$PROC_DIR/$_pid/status" 2>/dev/null) || { DNSMASQ_WHY="no Uid line for pid $_pid"; return 1; }
	set -- $_line
	case "${2:-}${3:-}" in
	'' | *[!0-9]*) DNSMASQ_WHY="unparseable Uid line for pid $_pid"; return 1 ;;
	esac
	[ "$2" = "$3" ] || { DNSMASQ_WHY="dnsmasq pid $_pid: real uid $2 differs from effective uid $3"; return 1; }
	DNSMASQ_UID=$2
	DNSMASQ_PID=$_pid
}

# log_allowed_uids: root (the trusted uid) plus the resolved dnsmasq uid, if any.
log_allowed_uids() {
	resolve_dnsmasq_uid || true
	echo "$VIGIE_TRUSTED_UID $DNSMASQ_UID"
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
