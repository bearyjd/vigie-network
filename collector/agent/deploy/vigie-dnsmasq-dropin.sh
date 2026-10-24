#!/bin/sh
# Manage the Vigie dnsmasq drop-in. Runs as root (init script at start, cron every 5 min).
# /tmp/dnsmasq.d is tmpfs, so the drop-in must be recreated after every boot, and GL.iNet
# reloads may clear it. Reloads until the desired drop-in has a successful reload confirmation.
#
#   ensure   create/repair the drop-in and log file; reload if changed or unconfirmed
#   check    exit 0 confirmed, 1 missing/unconfirmed, 2 differs or unsafe config/marker;
#            directory/file trust failures exit 70 (no changes made)
#
# Runs as root inside world-writable /tmp, so every path is verified first (vigie-lib.sh): no
# symlinks, trusted owner, private directories. Any failed check exits 70 with a message.
#
# Log access model: /tmp/vigie is root:vigie 0751 (dnsmasq, running as another user, only needs
# to traverse it) and dnsmasq.log is 0640 root:vigie, created HERE before dnsmasq first opens it,
# so only root, dnsmasq (owner) and the `vigie` group (the collector) can read it. ASSUMPTION
# (from dnsmasq's source, NOT yet verified on the router): dnsmasq opens an existing log-facility
# file, keeping its group, and chowns it to its run user. Verify after the first start:
#   ls -ln /tmp/vigie /tmp/vigie/dnsmasq.log   # dir 0751 root:vigie; log -rw-r----- group=vigie gid
#   (restart dnsmasq, then)  logread | grep dnsmasq | tail     # no "cannot open log" errors
# and that new lines appear (tail -n1 /tmp/vigie/dnsmasq.log). If dnsmasq instead creates the
# file itself with its own group, the collector cannot read it and the layout must change.
#
# Not yet run on the router (P0 item 4 pending). Path/command overrides: VIGIE_TEST=1 only.
set -u

. "$(dirname "$0")/vigie-lib.sh"

DROPIN_DIR=/tmp/dnsmasq.d
LOG_DIR=/tmp/vigie
RELOAD_CMD="/etc/init.d/dnsmasq reload"
if vtest; then
	DROPIN_DIR="${VIGIE_DROPIN_DIR:-$DROPIN_DIR}"
	LOG_DIR="${VIGIE_LOG_DIR:-$LOG_DIR}"
	RELOAD_CMD="${VIGIE_RELOAD_CMD:-$RELOAD_CMD}"
fi
FILE="$DROPIN_DIR/vigie.conf"
LOG="$LOG_DIR/dnsmasq.log"
# Root-owned confirmation outside dnsmasq's conf-dir; never parsed as dnsmasq configuration.
# It confirms command success, not DNS traffic or effective daemon configuration.
# Absence is conservative across upgrade/crash: retry, even if the drop-in already matches.
APPLIED="$LOG_DIR/.dnsmasq-applied"

want() {
	printf 'log-queries=extra\nlog-dhcp\nlog-facility=%s/dnsmasq.log\n' "$LOG_DIR"
}

state() {
	[ -L "$FILE" ] && return 2
	[ -f "$FILE" ] || return 1
	[ "$(tr -d '\r' <"$FILE")" = "$(want)" ] || return 2
	return 0
}

applied_state() {
	[ -L "$APPLIED" ] && return 2
	[ -e "$APPLIED" ] || return 1
	[ -f "$APPLIED" ] &&
		[ "$(stat -c %u "$APPLIED")" = "$VIGIE_TRUSTED_UID" ] &&
		[ "$(stat -c %a "$APPLIED")" = 600 ] || return 2
	[ "$(cat "$APPLIED")" = "$(want)" ] || return 2
}

case "${1:-}" in
check|ensure|prepare) require_logfs ;;
esac

case "${1:-}" in
check)
	state || exit $?
	require_dir "$DROPIN_DIR"
	require_dir "$LOG_DIR"
	require_file "$FILE" "$VIGIE_TRUSTED_UID"
	applied_state
	exit $?
	;;
ensure|prepare)
	ensure_dir "$LOG_DIR" 0751
	ensure_dir "$DROPIN_DIR" 0755
	if [ ! -e "$LOG" ] && [ ! -L "$LOG" ]; then
		# noclobber = O_EXCL: never opens through a symlink planted in the meantime.
		(umask 077 && set -C && : >"$LOG") 2>/dev/null || true
		[ -f "$LOG" ] && [ ! -L "$LOG" ] && chown "$VIGIE_OWNER" "$LOG"
	fi
	require_file "$LOG" "$(log_allowed_uids)"
	[ -f "$LOG" ] || refuse "$LOG could not be created"
	chmod 0640 "$LOG" || exit 1
	require_file "$FILE" "$VIGIE_TRUSTED_UID"
	require_file "$APPLIED" "$VIGIE_TRUSTED_UID"
	if [ -e "$APPLIED" ] && [ "$(stat -c %a "$APPLIED")" != 600 ]; then
		refuse "$APPLIED must have mode 600"
	fi
	if [ "$1" = prepare ] && state; then
		exit 0
	fi
	if state && applied_state; then
		exit 0
	fi
	# Invalidate BEFORE publication/reload. A crash anywhere before confirmation retries.
	rm -f "$APPLIED" || exit 1
	if ! state; then
		# Random name inside the verified directory (never a predictable $FILE.tmp.$$).
		tmp=$(umask 077 && mktemp "$DROPIN_DIR/vigie.conf.XXXXXX") || exit 1
		if ! { want >"$tmp" && chmod 644 "$tmp" && mv "$tmp" "$FILE"; }; then
			rm -f "$tmp"
			exit 1
		fi
	fi
	# Pre-DNS boot preparation stages files only; never assert the daemon applied them.
	[ "$1" != prepare ] || exit 0
	sh -c "$RELOAD_CMD" || exit $?
	# Only the successful reload path may publish confirmation; atomic rename prevents
	# a killed writer from leaving a partial confirmation that check could accept.
	tmp=$(umask 077 && mktemp "$LOG_DIR/.dnsmasq-applied.XXXXXX") || exit 1
	if want >"$tmp" && mv "$tmp" "$APPLIED"; then
		exit 0
	fi
	rm -f "$tmp"
	exit 1
	;;
*)
	echo "usage: $0 prepare|ensure|check" >&2
	exit 64
	;;
esac
