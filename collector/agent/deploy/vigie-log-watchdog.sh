#!/bin/sh
# Independent watchdog (root cron, every 5 min; NOT part of the collector): dnsmasq never
# rotates its facility file, so a stopped collector must not let it fill router RAM.
#
# Normal path: above MAX bytes the log is RENAMED to dnsmasq.log.1, a fresh 0640 file is created
# owned by the uid the running dnsmasq has (resolved from /proc/<pid>/status; group vigie), and
# dnsmasq gets SIGUSR2 (it closes and reopens its log file). The collector's tail drains the
# renamed file through its open handle and follows the new one. If that uid cannot be resolved
# or is 0 nothing is rotated (warning via logger, exit 70). If the new file is still empty 10 s
# after the signal while the old one kept growing, that is logged too.
# Emergency fallback, only when a file is above 2x MAX (rotation did not take effect): truncate
# it in place; the collector's cursor fingerprint notices and restarts at 0.
#
# Root acting on a path in /tmp is a symlink-attack primitive, so the directory and the files are
# verified first (vigie-lib.sh); a failed check exits 70 (and logs) and changes nothing.
set -u
. "$(dirname "$0")/vigie-lib.sh"

LOG=/tmp/vigie/dnsmasq.log
MAX=8388608
WAIT=10
SIGNAL_CMD=
if vtest; then
	LOG="${VIGIE_LOG_FILE:-$LOG}"
	MAX="${VIGIE_LOG_MAX_BYTES:-$MAX}"
	WAIT="${VIGIE_WAIT_SECS:-$WAIT}"
	SIGNAL_CMD="${VIGIE_SIGNAL_CMD:-}"
fi
OLD="$LOG.1"

[ -e "$LOG" ] || [ -L "$LOG" ] || exit 0
require_dir "$(dirname "$LOG")"
ALLOWED=$(log_allowed_uids)
require_file "$LOG" "$ALLOWED"
require_file "$OLD" "$ALLOWED"
resolve_dnsmasq_uid || true

warn() { logger -t vigie -p daemon.warn "$*" 2>/dev/null || true; }
fsize() { wc -c <"$1" 2>/dev/null || echo 0; }

# The new log belongs to the uid dnsmasq runs as, never to whoever owned the old file.
rotation_blocker() {
	[ -n "$DNSMASQ_UID" ] || { echo "cannot resolve the uid dnsmasq runs as ($DNSMASQ_WHY)"; return; }
	[ "$DNSMASQ_UID" != 0 ] || echo "dnsmasq runs as uid 0; a group-readable log is refused"
}

signal_dnsmasq() {
	if [ -n "$SIGNAL_CMD" ]; then
		sh -c "$SIGNAL_CMD"
	else
		kill -USR2 "$DNSMASQ_PID"
	fi
}

# dnsmasq should now write to the new file; empty after WAIT seconds while the renamed file
# kept growing means it never reopened.
check_reopened() {
	_i=0
	while [ "$_i" -lt "$WAIT" ] && [ "$(fsize "$LOG")" -eq 0 ]; do
		sleep 1
		_i=$((_i + 1))
	done
	if [ "$(fsize "$LOG")" -eq 0 ] && [ "$(fsize "$OLD")" -gt "$1" ]; then
		warn "$LOG is still empty ${WAIT}s after SIGUSR2 while $OLD kept growing: dnsmasq did not reopen its log"
	fi
}

rc=0
size=$(wc -c <"$LOG")
if [ "$size" -gt $((MAX * 2)) ]; then
	: >"$LOG"
elif [ "$size" -gt "$MAX" ]; then
	why=$(rotation_blocker)
	if [ -n "$why" ]; then
		warn "not rotating $LOG: $why"
		rc=70
	else
		mv -f "$LOG" "$OLD" || exit 1
		# noclobber = O_EXCL: the new name must not exist.
		(umask 077 && set -C && : >"$LOG") || refuse "cannot create $LOG after rotation"
		chown "$DNSMASQ_UID:${VIGIE_OWNER#*:}" "$LOG" && chmod 0640 "$LOG" || refuse "cannot set owner/mode on $LOG"
		old0=$(fsize "$OLD")
		signal_dnsmasq || {
			rc=$?
			warn "SIGUSR2 to dnsmasq failed; $OLD stays open until restart"
		}
		check_reopened "$old0"
	fi
fi
if [ -f "$OLD" ] && [ "$(wc -c <"$OLD")" -gt $((MAX * 2)) ]; then
	: >"$OLD"
fi
exit "$rc"
