#!/bin/sh
# Independent watchdog (root cron, every 5 min; NOT part of the collector): dnsmasq never
# rotates its facility file, so a stopped collector must not let it fill router RAM.
#
# Normal path: above MAX bytes the log is RENAMED to dnsmasq.log.1, a fresh 0640 file with the
# same owner is created, and dnsmasq gets SIGUSR2 (it closes and reopens its log file). The
# collector's tail drains the renamed file through its open handle and follows the new one.
# Emergency fallback, only when a file is above 2x MAX (rotation did not take effect): truncate
# it in place; the collector's cursor fingerprint notices and restarts at 0.
#
# Root acting on a path in /tmp is a symlink-attack primitive, so the directory and the files are
# verified first (vigie-lib.sh); a failed check exits 70 (and logs) and changes nothing.
set -u
. "$(dirname "$0")/vigie-lib.sh"

LOG=/tmp/vigie/dnsmasq.log
MAX=8388608
SIGNAL_CMD='pids=$(pidof dnsmasq) && kill -USR2 $pids'
if vtest; then
	LOG="${VIGIE_LOG_FILE:-$LOG}"
	MAX="${VIGIE_LOG_MAX_BYTES:-$MAX}"
	SIGNAL_CMD="${VIGIE_SIGNAL_CMD:-$SIGNAL_CMD}"
fi
OLD="$LOG.1"

[ -e "$LOG" ] || [ -L "$LOG" ] || exit 0
require_dir "$(dirname "$LOG")"
require_file "$LOG" "$VIGIE_LOG_ALLOWED_UIDS"
require_file "$OLD" "$VIGIE_LOG_ALLOWED_UIDS"

size=$(wc -c <"$LOG")
if [ "$size" -gt $((MAX * 2)) ]; then
	: >"$LOG"
elif [ "$size" -gt "$MAX" ]; then
	owner=$(stat -c %u "$LOG")
	mv -f "$LOG" "$OLD" || exit 1
	# noclobber = O_EXCL: the new name must not exist.
	(umask 077 && set -C && : >"$LOG") || refuse "cannot create $LOG after rotation"
	chown "$owner:${VIGIE_OWNER#*:}" "$LOG" && chmod 0640 "$LOG" || refuse "cannot set owner/mode on $LOG"
	sh -c "$SIGNAL_CMD" || logger -t vigie "SIGUSR2 to dnsmasq failed; $OLD stays open until restart" 2>/dev/null
fi
if [ -f "$OLD" ] && [ "$(wc -c <"$OLD")" -gt $((MAX * 2)) ]; then
	: >"$OLD"
fi
exit 0
