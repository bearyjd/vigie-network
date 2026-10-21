#!/bin/sh
# Independent watchdog (root cron, every 5 min; NOT part of the collector): dnsmasq never
# rotates its facility file, so a stopped collector must not let it fill router RAM.
# Root truncating a path in /tmp is a symlink-attack primitive, so the directory and the file
# are verified first (vigie-lib.sh); a failed check exits 70 and truncates nothing.
set -u
. "$(dirname "$0")/vigie-lib.sh"

LOG="${VIGIE_LOG_FILE:-/tmp/vigie/dnsmasq.log}"
MAX="${VIGIE_LOG_MAX_BYTES:-8388608}"
[ -e "$LOG" ] || [ -L "$LOG" ] || exit 0
require_dir "$(dirname "$LOG")"
require_file "$LOG" "$VIGIE_LOG_ALLOWED_UIDS"
size=$(wc -c <"$LOG")
if [ "$size" -gt "$MAX" ]; then
	# Truncate in place: dnsmasq keeps its descriptor; the collector tail sees len < cursor.
	: >"$LOG"
fi
exit 0
