#!/bin/sh
# Independent watchdog (root cron, every 5 min; NOT part of the collector): dnsmasq never
# rotates its facility file, so a stopped collector must not let it fill router RAM.
set -u
LOG="${VIGIE_LOG_FILE:-/tmp/vigie/dnsmasq.log}"
MAX="${VIGIE_LOG_MAX_BYTES:-8388608}"
[ -f "$LOG" ] || exit 0
size=$(wc -c <"$LOG")
if [ "$size" -gt "$MAX" ]; then
	# Truncate in place: dnsmasq keeps its descriptor; the collector tail sees len < cursor.
	: >"$LOG"
fi
exit 0
