#!/bin/sh
# Manage the Vigie dnsmasq drop-in. Runs as root (init script at start, cron every 5 min).
# /tmp/dnsmasq.d is tmpfs, so the drop-in must be recreated after every boot, and GL.iNet
# reloads may clear it. Reloads dnsmasq only when the drop-in actually changed.
#
#   ensure   create/repair the drop-in and log file; reload dnsmasq if changed
#   check    exit 0 ok, 1 missing, 2 differs (no changes made)
#
# Not yet run on the router (P0 item 4 pending). Overrides exist for tests only.
set -u

DROPIN_DIR="${VIGIE_DROPIN_DIR:-/tmp/dnsmasq.d}"
LOG_DIR="${VIGIE_LOG_DIR:-/tmp/vigie}"
RELOAD_CMD="${VIGIE_RELOAD_CMD:-/etc/init.d/dnsmasq reload}"
FILE="$DROPIN_DIR/vigie.conf"

want() {
	printf 'log-queries=extra\nlog-dhcp\nlog-facility=%s/dnsmasq.log\n' "$LOG_DIR"
}

state() {
	[ -f "$FILE" ] || return 1
	[ "$(tr -d '\r' <"$FILE")" = "$(want)" ] || return 2
	return 0
}

case "${1:-}" in
check)
	state
	exit $?
	;;
ensure)
	# World-readable on purpose (the unprivileged collector tails it); no secrets in it.
	mkdir -p "$LOG_DIR" "$DROPIN_DIR" || exit 1
	chmod 755 "$LOG_DIR"
	[ -f "$LOG_DIR/dnsmasq.log" ] || : >"$LOG_DIR/dnsmasq.log"
	chmod 644 "$LOG_DIR/dnsmasq.log"
	if state; then
		exit 0
	fi
	tmp="$FILE.tmp.$$"
	want >"$tmp" && chmod 644 "$tmp" && mv "$tmp" "$FILE" || exit 1
	sh -c "$RELOAD_CMD"
	exit 0
	;;
*)
	echo "usage: $0 ensure|check" >&2
	exit 64
	;;
esac
