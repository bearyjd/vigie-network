#!/bin/sh
# procd command wrapper for the collector (runs as the dedicated `vigie` user). Passes the exit
# code through. procd restarts the collector only a few times (`respawn 3600 5 5` in the init
# script), and exit codes 77 (refused to run as root) and 78 (bad config/key) will not fix
# themselves, so this counts those exits in a state dir the init script prepares and logs once
# the retry limit is reached. procd has no "gave up" hook; the count is the next best thing.
COLLECTOR=/usr/bin/vigie-collector
STATE=/var/run/vigie-collector-root/state
LIMIT=5
if [ "${VIGIE_TEST:-}" = 1 ]; then
	COLLECTOR="${VIGIE_COLLECTOR_BIN:-$COLLECTOR}"
	STATE="${VIGIE_RUN_STATE_DIR:-$STATE}"
fi
# procd signals this PID only. Install traps before creating the child, including
# the window before $! is assigned. Never signal an empty PID/group.
stop_rc=0
child=
forwarded=0
forward_stop() {
	[ -n "$child" ] && [ "$forwarded" -eq 0 ] || return 0
	# Set BEFORE kill: a repeated trap must never signal twice or after the reap.
	forwarded=1
	# Async POSIX children may inherit INT ignored: normalize both stops to TERM.
	# This is the dedicated UID's sole managed child, not atomic PID pinning.
	kill -TERM "$child" 2>/dev/null || :
}
# Called by the signal traps below.
# shellcheck disable=SC2329
request_stop() {
	# The first request owns shutdown, including the pre-assignment pending state.
	trap '' TERM INT
	[ "$stop_rc" -ne 0 ] || stop_rc=$1
	# Flag-only traps lose a stop delivered after the branch check but before wait.
	forward_stop
}
trap 'request_stop 143' TERM
trap 'request_stop 130' INT
[ "$stop_rc" -eq 0 ] || exit "$stop_rc"
"$COLLECTOR" "$@" &
child=$!
if [ "$stop_rc" -eq 0 ]; then
	wait "$child"
	rc=$?
else
	# Stop arrived between the pre-launch check and the first wait.
	forward_stop
	rc=128
fi
if [ "$stop_rc" -ne 0 ]; then
	# Further requests must not interrupt the final reap or cause repeated kills.
	trap '' TERM INT
	if [ "$rc" -ge 128 ]; then
		# The handler (or pending-stop branch) already forwarded exactly once.
		wait "$child"
	fi
	exit "$stop_rc"
fi
# A completed wait has consumed the child; late stop requests must not signal it.
trap '' TERM INT
[ "$stop_rc" -eq 0 ] || exit "$stop_rc"
child=
case $rc in
77 | 78)
	echo x >>"$STATE/fails" 2>/dev/null
	n=$(wc -l <"$STATE/fails" 2>/dev/null || echo 0)
	if [ "$n" -eq "$LIMIT" ]; then
		logger -t vigie -p daemon.crit "collector failed $n times with exit $rc (77 root refused, 78 config/key); procd is giving up at its retry limit. Fix it, then: /etc/init.d/vigie-collector restart"
	fi
	;;
esac
exit $rc
