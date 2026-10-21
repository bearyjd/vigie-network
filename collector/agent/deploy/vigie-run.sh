#!/bin/sh
# procd command wrapper for the collector (runs as the dedicated `vigie` user). Passes the exit
# code through. procd restarts the collector only a few times (`respawn 3600 5 5` in the init
# script), and exit codes 77 (refused to run as root) and 78 (bad config/key) will not fix
# themselves, so this counts those exits in a state dir the init script prepares and logs once
# the retry limit is reached. procd has no "gave up" hook; the count is the next best thing.
COLLECTOR=/usr/bin/vigie-collector
STATE=/var/run/vigie-collector
LIMIT=5
if [ "${VIGIE_TEST:-}" = 1 ]; then
	COLLECTOR="${VIGIE_COLLECTOR_BIN:-$COLLECTOR}"
	STATE="${VIGIE_RUN_STATE_DIR:-$STATE}"
fi
"$COLLECTOR" "$@"
rc=$?
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
