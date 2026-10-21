#!/bin/sh
# Vigie P0: undo logging-on.sh. Safe to run when logging is already off.
# Run on the router:  sh logging-off.sh
DIR=/tmp/vigie-p0
CONF=/tmp/dnsmasq.d/vigie-p0.conf

[ -f "$DIR/watchdog.pid" ] && kill "$(cat "$DIR/watchdog.pid")" 2>/dev/null
rm -f "$CONF"
/etc/init.d/dnsmasq restart
echo "Logging config removed. Log kept at $DIR/dnsmasq.log (delete with: rm -rf $DIR)."
