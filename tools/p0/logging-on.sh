#!/bin/sh
# Vigie P0: enable dnsmasq query + DHCP logging to a tmpfs file.
# Nothing is written to flash. A reboot (or logging-off.sh) reverts it.
# Effect: dnsmasq restarts once (DNS blips for ~1-2 s).
# Run on the router:  sh logging-on.sh
set -eu

DIR=/tmp/vigie-p0
LOG=$DIR/dnsmasq.log
CONFDIR=/tmp/dnsmasq.d
CONF=$CONFDIR/vigie-p0.conf
MAX_BYTES=$((8 * 1024 * 1024))

# Refuse to proceed unless dnsmasq actually reads our conf-dir.
if ! grep -qE "^conf-dir=$CONFDIR" /var/etc/dnsmasq.conf.* 2>/dev/null; then
	echo "ABORT: running dnsmasq config does not include conf-dir=$CONFDIR." >&2
	echo "Run probe.sh and send the 'generated dnsmasq config' section." >&2
	exit 1
fi

mkdir -p "$DIR" "$CONFDIR"
chmod 755 "$DIR"
: > "$LOG"
chmod 666 "$LOG"

cat > "$CONF" <<EOF
log-queries=extra
log-dhcp
log-facility=$LOG
EOF

# Watchdog: truncates the log if it grows past MAX_BYTES (tmpfs shares RAM).
# Lives only until reboot or logging-off.sh.
(
	while sleep 60; do
		size=$(wc -c < "$LOG" 2>/dev/null || echo 0)
		[ "$size" -gt "$MAX_BYTES" ] && : > "$LOG"
	done
) >/dev/null 2>&1 &
echo $! > "$DIR/watchdog.pid"

/etc/init.d/dnsmasq restart
sleep 2
if [ -s "$LOG" ]; then
	echo "OK: logging to $LOG ($(wc -l < "$LOG") lines so far)"
else
	echo "WARN: $LOG is empty. Do a DNS lookup from a LAN device, then check 'ls -l $LOG'." >&2
	echo "If still empty, dnsmasq may not be able to write the file; send me 'logread | grep dnsmasq | tail'." >&2
fi
echo "Revert with: sh logging-off.sh"
