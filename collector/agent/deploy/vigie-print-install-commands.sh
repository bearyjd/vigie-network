#!/bin/sh
# PRINTS the router commands that create the dedicated `vigie` user and the private paths.
# It executes nothing and writes nothing: the owner reviews the output and runs it on the
# router as root. OpenWrt/GL.iNet has no useradd; the user is added to /etc/passwd and /etc/group
# by hand. The collector must NOT run as nobody (avahi and others share that uid and would
# read the HMAC key); the conntrack helper likewise refuses uid 65534 and uses this uid.
#
# The uid is the first one in 6700..6799 that is unused in /etc/passwd (the gid defaults to the
# same number and must be unused in /etc/group). An uid in use is never reused: a collision would
# hand the HMAC key, or the helper's socket, to an unrelated account.
#
#   VIGIE_UID / VIGIE_GID   pick other numbers; must be unused, not 0, not 65534
#   (tests only, with VIGIE_TEST=1: VIGIE_PASSWD / VIGIE_GROUP_FILE replace /etc/passwd, /etc/group)
set -eu

PASSWD=/etc/passwd
GROUP=/etc/group
if [ "${VIGIE_TEST:-}" = 1 ]; then
	PASSWD="${VIGIE_PASSWD:-$PASSWD}"
	GROUP="${VIGIE_GROUP_FILE:-$GROUP}"
fi

# in_use FILE N: field 3 of FILE (uid in passwd, gid in group) is N. Unreadable file: fail closed.
in_use() {
	[ -r "$1" ] || {
		echo "cannot read $1" >&2
		exit 64
	}
	awk -F: -v n="$2" '$3 == n { f = 1 } END { exit !f }' "$1"
}

UID_N="${VIGIE_UID:-}"
if [ -z "$UID_N" ]; then
	UID_N=6700
	while in_use "$PASSWD" "$UID_N"; do
		UID_N=$((UID_N + 1))
		if [ "$UID_N" -gt 6799 ]; then
			echo "no free uid in 6700..6799 in $PASSWD" >&2
			exit 64
		fi
	done
fi
GID_N="${VIGIE_GID:-$UID_N}"
case "$UID_N$GID_N" in
'' | *[!0-9]*)
	echo "VIGIE_UID and VIGIE_GID must be numbers" >&2
	exit 64
	;;
esac
if [ "$UID_N" -eq 0 ] || [ "$UID_N" -eq 65534 ] || [ "$GID_N" -eq 0 ] || [ "$GID_N" -eq 65534 ]; then
	echo "refusing uid/gid 0 or 65534 (root / nobody)" >&2
	exit 64
fi
if ! [ "$UID_N" -ge 6700 ] || ! [ "$UID_N" -le 6799 ] || in_use "$PASSWD" "$UID_N"; then
	echo "uid $UID_N is outside 6700..6799 or already used in $PASSWD" >&2
	exit 64
fi
if in_use "$GROUP" "$GID_N"; then
	echo "gid $GID_N is already used in $GROUP" >&2
	exit 64
fi
if ! [ "$GID_N" -ge 1000 ] || ! [ "$GID_N" -le 4294967294 ]; then
	echo "gid must be a dedicated gid in 1000..4294967294" >&2
	exit 64
fi

# A pre-existing named group could differ from the selected numeric primary gid.
# This printer provisions a fresh dedicated account; never silently reuse an old one.
if awk -F: '$1 == "vigie" { f = 1 } END { exit !f }' "$PASSWD" ||
   awk -F: '$1 == "vigie" { f = 1 } END { exit !f }' "$GROUP"; then
	echo "vigie account/group already exists; inspect its ids instead of recreating it" >&2
	exit 64
fi

cat <<COMMANDS
# --- run on the router, as root, after reviewing ---

# 1. dedicated group and user (no login: OpenWrt ships /bin/false; use /sbin/nologin if present)
grep -q '^vigie:' /etc/group  || echo 'vigie:x:${GID_N}:' >> /etc/group
grep -q '^vigie:' /etc/passwd || echo 'vigie:x:${UID_N}:${GID_N}:vigie collector:/var/empty:/bin/false' >> /etc/passwd
grep -q '^vigie:' /etc/shadow || echo 'vigie:x:0:0:99999:7:::' >> /etc/shadow
# Verify the selected account before installing files or changing key ownership.
test "\$(id -u vigie)" = "${UID_N}" || exit 1
test "\$(id -g vigie)" = "${GID_N}" || exit 1
test "\$(id -gn vigie)" = "vigie" || exit 1

# 2. install the files (binary, scripts, init, config) under root ownership
install -d -m 0755 -o root -g root /etc/vigie /usr/libexec/vigie
# Never set SUID/SGID or file capabilities on the privilege helper.
install -m 0755 -o root -g root /tmp/vigie-privdrop /usr/bin/vigie-privdrop
install -m 0755 -o root -g root /tmp/vigie-collector /usr/bin/vigie-collector
install -m 0755 -o root -g root /tmp/vigie-conntrack /usr/bin/vigie-conntrack
install -m 0755 -o root -g root /tmp/vigie-deploy/vigie-lib.sh /tmp/vigie-deploy/vigie-dnsmasq-dropin.sh /tmp/vigie-deploy/vigie-log-watchdog.sh /tmp/vigie-deploy/vigie-run.sh /tmp/vigie-deploy/vigie-state-dir.sh /tmp/vigie-deploy/vigie-logfs.sh /tmp/vigie-deploy/vigie-logfs-boot.sh /usr/libexec/vigie/
install -m 0755 -o root -g root /tmp/vigie-deploy/vigie-logfs.init /etc/init.d/vigie-logfs
install -m 0755 -o root -g root /tmp/vigie-deploy/vigie-collector.init /etc/init.d/vigie-collector
install -m 0755 -o root -g root /tmp/vigie-deploy/vigie-conntrack.init /etc/init.d/vigie-conntrack
# First install only: copy collector.conf.example to /etc/vigie/collector.conf (0644 root:root)
# and edit it using the provisioner's output. Keep an existing configured file.

# 3. the HMAC key: owned by vigie, readable by nobody else
# (write the hex key to /etc/vigie/key first; do not paste it into shell history)
chown vigie:vigie /etc/vigie/key
chmod 0600 /etc/vigie/key

# 4. /tmp/vigie and /tmp/dnsmasq.d are NOT created here: they live on tmpfs, so the root drop-in
#    script (run by the init script at every start and by cron) creates and verifies them, and
#    it refuses a directory that somebody else created first.

# 5. start, then VERIFY the assumptions the scripts rely on
# Fixed 20 MiB private log filesystem, boot START=17 before dnsmasq START=19.
# Existing contents/foreign mounts are refused; inspect and preserve them before retrying.
/etc/init.d/vigie-logfs enable
/etc/init.d/vigie-logfs start
/etc/init.d/vigie-collector enable
/etc/init.d/vigie-collector start
# The collector/drop-in creates root:vigie 0751 first; the helper accepts that existing
# directory unchanged. Its init resolves --uid / --gid from the existing vigie account;
# starting the helper binary directly first would create a root:root 0755 directory.
/etc/init.d/vigie-conntrack enable
/etc/init.d/vigie-conntrack start
ls -ln /tmp/vigie /tmp/vigie/dnsmasq.log   # dir: uid 0, group ${GID_N}, drwxr-x--x; log: group ${GID_N}, -rw-r-----
ls -ln /tmp/vigie/conntrack.sock         # socket: uid ${UID_N}, gid ${GID_N}, srw-------
/etc/init.d/dnsmasq restart; sleep 2; logread | grep dnsmasq | tail   # no log-file errors
ps | grep -E 'dnsmasq|vigie-collector|vigie-conntrack'  # collector: vigie; conntrack: root

# 6. Firmware validation remains pending: verify real proc parsing, procd uid/respawn,
# dnsmasq ownership and reboot recovery before leaving these services unattended.

# Rollback: run separately, as root. Stop/disable before removing installed service files.
# FIRST remove/disable only owned Vigie cron ensure/watchdog jobs, then stop collector/helper.
# Restore the exact prior DNS configuration and restart/verify DNS before reviewing an unmount.
# /etc/init.d/vigie-logfs disable
# /etc/init.d/vigie-conntrack stop
# /etc/init.d/vigie-conntrack disable
# /etc/init.d/vigie-collector stop
# /etc/init.d/vigie-collector disable
# Remove Vigie watchdog/drop-in entries from root's crontab if you installed them.
# rm -f /tmp/dnsmasq.d/vigie.conf
# /etc/init.d/dnsmasq reload
# rm -f /etc/init.d/vigie-conntrack /etc/init.d/vigie-collector /usr/bin/vigie-conntrack /usr/bin/vigie-collector
# rm -f /usr/libexec/vigie/vigie-lib.sh /usr/libexec/vigie/vigie-dnsmasq-dropin.sh /usr/libexec/vigie/vigie-log-watchdog.sh /usr/libexec/vigie/vigie-run.sh /usr/libexec/vigie/vigie-state-dir.sh
# /etc/vigie (including its key/config) and tmpfs logs are retained for inspection/re-provisioning.
COMMANDS
