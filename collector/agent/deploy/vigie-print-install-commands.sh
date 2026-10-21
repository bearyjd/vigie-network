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
if [ "$UID_N" = 0 ] || [ "$UID_N" = 65534 ] || [ "$GID_N" = 0 ] || [ "$GID_N" = 65534 ]; then
	echo "refusing uid/gid 0 or 65534 (root / nobody)" >&2
	exit 64
fi
if [ "$UID_N" -lt 6700 ] || [ "$UID_N" -gt 6799 ] || in_use "$PASSWD" "$UID_N"; then
	echo "uid $UID_N is outside 6700..6799 or already used in $PASSWD" >&2
	exit 64
fi
if in_use "$GROUP" "$GID_N"; then
	echo "gid $GID_N is already used in $GROUP" >&2
	exit 64
fi

cat <<COMMANDS
# --- run on the router, as root, after reviewing ---

# 1. dedicated group and user (no login: OpenWrt ships /bin/false; use /sbin/nologin if present)
grep -q '^vigie:' /etc/group  || echo 'vigie:x:${GID_N}:' >> /etc/group
grep -q '^vigie:' /etc/passwd || echo 'vigie:x:${UID_N}:${GID_N}:vigie collector:/var/empty:/bin/false' >> /etc/passwd
grep -q '^vigie:' /etc/shadow || echo 'vigie:x:0:0:99999:7:::' >> /etc/shadow
id vigie    # expect uid=${UID_N} gid=${GID_N}

# 2. install the files (binary, scripts, init, config) under root ownership
install -d -m 0755 -o root -g root /etc/vigie /usr/libexec/vigie
# install -m 0755 vigie-collector /usr/bin/vigie-collector
# install -m 0755 vigie-lib.sh vigie-dnsmasq-dropin.sh vigie-log-watchdog.sh /usr/libexec/vigie/
# install -m 0755 vigie-collector.init /etc/init.d/vigie-collector
# install -m 0644 collector.conf.example /etc/vigie/collector.conf   # then edit it

# 3. the HMAC key: owned by vigie, readable by nobody else
# (write the hex key to /etc/vigie/key first; do not paste it into shell history)
chown vigie:vigie /etc/vigie/key
chmod 0600 /etc/vigie/key

# 4. /tmp/vigie and /tmp/dnsmasq.d are NOT created here: they live on tmpfs, so the root drop-in
#    script (run by the init script at every start and by cron) creates and verifies them, and
#    it refuses a directory that somebody else created first.

# 5. start, then VERIFY the assumptions the scripts rely on
/etc/init.d/vigie-collector enable
/etc/init.d/vigie-collector start
ls -ln /tmp/vigie /tmp/vigie/dnsmasq.log   # dir: uid 0, group ${GID_N}, drwxr-x--x; log: group ${GID_N}, -rw-r-----
/etc/init.d/dnsmasq restart; sleep 2; logread | grep dnsmasq | tail   # no log-file errors
ps | grep -E 'dnsmasq|vigie-collector'  # collector runs as vigie, not root/nobody

# 6. the conntrack helper (separate branch) runs as root and creates a 0600 socket owned by the
#    agent's uid; access is restricted by that file ownership alone. Pass it the uid:
#      <conntrack-helper> --uid ${UID_N}
COMMANDS
