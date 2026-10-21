#!/bin/sh
# PRINTS the router commands that create the dedicated `vigie` user and the private paths.
# It executes nothing and writes nothing: the owner reviews the output and runs it on the
# router as root. OpenWrt/GL.iNet has no useradd; the user is added to /etc/passwd and /etc/group
# by hand. The collector must NOT run as nobody (avahi and others share that uid and would
# read the HMAC key); the conntrack helper likewise refuses uid 65534 and uses this uid.
#
#   VIGIE_UID / VIGIE_GID   numeric ids to use (default 6700); pick ones unused in /etc/passwd
set -eu

UID_N="${VIGIE_UID:-6700}"
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

# 4. log and drop-in directories (the drop-in script also creates these, same modes)
install -d -m 0750 -o root -g vigie /tmp/vigie
install -d -m 0755 -o root -g root /tmp/dnsmasq.d

# 5. start, then VERIFY the assumptions the scripts rely on
/etc/init.d/vigie-collector enable
/etc/init.d/vigie-collector start
ls -ldn /tmp/vigie /tmp/dnsmasq.d     # dirs: uid 0; /tmp/vigie group ${GID_N}, drwxr-x---
ls -ln  /tmp/vigie/dnsmasq.log        # group ${GID_N}, -rw-r-----; owner 0 or dnsmasq's uid
ps | grep -E 'dnsmasq|vigie-collector'  # collector runs as vigie, not root/nobody
COMMANDS
