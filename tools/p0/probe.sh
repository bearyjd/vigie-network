#!/bin/sh
# Vigie P0 router probe. READ-ONLY: changes nothing on the router.
# Run on the router:  sh probe.sh > /tmp/vigie-p0-probe.txt
# Output has LAN details (counts, config); it prints no MAC addresses or SSIDs.
# Review it before sharing.

sec() { printf '\n== %s ==\n' "$1"; }

sec "system"
uname -a
cat /etc/glversion 2>/dev/null
grep -E 'DISTRIB_(RELEASE|ARCH|TARGET)' /etc/openwrt_release

sec "memory / tmpfs"
free | head -2
df -k /tmp | tail -1

sec "generated dnsmasq config (what dnsmasq actually runs with)"
for f in /var/etc/dnsmasq.conf.*; do
	[ -f "$f" ] || continue
	echo "# $f"
	grep -E '^(log-|conf-dir|dhcp-leasefile|port=|local-service|no-resolv|server=)' "$f"
done

sec "uci dhcp.@dnsmasq[0]"
uci show dhcp.@dnsmasq[0] 2>/dev/null

sec "init script option support (counts of option names)"
grep -oE 'logqueries|logdhcp|logfacility|confdir|extraconfig' /etc/init.d/dnsmasq /lib/functions.sh 2>/dev/null | sort | uniq -c

sec "dnsmasq conf-dir contents"
ls -la /tmp/dnsmasq.d /tmp/dnsmasq.cfg*.d 2>&1 | head -20

sec "jail / procd tooling"
for b in ujail procd ubusd; do
	command -v "$b" >/dev/null 2>&1 && echo "$b: $(command -v $b)" || echo "$b: MISSING"
done

sec "time sanity (router has no RTC)"
date -u
uci show system.ntp 2>/dev/null | grep -E 'enabled|enable_server|server'

sec "mDNS / SSDP sockets"
netstat -lnup 2>/dev/null | grep -E ':(5353|1900) '
ps | grep -E 'avahi|umdns|miniupnp' | grep -v grep

sec "WAN exposure of port 53"
iptables -S INPUT 2>/dev/null | grep -E 'dport 53|dpt:53'
iptables -S zone_wan_input 2>/dev/null | head -20
uci show firewall 2>/dev/null | grep -E "\.name=|\.input=" | head -30

sec "wireless isolation / networks (no SSIDs)"
uci show wireless 2>/dev/null | grep -E "\.isolate=|\.network="

sec "leases: randomized (locally administered) vs global MACs"
wc -l < /tmp/dhcp.leases
awk '{ c=substr($2,2,1); if (c ~ /[26aAeE]/) r++; else g++ }
     END { print "randomized=" r+0, "global=" g+0 }' /tmp/dhcp.leases

sec "neighbors: randomized vs global MACs on br-lan"
ip neigh show dev br-lan 2>/dev/null | awk '{ c=substr($5,2,1); if (c ~ /[26aAeE]/) r++; else g++ }
     END { print "randomized=" r+0, "global=" g+0 }'

sec "conntrack"
echo "acct=$(cat /proc/sys/net/netfilter/nf_conntrack_acct) max=$(cat /proc/sys/net/netfilter/nf_conntrack_max) entries=$(wc -l < /proc/net/nf_conntrack)"
ls -l /proc/net/nf_conntrack
id

sec "logread ring buffer"
uci get system.@system[0].log_size 2>/dev/null || echo "log_size: default"
logread | wc -l

sec "sysupgrade keep list (collector secrets must not leak here)"
grep -v '^#' /etc/sysupgrade.conf 2>/dev/null

sec "done"
