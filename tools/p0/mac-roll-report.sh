#!/bin/sh
# Vigie P0: measure how your devices roll MACs, from a dnsmasq log with log-dhcp on.
# Usage:  sh mac-roll-report.sh /tmp/vigie-p0/dnsmasq.log
# Works on the router (BusyBox awk) or on a copy of the log on your workstation.
#
# Output groups DHCP ACKs by (vendor class | requested-options | hostname). One group
# with several distinct MACs = one device rolling its MAC (or identical twins).
# It prints hostnames and MACs: keep it local, redact before sharing.
# Log line formats are assumed from dnsmasq docs and must be confirmed against a
# real log; the "parsed ACKs" line tells you whether parsing worked at all.

f="${1:?usage: mac-roll-report.sh <dnsmasq.log>}"

awk '
/dnsmasq-dhcp\[/ {
	line = $0
	sub(/^.*dnsmasq-dhcp\[[0-9]+\]: /, "", line)
	xid = line
	sub(/ .*$/, "", xid)
	rest = substr(line, length(xid) + 2)

	if (rest ~ /^requested options:/) {
		o = substr(rest, 20)
		gsub(/:[^,]*/, "", o)
		gsub(/ /, "", o)
		opt[xid] = o
	} else if (rest ~ /^vendor class:/) {
		vc[xid] = substr(rest, 15)
	} else if (rest ~ /^DHCPACK\(/) {
		split(rest, b, " ")
		mac = b[3]
		host = (b[4] == "") ? "-" : b[4]
		o = (xid in opt) ? opt[xid] : "?"
		v = (xid in vc) ? vc[xid] : "-"
		key = v "|" o "|" host
		acks++
		if (!((key SUBSEP mac) in seen)) {
			seen[key, mac] = 1
			nmac[key]++
			if (!(mac in allmac)) {
				allmac[mac] = 1
				total++
				if (substr(mac, 2, 1) ~ /[26aAeE]/) nrand++
			}
		}
	}
}
END {
	print "parsed ACKs: " acks + 0
	print "distinct MACs: " total + 0 "  (randomized: " nrand + 0 ")"
	print ""
	print "MACs\tvendor|options|hostname"
	for (k in nmac) print nmac[k] "\t" k | "sort -rn"
	close("sort -rn")
	print ""
	print "Groups with 2+ MACs are rolling-MAC candidates (or identical devices)."
}
' "$f"
