#!/bin/sh
# Asserts mac-roll-report.sh groups rolling MACs correctly on the synthetic fixture.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(sh "$here/../../tools/p0/mac-roll-report.sh" "$here/../fixtures/p0/dnsmasq-dhcp-sample.log")
fail() { echo "FAIL: $1" >&2; echo "$out" >&2; exit 1; }
echo "$out" | grep -q '^parsed ACKs: 7$'                      || fail "ACK count"
echo "$out" | grep -q '^distinct MACs: 6  (randomized: 5)$'   || fail "MAC totals"
echo "$out" | grep -qP '^3\tandroid-dhcp-14\|.*\|Pixel-8$'    || fail "Pixel group of 3"
echo "$out" | grep -qP '^2\t-\|.*\|iPhone$'                   || fail "iPhone group of 2"
echo "$out" | grep -qP '^1\t-\|.*\|DiskStation$'              || fail "stable device single MAC"
echo "PASS"
