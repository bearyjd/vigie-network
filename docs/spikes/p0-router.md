# P0 spike: GL-XE3000 router facts

Goal: answer the PRP-001 §12 P0 checklist with evidence before any collector code. Scripts live in `tools/p0/`. Nothing here writes to flash; a reboot reverts everything.

## Run order (on the router)

Copy the scripts over (`scp tools/p0/*.sh root@192.168.1.1:/tmp/`), then:

1. `sh /tmp/probe.sh > /tmp/vigie-p0-probe.txt` — read-only. Paste the file back (it has no MACs or SSIDs).
2. `sh /tmp/logging-on.sh` — enables dnsmasq query + DHCP logging to `/tmp/vigie-p0/dnsmasq.log` via a tmpfs conf file; restarts dnsmasq once (~1–2 s DNS blip). It aborts without changing anything if dnsmasq's generated config does not read `/tmp/dnsmasq.d`.
3. Let it run 24–48 h while devices come and go (reconnect your phones a few times).
4. `sh /tmp/mac-roll-report.sh /tmp/vigie-p0/dnsmasq.log` — prints hostnames and MACs, so redact before pasting. Also `tail -50 /tmp/vigie-p0/dnsmasq.log | grep -v ' query\[' ` with MACs masked helps me confirm line formats.
5. `ls -l /tmp/vigie-p0/dnsmasq.log; free` at the end to record log growth and RAM.
6. `sh /tmp/logging-off.sh` to revert (or just reboot).

## Checklist (PRP-001 §12 P0)

Probe run 2026-10-20 (GL-XE3000, firmware 4.8.3). "Pending" items need the logging run or compiled code.

| # | Question | Result |
|---|---|---|
| 1 | Does the running dnsmasq read `/tmp/dnsmasq.d`? | **Yes** (`conf-dir=/tmp/dnsmasq.d`). Dir already holds `conntrack` and a `via_domain` symlink from GL.iNet; our drop-in coexists. `logging-on.sh` gate passes |
| 2 | Does `log-dhcp` log option 55 / option 60? | Pending (needs logging run) |
| 3 | Do DHCP log lines match the report script's formats? | Pending |
| 4 | Does the config survive GL.iNet reloads / restarts? | Pending. `/tmp/dnsmasq.d` is tmpfs, so **production must recreate the drop-in at every collector start** (UCI `logqueries`/`logdhcp`/`logfacility` are supported by the init script, but UCI `logqueries` gives plain `log-queries`, not `extra`) |
| 5 | How do the owner's devices roll MACs? | Pending. Leases now: 26 total, 7 randomized (27 %), 19 global |
| 6 | Log growth and RAM impact | Pending. Baseline: ~480 MB RAM, ~230 MB available, 240 MB tmpfs |
| 7 | `ujail` available? | **No** (`procd` and `ubusd` present). PRP §4 changed to privilege separation (root helper for conntrack only, unprivileged parser) |
| 8 | Can another process bind :5353 beside avahi? | Pending (P1). avahi runs as `nobody` on 0.0.0.0:5353 and [::]:5353. Port 1900 is free (no miniupnpd/umdns) |
| 9 | Time sanity | NTP enabled (`pool.ntp.org`); clock was correct at probe time. Boot-time behavior still to confirm in P1 |
| 10 | Collector-killed 24 h RAM test | Pending (watchdog approximates; full test in P1) |
| 11 | Is inbound WAN port 53 dropped? | **Probably.** `wan` zone input policy is DROP and `zone_wan_input` has no accept for 53; GL.iNet also adds `*_drop_leaked_dns` rules. Not tested from outside the LAN. Check no port forward targets 53 |
| 12 | `/etc/sysupgrade.conf` safe for collector secrets? | Keep list holds only `/etc/config/gl_nas/`. `/etc/vigie` would **not** be preserved across a firmware upgrade (key must be re-provisioned or explicitly kept) |

## Other findings

- **`logread` ring buffer is 64 KB** (570 lines now). Query logging would wrap it in minutes; a tmpfs log file is required, confirming PRP §4.
- **conntrack:** `nf_conntrack_acct=1`, `max=16384`, 783 entries; file is `root:root 0440`, probe ran as root. Collector needs a root helper for it.
- **IPv6 is present** (ULA prefix, link-local addresses on `br-lan`). The neighbor table showed 137 entries against 26 leases: it holds several IPv6 addresses per host plus failed/stale entries. The probe's neighbor count was therefore not a device count (probe fixed to count distinct MACs). The collector must map flows and DNS queries to MACs through **both** IPv4 and IPv6 neighbors and dedupe by MAC; IPv6 privacy addresses will rotate too.
- **Guest network** is a separate zone (input REJECT, Allow-DNS and Allow-DHCP rules), so guest clients query the router's dnsmasq and will appear in the same log. Vigie must scope guest-zone devices explicitly.
- **AdGuard Home hooks:** GL.iNet ships firewall rules for AdGuard Home (`*_drop_leak_adgdns`) although AGH is not running. If AGH is enabled in the GL.iNet UI later, dnsmasq stops seeing client queries; the collector needs a health check that raises an event when the DNS log goes quiet.
- **WAN address:** dnsmasq listened on the public WAN IP in the earlier netstat output; the firewall appears to block it (item 11).
