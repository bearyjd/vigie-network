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

| # | Question | How answered | Result |
|---|---|---|---|
| 1 | Does the running dnsmasq read `/tmp/dnsmasq.d`? | probe: generated config | |
| 2 | Does `log-dhcp` log option 55 (`requested options:`) and option 60 (`vendor class:`)? | log after step 3 | |
| 3 | Do DHCP log lines match the formats `mac-roll-report.sh` assumes? (`parsed ACKs` > 0) | report | |
| 4 | Does the config survive GL.iNet reloads / dnsmasq restarts / `network reload`? | restart check after step 2; reboot reverts by design | |
| 5 | How do the owner's devices roll MACs (per SSID / connection / day)? | report: groups with 2+ MACs; compare over 48 h | |
| 6 | Log growth rate (MB/day) and RAM impact | step 5 | |
| 7 | `ujail` available? | probe | |
| 8 | Can another process bind :5353 beside avahi (`SO_REUSEPORT`)? | needs a Rust test binary; deferred to P1 collector spike | |
| 9 | Time sanity after boot (NTP) | probe | |
| 10 | Collector-killed-24 h RAM test | watchdog in `logging-on.sh` approximates it; full test in P1 | |
| 11 | Is inbound WAN port 53 dropped? | probe: firewall section; confirm from outside the LAN | |
| 12 | Is `/etc/sysupgrade.conf` free of paths that would carry collector secrets? | probe | |

## Findings

_To be filled in from the router output._
