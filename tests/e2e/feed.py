#!/usr/bin/env python3
"""Feeds the e2e collector with fixture inputs, in timed steps (stdlib only).

The agent tails the dnsmasq log from its END on the first poll, so everything is appended AFTER
the agent has started. The neighbor table is served by a wrapper `ip` script that prints
$VIGIE_E2E_NEIGH_FILE; this script rewrites that file and the leases file between steps.

Devices (all fictional):
  laptop   3c:22:fb:11:22:33  192.168.1.20  host alice-laptop   (stable, global MAC)
  camera   ec:71:db:aa:bb:cc  192.168.1.30  host cam-front      (periodic queries)
  phone    c2:11:22:33:44:01/02/03 (locally administered, rolling) 192.168.1.50 host Pixel-8,
           same opt55 and vendor class on every MAC; one MAC per step

Usage: feed.py ROOT STEP_SECONDS
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

LAPTOP = ("3c:22:fb:11:22:33", "192.168.1.20", "alice-laptop")
CAMERA = ("ec:71:db:aa:bb:cc", "192.168.1.30", "cam-front")
PHONE_MACS = ("c2:11:22:33:44:01", "c2:11:22:33:44:02", "c2:11:22:33:44:03")
PHONE_IP, PHONE_HOST = "192.168.1.50", "Pixel-8"
PHONE_OPT55 = "1:netmask, 3:router, 6:dns-server, 15:domain-name, 26:mtu, 28:broadcast, 51:lease-time, 58:T1, 59:T2"
LAPTOP_OPT55 = "1:netmask, 3:router, 6:dns-server, 15:domain-name, 119:domain-search, 121:classless-static-route"
CAMERA_OPT55 = "1:netmask, 3:router, 6:dns-server"
CAMERA_VENDOR = "udhcp 1.31.1"

_serial = [5000]


def _stamp() -> str:
    t = time.localtime()
    return f"{time.strftime('%b', t)} {t.tm_mday:2d} {time.strftime('%H:%M:%S', t)}"


def _next() -> int:
    _serial[0] += 1
    return _serial[0]


def dhcp_block(mac: str, ip: str, host: str, opt55: str, vendor: str | None) -> list[str]:
    n, p = _next(), f"{_stamp()} dnsmasq-dhcp[5023]: "
    lines = [f"{p}{n} DHCPREQUEST(br-lan) {ip} {mac}"]
    if os.environ.get("VIGIE_E2E_NO_TAGS") != "1":  # real dnsmasq emits this line (F1, fixed)
        lines.append(f"{p}{n} tags: br-lan")
    lines.append(f"{p}{n} requested options: {opt55}")
    if vendor:
        lines.append(f"{p}{n} vendor class: {vendor}")
    lines += [
        f"{p}{n} client provides name: {host}",
        f"{p}{n} DHCPACK(br-lan) {ip} {mac} {host}",
    ]
    return lines


def dns_pair(client_ip: str, name: str, answer: str) -> list[str]:
    n, p = _next(), f"{_stamp()} dnsmasq[5023]: "
    return [
        f"{p}{n} {client_ip}/40000 query[A] {name} from {client_ip}",
        f"{p}{n} {client_ip}/40000 reply {name} is {answer}",
    ]


def append(path: Path, lines: list[str]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_state(root: Path, phone_mac: str) -> None:
    exp = int(time.time()) + 3600
    leases = [
        f"{exp} {LAPTOP[0]} {LAPTOP[1]} {LAPTOP[2]} *",
        f"{exp} {CAMERA[0]} {CAMERA[1]} {CAMERA[2]} *",
        f"{exp} {phone_mac} {PHONE_IP} {PHONE_HOST} *",
    ]
    (root / "dhcp.leases").write_text("\n".join(leases) + "\n", encoding="utf-8")
    neigh = [
        f"{LAPTOP[1]} dev br-lan lladdr {LAPTOP[0]} REACHABLE",
        f"{CAMERA[1]} dev br-lan lladdr {CAMERA[0]} REACHABLE",
        f"{PHONE_IP} dev br-lan lladdr {phone_mac} REACHABLE",
    ]
    (root / "neigh.txt").write_text("\n".join(neigh) + "\n", encoding="utf-8")


def main() -> int:
    root, step_s = Path(sys.argv[1]), int(sys.argv[2])
    log = root / "dnsmasq.log"
    for i, mac in enumerate(PHONE_MACS):
        write_state(root, mac)
        lines = dhcp_block(mac, PHONE_IP, PHONE_HOST, PHONE_OPT55, "android-dhcp-14")
        if i == 0:
            lines += dhcp_block(*LAPTOP[0:1], LAPTOP[1], LAPTOP[2], LAPTOP_OPT55, None)
            lines += dhcp_block(CAMERA[0], CAMERA[1], CAMERA[2], CAMERA_OPT55, CAMERA_VENDOR)
        append(log, lines)
        for tick in range(step_s):
            q = dns_pair(CAMERA[1], "cam.vendor.example", "203.0.113.5")
            if tick % 3 == 0:
                q += dns_pair(PHONE_IP, "play.googleapis.com", "142.250.0.1")
            if tick % 4 == 0:
                q += dns_pair(LAPTOP[1], "news.example.org", "198.51.100.7")
            append(log, q)
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
