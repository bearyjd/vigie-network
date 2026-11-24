---
title: "E0 feasibility reporter: LAN must be declared, not is_private"
author: Bearyjd
date: 2026-11-24
branch: feat/e0-endpoint-feasibility
id: l-8f007c20
scope: repo
status: active
src: agent
touches:
  - tools/endpoint_feasibility.py
  - scripts/ci.sh
---

tools/endpoint_feasibility.py (package tools/endpoint_e0) decides LAN, router and WAN destinations from the scope's declared lan_prefixes and router_ips, never ipaddress is_private: Python 3.12 marks the documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32 private, so synthetic WAN keys vanished and the denominator collapsed to zero. A private address off the declared LAN (a VPN peer) stays eligible. raw_flow.ts is the batch window_end, so the key window comes from the batches row joined on (collector_id, batch_id). The tool is stdlib only because CI runs bare uvx pytest over tools/tests, and tools/*.py is not covered by any ruff run in scripts/ci.sh.
