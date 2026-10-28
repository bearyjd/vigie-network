---
title: "Vigie soak 1 failed: tower lost its LAN address, not a router fault"
author: Bearyjd
date: 2026-10-28
branch: docs/trail-learning-soak-cause
cost: { minutes: 27, tokens: 29071 }
---

## Decided
- Supersedes the 2026-10-28 housekeeping note, which said the cause was unknown.
- The real 48h soak (unit vigie-monitoring-20261024-soak-v2) ended 2026-10-26 12:51 PDT after ~30.85h with status fail (dns_probe_failed, invalid_metrics, missing_metrics, parsed_dns_stale). It was healthy for ~31h before that.
- Cause: the tower's wlp9s0f0 DHCP restarted at 12:48:37 PDT and it lost 192.168.1.167 at 12:48:53, 15s after the router's last good POST (12:48:22). The ingest container is published on 192.168.1.167:18443, so the router's collector could not reach it. Router log shows vigie-privdrop "send failed (status None); retry in ~260s" in a loop.
- The tower now reaches the router only via tailscale0 (ip route get 192.168.1.1) and sits on 10.15.12.94. Owner says it is tailscale-only until about 2026-10-28, then back on the LAN.
- Do not repoint the collector or ingest while the tower is off the LAN. It is a live deploy change for a temporary state.

## Tried and ruled out
- Router reboot or collector restart: router_boot_id, collector_start and helper_start never changed in the journal.
- Resource exhaustion: router log fs 16.7 of 20.5 MiB, collector RSS flat at ~2 MiB.
- Server-side errors: ingest, pipeline and API logged none in the window; ingest was just waiting for POSTs.
- A DHCP reservation alone is not the fix while the tower is on a different network. It only helps once the tower is back on 192.168.1.x.

## Watch out
- The metrics key only runs metrics-v1, which exits 70 on the router. Why is unverified. A ps grep for collector|helper showed no separate helper process.
- Router logread tail only reached Oct 27, so the failure moment itself is not visible there. Kernel CheckRxError! spam (MT7981 driver) is probably unrelated.
- Rerun the soak only after the tower is back on 192.168.1.x with a stable address (router DHCP reservation) and the router POSTs resume in the ingest log. The tower must stay on the LAN for the full 48h.
- Consider a soak precheck that fails fast if the ingest address is not bound locally. This run lost ~29h of wall time to a dead endpoint.
- Branch and worktree cleanup done 2026-10-28: ~48 merged branches and ~40 worktrees removed, none in use by a vigie service. Unmerged branches were left in place.
