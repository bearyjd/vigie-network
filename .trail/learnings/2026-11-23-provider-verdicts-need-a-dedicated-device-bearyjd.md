---
title: Provider verdicts need a dedicated device binding before local attribution
author: Bearyjd
date: 2026-11-23
branch: feat/nextdns-verdict-context
id: l-c8f33506
scope: repo
status: active
src: agent
touches:
  - docs/roadmap.md
  - collector/agent/src/log_poll.rs
  - server/src/vigie_ingest/store.py
  - deploy/compose.yaml
---

## Decided

A NextDNS event can add context to a router DNS observation only if the owner can attest an exclusive, time-bounded binding from the provider log device ID to the observed collector and MAC. Compare raw events on both sides before filtering to threat-feed verdicts. Keep the first slice a manual report that can read the ingest shards without expanding API mounts.

## Tried and ruled out

A router-wide provider ID plus a unique observed name and timestamp can misattribute a block. The collector drops queries from clients whose IP cannot be mapped to a MAC, and a known device can ask for the same name from cache. Filtering provider logs by blocked status or device ID first can also hide competing events.

## Watch out

A collector timestamp is the dnsmasq tail-poll time, and ingest can clamp it to a window edge. A unique match is bounded evidence, not an authenticated transaction. Documented raw log pagination and the exact reason ID matter. The provider's settings keys and UI labels do not define log reason IDs.

In the code: collector/agent/src/log_poll.rs and dnsmasq.rs assign poll times and retain mapped queries. server/src/vigie_ingest/store.py clamps raw timestamps. deploy/compose.yaml omits raw shards from the API mount. docs/nextdns.md describes the operator report and provider evidence.
