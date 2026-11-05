---
title: "Resuming Vigie during soak 3: read-only check only"
author: Bearyjd
date: 2026-11-05
branch: main
cost: { minutes: 1, tokens: 52301 }
touches:
  - ".omc/STATE.md"
---

## Decided
After /clear, read head of .omc/STATE.md (RESUME HERE), then do only the read-only soak check: ssh to vigie-dev, `sudo -n -u vigie env XDG_RUNTIME_DIR=/run/user/1001 HOME=/home/vigie systemctl --user is-active vigie-soak.service`, tail the journal and journal.jsonl row count. Soak 3 started 2026-11-05T02:01:19Z, earliest end 2026-11-07T02:01Z.

## Tried and ruled out
Nothing deployed or restarted. Redeploying main, ntfy apply and apt timer restore all wait until the soak ends and the owner approves.

## Watch out
The journal shows one failed start at 02:00:55Z (systemd-inhibit: Access denied) followed by a good start at 02:01:19Z; it is not a restart during the run. Do not touch router, collector, VM or units until the soak ends.
