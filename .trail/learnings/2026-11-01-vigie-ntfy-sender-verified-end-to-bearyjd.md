---
title: Vigie ntfy sender verified end to end on the real phone (2026-11-01)
author: Bearyjd
date: 2026-11-01
branch: main
cost: { minutes: 63, tokens: 942939 }
touches:
  - ".omc/RESUME.md"
---

## Decided
- The standalone sender (deploy/persistent/ntfy_sender.py, PR #49) works for real: dry run under `podman unshare python3 -I ntfy_sender.py CONFIG --once` (delivery file absent -> sent=0 exit 0), then one test record built from the writer's own TITLES/BODIES templates reached the owner's phone via public ntfy.sh (sent=1, 200), and a repeat run sent nothing (cursor advanced to end of file).
- Topic is a 32-char random string in ~/.config/vigie-ntfy/topic (0600). The owner creates it with a silent `!` command; never print it in chat (`!` output lands in the conversation) and check only owner/mode/length. Readable names are not acceptable on public ntfy.sh: the topic is the only access control and spoofed alerts are the main risk; a display name in the app gives readability.
- The shell here is a distrobox: host podman/systemd calls need `distrobox-host-exec`; `systemd-run -p` does not expand %t/%h specifiers.

## Tried and ruled out
- Mount-namespace sandbox directives in the sender unit (PrivateTmp, ProtectSystem, ...) break `podman unshare`; found by bisecting with `systemd-run --user`, not by reasoning.
- A plain host-side unit reading the delivery file: it is owned by a container subuid with mode 0600.

## Watch out
- Delivery is still OFF: the pipeline needs VIGIE_DELIVERY_ENABLED/VIGIE_DELIVERY_FILE (live pipeline restart; do after soak 2 ends 2026-11-02 18:49 UTC) and the timer/service are not installed.
- Test files remain in ~/.local/state/vigie-ntfy/test/ until the owner says to delete them.
