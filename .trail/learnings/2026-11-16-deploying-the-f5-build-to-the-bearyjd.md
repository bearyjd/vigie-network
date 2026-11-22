---
title: "Deploying the F5 build to the pilot VM: which image takes the pre-deploy backup"
author: Bearyjd
date: 2026-11-16
branch: main
cost: { minutes: 2, tokens: 2006 }
id: l-9ab80588
scope: repo
status: active
src: agent
touches:
  - docs/deploy.md
  - server/src/vigie_pipeline/new_device_notice.py
---

## Decided
The backup tool needs an exact overrides schema version match, so the safety backup before the v10 migration must be taken with the image that still expects v9 (the already-loaded fix image), not the new build. Rollback after the migration is the old image plus restoring that backup; swapping the image alone does not work. Housekeeping done 2026-11-15: ten merged remote feature branches deleted, no stale worktrees existed.

## Tried and ruled out
Taking the backup with the new image: it refuses a v9 overrides file. Deleting the scratch replay directories without being asked: left for the owner.

## Watch out
In the code: docs/deploy.md has the deploy order (backup with the old image first); server/src/vigie_pipeline/new_device_notice.py derives its resume gap from the pipeline pass interval (the pilot VM loops every 30 s), and its flag VIGIE_NEW_DEVICE_NOTICE goes into the pipeline quadlet on the VM, not compose. Enabling F5 means deploying a build the VM does not run yet (live migration plus restarts), not a flag flip. Delivery and ntfy stay off when F5 is first enabled so notices only reach the inbox.
