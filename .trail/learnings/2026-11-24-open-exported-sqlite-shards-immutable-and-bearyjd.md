---
title: Open exported SQLite shards immutable and refuse non-empty WAL or journal sidecars
author: Bearyjd
date: 2026-11-24
branch: feat/e0-endpoint-feasibility
id: l-3ff657e6
scope: repo
status: active
src: agent
touches:
  - tools/endpoint_e0/router.py
---

## Decided
The offline E0 reporter opens raw shard databases with SQLite `immutable=1` so it never creates -shm/-wal sidecars next to the owner's data, and it exits 2 with a "checkpoint or run on a copy" message when a shard has a non-empty -wal or a hot -journal.

## Tried and ruled out
- Plain read-only open: still creates sidecar files for WAL-mode shards and fails with "attempt to write a readonly database" on a read-only directory.

## Watch out
- An immutable open silently ignores committed rows that still sit in the -wal file, so the non-empty-wal refusal is what keeps it from undercounting. It takes no locks, so run it only on a copy nothing is writing to.

In the code: tools/endpoint_e0/router.py shard opening; tests in tools/tests/test_endpoint_e0_*.py.
