# vigie-pipeline (P1 core) ops notes

```sh
export VIGIE_DATA_DIR=/var/lib/vigie
uv run python -m vigie_pipeline run --once          # one pass, exit 1 on unreadable shard/schema
uv run python -m vigie_pipeline run --loop 30       # repeat every 30 s; failures are logged and retried
# first start on an empty data dir: --migrate lets the pipeline apply ingest's migrations
```

Settings (flag / env): `--transient-window-s` / `VIGIE_TRANSIENT_WINDOW_S` (24 h),
`--min-dwell-s` / `VIGIE_TRANSIENT_MIN_DWELL_S` (2 h), `--promotion-cap` /
`VIGIE_PROMOTION_CAP_PER_HOUR` (20). `0` for the window is an error.

## Trust model
- A hostname never promotes a device. A transient device is promoted only after it was received
  in >= 2 distinct server hours (`batches.received_at`) and its first-to-last-seen dwell is >= the
  minimum, at most `promotion cap` per server hour (extra devices stay transient and one
  `promotion_rate_limited` event is emitted per hour). Unpromoted transients are retired after the
  window; a retired device seen again returns to transient (`device_reappeared`).
- `dhcp_fingerprint` / `vendor_class` are first-wins. A differing value for the same MAC is not
  stored; the device is set to `identity_state='conflict'` and one `identity_conflict` event per
  (device, field) per day is emitted (short hashes only). Hostnames may change freely.

## overrides.db and file permissions
The pipeline opens `overrides.db` with `mode=ro` plus `PRAGMA query_only=ON` and never writes
data pages. `overrides.db` is expected to be in WAL mode (written by `vigie-api`). Reading a WAL
database may still create or touch the `-wal` / `-shm` sidecar files, so the pipeline and the API
**must run as the same uid/group** (or the data directory must otherwise allow the pipeline to
create the sidecars); a pipeline that cannot create `-shm` cannot read a WAL database.
Precisely: the `overrides.db` file bytes are never modified by the pipeline (a test asserts it), but a
read-only open of a WAL database creates `overrides.db-wal` and `overrides.db-shm` beside it; those
are SQLite bookkeeping, not data. Each run reads its snapshot inside one `BEGIN`/`COMMIT` read
transaction, so rules, groups, versions and decisions are mutually consistent.

## Identity stitching
After each `run_once` has folded new batches into `observations`, a stitching pass runs in two
phases (full design, formula, bounds and threat table: [`docs/stitching.md`](../../../docs/stitching.md);
rationale: [`docs/stitching-design.md`](../../../docs/stitching-design.md)): a read-only COMPUTE
that never blocks writers and turns at most `MACS_PER_PASS` (256) rule-attached MACs and 256 self
MACs (round-robin, persisted cursors) into decisions, then one short, count-bounded `BEGIN
IMMEDIATE` APPLY that re-reads `overrides.db` and re-validates every decision before writing.

- **Activity.** Row timestamps (leases, neighbours, DNS, flows) are folded per MAC into
  `mac_activity (mac, start, end)` intervals (a silence over 5 min splits an interval; 7 d
  retention; at most 64 rows per MAC, the smallest silences coalesced). Stamps outside
  [received - 1 h, received + 300 s] are ignored in every batch. `mac_first_received` holds the
  SERVER time a MAC was first received; activity earlier than that minus 1 h is clipped when loaded.
  Stamps dropped for the lag are recorded in one merged `evidence_gaps` list (any collector): a MAC
  whose activity window overlaps a gap is not mature. Derived data; safe to drop.
- **Candidates.** A randomized, self-linked MAC is compared with the MACs of its (opt55, opt60,
  name) buckets. Required: opt55 AND opt60 equal and non-empty, plus hostname OR mDNS name equal.
  Rows go to `identity_candidates` (`open|suggested|ambiguous|vetoed|dismissed`); full values only
  in its `evidence` column.
- **Ambiguity / veto.** Two matching devices active together beyond the grace window (default
  600 s) make the signature `ambiguous`; a **mature** candidate whose overlap with the matching
  devices exceeds the grace, covers all of its own time, or leaves it under half a gap of its own
  is `vetoed` (permanent; only a human `dismissed` state clears it). Mature = more than the grace
  of covered time AND first received by the server more than the grace ago AND no evidence gap in
  its window; an immature MAC is never rule-attached and its overlap stays provisional (`open`).
- **Standing rules.** `identity_rules` (read-only) attach a mature randomized self MAC to the
  rule's canonical device (`link_source='rule'`, `mac_attached`, orphan retired, its candidate rows
  dismissed and its suggestions expired) only if exactly one device's active rule matches, there is
  no sustained overlap with the peers derived from the rule and the target identity, the rule is
  still active and the target still in an explicit `auto_inherit=1` group when re-read under the
  lock, and both devices are `identity_state='ok'`. Otherwise a `rule_hit_needs_confirm`
  suggestion. Human-ness of a rule is enforced by the API alone (sole writer of `identity_rules`).
  Revoking or expiring a rule never detaches.
- **Incomplete evidence degrades.** A lookup over `BUCKET_ROWS` (1024) rows, a merge component
  over `MAX_ALIAS_IDS`, a target with over `TARGET_KEYS` signatures, an evidence gap or a malformed
  rule on the target turn a rule hit into a `rule_hit_needs_confirm` suggestion (`reason_text`
  names the cause) or a provisional row, never an attach; one `stitch_deferred` event per reason
  per UTC day. The post-attach re-check flags (`rule_attach_suspect`, once per MAC) on sustained
  overlap with the peers of its attach-time evidence, and on incomplete evidence.
- **Fail closed.** overrides.db absent: no rules, basis versions 0. Present but unreadable or
  malformed: stitching is skipped for the run (`stitching_skipped`, once a day), the batches are
  processed with no identity links and the cursor advances.
- **Bounds.** Name groups and compatible pools over 64 live self MACs are floods
  (`signature_flood`, once per group per day); at most 200 candidate/suggestion/widen rows, 20
  attaches and 64 open suggestions per target device per pass; the compute phase stops between
  subjects after 5 s. All constants are in `config.py`.
- **Config.** `VIGIE_STITCH_THRESHOLD` (0.8), `VIGIE_OVERLAP_GRACE_S` (600), `VIGIE_ACTIVITY_GAP_S`
  (300); weights are the constants `SIGNAL_WEIGHTS` in `config.py`.
- **Events.** `identity_candidate`, `identity_candidate_ambiguous`, `identity_overlap_veto`,
  `mac_attached`, `rule_attach_suspect`, `signature_flood`, `stitch_deferred`, `rule_malformed`,
  `stitching_skipped`. Hostnames, fingerprints and MACs appear only as short hashes.

## Known gaps
- 90-day pruning/aggregation of retired transient MAC rows (PRP section 8 housekeeping) is NOT
  implemented; see the strict-xfail test `test_retired_transient_mac_rows_are_pruned_after_90_days`.
  `observations` and `transient_*` rows grow until it lands.
- Ingest owns `devices`/`observations`/`collectors`/`batches`; the pipeline verifies their schema
  version and refuses to run (or to downgrade) unless `--migrate` is given.
- Identity stitching does not yet include behavioural demotion (needs the features stage) and
  never detaches; accept/merge/undo are API work. See `docs/stitching.md`.
