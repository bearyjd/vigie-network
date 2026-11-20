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
Monitoring: `VIGIE_MONITORING_LARGE_UPLOAD_BYTES` (1 GiB) and `VIGIE_MONITORING_BASELINE` (`pooled`
default, or `tod`; exact match, anything else fails at startup; a change relearns every profile;
see `docs/monitoring.md`).

## Trust model
- A hostname never promotes a device. A transient device is promoted only after it was received
  in >= 2 distinct server hours (`batches.received_at`) and its first-to-last-seen dwell is >= the
  minimum, at most `promotion cap` per server hour (extra devices stay transient and one
  `promotion_rate_limited` event is emitted per hour). Unpromoted transients are retired after the
  window; a retired device seen again returns to transient (`device_reappeared`).
- Retired-MAC prune (irreversible). `transient_state.since` means "since the current status
  began": every retirement stamps it with the SERVER clock at the moment of the transition (the
  transient sweep reads the clock again after the batches; the stitcher stamps the orphan it
  retires), a retired device keeps it, a revival rewrites it, so a device revived and retired
  again restarts its clock. A collector timestamp (`observations.last_seen`) is untrusted and
  never sets the age by itself. A device's self-linked `observations` rows are deleted 90 days
  after that stamp, at most `PRUNE_BATCH_ROWS` rows per pass, oldest retirement first; the device
  row stays. A device retired before the stamp existed has none and is not prunable: ONE backfill
  (marker `stitch_state` key `retired_stamp_backfilled`, never repeated) stamps it, so on an
  existing install such devices become prunable only 90 days after that pass. Each pass logs
  `retired_macs_pruned count=N` (a count, never a MAC) and adds N to
  `pipeline_meta.retired_mac_rows_pruned`; the pruned MAC's `mac_last_ip` row goes with it.
  `monitoring_assignment_versions`, `monitoring_dirty`, `characterization_*`,
  `mac_first_received` and `mac_activity` are left alone (own retention or own meaning); a test
  classifies every column of both databases that names a device or MAC as protected or left
  alone, so a new one cannot slip by. A MAC that returns starts over as a new transient.
  - Clock guard: the 90 days are counted on the MINIMUM of the server's `now`, the newest
    `mac_activity` end, and every collector's own newest batch time (`window_end` of its newest
    recorded batch, its receipt for a legacy row). activity.py accepts a stamp only within a
    window around the batch receipt, so after a forward step of the server clock alone, or of a
    collector alone, nothing new is accepted and the frontier, hence the cutoff, stops; a single
    collector that followed the server's step cannot corroborate it. No activity or no recorded
    batch prunes nothing. Consequence: a collector that goes silent holds the clock back until
    its last batch is purged (7 days), so the prune waits (fails safe), never runs early.
  - Fails closed. It runs only when `overrides.db` exists, opens read-only, is at exactly the
    supported schema version (a reviewed literal, `SUPPORTED_USER_VERSION`), has every table the
    protected-device query reads and holds only non-empty text device ids; otherwise it logs
    `prune_skipped` (error text only) and deletes nothing. A missing `overrides.db` is normal
    before the API first ran and logs at DEBUG only; a file that exists but is unusable logs at
    ERROR. A busy or locked inventory skips the prune and the rest of the pass still runs.
  - Deferred (the pass rolls back and logs `prune_deferred` with a reason, retried next pass):
    `overrides_changed` when `overrides.db` committed (`PRAGMA data_version` on a connection
    opened for the prune alone, so no earlier stage can hold it still), was removed or was
    replaced (st_dev/st_ino taken before the open, re-read inside the lock) since the protected
    set was read, or cannot be asked; `batches_unsettled` when a batch cannot be shown processed:
    one arrived during the pass above a cursor that does not cover it, the newest batch was
    purged or its rowid reused, a collector's cursor names no real row of its batch table (the
    `_pending` check, so a stale cursor after retention cannot make a returning batch look done),
    a batch was unreadable, or a batch was read after ingest retention had removed its raw
    shards. Any of these would turn a returning MAC into a new device instead of a revived one.
  - Protected (never pruned): devices that `overrides.db` refers to (named or grouped, marked
    essential, targeted by an identity rule, named by an incident decision or a candidate
    decision, or on either end of any identity merge or link, undone or revoked ones included).
    A cleared incident decision still protects while its row exists, but the API deletes
    `incident_decisions` rows together with their incident (120 days, after the pipeline pruned
    it), so that protection ends with the incident. Also excluded while any inventory row still
    names the device or MAC: `identity_candidates` (either end) in every state but `dismissed`,
    `suggestions` of the label, move_group, quarantine and merge_identity actions only while
    unexpired on the corroborated clock, `monitoring_profiles`, `monitoring_incidents`,
    `monitoring_suspicious` and `monitoring_unavailable` (by device), `measurements_hourly` and
    `monitoring_dirty` (by MAC), and `rule_attachments`. A dismissed candidate and an expired
    suggestion no longer pin a device because neither table is ever deleted from; the owner's
    decision about the pair lives in `candidate_decisions` and `identity_merges` (protected
    above). Only `link_source='self'` rows of `retired` devices qualify, and the row's collector
    `last_seen` must also be older than the cutoff.
  - Cost: candidates are selected before the write lock (protections applied in SQL, so a
    protected oldest batch cannot starve the limit); inside the lock the batch check (rowid
    range seek above the pass's mark plus a walk of the few collectors) runs, then one
    point-lookup DELETE per candidate repeating the whole predicate, then the `overrides.db`
    re-check, the counter bump and the commit. No statement inside that lock scans
    `observations`, `devices` or `batches`.
  - Accepted residual: `overrides.db` and `inventory.db` cannot share a transaction. A human
    decision committed after the final `overrides.db` re-check and before `COMMIT` (a window of
    microseconds) is not seen and can still lose its MAC. Closing it would need a write lock on
    `overrides.db`, which the pipeline deliberately never holds.
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
  per UTC day. The post-attach re-check flags (`rule_attach_suspect`, once per MAC and reason) on
  sustained overlap with the peers of its attach-time evidence, on incomplete evidence, and when
  the rule or group no longer authorises the attachment. Names are compared through one Unicode
  fold stored in `observations.hostname_fold`/`mdns_fold`.
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
- Ingest owns `devices`/`observations`/`collectors`/`batches`; the pipeline verifies their schema
  version and refuses to run (or to downgrade) unless `--migrate` is given.
- Identity stitching does not yet include behavioural demotion (needs the features stage) and
  never detaches; accept/merge/undo are API work. See `docs/stitching.md`.
