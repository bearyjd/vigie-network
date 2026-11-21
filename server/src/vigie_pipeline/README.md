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
- Retired-MAC prune (irreversible; code in `prune.py`). `transient_state.since` means "since the
  current status began". Every retirement stamps it with the SERVER clock at the transition, but
  never earlier than the newest `batches.received_at` nor the newest `collectors.last_sent_ts` (the
  latter is never purged, so a clock set back cannot backdate a stamp even after the batch rows
  are gone; neither recorded means the clock itself). A stamp more than a day ahead of the server
  clock (a batch received under a stepped-forward clock: those devices cannot be pruned until that
  date) is named once per sweep that retires something, WARNING `retirement_stamp_ahead`: the transient sweep reads the clock again
  after the batches, and the stitcher stamps the orphan it retires. A retired device keeps its
  stamp, a revival rewrites it. A collector timestamp (`observations.last_seen`) is untrusted; it
  only adds a second condition (older than the cutoff too). A device's self-linked `observations`
  rows are deleted 90 days after the stamp, at most `PRUNE_BATCH_ROWS` rows per pass, oldest
  retirement first; the device row stays, and the MAC's `mac_last_ip` row goes with it. Each pass
  logs `retired_macs_pruned count=N` (a count, never a MAC) and adds N to
  `pipeline_meta.retired_mac_rows_pruned`. A retired device without a stamp (retired before stamps
  existed, or by a build rolled back to) is not prunable until stamped: the sweep stamps such
  devices with the current clock once a day (`stitch_state` key `retired_stamp_backfilled` holds
  the time of the last scan; one from the future counts as due), so they become prunable 90 days
  after that. `monitoring_assignment_versions`, `monitoring_dirty`, `characterization_*`,
  `mac_first_received` and `mac_activity` are left alone (own retention or own meaning); a test
  classifies every column of both databases that names a device or MAC, directly or through a
  suggestion, incident or candidate id, a target or a lineage, as protected, excluded or left alone
  with a reason, so a new one cannot slip by. Accepted trade-off: a randomized MAC that returns
  after its rows were pruned starts over as a new transient device with a NEW id instead of
  reviving the old one (nothing the owner decided is affected: see Protected).
  - Clock. The 90 days are counted on the older of the server's `now` and the oldest
    `collectors.last_sent_ts` of the non-revoked collectors that ever sent. Ingest keeps that
    column as a never-purged running maximum of accepted send times and accepts a send time only
    within its skew window of the server clock, so a stepped server clock cannot drag it along
    for a collector that kept true time, and purging batch rows does not erase it. No such
    collector prunes nothing. Consequence: a collector that falls silent, or is retired without
    being revoked, holds the clock back until it is revoked; the pass then logs the WARNING
    `prune_clock_held_back` naming that collector once its last send is more than 7 days old
    (every pass while it holds). With a single collector that follows a stepped server clock
    nothing can tell, and that case is accepted.
  - Fails closed. It runs only when `overrides.db` exists, opens read-only, is at exactly the
    supported schema version (a reviewed literal, `SUPPORTED_USER_VERSION`), has every table the
    protected read needs and holds only non-empty text ids; otherwise it logs `prune_skipped`
    (error text only) and deletes nothing. A missing `overrides.db` is normal before the API
    first ran and logs at DEBUG only (at ERROR once either marker below is set: a lost file);
    a file that exists but is unusable logs at ERROR. A busy or
    locked inventory skips the prune and the rest of the pass still runs. A pass in which any
    batch could not be read (`failures`) skips the prune. A lost `overrides.db`: once a read has
    found a decision that does not expire (any protected source except incident decisions, which
    the API deletes with their incident) the pipeline sets the `stitch_state` marker
    `prune_overrides_seen`; if a later read finds none at all the prune is skipped and logged at
    ERROR (`overrides_lost_decisions`: the file was probably lost or recreated empty). An install
    that never had a decision prunes as usual. A rolled-back `overrides.db`: the pipeline also
    keeps the file's largest `audit_log.seq` (AUTOINCREMENT, written with every decision) as the
    `stitch_state` row `prune_overrides_audit_mark`; a read that shows a smaller one, or a mark
    that cannot be read, skips the prune and logs ERROR `overrides_rolled_back` (an older backup
    restored over the file, or a file recreated and given one new decision, which the presence
    marker cannot tell). If the owner really did remove every decision, or restored a backup on
    purpose, delete the marker rows (`prune_overrides_seen`, `prune_overrides_audit_mark` and
    `prune_overrides_latched`) to resume. Either finding is latched in `prune_overrides_latched`
    (later passes log ERROR `overrides_latched`): the audit counter catching up through unrelated
    audit rows does not show the lost decisions came back, so until the rows are deleted nothing is
    pruned.
  - Re-check. The protected set is read on a connection opened for the prune alone (no earlier
    stage's open cursor can hold its `PRAGMA data_version` still), with the file's st_dev/st_ino
    taken before the open. Inside the write lock, after the deletes and before `COMMIT`, both are
    read again: a commit, removal or replacement since, or an inability to ask, rolls the whole
    pass back and logs `prune_deferred reason=overrides_changed`.
  - Protected (never pruned): devices that `overrides.db` refers to (named or grouped, marked
    essential, targeted by an identity rule, named by an incident decision or a candidate
    decision, on either end of any identity merge or link, undone or revoked ones included) and
    the devices of every suggestion the owner accepted or rejected (`suggestion_decisions` is
    keyed by suggestion id, so the inventory's `suggestions` row names the devices), whatever its
    action and whether or not it expired. An incident decision, cleared ones included, protects
    while its row exists; the API deletes the row together with its incident. Also excluded while
    an inventory row still names the device or MAC: `identity_candidates` (either end) while
    `open`, `suggested` or in a state this build does not know (`dismissed`, `vetoed` and
    `cleared` do not pin: a veto is keyed by device id and the row survives the MAC rows, and the
    owner's decision lives in `candidate_decisions`, protected above); an `open` or `suggested`
    candidate settles when a rule settles its MAC or fresh evidence rewrites it, and one that
    never does keeps that device's MAC rows for good, an accepted limit (a few rows, never a wrong
    deletion); `suggestions` of any action while unexpired on the trusted clock;
    `monitoring_profiles`, `monitoring_incidents`, `monitoring_suspicious` and
    `monitoring_unavailable` (by device); `measurements_hourly` and `monitoring_dirty` (by MAC);
    and `rule_attachments`. Only `link_source='self'` rows of `retired` devices qualify.
  - Accepted, monitoring: `monitoring_profiles` is upserted for every analysed MAC and never
    deleted, so on an install with monitoring a device that was ever measured (any flow or DNS
    traffic, visitor phones included) is never pruned; only devices monitoring never analysed
    are. This errs on the safe side and is a documented limit, not a bug.
  - Accepted, events: the prune deletes observation rows, not `events`. The `new_device` and
    `device_reappeared` events (and `identity_conflict`, as a short hash) carry the MAC in their
    `summary`, joined to the surviving device row by `device_id`, and stay until event retention
    exists (not implemented, see docs/deploy.md). Redacting them would need a scan of `events`
    (no index leads with `device_id` for those kinds) which the prune lock must not do.
  - Cost: candidates are selected before the write lock (protections applied in SQL, so a
    protected oldest batch cannot starve the limit); inside the lock there is one point-lookup
    DELETE per candidate repeating the whole predicate, then the `overrides.db` re-check, the
    counter bump and the commit. No statement inside that lock scans `observations`, `devices`
    or `batches`.
  - Accepted residual: `overrides.db` and `inventory.db` cannot share a transaction. A human
    decision committed after the final `data_version` read and before `COMMIT` (a window of
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
