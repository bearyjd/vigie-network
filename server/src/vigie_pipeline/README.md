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

## Identity stitching
After each `run_once` has folded new batches into `observations`, a stitching stage runs in one
transaction (full design, formula and limits: [`docs/stitching.md`](../../../docs/stitching.md)).

- **Activity.** Row timestamps (leases, neighbours, DNS, flows) are folded per MAC into
  `mac_activity (mac, start, end)` intervals (a silence over 5 min splits an interval; 7 d
  retention; pipeline schema v4). Derived data; safe to drop.
- **Candidates.** A randomized, self-linked MAC is compared with every other MAC. Required:
  opt55 AND opt60 equal and non-empty, plus hostname OR mDNS name equal. Anything weaker is not a
  candidate, so a hostname alone never is. Rows go to `identity_candidates`
  (`open|suggested|ambiguous|vetoed|dismissed`); full values only in its `evidence` column.
- **Ambiguity / veto.** Two matching devices that were active together beyond the grace window
  (default 600 s) make the signature `ambiguous`; a candidate whose own sustained overlap with the
  matching devices exceeds the grace is `vetoed`. Neither produces a suggestion.
- **Suggestions.** A unique, non-vetoed candidate scoring >= 0.8 gets one immutable
  `merge_identity` suggestion (`fingerprint_match`, basis = current override versions from
  overrides.db). Nothing is merged: a human accepts via the API (next round).
- **Standing rules.** `identity_rules` (read-only) attach a randomized self MAC to the rule's
  canonical device (`link_source='rule'`, `mac_attached` event, orphan device retired) only if
  exactly one device's active rule matches, there is no sustained overlap, and the device's group
  has `auto_inherit=1` or it has no group. `auto_inherit=0` raises a `rule_hit_needs_confirm`
  suggestion instead. Revoking or expiring a rule never detaches an existing attachment.
- **Fail closed.** overrides.db absent: no rules, basis versions 0. Present but unreadable:
  stitching is skipped for that run (`stitching_skipped` at ERROR) and the rest of the run goes on.
- **Config.** `VIGIE_STITCH_THRESHOLD` (0.8), `VIGIE_OVERLAP_GRACE_S` (600), `VIGIE_ACTIVITY_GAP_S`
  (300); weights are the constants `SIGNAL_WEIGHTS` in `config.py`.
- **Events.** `identity_candidate`, `identity_candidate_ambiguous`, `identity_overlap_veto`,
  `mac_attached` (hostnames, fingerprints and MACs appear only as short hashes).

## Known gaps
- 90-day pruning/aggregation of retired transient MAC rows (PRP section 8 housekeeping) is NOT
  implemented; see the strict-xfail test `test_retired_transient_mac_rows_are_pruned_after_90_days`.
  `observations` and `transient_*` rows grow until it lands.
- Ingest owns `devices`/`observations`/`collectors`/`batches`; the pipeline verifies their schema
  version and refuses to run (or to downgrade) unless `--migrate` is given.
- Identity stitching does not yet include behavioural demotion (needs the features stage) and
  never detaches; accept/merge/undo are API work. See `docs/stitching.md`.
