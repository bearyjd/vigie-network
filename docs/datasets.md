# Offline known-issue datasets (staging, accept, reject)

Units 3a and 3b of the exposure-evidence proposal in [roadmap.md](roadmap.md) (decisions D7-D9).
**Nothing is fetched and nothing is applied yet.** An operator downloads a dataset by hand and
stages the file, then accepts or rejects it by hand; scheduled fetch, any reader and device
mapping are later units. Accepting changes status only: no reader uses these tables yet.

```
python -m vigie_api dataset stage --source kev|urlhaus --file PATH --version V --licence L [--data-dir D]
python -m vigie_api dataset list [--data-dir D]
python -m vigie_api dataset accept IMPORT_ID [--by WHO] [--force] [--data-dir D]
python -m vigie_api dataset reject IMPORT_ID [--by WHO] [--reason TEXT] [--data-dir D]
```

`stage` reads the file bounded (per-source input cap, regular files only, no symlinks, no
controlling tty), parses it strictly and writes in ONE transaction an import row, its entries
and one `dataset.stage` audit row (source, version, sha256, content_sha256, entry and skipped counts; never
entry contents) as principal `cli:local`. A structurally bad file is rejected whole (exit 2).
Staging the same bytes twice for one source is refused (exit 1, `dataset_already_staged`), and
so is a sixth still-`staged` import of one source (`dataset_staging_full`). A new version is
simply another staged import.

## Accept and reject (unit 3b, CLI only)

Each command is ONE `BEGIN IMMEDIATE` transaction with ONE audit row (`dataset.accept` /
`dataset.reject`; source, version, sha256, entry and skipped counts, operator, plus `force` and
the superseded import id on accept, `reason` on reject; never entry contents), rolled back on
any failure. The audit principal is `cli:local`; `--by` (default `cli:local`, 1-128 printable
characters) is the operator identity stored in `accepted_by` / `rejected_by`. Exit 1 for a
refusal (unknown id `dataset_import_not_found`, or any conflict), 2 for invalid input, 3 for a
database error.

- **Statuses.** Only a `staged` import may transition (`dataset_not_staged` otherwise, nothing
  changes). `staged -> accepted` or `staged -> rejected`. **Rejected is terminal**, and
  re-staging the same bytes stays blocked by the unique (source, sha256) row; this is intended
  (stage a corrected file instead). Rejected staging rows are not deleted (pruning is a
  follow-up). Both outcomes free a staging slot, so a sixth import can be staged afterwards.
- **Supersede rule.** The live dataset of a source is its `accepted` import with
  `superseded_at IS NULL`; `dataset_writes.latest_accepted(ov, source)` returns it and a partial
  unique index guarantees there is at most one. Accepting a newer import sets
  `superseded_by` / `superseded_at` on the previous live one in the same transaction; its status
  stays `accepted` (no table rebuild, history kept). Rolling back to an older import is not
  supported: an older version is refused, see below.
- **Version rule.** `stage` requires a date version (`YYYY.MM.DD` or `YYYY-MM-DD`, a real
  date; exit 2 otherwise), so a source can never be locked by an unorderable label. Accept
  re-checks it, including for the first accept. A version dated later than tomorrow (relative
  to the command's clock) is refused at stage (exit 2) and at accept (`dataset_version_future`),
  so a typo such as 2099 cannot pin a source ahead of every real release.
- **Version guard.** Versions are compared only as dates, `YYYY.MM.DD` or `YYYY-MM-DD` (KEV
  `catalogVersion`, URLhaus dump date). An import older than the live one is refused
  (`dataset_version_older`); the same date is allowed (a republished file). If either version is
  not such a date the accept fails closed (`dataset_version_incomparable`). The first accept for
  a source has no ordering or churn check. `--force` does not bypass this guard.
  `--allow-older` does: it accepts a version older than (or unorderable against) the live one,
  is recorded as `allow_older` in the audit row, and still enforces the future, churn and
  content checks. It is the deliberate way to roll back or to replace a bad live import.
- **Churn guard.** If the entry count differs from the live import by more than 50% in either
  direction (`CHURN_MAX_FRACTION`; from a live count of 0 any increase) the accept is refused
  (`dataset_churn_exceeded`) unless `--force` is given. `force` is recorded in the audit row.
  Known limit: the comparison is only against the live import, so a series of accepts that each
  change the count by under 50% can walk a dataset far from its baseline without `--force`.
- **Re-validation.** On accept every staged row of the import is re-checked against the shape the
  parser produces for that source (key and payload fields, KEV CVE id and date, URLhaus host),
  and the row count must equal `entry_count`; any mismatch refuses
  (`dataset_staged_invalid`). URLhaus hosts must be exactly the key the parser derives (same
  address and canonicalisation rules); strings must be printable (no control or bidi characters).
  Rows are streamed, never copied.
- **Content digest.** `stage` stores `content_sha256`, a digest of the sorted (key, payload) rows,
  and puts it in the audit detail. Accept recomputes it while streaming and refuses a mismatch
  (`dataset_digest_mismatch`), so rows changed after staging cannot be accepted. Migration 9
  backfills the digest (same framing) for every existing import that has staged entries; one with
  no entries keeps no digest and accept refuses it (`dataset_digest_missing`): restage it. The
  digest proves integrity since staging, not authenticity: a forged staged import with a
  self-consistent digest passes accept, so only the CLI should write these tables.
- **What the database enforces** (CHECKs, triggers `trg_dataset_*`, a partial unique index and a
  foreign key): rows are inserted `staged`, with a digest and no accept record; imports are never
  deleted; identity columns (source, version, licence, hashes, counts, creator) never change;
  the only status moves are `staged -> accepted|rejected`, plus a one-time supersede of an
  accepted row to a `staged` or `accepted` import of the same source (never a rejected one);
  staged entries are insert-only, and only while their import is `staged`; at most one live
  accepted import per source; reject/supersede columns are paired with their status.
- **What only the application enforces**: version ordering, future versions, the churn limit,
  the shape and digest re-validation, `--force`/`--allow-older`, and the audit row (all in
  `dataset_writes`). A direct SQL writer can bypass these, and could stage entries that match a
  digest it computed itself.
- **Migration 9 on a v8 database.** Existing `rejected` rows get `rejected_by='migration-9'`.
  A hand-edited v8 database with two accepted imports of one source makes the migration fail
  closed on the unique live-accepted index, so the API will not start: mark all but the newest
  such import `staged` or `rejected` by hand (sqlite3, with a backup) and restart.
- **Deploy order.** Running this CLI against a live overrides.db migrates it to schema v9, and an
  older API image refuses to start on a newer schema. Deploy the API image first, then use the
  CLI. There is no downgrade.
- **Pruning.** Staging rows of rejected and superseded imports are never pruned yet (follow-up;
  the delete triggers will need a deliberate pruning path).
- **Licence review stays human.** Accept does not judge the licence: read the recorded licence
  before accepting.

## Tables (overrides.db, migrations 8 and 9)

- `dataset_imports`: id, source (`kev`|`urlhaus`), version, licence, sha256 of the raw bytes,
  entry_count, skipped_count, status (`staged`|`accepted`|`rejected`, default `staged`),
  created_at/by, and accepted_by/at. A row cannot be `accepted` without an accept record. Migration
  9 adds rejected_by/at (required exactly when `rejected`), reject_reason (1-200 characters, only
  when `rejected`), superseded_by/at (paired, only on `accepted` rows) and content_sha256 (digest
  of the staged entries; NULL only for a pre-migration import without entries).
  Unique on (source, sha256). Version and licence are recorded so provenance is never lost.
- `dataset_entries_staging`: (import_id, key, payload JSON), one row per key.

## Parser privacy and safety rules (`vigie_api/dataset_parse.py`, pure, no I/O)

- **Caps, per source.** KEV: 8 MiB and 20,000 entries (the real catalog is ~1.3 MB and ~1.5k
  entries). Before `json.loads` runs, raw byte counts bound the structure: `{` plus `[` at most
  3 per allowed entry and `,` at most 64 per allowed entry, so lists of `0`, `[]` or `{}`
  cannot amplify. Giant strings and deeply nested arrays are bounded by the input cap and by
  Python's recursion limit (a clean rejection), not by the counts. URLhaus: 64 MiB and 250,000
  rows, counted while a lazy CSV reader iterates and stopped at the cap, with each physical
  line bounded to 16 KiB before it is tokenized. 512 characters per field.
- **Memory.** URLhaus is decoded as a stream (UTF-8, strict) one bounded line at a time, never
  as one big string. Measured with `tracemalloc` on a synthetic 64 MiB file (224,060 rows),
  `parse_urlhaus` allocates about 90 MiB on top of the input bytes, mostly the parsed entries;
  the process also holds the input itself and, while staging, a second copy of the entries
  in the insert.
- A UTF-8 byte-order mark is ignored in both formats. An empty KEV catalog (no
  vulnerabilities) is rejected, as is a URLhaus file with no usable rows.
- KEV (CISA JSON): only `cveID`, `vendorProject`, `product`, `dateAdded` are kept. The CVE id is
  ASCII with no leading zeros beyond four digits; the date must be a real date. Duplicates are
  malformed.
- URLhaus (CSV, strict quoting, so a newline in a quoted field stays in that field): only the
  lower-cased **host** and the threat label are kept. Path, query, port and credentials are
  discarded before anything is stored. Only http/https URLs count. The host must be ASCII
  (Kelvin-sign and other lookalikes fail), one trailing dot is dropped, IPv6 literals are
  normalised and stored without brackets, and an IPv4-mapped IPv6 literal is stored as the
  plain IPv4 address. The port must be valid. Every DNS label must be 1-63 characters of `[a-z0-9-]` with no
  leading or trailing hyphen (253 in total); percent-encoded hosts such as `evil%2ecom` are
  skipped, not decoded. Duplicate hosts keep the first row. A comment is a row that is one
  physical line starting with `#` in column 0, as `csv.reader` itself sees it; a `#` line that
  opens a multi-line quoted field would swallow rows and rejects the file. A `#` anywhere else
  is plain data.
- **Deliberately skipped address forms.** A host whose last label is numeric or `0x..` is an
  address and is kept only as a strict dotted quad. Browser-ambiguous forms (`0x7f.0.0.1`,
  `127.1`, `010.0.0.1`, `2130706433`) are skipped, never guessed, and so are IPv4-compatible
  (`[::1.2.3.4]`) and NAT64 (`64:ff9b::/96`) literals. The later matcher unit must
  treat them the same way.
- **Skip vs reject.** A bad URL column (oversized, non-printable) or an unusable host, scheme
  or port skips that row only; it is counted in `skipped_count` (import row and audit detail)
  for the later accept step to show. The file is rejected only when more than half of its data
  rows are skipped (not the expected format). Any other column that is oversized, has control
  characters or the wrong column count, bad quoting, or a physical line over 16 KiB rejects the
  whole file.

## Staging capacity

At most 5 imports per source may be in `staged` status. Accepting or rejecting an import frees
its slot.
