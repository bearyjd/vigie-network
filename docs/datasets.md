# Offline known-issue datasets (staging only)

Unit 3a of the exposure-evidence proposal in [roadmap.md](roadmap.md) (decisions D7-D9).
**Nothing is fetched and nothing is applied yet.** An operator downloads a dataset by hand and
stages the file; accept/reject, scheduled fetch and device mapping are later units.

```
python -m vigie_api dataset stage --source kev|urlhaus --file PATH --version V --licence L [--data-dir D]
python -m vigie_api dataset list [--data-dir D]
```

`stage` reads the file bounded (64 MiB, regular files only, symlinks refused), parses it
strictly (any malformed row rejects the whole file, exit 2), and writes in ONE transaction an
import row, its entries and one `dataset.stage` audit row (source, version, sha256, entry count;
never entry contents) as principal `cli:local`. Staging the same bytes twice for one source is
refused (exit 1, `dataset_already_staged`). A new version is simply another staged import.

## Tables (overrides.db, migration 8)

- `dataset_imports`: id, source (`kev`|`urlhaus`), version, licence, sha256 of the raw bytes,
  entry_count, status (`staged`|`accepted`|`rejected`, default `staged`), created_at/by.
  Unique on (source, sha256). The version and licence are recorded so provenance is never lost.
- `dataset_entries_staging`: (import_id, key, payload JSON), one row per key.

## Parser privacy and safety rules (`vigie_api/dataset_parse.py`, pure, no I/O)

- KEV (CISA JSON): only `cveID`, `vendorProject`, `product`, `dateAdded` are kept; descriptions
  and notes are dropped. Duplicate CVE ids are malformed.
- URLhaus (CSV): only the lower-cased **host** and the threat label are kept. Path, query, port
  and credentials of a listed URL are discarded before anything is stored. Hosts are restricted
  to `[a-z0-9.:-]`, so unicode lookalikes and backslash tricks are rejected. Duplicate hosts
  keep the first row.
- Caps for both: 64 MiB input, 2,000,000 entries, 512 characters per field; non-printable
  characters are rejected.
