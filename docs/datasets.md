# Offline known-issue datasets (staging only)

Unit 3a of the exposure-evidence proposal in [roadmap.md](roadmap.md) (decisions D7-D9).
**Nothing is fetched and nothing is applied yet.** An operator downloads a dataset by hand and
stages the file; accept/reject, scheduled fetch and device mapping are later units.

```
python -m vigie_api dataset stage --source kev|urlhaus --file PATH --version V --licence L [--data-dir D]
python -m vigie_api dataset list [--data-dir D]
```

`stage` reads the file bounded (per-source input cap, regular files only, no symlinks, no
controlling tty), parses it strictly and writes in ONE transaction an import row, its entries
and one `dataset.stage` audit row (source, version, sha256, entry and skipped counts; never
entry contents) as principal `cli:local`. A structurally bad file is rejected whole (exit 2).
Staging the same bytes twice for one source is refused (exit 1, `dataset_already_staged`), and
so is a sixth still-`staged` import of one source (`dataset_staging_full`). A new version is
simply another staged import.

## Tables (overrides.db, migration 8)

- `dataset_imports`: id, source (`kev`|`urlhaus`), version, licence, sha256 of the raw bytes,
  entry_count, skipped_count, status (`staged`|`accepted`|`rejected`, default `staged`),
  created_at/by, and accepted_by/at. A row cannot be `accepted` without an accept record.
  Unique on (source, sha256). Version and licence are recorded so provenance is never lost.
- `dataset_entries_staging`: (import_id, key, payload JSON), one row per key.

## Parser privacy and safety rules (`vigie_api/dataset_parse.py`, pure, no I/O)

- Caps are checked before the structure they protect is built. KEV: 16 MiB, 100,000 entries
  (a brace pre-scan rejects before `json.loads`). URLhaus: 64 MiB, 250,000 rows, counted while
  iterating and stopped at the cap. 512 characters per field; control characters are rejected
  in every field.
- KEV (CISA JSON): only `cveID`, `vendorProject`, `product`, `dateAdded` are kept. The CVE id is
  ASCII with no leading zeros beyond four digits; the date must be a real date. Duplicates are
  malformed.
- URLhaus (CSV, read with a real CSV reader, so a newline inside a quoted URL is rejected, not
  split): only the lower-cased **host** and the threat label are kept. Path, query, port and
  credentials are discarded before anything is stored. Only http/https URLs count. The host
  must be ASCII (Kelvin-sign and other lookalikes fail), a trailing dot is dropped, IPv4/IPv6
  literals are normalised (IPv6 stored without brackets), and the port must be valid.
  Duplicate hosts keep the first row.
- A row whose host, scheme or port is unusable is **skipped and counted**; the import is
  rejected if more than max(100, 1% of data rows) are skipped.
