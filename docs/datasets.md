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

- **Caps, per source.** KEV: 8 MiB and 20,000 entries (the real catalog is ~1.3 MB and ~1.5k
  entries). Before `json.loads` runs, raw byte counts bound the structure: `{` plus `[` at most
  3 per allowed entry and `,` at most 64 per allowed entry, so lists of `0`, `[]` or `{}`
  cannot amplify. Giant strings and deeply nested arrays are bounded by the input cap and by
  Python's recursion limit (a clean rejection), not by the counts. URLhaus: 64 MiB and 250,000
  rows, counted while a lazy CSV reader iterates and stopped at the cap, with each physical
  line bounded to 16 KiB before it is tokenized. 512 characters per field.
- **Memory.** Decoding and tokenizing a URLhaus file peaks at roughly 5x the input size (about
  320 MiB for a file at the cap). Run staging on a host with that headroom.
- KEV (CISA JSON): only `cveID`, `vendorProject`, `product`, `dateAdded` are kept. The CVE id is
  ASCII with no leading zeros beyond four digits; the date must be a real date. Duplicates are
  malformed.
- URLhaus (CSV, strict quoting, so a newline in a quoted field stays in that field): only the
  lower-cased **host** and the threat label are kept. Path, query, port and credentials are
  discarded before anything is stored. Only http/https URLs count. The host must be ASCII
  (Kelvin-sign and other lookalikes fail), one trailing dot is dropped, IPv6 literals are
  normalised and stored without brackets, and an IPv4-mapped IPv6 literal is stored as the
  plain IPv4 address. The port must be valid. Duplicate hosts keep the first row.
- **Deliberately skipped address forms.** A host whose last label is numeric or `0x..` is an
  address and is kept only as a strict dotted quad. Browser-ambiguous forms (`0x7f.0.0.1`,
  `127.1`, `010.0.0.1`, `2130706433`) are skipped, never guessed. The later matcher unit must
  treat them the same way.
- **Skip vs reject.** A bad URL column (oversized, non-printable) or an unusable host, scheme
  or port skips that row only; it is counted in `skipped_count` (import row and audit detail)
  for the later accept step to show. The file is rejected only when more than half of its data
  rows are skipped (not the expected format). Any other column that is oversized, has control
  characters or the wrong column count, bad quoting, or a physical line over 16 KiB rejects the
  whole file.

## Staging capacity

At most 5 imports per source may be in `staged` status. There is no accept/reject yet (unit
3b), so until it lands a source is permanently full after five stagings. That is intended;
there is no workaround.
