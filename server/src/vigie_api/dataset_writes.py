"""Stage an offline dataset: one import row, its entries and ONE audit row, in one transaction.

Staging is the only write: nothing reads these tables yet. The audit row carries the source,
version, hash and entry count, never entry contents. The hash is of the raw bytes, so importing
the same file twice for one source is refused instead of stacking duplicates.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable

from vigie_api import dataset_parse
from vigie_api.errors import ApiError

AUDIT_ACTION = "dataset.stage"
MAX_STAGED = 5  # unaccepted imports per source; bounds what a stream of new files can store
PARSERS: dict[str, Callable[[bytes], tuple[list[dataset_parse.Entry], int]]] = {
    "kev": lambda data: (dataset_parse.parse_kev(data), 0),
    "urlhaus": dataset_parse.parse_urlhaus,
}


def _invalid(message: str) -> ApiError:
    return ApiError(422, "dataset_invalid", message)


def _label(name: str, value: str) -> str:
    text = value.strip()
    if not text or len(text) > dataset_parse.MAX_FIELD_LEN or not text.isprintable():
        raise _invalid(f"{name} must be 1-{dataset_parse.MAX_FIELD_LEN} printable characters")
    return text


def _compact(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _guard(ov: sqlite3.Connection, source: str, sha256: str) -> None:
    if ov.execute(
        "SELECT 1 FROM dataset_imports WHERE source=? AND sha256=?", (source, sha256)
    ).fetchone():
        raise ApiError(409, "dataset_already_staged", "this exact file is already staged")
    (staged,) = ov.execute(
        "SELECT COUNT(*) FROM dataset_imports WHERE source=? AND status='staged'", (source,)
    ).fetchone()
    if staged >= MAX_STAGED:
        raise ApiError(
            409, "dataset_staging_full", f"{MAX_STAGED} imports of {source} are already staged"
        )


def stage(
    ov: sqlite3.Connection,
    source: str,
    data: bytes,
    version: str,
    licence: str,
    principal: str,
    now_iso: str,
    id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> str:
    parser = PARSERS.get(source)
    if parser is None:
        raise _invalid(f"unknown source {source!r}")
    version, licence = _label("version", version), _label("licence", licence)
    principal, now_iso = _label("principal", principal), _label("now_iso", now_iso)
    try:
        entries, skipped = parser(data)
    except ValueError as exc:
        raise _invalid(str(exc)) from None
    sha256 = hashlib.sha256(data).hexdigest()
    import_id = id_factory()
    detail = {
        "source": source, "version": version, "sha256": sha256,
        "entry_count": len(entries), "skipped_count": skipped,
    }  # fmt: skip
    ov.execute("BEGIN IMMEDIATE")
    try:
        _guard(ov, source, sha256)
        ov.execute(
            "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,"
            "skipped_count,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                import_id,
                source,
                version,
                licence,
                sha256,
                len(entries),
                skipped,
                now_iso,
                principal,
            ),
        )
        ov.executemany(
            "INSERT INTO dataset_entries_staging (import_id,key,payload) VALUES (?,?,?)",
            ((import_id, e.key, _compact(e.payload)) for e in entries),
        )
        ov.execute(
            "INSERT INTO audit_log (id,ts,principal,action,target,detail) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), now_iso, principal, AUDIT_ACTION, import_id, _compact(detail)),
        )
        ov.execute("COMMIT")
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise
    return import_id
