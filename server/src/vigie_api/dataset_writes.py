"""Stage, accept or reject an offline dataset: one transaction and ONE audit row per command.

Nothing reads these tables yet. Audit rows carry the source, version, hash and counts, never
entry contents. Accept and reject only flip status; they never copy or delete entry rows.
The hash is of the raw bytes, so importing the same file twice for one source is refused
instead of stacking duplicates.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Iterable
from datetime import date, timedelta

from vigie_api import dataset_parse
from vigie_api.errors import ApiError

AUDIT_ACTION = "dataset.stage"
ACCEPT_ACTION = "dataset.accept"
REJECT_ACTION = "dataset.reject"
MAX_REASON_LEN = 200  # mirrors the reject_reason CHECK in migration 9
MAX_BY_LEN = 128
CHURN_MAX_FRACTION = 0.5  # accept refuses a +-50% entry_count change vs the live import
MAX_STAGED = 5  # unaccepted imports per source; bounds what a stream of new files can store
PARSERS: dict[str, Callable[[bytes], tuple[list[dataset_parse.Entry], int]]] = {
    "kev": lambda data: (dataset_parse.parse_kev(data), 0),
    "urlhaus": dataset_parse.parse_urlhaus,
}


def _invalid(message: str) -> ApiError:
    return ApiError(422, "dataset_invalid", message)


def _label(name: str, value: str, limit: int = dataset_parse.MAX_FIELD_LEN) -> str:
    text = value.strip()
    if not text or len(text) > limit or not text.isprintable():
        raise _invalid(f"{name} must be 1-{limit} printable characters")
    return text


def content_digest(rows: Iterable[tuple[str, str]]) -> str:
    """SHA-256 over (key, payload) rows in key order, length-prefixed so rows cannot blur."""
    digest = hashlib.sha256()
    for key, payload in rows:
        for part in (key, payload):
            raw = part.encode()
            digest.update(f"{len(raw)}:".encode() + raw)
    return digest.hexdigest()


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
    version_date = _version_date(version)
    if version_date is None:
        raise _invalid("version must be a date, YYYY.MM.DD or YYYY-MM-DD")
    if _is_future(version_date, now_iso):
        raise _invalid("version is in the future (later than tomorrow); check the date")
    try:
        entries, skipped = parser(data)
    except ValueError as exc:
        raise _invalid(str(exc)) from None
    sha256 = hashlib.sha256(data).hexdigest()
    staged_rows = sorted((e.key, _compact(e.payload)) for e in entries)
    content_sha256 = content_digest(staged_rows)
    import_id = id_factory()
    detail = {
        "source": source, "version": version, "sha256": sha256,
        "entry_count": len(entries), "skipped_count": skipped, "content_sha256": content_sha256,
    }  # fmt: skip
    ov.execute("BEGIN IMMEDIATE")
    try:
        _guard(ov, source, sha256)
        ov.execute(
            "INSERT INTO dataset_imports (id,source,version,licence,sha256,entry_count,"
            "skipped_count,created_at,created_by,content_sha256) VALUES (?,?,?,?,?,?,?,?,?,?)",
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
                content_sha256,
            ),
        )
        ov.executemany(
            "INSERT INTO dataset_entries_staging (import_id,key,payload) VALUES (?,?,?)",
            ((import_id, key, payload) for key, payload in staged_rows),
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


_VERSION = re.compile(r"([0-9]{4})([.-])([0-9]{2})\2([0-9]{2})", re.ASCII)
FUTURE_SLACK = timedelta(days=1)  # a version dated later than tomorrow is a typo, not a release


def _version_date(version: str) -> date | None:
    """YYYY.MM.DD or YYYY-MM-DD (KEV catalogVersion, URLhaus dump dates), else None."""
    match = _VERSION.fullmatch(version)
    try:
        return date(*map(int, match.group(1, 3, 4))) if match else None
    except ValueError:
        return None


def _today(now_iso: str) -> date:
    try:
        return date.fromisoformat(now_iso[:10])
    except ValueError:
        raise _invalid("now_iso must start with a YYYY-MM-DD date") from None


def _is_future(version_date: date, now_iso: str) -> bool:
    return version_date > _today(now_iso) + FUTURE_SLACK


def latest_accepted(ov: sqlite3.Connection, source: str) -> sqlite3.Row | None:
    """The live dataset of a source: its accepted import that no later accept superseded."""
    return ov.execute(
        "SELECT * FROM dataset_imports WHERE source=? AND status='accepted'"
        " AND superseded_at IS NULL",
        (source,),
    ).fetchone()


def _conflict(code: str, message: str) -> ApiError:
    return ApiError(409, code, message)


def _check_version(
    new: sqlite3.Row, live: sqlite3.Row | None, now_iso: str, allow_older: bool
) -> None:
    new_date = _version_date(new["version"])
    if new_date is None:
        raise _conflict(
            "dataset_version_incomparable", f"version {new['version']!r} is not a YYYY.MM.DD date"
        )
    if _is_future(new_date, now_iso):
        raise _conflict("dataset_version_future", f"version {new['version']!r} is in the future")
    if live is None or allow_older:  # --allow-older is the deliberate way past the ordering rule
        return
    live_date = _version_date(live["version"])
    if live_date is None:
        raise _conflict(
            "dataset_version_incomparable",
            f"accepted version {live['version']!r} is not a YYYY.MM.DD date; use --allow-older",
        )
    if new_date < live_date:
        raise _conflict(
            "dataset_version_older",
            f"version {new['version']!r} is older than accepted {live['version']!r};"
            " use --allow-older to accept it deliberately",
        )


def _check_churn(new: sqlite3.Row, live: sqlite3.Row) -> None:
    before, after = live["entry_count"], new["entry_count"]
    if abs(after - before) > CHURN_MAX_FRACTION * before:
        raise _conflict(
            "dataset_churn_exceeded",
            f"entry count {before} -> {after} changes by more than "
            f"{CHURN_MAX_FRACTION:.0%}; use --force after review",
        )


def _revalidate(ov: sqlite3.Connection, row: sqlite3.Row) -> None:
    """Shape, count and content digest of the staged rows, streamed in key order."""
    if row["content_sha256"] is None:
        raise _conflict(
            "dataset_digest_missing",
            "import has no content digest (staged by an older build); restage it",
        )
    seen = 0

    def stream():
        nonlocal seen
        for key, payload in ov.execute(
            "SELECT key,payload FROM dataset_entries_staging WHERE import_id=? ORDER BY key",
            (row["id"],),
        ):
            if not dataset_parse.is_valid_staged(row["source"], key, payload):
                raise _conflict(
                    "dataset_staged_invalid", "a staged entry does not match its schema"
                )
            seen += 1
            yield key, payload

    digest = content_digest(stream())
    if seen != row["entry_count"]:
        raise _conflict(
            "dataset_staged_invalid",
            f"{seen} staged entries, import recorded {row['entry_count']}",
        )
    if digest != row["content_sha256"]:
        raise _conflict("dataset_digest_mismatch", "staged entries changed since they were staged")


def _audit_detail(row: sqlite3.Row, by: str, **extra: object) -> dict:
    return {
        "source": row["source"], "version": row["version"], "sha256": row["sha256"],
        "entry_count": row["entry_count"], "skipped_count": row["skipped_count"], "by": by,
        "content_sha256": row["content_sha256"],
        **extra,
    }  # fmt: skip


def _decide(ov, import_id, principal, now_iso, action, apply):
    """Run `apply(row)` -> (SQL updates, audit detail) on a staged import, atomically."""
    ov.execute("BEGIN IMMEDIATE")
    try:
        row = ov.execute("SELECT * FROM dataset_imports WHERE id=?", (import_id,)).fetchone()
        if row is None:
            raise ApiError(404, "dataset_import_not_found", f"no import {import_id!r}")
        if row["status"] != "staged":
            raise _conflict("dataset_not_staged", f"import is {row['status']}, not staged")
        for sql, params in (updates := apply(row))[0]:
            ov.execute(sql, params)
        ov.execute(
            "INSERT INTO audit_log (id,ts,principal,action,target,detail) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), now_iso, principal, action, import_id, _compact(updates[1])),
        )
        ov.execute("COMMIT")
    except BaseException:
        if ov.in_transaction:
            ov.execute("ROLLBACK")
        raise


def accept(
    ov: sqlite3.Connection,
    import_id: str,
    principal: str,
    by: str,
    now_iso: str,
    *,
    force: bool = False,
    allow_older: bool = False,
) -> None:
    principal, by = _label("principal", principal), _label("by", by, MAX_BY_LEN)
    now_iso = _label("now_iso", now_iso)

    def apply(row):
        live = latest_accepted(ov, row["source"])
        _check_version(row, live, now_iso, allow_older)
        if live is not None:
            if not force:
                _check_churn(row, live)
        _revalidate(ov, row)
        steps = []
        if live is not None:  # supersede first: one live accepted import per source
            steps.append((
                "UPDATE dataset_imports SET superseded_by=?, superseded_at=? WHERE id=?",
                (import_id, now_iso, live["id"]),
            ))  # fmt: skip
        steps.append((
            "UPDATE dataset_imports SET status='accepted', accepted_by=?, accepted_at=?"
            " WHERE id=?",
            (by, now_iso, import_id),
        ))  # fmt: skip
        detail = _audit_detail(
            row,
            by,
            force=force,
            allow_older=allow_older,
            superseded=None if live is None else live["id"],
        )
        return steps, detail

    _decide(ov, import_id, principal, now_iso, ACCEPT_ACTION, apply)


def reject(
    ov: sqlite3.Connection,
    import_id: str,
    principal: str,
    by: str,
    now_iso: str,
    reason: str | None = None,
) -> None:
    principal, by = _label("principal", principal), _label("by", by, MAX_BY_LEN)
    now_iso = _label("now_iso", now_iso)
    reason = None if reason is None else _label("reason", reason, MAX_REASON_LEN)

    def apply(row):
        step = (
            "UPDATE dataset_imports SET status='rejected', rejected_by=?, rejected_at=?,"
            " reject_reason=? WHERE id=?",
            (by, now_iso, reason, import_id),
        )
        return [step], _audit_detail(row, by, reason=reason)

    _decide(ov, import_id, principal, now_iso, REJECT_ACTION, apply)
