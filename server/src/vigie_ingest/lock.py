"""Exclusive per-data-dir process lock (rate limits and shard locks are per process)."""

from __future__ import annotations

import contextlib
import fcntl
from collections.abc import Iterator
from pathlib import Path

LOCK_NAME = ".ingest.lock"


class LockHeld(Exception):
    pass


@contextlib.contextmanager
def exclusive_data_dir(data_dir: Path) -> Iterator[None]:
    """Hold an exclusive flock on <data_dir>/.ingest.lock for the life of the process."""
    path = data_dir / LOCK_NAME
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        handle = path.open("a")
    except OSError as exc:
        raise LockHeld(f"cannot open {path}: {exc}") from exc
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockHeld(f"{path} is held: another vigie-ingest uses this data dir") from exc
        except OSError as exc:
            raise LockHeld(
                f"flock on {path} failed ({exc}): the filesystem may not support file locks; "
                "put the data dir on a local filesystem"
            ) from exc
        yield
    finally:
        handle.close()  # also releases the flock
