"""The server moment a retirement is stamped with (transient_state.since: the prune's clock)."""

from __future__ import annotations

import sqlite3

from vigie_ingest.db import iso_utc


def retirement_stamp(inv: sqlite3.Connection, now: float) -> str:
    """max(now, the newest batch receipt): the server clock being set back must not backdate a
    retirement, or the 90 days would run from a moment before the device was retired. Receipts
    are server-written ISO instants, so they order as text; the newest is an index seek
    (idx_batches_received). With no batch recorded the clock is all there is."""
    newest = inv.execute("SELECT MAX(received_at) FROM batches").fetchone()[0]
    stamp = iso_utc(now)
    return stamp if newest is None or newest <= stamp else newest
