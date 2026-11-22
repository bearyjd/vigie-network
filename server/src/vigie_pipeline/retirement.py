"""The server moment a retirement is stamped with (transient_state.since: the prune's clock)."""

from __future__ import annotations

import sqlite3

from vigie_ingest.db import iso_utc


def retirement_stamp(inv: sqlite3.Connection, now: float) -> str:
    """The newest of now, the newest batch receipt and the newest `collectors.last_sent_ts`: the
    server clock being set back must not backdate a retirement, or the 90 days would run from a
    moment before the device was retired. Receipts are server-written ISO instants, so they order
    as text; the newest is an index seek (idx_batches_received). Batch rows are purged, so the
    never-purged `last_sent_ts` (a number; anything else is ignored) keeps the floor once they are
    gone. With neither recorded the clock is all there is."""
    newest = inv.execute("SELECT MAX(received_at) FROM batches").fetchone()[0]
    sent = inv.execute(
        "SELECT MAX(CASE WHEN typeof(last_sent_ts) IN ('integer','real') THEN last_sent_ts END)"
        " FROM collectors"
    ).fetchone()[0]
    stamps = [iso_utc(now)]
    if newest is not None:
        stamps.append(newest)
    if sent is not None and sent > 0:
        stamps.append(iso_utc(sent))
    return max(stamps)
