"""A device with no observations can never match the candidate query (it joins observations), so
the scan cursor must count it as decided: a pruned or stitch-orphaned device behind the cursor
must not pin it forever."""

from __future__ import annotations

from pipeline_helpers import T0, data  # noqa: F401
from test_f5_new_device_sweep import (
    DWELL,
    SK,
    arrive,
    device_of,
    incidents,
    run,
    start,
    wide_gap,  # noqa: F401
)
from test_f5_new_device_sweep_fix4 import cursor, top_event_seq


def test_a_device_whose_observations_are_gone_does_not_pin_the_cursor(data):
    start(data, new_device_max_per_day=20)
    waiting, later = "00:1a:2b:00:00:0a", "00:1a:2b:00:00:0b"
    arrive(data, waiting, at=T0, measured=False)  # undecided: nobody measured it
    arrive(data, later, at=T0 + 10)
    now = T0 + DWELL + SK + 60
    run(data, now, new_device_max_per_day=20)
    first_seq = data.q("SELECT seq FROM events WHERE device_id=?", device_of(data, waiting))[0][0]
    assert cursor(data) < first_seq  # pinned behind the waiting device, as designed
    data.inv.execute("DELETE FROM observations WHERE device_id=?", (device_of(data, waiting),))
    run(data, now + 30, new_device_max_per_day=20)
    assert cursor(data) == top_event_seq(data)
    assert [r["device_id"] for r in incidents(data)] == [device_of(data, later)]
