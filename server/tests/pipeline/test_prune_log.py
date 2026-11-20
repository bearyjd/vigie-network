"""A prune is logged as a count, never as a MAC: the MAC is the very thing being forgotten."""

from __future__ import annotations

import logging

from pipeline_helpers import data  # noqa: F401
from test_prune_guards import (  # noqa: F401
    _visible_pipeline_log,
    migrated_overrides,
    prune,
    retire,
    set_clock,
)


def pruned_lines(caplog):
    return [r for r in caplog.records if r.getMessage() == "retired_macs_pruned"]


def test_the_log_line_carries_the_count_and_no_mac(data, caplog):
    macs = retire(data, count=3)
    migrated_overrides(data.root)
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert prune(data) == 3
    (line,) = pruned_lines(caplog)
    assert line.fields == {"count": 3}
    everything = caplog.text + repr([r.__dict__ for r in caplog.records])
    assert not any(mac in everything for mac in macs)


def test_nothing_pruned_logs_no_line(data, caplog):
    retire(data)
    migrated_overrides(data.root)
    set_clock(data, None)  # no accepted activity: nothing may be pruned
    with caplog.at_level(logging.INFO, logger="vigie_pipeline"):
        assert prune(data) == 0
    assert pruned_lines(caplog) == []
