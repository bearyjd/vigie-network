"""Each validator guard holds on its own, not only behind the parser's catch-all."""

from __future__ import annotations

import json

import pytest
from probe_helpers import state_doc, target_state, write_probe_file
from test_probes import START, events, fold, inv, outage, settings, status  # noqa: F401
from test_probes_review import CONFUSED

from vigie_pipeline import probe_file
from vigie_pipeline.probe_file import ProbeFileInvalid


@pytest.mark.parametrize("name", sorted(CONFUSED))
def test_the_target_validator_itself_never_leaks_a_typeerror(name):
    target = json.loads(CONFUSED[name])["targets"][0]
    with pytest.raises(ProbeFileInvalid):
        probe_file._target(target)


def test_a_foreign_open_outage_row_with_an_odd_token_does_not_break_the_fold(inv, settings):
    inv.execute(
        "INSERT INTO events (id, device_id, ts, kind, severity, summary, dedup)"
        " VALUES ('x', NULL, '2027-01-15T00:00:00Z', 'probe_outage', 'warn', 's', 'router-dns:abc')"
    )
    write_probe_file(settings.file, state_doc(outage()))
    fold(inv, settings)
    assert status(inv)["stale"] is False
    assert f"router-dns:{START}" in [e[3] for e in events(inv)]


def test_valid_target_still_passes_the_validator():
    assert probe_file._target(target_state()).id == "router-dns"
