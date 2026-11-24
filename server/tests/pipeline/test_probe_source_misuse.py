"""What the pipeline does with a probe_file it should not trust (characterisation)."""

from __future__ import annotations

import json

import pytest
from probe_helpers import NOW, state_doc, target_state, write_probe_file

from vigie_pipeline import probes
from vigie_pipeline.config import ProbeSettings
from vigie_pipeline.schema import open_pipeline_inventory


@pytest.fixture
def inv(tmp_path):
    probes._reset_log_memory()
    conn = open_pipeline_inventory(tmp_path / "inventory.db", migrate=True)
    yield conn
    conn.close()


@pytest.fixture
def settings(tmp_path):
    return ProbeSettings(file=tmp_path / "probe-state.json")


def fold(inv, settings):
    probes.fold_probes(inv, settings, lambda: NOW + 5)


def stored(inv):
    return json.loads(
        inv.execute("SELECT value FROM pipeline_meta WHERE key='probe_status'").fetchone()[0]
    )


def kinds(inv):
    return [r[0] for r in inv.execute("SELECT kind FROM events WHERE kind LIKE 'probe_%'")]


def open_outage(ident):
    return target_state(
        ident, state="outage", consecutive_fail=3, consecutive_ok=0, last_ok_at=None,
        episode_start=int(NOW) - 120, last_error_class="timeout", episodes_today=1,
    )  # fmt: skip


@pytest.mark.parametrize("version", [0, 2, 1.0, "1", True, None])
def test_an_unknown_version_is_never_trusted_even_when_it_carries_an_outage(inv, settings, version):
    write_probe_file(settings.file, state_doc(open_outage("router-dns"), v=version))
    fold(inv, settings)
    snap = stored(inv)
    assert (snap["stale"], snap["reason"], snap["targets"]) == (True, "invalid", [])
    assert kinds(inv) == ["probe_stale"]


@pytest.mark.parametrize("ident", ["not-in-any-config", "x", "a" * 32, "0_9-z"])
def test_a_well_formed_but_unexpected_target_id_is_accepted_documented_current_behaviour(
    inv, settings, ident
):
    """docs/monitoring.md: the reader has no id allowlist, so the spec's unknown-target-id
    acceptance test is intentionally not implemented. Pinned so adding one is a visible change."""
    write_probe_file(settings.file, state_doc(open_outage(ident)))
    fold(inv, settings)
    snap = stored(inv)
    assert snap["stale"] is False and [t["id"] for t in snap["targets"]] == [ident]
    assert kinds(inv) == ["probe_outage"]


@pytest.mark.parametrize("ident", ["Router", "a b", "../x", "a" * 33, "", "réseau"])
def test_a_malformed_target_id_makes_the_whole_file_unavailable(inv, settings, ident):
    write_probe_file(settings.file, state_doc(target_state("ok-one"), open_outage(ident)))
    fold(inv, settings)
    snap = stored(inv)
    assert (snap["stale"], snap["reason"], snap["targets"]) == (True, "invalid", [])
    assert kinds(inv) == ["probe_stale"]
