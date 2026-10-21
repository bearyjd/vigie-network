"""End to end: generated streams posted to the real ingest app with the real signing code."""

from __future__ import annotations

import pytest
from conftest import FIXTURES

from trafficgen import PROFILES
from trafficgen.cli import FIXTURE_FILE_BUDGET_BYTES, FIXTURE_SPECS, FIXTURE_TOTAL_BUDGET_BYTES
from trafficgen.generator import emissions_to_jsonl, load_emissions


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_gets_expected_status(gen, ingest, profile):
    results = ingest.replay(gen(profile, 4, 10).emissions)
    bad = [(r.emission.label, r.status, r.emission.expect_status) for r in results if not r.ok]
    assert not bad


def test_baseline_all_200_not_duplicate(gen, ingest):
    results = ingest.replay(gen("baseline", 4, 10).emissions)
    assert all(r.status == 200 and r.payload == {"duplicate": False} for r in results)


def test_replay_outcomes(gen, ingest):
    results = {r.emission.label: r for r in ingest.replay(gen("replay", 4, 8).emissions)}
    assert (results["replay_identical"].status, results["replay_identical"].payload) == (
        200,
        {"duplicate": True},
    )
    assert results["replay_header_ts_bumped"].status == 401


def test_out_of_order_and_stale_rejections(gen, ingest):
    r = ingest.replay(gen("out_of_order", 4, 8).emissions)
    assert [x.status for x in r].count(409) == 1
    assert next(x for x in r if x.status == 409).payload == {"error": "seq_regression"}


def test_stale_rejected_400(gen, ingest):
    r = ingest.replay(gen("stale_ts", 4, 8).emissions)
    assert next(x for x in r if x.emission.expect_status == 400).payload == {
        "error": "sent_ts_out_of_range"
    }


def test_wrong_key_is_401(gen, ingest):
    from trafficgen.transport import run

    ems = gen("baseline", 4, 4).emissions
    ingest.clock[0] = float(ems[0].arrival_ts)
    out = run(ems[:1], b"\x01" * 32, ingest.post, on_arrival=None)
    assert out[0].status == 401


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.jsonl")), ids=lambda p: p.stem)
def test_committed_fixtures_replay_and_stay_small(ingest, path):
    assert path.stat().st_size < FIXTURE_FILE_BUDGET_BYTES
    ems = load_emissions(path)
    assert all(r.ok for r in ingest.replay(ems))
    assert emissions_to_jsonl(ems) == path.read_text()


def test_fixture_set_is_complete_and_within_total_budget():
    files = sorted(FIXTURES.glob("*.jsonl"))
    assert {p.stem for p in files} == set(FIXTURE_SPECS)
    assert sum(p.stat().st_size for p in files) < FIXTURE_TOTAL_BUDGET_BYTES
