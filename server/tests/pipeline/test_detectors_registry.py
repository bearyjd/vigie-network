"""The detector ids live in one registry; every consumer must agree with it."""

from typing import get_args

from vigie_api import evidence_determinations
from vigie_api.models import IncidentOut
from vigie_pipeline import delivery_types, monitoring_engine
from vigie_pipeline.detectors import ALL, ENGINE, OPEN_ONLY


def test_registry_sets_are_consistent():
    assert set(ENGINE) | set(OPEN_ONLY) == set(ALL)
    assert not set(ENGINE) & set(OPEN_ONLY)


def test_consumers_use_the_registry():
    # Identity (not equality): a consumer re-listing the same ids as its own tuple fails.
    assert delivery_types.DEFAULT_DETECTORS is ENGINE
    assert delivery_types.OPEN_ONLY_DETECTORS is OPEN_ONLY
    assert monitoring_engine.ENGINE_DETECTORS is ENGINE
    assert evidence_determinations.DETECTORS is ALL


def test_incident_literal_matches_registry():
    literal = IncidentOut.model_fields["detector"].annotation
    assert get_args(literal) == ALL
