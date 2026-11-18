"""The detector ids live in one registry; every consumer must agree with it."""

from typing import get_args

from vigie_api.models import IncidentOut
from vigie_pipeline import delivery_types, monitoring_engine
from vigie_pipeline.detectors import ALL, ENGINE, OPEN_ONLY


def test_registry_sets_are_consistent():
    assert set(ENGINE) | set(OPEN_ONLY) == set(ALL)
    assert not set(ENGINE) & set(OPEN_ONLY)


def test_consumers_use_the_registry():
    assert delivery_types.DEFAULT_DETECTORS == ENGINE
    assert delivery_types.OPEN_ONLY_DETECTORS == OPEN_ONLY
    assert monitoring_engine.ENGINE_DETECTORS == ENGINE


def test_incident_literal_matches_registry():
    literal = IncidentOut.model_fields["detector"].annotation
    assert set(get_args(literal)) == set(ALL)
