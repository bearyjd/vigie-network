"""The detector ids live in one registry; every consumer must agree with it."""

import re
from pathlib import Path
from typing import get_args

from vigie_api import evidence_determinations
from vigie_api.models import IncidentOut
from vigie_pipeline import delivery_types, monitoring_engine, new_device_notice
from vigie_pipeline.detectors import ALL, ENGINE, NEW_DEVICE, OPEN_ONLY


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


def test_new_device_constant_is_registered():
    assert NEW_DEVICE == "new_device"
    assert OPEN_ONLY == (NEW_DEVICE,)
    assert new_device_notice.DETECTOR is NEW_DEVICE


def test_no_new_device_literal_in_consumers():
    root = Path(__file__).resolve().parents[2] / "src"
    for rel in (
        "vigie_pipeline/new_device_notice.py",
        "vigie_api/monitoring.py",
        "vigie_api/evidence_determinations.py",
    ):
        assert '"new_device"' not in (root / rel).read_text(), (
            f"{rel} re-lists the literal; use detectors.NEW_DEVICE"
        )


def test_ui_detector_labels_match_registry():
    js = Path(__file__).resolve().parents[2] / "src/vigie_api/ui/views.js"
    m = re.search(r"const DETECTORS = new Map\(\[(.*?)\]\);", js.read_text())
    assert m, "views.js: `const DETECTORS = new Map([...]);` not found; update this test"
    keys = tuple(re.findall(r"\['([a-z_]+)',", m.group(1)))
    assert set(keys) == set(ALL), (
        f"views.js DETECTORS keys {sorted(keys)} != registry.ALL {sorted(ALL)}; keep them in sync"
    )
    assert len(keys) == len(ALL), f"views.js DETECTORS has duplicate keys: {keys}"
