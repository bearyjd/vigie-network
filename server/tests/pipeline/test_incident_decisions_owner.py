"""incident_decisions is API-owned: only vigie_pipeline.overrides may query it."""

import re
from pathlib import Path

import vigie_pipeline

QUERY = re.compile(r"\b(FROM|JOIN|INTO|UPDATE)\s+incident_decisions\b", re.IGNORECASE)


def test_only_overrides_module_queries_incident_decisions():
    pkg = Path(vigie_pipeline.__file__).parent
    offenders = [
        p.name
        for p in sorted(pkg.glob("*.py"))
        if p.name != "overrides.py" and QUERY.search(p.read_text())
    ]
    assert offenders == []
