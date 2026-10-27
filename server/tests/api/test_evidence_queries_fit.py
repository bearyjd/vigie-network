"""search_queries must describe only the evidence the final, size-fitted pack still contains."""

from __future__ import annotations

import json
import re

from evidence_helpers import SALT_A, sample, section

from vigie_api import evidence_export
from vigie_api.evidence_redact import build_queries, redact
from vigie_api.evidence_render import fit
from vigie_api.evidence_types import Pack, Sensitive

QUERY_FRAGMENT = re.compile(r"^DHCP parameter request list (.+)$")


def many_fingerprints(count: int) -> Pack:
    base = sample()
    items = [
        {"mac": Sensitive("mac", f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}"),
         "opt55": Sensitive("opt55", f"1,3,{i % 250 + 1},{i // 250 + 1}")}
        for i in range(count)
    ]  # fmt: skip
    body = {**base.body, "sections": {**base.body["sections"], "fingerprints": section(items)}}
    return Pack(body)


def test_fit_rebuilds_queries_from_the_truncated_pack():
    calls = []

    def requery(pack: Pack) -> list:
        calls.append(len(pack.body["sections"]["fingerprints"]["items"]))
        return [{"q": f"kept {calls[-1]}", "built_from": ["opt55"]}]

    items = [{"opt55": f"1,3,{i}"} for i in range(1, 2000)]
    base = redact(sample(), "pseudonymized", SALT_A).body
    body = {**base, "sections": {"fingerprints": section(items)}, "search_queries": []}
    out, data = fit(Pack(body, redacted=True), "json", 30_000, requery=requery)
    kept = len(out.body["sections"]["fingerprints"]["items"])
    assert 0 < kept < 1999 and calls and calls[-1] == kept
    assert out.body["search_queries"] == [{"q": f"kept {kept}", "built_from": ["opt55"]}]
    assert json.loads(data)["search_queries"] == out.body["search_queries"]


def test_export_queries_only_cover_fingerprints_that_survived_size_fitting(monkeypatch):
    monkeypatch.setattr(evidence_export, "assemble", lambda *a, **k: many_fingerprints(1500))
    export = evidence_export.build_export(
        None, None, "d1", level="pseudonymized", fmt="json", confirm_full=False,
        now=0.0, vigie_version="t", rng=lambda n: SALT_A[:n], cap=40_000,
    )  # fmt: skip
    doc = json.loads(export.data)
    fingerprints = doc["sections"]["fingerprints"]
    assert fingerprints["status"] == "truncated" and fingerprints["omitted_count"] > 0
    kept_lists = {item["opt55"] for item in fingerprints["items"]}
    queried = [QUERY_FRAGMENT.match(q["q"]) for q in doc["search_queries"]]
    fragments = {m[1] for m in queried if m}
    assert fragments, "expected at least one opt55 query from the retained fingerprints"
    assert fragments <= kept_lists
    assert len(fragments) <= min(len(kept_lists), 12)


def test_queries_for_the_full_pack_are_unchanged_when_nothing_is_dropped():
    pack = sample()
    redacted = redact(pack, "pseudonymized", SALT_A)
    assert redacted.body["search_queries"] == build_queries(pack.body, "pseudonymized")
