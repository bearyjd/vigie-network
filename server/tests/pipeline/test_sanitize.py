from __future__ import annotations

from pipeline_helpers import data  # noqa: F401

from vigie_pipeline.sanitize import clean_text
from vigie_pipeline.sources import _clean

HOSTILE = "evil\x1b[2J‮<script>\x00"


def test_hostile_string_stripped():
    assert clean_text(HOSTILE) == "evil[2J<script>"


def test_each_class_removed():
    for ch in ("\x00", "\x07", "\x7f", "\x85", "\x9f", "‪", "‮", "⁦", "⁩",
               " ", " ", "​", "﻿"):  # fmt: skip
        assert clean_text(f"a{ch}b") == "ab", repr(ch)


def test_bounded_and_nfc():
    assert len(clean_text("x" * 1000)) == 256
    assert clean_text("é") == "é"


def test_empty_becomes_none():
    assert clean_text(None) is None
    assert clean_text(" \x00‮ ") is None
    assert clean_text("  ok  ") == "ok"


def test_source_clean_uses_sanitiser():
    assert _clean(HOSTILE) == "evil[2J<script>"


def test_hostile_strings_stored_clean_end_to_end(data):
    from pipeline_helpers import Data  # noqa: F401
    from test_processor import run

    nic = "00:11:22:33:44:55"
    data.add_batch(leases=[(nic, HOSTILE, "[1, 3]", HOSTILE)], sightings=[(nic, "mdns", HOSTILE)])
    run(data)
    (o,) = data.q("SELECT * FROM observations WHERE mac=?", nic)
    assert (o["hostname"], o["vendor_class"], o["mdns_name"]) == ("evil[2J<script>",) * 3
