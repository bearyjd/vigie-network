"""The label scrubber is a STRICT ACCEPTOR: a label passes verbatim or becomes a stable alias.
Nothing is ever cleaned, dropped or partially redacted, so every separator trick, hostname, IP,
email, URL or serial is impossible by construction and the function is idempotent."""

from __future__ import annotations

import random
import re
import unicodedata

import pytest

from vigie_pipeline.delivery_publish import alias, build_message, scrub_label

DEV = "dev-1"
ALIAS = re.compile(r"Device [a-z]{4}")
HEX = set("0123456789abcdef")

REJECTED = [
    "foo.рф", "TV 10.0.0.1x", "SN1234567", "ᄀ​ᅡ",  # Codex's cases
    "deviceaa-bb-cc-dd-ee-ff", "aa/bb/cc/dd/ee/ff", "aa–bb–cc–dd–ee–ff",
    "aa​bb​cc​dd​ee​ff", "aabbccddeeff", "TV_aabbccddeeff",
    "TV AA  BB  CC  DD  EE  FF", "aa bb cc dd ee ff", "deadbeefcafe", "aabb.ccdd.eeff",
    "aa:bb:cc:dd:ee:ff", "192。1。68。1。1", "192.168.1.1", "10.0.0.5",
    "１９２.168.1.1", "2001:db8::1", "fe80::1", "bob@example.com", "me@home",
    "http://10.0.0.5/x", "evil.example.com", "evil。example。com", "foo.​com",
    "router.local", "12345678", "1 2 3 4 5 6 7 8", "Room 1234", "TV_2", "Tom & Jerry",
    "Mr. Smith", "Küche \U0001f642", "١٢", "x́", "a​b", "a—b",
    "a‑b", "x" * 49, "Wordwordwordwordword", "", "   ", "​", None, "tab\x00",
]  # fmt: skip
ACCEPTED = [
    "Living room TV", "Pi-hole 2", "Kid tablet", "Mum's laptop", "Büro Drucker", "Küche",
    "Garage door 3", "Anna’s phone", "Salle de bain", "リビング", "TV",
    "спальня", "Bedroom 1 and 2",
]  # fmt: skip


@pytest.mark.parametrize("raw", REJECTED)
def test_everything_else_becomes_the_alias_and_never_a_cleaned_string(raw):
    for label in (raw, f"Kid {raw} tab") if isinstance(raw, str) and raw.strip() else (raw,):
        out = scrub_label(label, DEV)
        assert out == alias(DEV) and ALIAS.fullmatch(out), (label, out)
        assert scrub_label(out, DEV) == out


@pytest.mark.parametrize("label", ACCEPTED)
def test_ordinary_labels_survive_verbatim(label):
    assert scrub_label(label, DEV) == label


def test_whitespace_is_collapsed_and_edges_stripped_nothing_else_changes():
    assert scrub_label("  Zimmer  von \t\n  Kim ", DEV) == "Zimmer von Kim"
    assert scrub_label("ＴＶ", DEV) == "TV"  # NFKC


def test_boundaries():
    name = "x" * 19 + " " + "y" * 19 + " " + "z" * 8
    assert len(name) == 48 and scrub_label(name, DEV) == name
    assert scrub_label(name + "z", DEV) == alias(DEV)  # 49
    assert scrub_label("Room 123", DEV) == "Room 123" and scrub_label("Room 1234", DEV) == alias(
        DEV
    )
    assert scrub_label("x" * 19, DEV) == "x" * 19 and scrub_label("x" * 20, DEV) == alias(DEV)
    assert scrub_label("Kid-tablet-of-" + "x" * 20, DEV) == alias(DEV)  # one long word
    assert scrub_label("xyzxyzxyzxyzxyz", DEV) == "xyzxyzxyzxyzxyz"  # not hex: 0 hex chars
    assert scrub_label("Dad's cafe bad", DEV) == "Dad's cafe bad"  # 9 hex-ish letters: fine
    assert scrub_label("Dad's decade face bed", DEV) == alias(DEV)  # 12+ hex letters squashed


def test_alias_is_letters_only_stable_per_device_and_differs_between_devices():
    assert alias("dev-1") == alias("dev-1") and ALIAS.fullmatch(alias("dev-1"))
    assert len({alias(f"dev-{i}") for i in range(200)}) > 100
    assert scrub_label(alias("dev-1"), "dev-1") == alias("dev-1")  # accepted as is


def test_build_message_uses_the_device_for_the_alias():
    msg = build_message("d" * 32, "open", "i1", "aa:bb:cc:dd:ee:ff", DEV)
    assert alias(DEV) in msg.body and "aa:bb" not in msg.body
    assert "Living room TV" in build_message("d" * 32, "open", "i1", "Living room TV", DEV).body


# ---- property test: an independent reference acceptor, thousands of random strings -----------
def _reference(raw: str) -> str | None:
    """The spec, written independently of the implementation: the accepted text or None."""
    text = " ".join(unicodedata.normalize("NFKC", raw).split())
    if not 1 <= len(text) <= 48:
        return None
    if not all(c.isalpha() or c in " '’-" or c in "0123456789" for c in text):
        return None
    if sum(c in "0123456789" for c in text) > 3:
        return None
    squashed = [c.lower() for c in text if c.isalnum()]
    if sum(c in HEX for c in squashed) >= 12:
        return None
    if any(len(w) >= 20 for w in re.split(r"[ '’-]", text)):
        return None
    return text


POOLS = [
    list("abcdefghijklmnopqrstuvwxyzABCDEF "),
    list("0123456789 "),
    list("!\"#$%&()*+,./:;<=>?@[\\]^_`{|}~'-\t\n"),
    ["​", "‍", "﻿", "­", "⁠", "‮", "\x00", "\x1b", "́", "̸"],
    ["\U0001f642", "–", "—", "‑", "。", "．", "：", " ", "　"],
    list("üéрф中文リ١٢１Ａ"),
    ["aabbccddeeff", "aa-bb-cc", "10.0.0.1", "a.b.com", "x@y.z", "deadbeef", "12345", "TV", "2"],
]  # fmt: skip
SAMPLES = 6000


PLAIN = [list("ghijklmnopqrstuvwxyz GHIJKLMNOPQRSTUVWXYZ -'"), list("\u00fc\u00e9\u0440\u4e2d 012")]


def _random_label(rng: random.Random) -> str:
    if rng.random() < 0.5:  # mostly plain names, so the accepting branch is well covered
        pools = PLAIN + [rng.choice(POOLS)]
        return "".join(rng.choice(rng.choice(pools)) for _ in range(rng.randrange(1, 30)))
    return "".join(rng.choice(rng.choice(POOLS)) for _ in range(rng.randrange(0, 40)))


def test_property_output_is_the_reference_acceptance_or_the_alias():
    accepted = 0
    for seed in range(SAMPLES):
        raw = _random_label(random.Random(seed))  # noqa: S311
        out = scrub_label(raw, DEV)
        want = _reference(raw)
        assert out == (alias(DEV) if want is None else want), (seed, raw, out)
        assert scrub_label(out, DEV) == out, (seed, out)  # idempotent
        assert not set(".@:/_") & set(out), (seed, out)
        if want is not None:
            accepted += 1
            assert len(out) <= 48 and sum(c.isdigit() for c in out) <= 3
            assert scrub_label(want, DEV) == want  # differential: accepted text is a fixed point
    assert SAMPLES * 0.05 < accepted < SAMPLES * 0.95  # both branches are exercised
