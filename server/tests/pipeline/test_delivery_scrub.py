"""The label scrubber is a FAIL-SAFE net: a suspect label becomes a stable alias, never a
partially redacted string. Separators are never enumerated: the check squashes them all away."""

from __future__ import annotations

import random
import re
import unicodedata

import pytest

from vigie_pipeline import delivery_publish as dp
from vigie_pipeline.delivery_publish import build_message, scrub_label

DEV = "dev-1"
ALIAS = re.compile(r"Device [0-9a-f]{4}")
SUSPECT_FORMS = [
    "deviceaa-bb-cc-dd-ee-ff", "aa/bb/cc/dd/ee/ff", "aa–bb–cc–dd–ee–ff",
    "aa​bb​cc​dd​ee​ff", "aabbccddeeff", "TV_aabbccddeeff",
    "TV AA  BB  CC  DD  EE  FF", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", "0123456789abcdef0123",
    "192。1。68。1。1", "192.168.1.1", "10.0.0.5", "１９２.168.1.1",
    "2001:db8::1", "fe80::1", "bob@example.com", "me@home", "http://10.0.0.5/x", "https://a",
    "evil.example.com", "evil。example。com", "foo.​com", "router.local",
    "12345678", "1 2 3 4 5 6 7 8",
]  # fmt: skip


def _suspect_features(text: str) -> bool:
    nfkc = unicodedata.normalize("NFKC", text)
    squashed = "".join(c for c in nfkc if c.isalnum()).lower()
    return (
        len(re.sub("[^0-9a-f]", "", squashed)) >= 12
        or sum(c.isdigit() for c in squashed) >= 8
        or "@" in nfkc
        or "://" in nfkc
        or bool(re.search(r"[\w-]+(\.[\w-]+)+\.[a-z]{2,}\b", nfkc, re.I))
    )


@pytest.mark.parametrize("raw", SUSPECT_FORMS)
def test_suspect_labels_become_the_alias_never_a_partial_redaction(raw):
    for label in (raw, f"Kid {raw} tab"):
        out = scrub_label(label, DEV)
        assert ALIAS.fullmatch(out), out
        assert scrub_label(out, DEV) == out


def test_alias_is_stable_per_device_and_differs_between_devices():
    a1 = scrub_label("aabbccddeeff", "dev-1")
    assert a1 == scrub_label("1.2.3.4.5.6.7.8.9", "dev-1")
    assert len({scrub_label("aabbccddeeff", f"dev-{i}") for i in range(50)}) > 20


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("Living room TV", "Living room TV"), ("Pi-hole 2", "Pi-hole 2"),
        ("Kid tablet", "Kid tablet"), ("Mum's laptop", "Mum's laptop"),
        ("Büro Drucker", "Büro Drucker"), ("Küche 🙂", "Küche"), ("Anna’s phone", "Anna’s phone"),
        ("Tom & Jerry", "Tom & Jerry"), ("Mr. Smith", "Mr. Smith"),
        ("Salle de bain", "Salle de bain"),
        ("Zimmer  von   Kim", "Zimmer von Kim"), ("Kitchen: cam/2", "Kitchen cam2"),
    ],
)  # fmt: skip
def test_ordinary_labels_survive(label, expected):
    assert scrub_label(label, DEV) == expected
    assert scrub_label(expected, DEV) == expected


def test_only_allowlisted_characters_survive():
    out = scrub_label("A<b>*c|d;e(f)g=h+i{j}k\x00l\x1bm‮n", DEV)
    assert re.fullmatch(r"[\w '’&.\-]+", out), out


def test_empty_and_unprintable_labels_use_the_alias():
    for raw in ("", "   ", "​​", "🙂🙂", None):
        assert ALIAS.fullmatch(scrub_label(raw, DEV))


def test_output_is_bounded():
    out = scrub_label("xyz " * 500, DEV)
    assert len(out) <= 64 and scrub_label(out, DEV) == out


def test_label_with_a_zero_width_trick_cannot_rebuild_a_hostname():
    assert ALIAS.fullmatch(scrub_label("foo.​com", DEV))
    assert ALIAS.fullmatch(scrub_label("foo​.com", DEV))


def test_build_message_uses_the_device_for_the_alias():
    msg = build_message("d" * 32, "open", "i1", "aa:bb:cc:dd:ee:ff", DEV)
    assert scrub_label("x1234567890", DEV) in msg.body
    assert "aa:bb" not in msg.body


SEPARATORS = (
    list("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n")
    + ["‐", "‑", "‒", "–", "—", "−", "​", "‌", "‍",
       " ", "　", "́", "̸", "﻿", "⁠", "­", "－", "／",
       "∕", "：", "。", "", "", "  "]
)  # fmt: skip
FILLER = list("abcdefxyz ghijklmnopqrstuvw0123456789 ")
FUZZ_SEEDS = range(400)


def _random_text(rng: random.Random) -> str:
    mac = [f"{rng.randrange(256):02x}" for _ in range(6)]
    if rng.random() < 0.5:
        mac = [m.upper() for m in mac]
    sep = [rng.choice(SEPARATORS) for _ in range(5)]
    joined = mac[0] + "".join(s + m for s, m in zip(sep, mac[1:], strict=True))
    around = lambda: "".join(rng.choice(FILLER) for _ in range(rng.randrange(0, 12)))  # noqa: E731
    return around() + joined + around()


@pytest.mark.parametrize("seed", FUZZ_SEEDS)
def test_fuzz_random_macs_with_random_separators_never_leak(seed):
    rng = random.Random(seed)  # noqa: S311
    raw = _random_text(rng)
    out = scrub_label(raw, DEV)
    squashed = "".join(c for c in unicodedata.normalize("NFKC", out) if c.isalnum()).lower()
    assert len(re.sub("[^0-9a-f]", "", squashed)) < 12
    assert ALIAS.fullmatch(out) or not _suspect_features(out)
    assert scrub_label(out, DEV) == out


def test_fuzz_actually_produces_hostile_inputs():
    texts = [_random_text(random.Random(s)) for s in FUZZ_SEEDS]  # noqa: S311
    assert sum(1 for t in texts if _suspect_features(t)) > len(texts) * 0.8


def test_regexes_never_see_more_than_256_characters(monkeypatch):
    seen = []

    class Spy:
        def __init__(self, inner):
            self.inner = inner

        def search(self, text, *a):
            seen.append(len(text))
            return self.inner.search(text, *a)

    for name in ("_HOSTNAME", "_IPV4", "_IPV6"):
        monkeypatch.setattr(dp, name, Spy(getattr(dp, name)))
    scrub_label("a" * 1_000_000, DEV)
    scrub_label("ﷺ" * 100_000, DEV)  # NFKC expands this character to 18
    assert seen and max(seen) <= 256
