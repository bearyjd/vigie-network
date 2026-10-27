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
ALIAS = re.compile(r"Device [a-z]{6}")
HEX = set("0123456789abcdef")

REJECTED = [
    "ㅤ", "ᅠ", "ᅟ", "ㅤㅤ TV", "аа bb cc dd ee ff", "ааbbccddeeff", "Ελλάδα", "中文",
    "المطبخ", "リビング", "спальня",
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
    "Garage door 3", "Anna’s phone", "Salle de bain", "TV", "Bedroom 1 and 2", "Café", "Straße",
    "Åsa", "François",
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


@pytest.mark.parametrize(
    "raw",
    [
        "Router\nKitchen", "Router" + " " * 4090 + "@secret", "Router @secret" + " " * 4090,
        " TV", "TV ", "Two  spaces", "tab\tname", "Zimmer\u00a0von", "\uff34\uff36",
        "\u0251b-cd-ef-\u0251b-cd-ef", "private\ua78fexample\ua78fcom", "\u0251", "TV\u0301",
        "x" * 4090 + " @secret", "Caf\u00e9\u00d7", "Caf\u00f7", "\u00aa", "Kid\u00b5",
    ],
)  # fmt: skip
def test_nothing_is_normalised_trimmed_or_truncated_before_validation(raw):
    assert scrub_label(raw, DEV) == alias(DEV)


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


def test_aliases_of_similar_ids_do_not_collide():
    assert alias("529") != alias("1497")  # four letters collided for exactly these two


def test_build_message_uses_the_device_for_the_alias():
    msg = build_message("d" * 32, "open", "i1", "aa:bb:cc:dd:ee:ff", DEV)
    assert alias(DEV) in msg.body and "aa:bb" not in msg.body
    assert "Living room TV" in build_message("d" * 32, "open", "i1", "Living room TV", DEV).body


# ---- property test: an independent reference acceptor, thousands of random strings -----------
ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '\u2019-") | {
    chr(c) for c in range(0xC0, 0x100)
} - {"\u00d7", "\u00f7"}


def _reference(raw: str) -> str | None:
    """The spec, written independently of the implementation: the input itself or None."""
    if not 1 <= len(raw) <= 48 or raw != raw.strip() or "  " in raw:
        return None
    if not set(raw) <= ALLOWED or unicodedata.normalize("NFKC", raw) != raw:
        return None
    letters = [c for c in raw if c.isalpha()]
    if not letters or sum(c.isdigit() for c in raw) > 3:
        return None
    if sum(c.lower() in HEX for c in raw if c.isascii() and c.isalnum()) >= 12:
        return None
    if any(len(w) >= 20 for w in re.split(r"[ '\u2019-]", raw)):
        return None
    return raw


POOLS = [
    list("abcdefghijklmnopqrstuvwxyzABCDEF "),
    list("0123456789 "),
    list("!\"#$%&()*+,./:;<=>?@[\\]^_`{|}~'-\t\n"),
    ["​", "‍", "﻿", "­", "⁠", "‮", "\x00", "\x1b", "́", "̸"],
    ["ㅤ", "ᅠ", "ᅟ", "а", "б", "α", "ا", "中"],
    ["ㅤ", "ᅠ", "ᅟ", "а", "б", "α", "ا", "中"],
    list("\u0251\ua78f\u03bf\u0435\u0131\u2113\uff45\u1d00\u0299\u0261\u0121\u0e00"),
    ["\U0001f642", "–", "—", "‑", "。", "．", "：", " ", "　"],
    list("üéрф中文リ١٢１Ａ"),
    ["aabbccddeeff", "aa-bb-cc", "10.0.0.1", "a.b.com", "x@y.z", "deadbeef", "12345", "TV", "2"],
]  # fmt: skip
SAMPLES = 6000


PLAIN = [list("ghijklmnopqrstuvwxyz GHIJKLMNOPQRSTUVWXYZ -'"), list("\u00fc\u00e9\u00df 012")]


def _random_label(rng: random.Random) -> str:
    if rng.random() < 0.5:  # mostly plain names, so the accepting branch is well covered
        pools = PLAIN + [rng.choice(POOLS)]
        return "".join(rng.choice(rng.choice(pools)) for _ in range(rng.randrange(1, 30)))
    if rng.random() < 0.15:  # any codepoint of any category
        picks = (rng.randrange(0x110000) for _ in range(rng.randrange(1, 12)))
        return "".join(chr(c) for c in picks if not 0xD800 <= c < 0xE000)
    return "".join(rng.choice(rng.choice(POOLS)) for _ in range(rng.randrange(0, 40)))


def test_property_output_is_the_input_verbatim_or_the_alias():
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


@pytest.mark.parametrize("raw", ["123", "1 - 2", "' -", "-", "7"])
def test_a_label_without_a_latin_letter_is_the_alias(raw):
    assert scrub_label(raw, DEV) == alias(DEV)


@pytest.mark.parametrize("raw", ["\u3164", "\u1160", "\u115f"])
def test_invisible_letters_are_never_returned(raw):
    assert scrub_label(raw, DEV) == alias(DEV)
    assert scrub_label(f"TV {raw}", DEV) == alias(DEV)


def test_cyrillic_lookalike_cannot_bypass_the_hex_squash():
    assert scrub_label("aa bb cc dd ee ff", DEV) == alias(DEV)
    assert scrub_label("\u0430\u0430 bb cc dd ee ff", DEV) == alias(DEV)


def test_symbols_named_latin_are_not_letters():
    assert scrub_label("Kid \u271d tab", DEV) == alias(DEV)  # LATIN CROSS is a symbol (So)


def test_every_allowed_character_is_already_nfkc_stable():
    assert all(unicodedata.normalize("NFKC", c) == c for c in ALLOWED)
