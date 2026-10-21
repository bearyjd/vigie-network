from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from conftest import FIXTURES, T0, _Closable

from trafficgen import cli
from trafficgen.cli import FIXTURE_SPECS, main
from trafficgen.generator import emissions_to_jsonl, generate


def test_generate_writes_batches_and_manifest(tmp_path):
    assert (
        main(
            [
                "generate",
                "--profile",
                "mac_clone",
                "--seed",
                "3",
                "--windows",
                "6",
                "--out",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert (tmp_path / "mac_clone.jsonl").stat().st_size > 0
    manifest = json.loads((tmp_path / "mac_clone.manifest.json").read_text())
    assert manifest["profile"] == "mac_clone" and manifest["seed"] == 3


def test_unknown_profile_rejected(tmp_path):
    with pytest.raises(SystemExit):
        main(["generate", "--profile", "nope", "--out", str(tmp_path)])


def test_post_requires_key(capsys, monkeypatch):
    monkeypatch.delenv("VIGIE_TRAFFICGEN_KEY", raising=False)
    with pytest.raises(SystemExit):
        main(["post", "--profile", "baseline", "--url", "http://127.0.0.1:1"])


def test_post_reports_connection_error(tmp_path, capsys):
    key = tmp_path / "k"
    key.write_text((b"\x07" * 32).hex())
    rc = main(
        [
            "post",
            "--profile",
            "baseline",
            "--windows",
            "4",
            "--url",
            "http://127.0.0.1:9",
            "--key-file",
            str(key),
        ]
    )
    assert rc == 2


@pytest.mark.parametrize("name", sorted(FIXTURE_SPECS))
def test_committed_fixtures_match_generator(name):
    """Fixtures are reproducible: regenerate with the recorded params, compare byte for byte."""
    spec = FIXTURE_SPECS[name]
    sc = generate(spec["profile"], **spec["kwargs"])
    assert (FIXTURES / f"{name}.jsonl").read_text() == emissions_to_jsonl(sc.emissions)
    assert json.loads((FIXTURES / f"{name}.manifest.json").read_text()) == sc.manifest


@pytest.mark.parametrize("profile,rc", [("baseline", 0), ("stale_ts", 0), ("replay", 0)])
def test_post_end_to_end_paced_fake_clock(fake, keyfile, capsys, profile, rc):
    """`post` maps the synthetic timeline onto the (fake) wall clock; a real-time server accepts."""
    argv = ["post", "--profile", profile, "--windows", "4", "--seed", "2", "--url", "http://x",
            "--key-file", str(keyfile)]  # fmt: skip
    assert main(argv) == rc
    assert "UNEXPECTED" not in capsys.readouterr().out


def test_post_flags_unexpected_status(monkeypatch, keyfile, capsys):
    monkeypatch.setattr(cli, "time", SimpleNamespace(time=lambda: T0, sleep=lambda s: None))
    monkeypatch.setattr(cli, "http_post", lambda url, **kw: (lambda b, h: (500, {}), _Closable()))
    argv = ["post", "--profile", "baseline", "--windows", "4", "--url", "http://x",
            "--key-file", str(keyfile)]  # fmt: skip
    assert main(argv) == 1
    assert "UNEXPECTED" in capsys.readouterr().out
