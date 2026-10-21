"""`post`: real-time pacing by default, skew refusal, and key handling."""

from __future__ import annotations

import io
import json

import pytest

from trafficgen import DEFAULT_KEY
from trafficgen.cli import main


def _post(keyfile, *extra, windows="10"):
    return main(
        ["post", "--profile", "baseline", "--windows", windows, "--url", "http://x",
         "--key-file", str(keyfile), *extra]
    )  # fmt: skip


def test_default_post_is_paced_and_accepted_by_server_with_skew_limit(fake, keyfile, capsys):
    """10 windows span 9 min > the 300 s skew limit; only real-time replay is accepted."""
    assert _post(keyfile) == 0
    out = capsys.readouterr().out
    assert "UNEXPECTED" not in out
    assert fake.slept >= 9 * 60 - 1


def test_unpaced_long_span_refused_exit_2(fake, keyfile, capsys):
    assert _post(keyfile, "--no-pace") == 2
    err = capsys.readouterr().err
    assert "--max-skew-s" in err and "--no-pace-check" in err
    assert fake.slept == 0


def test_unpaced_refusal_threshold_is_max_skew_s(fake, keyfile):
    assert _post(keyfile, "--no-pace", windows="6") == 2  # 300 s span > 240 default
    assert _post(keyfile, "--no-pace", "--max-skew-s", "300", windows="6") != 2  # at the limit


def test_unpaced_short_span_allowed(fake, keyfile):
    assert _post(keyfile, "--no-pace", windows="4") == 0  # 180 s span < 240 default


def test_no_pace_check_overrides_and_server_then_rejects(fake, keyfile, capsys):
    """The guard is meaningful: without it the server really answers 400."""
    rc = _post(keyfile, "--no-pace", "--no-pace-check")
    assert rc == 1
    assert "400" in capsys.readouterr().out


def test_key_not_accepted_in_argv(keyfile):
    with pytest.raises(SystemExit) as exc:
        main(["post", "--profile", "baseline", "--url", "http://x", "--key-hex", "00" * 32])
    assert exc.value.code == 2


def test_key_from_env(fake, monkeypatch, keyfile):
    monkeypatch.setenv("VIGIE_TRAFFICGEN_KEY", DEFAULT_KEY.hex())
    rc = main(["post", "--profile", "baseline", "--windows", "4", "--url", "http://x"])
    assert rc == 0


def test_key_from_stdin(fake, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(DEFAULT_KEY.hex() + "\n"))
    rc = main(["post", "--profile", "baseline", "--windows", "4", "--url", "http://x",
               "--key-stdin"])  # fmt: skip
    assert rc == 0


def test_no_key_source_is_usage_error(monkeypatch):
    monkeypatch.delenv("VIGIE_TRAFFICGEN_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["post", "--profile", "baseline", "--url", "http://x"])
    assert exc.value.code == 2


def test_two_key_sources_is_usage_error(keyfile):
    with pytest.raises(SystemExit) as exc:
        main(["post", "--profile", "baseline", "--url", "http://x", "--key-file", str(keyfile),
              "--key-stdin"])  # fmt: skip
    assert exc.value.code == 2


def test_missing_key_file_clean_error(tmp_path, capsys):
    rc = main(["post", "--profile", "baseline", "--url", "http://x", "--key-file",
               str(tmp_path / "nope")])  # fmt: skip
    cap = capsys.readouterr()
    assert rc == 2 and "Traceback" not in cap.err and "cannot read key" in cap.err


@pytest.mark.parametrize("content", ["zz-not-hex-SECRETMATERIAL", "abc", ""])
def test_bad_hex_key_clean_error_never_echoes_key(tmp_path, capsys, content):
    p = tmp_path / "k"
    p.write_text(content)
    rc = main(["post", "--profile", "baseline", "--url", "http://x", "--key-file", str(p)])
    cap = capsys.readouterr()
    assert rc == 2 and "Traceback" not in cap.err
    assert "SECRETMATERIAL" not in cap.err + cap.out and "invalid key" in cap.err


def test_short_key_rejected(tmp_path, capsys):
    p = tmp_path / "k"
    p.write_text("00" * 8)
    assert main(["post", "--profile", "baseline", "--url", "http://x", "--key-file", str(p)]) == 2
    assert "32 bytes" in capsys.readouterr().err


def test_key_value_never_printed_on_success(fake, keyfile, capsys):
    _post(
        keyfile,
        windows="4",
    )
    cap = capsys.readouterr()
    assert DEFAULT_KEY.hex() not in cap.out + cap.err
    json.dumps(cap.out)
