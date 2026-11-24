"""M2b-I CLI: offline file in, canonical JSON out, fixed errors and exit codes."""

from __future__ import annotations

from pathlib import Path

import pytest

from vigie_pipeline import product_signal_input as psi
from vigie_pipeline.product_signal_cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "product_signal"


def run(capsysbinary, *args: str) -> tuple[int, bytes, bytes]:
    code = main(list(args))
    out = capsysbinary.readouterr()
    return code, out.out, out.err


def test_golden_report_is_byte_identical(capsysbinary):
    code, out, err = run(capsysbinary, "--inventory", str(FIXTURES / "inventory.json"))
    assert (code, err) == (0, b"")
    assert out == (FIXTURES / "report.json").read_bytes()


def test_threshold_is_echoed_and_evaluated(capsysbinary):
    code, out, _ = run(
        capsysbinary, "--inventory", str(FIXTURES / "inventory.json"), "--threshold", "0.3"
    )
    assert code == 0
    assert b'"threshold":{"met":true,"value":"0.3"}' in out


def test_invalid_threshold_exits_2(capsysbinary):
    code, out, err = run(
        capsysbinary, "--inventory", str(FIXTURES / "inventory.json"), "--threshold", "2"
    )
    assert (code, out) == (2, b"")
    assert err == b"vigie-product-signal: invalid threshold\n"


def test_missing_arguments_exit_2_with_fixed_message(capsysbinary):
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2
    assert b"invalid or missing report arguments" in capsysbinary.readouterr().err


def test_unreadable_inventory_exits_3(capsysbinary, tmp_path):
    code, out, err = run(capsysbinary, "--inventory", str(tmp_path / "absent.json"))
    assert (code, out) == (3, b"")
    assert err == b"vigie-product-signal: cannot read inventory\n"


def test_invalid_inventory_exits_4_without_echoing_content(capsysbinary, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"format": "secret-value"}')
    code, out, err = run(capsysbinary, "--inventory", str(bad))
    assert (code, out) == (4, b"")
    assert err.startswith(b"vigie-product-signal: invalid inventory: ")
    assert b"secret" not in err


def test_oversize_inventory_is_rejected_with_a_bounded_read(capsysbinary, tmp_path, monkeypatch):
    monkeypatch.setattr(psi, "MAX_INPUT_BYTES", 16)
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 1024)
    seen: list[int] = []
    real = psi.load_inventory
    monkeypatch.setattr(psi, "load_inventory", lambda data: seen.append(len(data)) or real(data))
    code, _, err = run(capsysbinary, "--inventory", str(big))
    assert code == 4
    assert b"too large" in err
    assert seen == [17]  # read stops at cap + 1 bytes
