"""Contracts for the read-only two-sender truncate check (PRP-004, H4).

Everything lives under tmp_path with placeholder names; nothing real is read or written.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PERSISTENT = Path(__file__).parents[1] / "persistent"
SPEC = importlib.util.spec_from_file_location(
    "senders_caught_up", PERSISTENT / "senders_caught_up.py"
)
assert SPEC is not None and SPEC.loader is not None
scu: Any = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scu
SPEC.loader.exec_module(scu)

FIRST_LINE = b'{"delivery_id": "a"}\n'
DELIVERY = FIRST_LINE + b'{"delivery_id": "b"}\n'


def private(path: Path, data: bytes | str) -> Path:
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)
    return path


def make_sender(tmp: Path, name: str, offset: int | None, content: bytes = DELIVERY) -> Path:
    """A config + cursor for one sender; offset None means no cursor file."""
    delivery = tmp / "delivery.jsonl"
    if not delivery.exists():
        private(delivery, content)
    cursor = tmp / f"{name}.cursor"
    if offset is not None:
        info = delivery.stat()
        body = {
            "offset": offset,
            "dev": info.st_dev,
            "ino": info.st_ino,
            "head": scu.ha._head_of(delivery.read_bytes()),
            "discard": False,
        }
        private(cursor, json.dumps(body))
    cfg = {"delivery_file": str(delivery), "cursor_file": str(cursor), "unrelated": "x"}
    return private(tmp / f"{name}.json", json.dumps(cfg))


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = scu.main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_both_caught_up_exit_0(tmp_path, capsys) -> None:
    n = len(DELIVERY)
    ntfy = make_sender(tmp_path, "ntfy", n)
    ha = make_sender(tmp_path, "ha", n)
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy), "--ha-config", str(ha))
    assert code == 0
    assert out.splitlines() == [
        f"ntfy: offset={n} size={n} caught_up",
        f"ha: offset={n} size={n} caught_up",
    ]


@pytest.mark.parametrize("behind", ["ntfy", "ha"])
def test_either_behind_exit_1(tmp_path, capsys, behind) -> None:
    n = len(DELIVERY)
    ntfy = make_sender(tmp_path, "ntfy", len(FIRST_LINE) if behind == "ntfy" else n)
    ha = make_sender(tmp_path, "ha", len(FIRST_LINE) if behind == "ha" else n)
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy), "--ha-config", str(ha))
    assert code == 1
    assert f"{behind}: offset={len(FIRST_LINE)} size={n} behind" in out.splitlines()


def test_single_sender_is_enough(tmp_path, capsys) -> None:
    n = len(DELIVERY)
    ha = make_sender(tmp_path, "ha", n)
    code, out, _ = run(capsys, "--ha-config", str(ha))
    assert code == 0 and out.splitlines() == [f"ha: offset={n} size={n} caught_up"]


def test_no_config_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        scu.main([])
    assert exc.value.code == 2


def test_cursor_ahead_of_size_is_behind(tmp_path, capsys) -> None:
    ahead = len(DELIVERY) + 5
    ntfy = make_sender(tmp_path, "ntfy", ahead)
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 1
    assert out.splitlines() == [f"ntfy: offset={ahead} size={len(DELIVERY)} behind"]


def test_cursor_for_replaced_file_is_behind_even_if_offsets_match(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))
    other = tmp_path / "other"
    private(other, DELIVERY)
    os.replace(other, tmp_path / "delivery.jsonl")  # same size and bytes, other inode
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 1 and "behind" in out


def test_cursor_with_other_first_line_is_behind(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))
    private(tmp_path / "delivery.jsonl", b'{"delivery_id": "z"}\n' + DELIVERY[len(FIRST_LINE) :])
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 1 and "behind" in out


def test_empty_file_with_zero_offset_is_caught_up(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", 0, content=b"")
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 0 and out.splitlines() == ["ntfy: offset=0 size=0 caught_up"]


def test_missing_cursor_exit_2_and_not_created(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", None)
    code, out, err = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2 and "caught_up" not in out
    assert not (tmp_path / "ntfy.cursor").exists()
    assert "ntfy" in err


def test_error_outranks_behind(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(FIRST_LINE))
    ha = make_sender(tmp_path, "ha", None)
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy), "--ha-config", str(ha))
    assert code == 2 and "ntfy: offset=" in out


def test_missing_delivery_file_exit_2(tmp_path, capsys) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))
    (tmp_path / "delivery.jsonl").unlink()
    code, _, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[]",
        "{}",
        '{"cursor_file": "/x"}',
        '{"delivery_file": "/x"}',
        '{"delivery_file": "rel", "cursor_file": "/x"}',
        '{"delivery_file": 1, "cursor_file": "/x"}',
    ],
)
def test_bad_config_exit_2(tmp_path, capsys, body) -> None:
    cfg = private(tmp_path / "bad.json", body)
    code, out, _ = run(capsys, "--ha-config", str(cfg))
    assert code == 2 and "caught_up" not in out


def test_missing_config_and_loose_mode_exit_2(tmp_path, capsys) -> None:
    code, _, _ = run(capsys, "--ha-config", str(tmp_path / "nope.json"))
    assert code == 2
    ha = make_sender(tmp_path, "ha", len(DELIVERY))
    ha.chmod(0o644)
    code, _, _ = run(capsys, "--ha-config", str(ha))
    assert code == 2


@pytest.mark.parametrize(
    "cursor",
    [
        "not json",
        "{}",
        '{"offset": -1, "dev": 0, "ino": 0, "head": ""}',
        '{"offset": true, "dev": 0, "ino": 0, "head": ""}',
    ],
)
def test_corrupt_cursor_exit_2(tmp_path, capsys, cursor) -> None:
    ntfy = make_sender(tmp_path, "ntfy", 0)
    private(tmp_path / "ntfy.cursor", cursor)
    code, out, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2 and "caught_up" not in out


def snapshot(directory: Path) -> dict[str, tuple[int, int, bytes]]:
    return {
        p.name: (p.stat().st_mtime_ns, p.stat().st_size, p.read_bytes())
        for p in sorted(directory.iterdir())
    }


@pytest.mark.parametrize("offset", [len(DELIVERY), len(FIRST_LINE), None])
def test_nothing_is_written(tmp_path, capsys, offset) -> None:
    ntfy = make_sender(tmp_path, "ntfy", offset)
    ha = make_sender(tmp_path, "ha", len(DELIVERY))
    before = snapshot(tmp_path)
    run(capsys, "--ntfy-config", str(ntfy), "--ha-config", str(ha))
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("offset", [len(DELIVERY), len(FIRST_LINE), None])
def test_output_never_contains_paths(tmp_path, capsys, offset) -> None:
    ntfy = make_sender(tmp_path, "ntfy", offset)
    ha = make_sender(tmp_path, "ha", None)
    code, out, err = run(capsys, "--ntfy-config", str(ntfy), "--ha-config", str(ha))
    for text in (out, err):
        assert str(tmp_path) not in text and "delivery.jsonl" not in text
        assert ".cursor" not in text
    assert code == 2


def cursor_for_zero(tmp: Path, name: str, delivery: Path) -> Path:
    """Config and an offset-0 cursor that point at `delivery` (any file type)."""
    cursor = private(tmp / f"{name}.cursor", '{"offset": 0, "dev": 0, "ino": 0, "head": ""}')
    cfg = {"delivery_file": str(delivery), "cursor_file": str(cursor)}
    return private(tmp / f"{name}.json", json.dumps(cfg))


def test_fifo_delivery_file_exit_2_without_hanging(tmp_path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    cfg = cursor_for_zero(tmp_path, "ntfy", fifo)
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(PERSISTENT / "senders_caught_up.py"), "--ntfy-config", str(cfg)],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert proc.returncode == 2 and "caught_up" not in proc.stdout


def test_symlinked_delivery_file_exit_2(tmp_path, capsys) -> None:
    real = private(tmp_path / "real.jsonl", DELIVERY)
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    cfg = cursor_for_zero(tmp_path, "ntfy", link)
    real.write_bytes(b"")  # size 0 == offset 0: only the symlink refusal can stop "caught_up"
    code, out, _ = run(capsys, "--ntfy-config", str(cfg))
    assert code == 2 and "caught_up" not in out


@pytest.mark.parametrize("target", ["_first_line_hash", "_paths"])
def test_oserror_from_a_read_exits_2_with_a_fixed_message(
    tmp_path, capsys, monkeypatch, target
) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))

    def boom(*_a: object, **_k: object) -> None:
        raise OSError(5, "Input/output error", str(tmp_path))

    owner = scu.ha if target == "_first_line_hash" else scu
    monkeypatch.setattr(owner, target, boom)
    code, out, err = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2 and "caught_up" not in out and str(tmp_path) not in err
    assert "Input/output error" in err  # mapped by check(), not the generic catch-all


def test_fstat_oserror_exits_2(tmp_path, capsys, monkeypatch) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))
    real_fstat = os.fstat
    calls: list[int] = []

    def flaky(fd: int) -> os.stat_result:
        calls.append(fd)
        if len(calls) == 3:  # config, cursor, then the delivery file
            raise OSError(5, "Input/output error")
        return real_fstat(fd)

    monkeypatch.setattr(scu.os, "fstat", flaky)
    code, _, _ = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2


def test_unexpected_exception_exits_2_with_a_fixed_message(tmp_path, capsys, monkeypatch) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError(f"secret {tmp_path}")

    monkeypatch.setattr(scu, "check", boom)
    code, out, err = run(capsys, "--ntfy-config", str(ntfy))
    assert code == 2 and "caught_up" not in out
    assert str(tmp_path) not in err and "Traceback" not in err


def test_keyboard_interrupt_is_not_swallowed(tmp_path, monkeypatch) -> None:
    ntfy = make_sender(tmp_path, "ntfy", len(DELIVERY))

    def stop(*_a: object, **_k: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(scu, "check", stop)
    with pytest.raises(KeyboardInterrupt):
        scu.main(["--ntfy-config", str(ntfy)])


def test_missing_ha_sender_exits_2_without_a_path(tmp_path) -> None:
    lone = tmp_path / "lonely"
    lone.mkdir()
    script = lone / "senders_caught_up.py"
    script.write_bytes((PERSISTENT / "senders_caught_up.py").read_bytes())
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(script), "--ha-config", str(tmp_path / "x.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2 and "Traceback" not in proc.stderr
    assert str(tmp_path) not in proc.stderr + proc.stdout


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_never_exits_0(capsys, flag) -> None:
    with pytest.raises(SystemExit) as exc:
        scu.main([flag])
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("empty_flag", ["--ntfy-config", "--ha-config"])
def test_empty_flag_value_is_an_error_not_skipped(tmp_path, capsys, empty_flag) -> None:
    caught_up = make_sender(tmp_path, "other", len(DELIVERY))
    other_flag = "--ha-config" if empty_flag == "--ntfy-config" else "--ntfy-config"
    code, out, _ = run(capsys, empty_flag, "", other_flag, str(caught_up))
    assert code == 2 and "caught_up" in out  # the named other sender is still reported


def test_only_an_empty_flag_value_exits_2(capsys) -> None:
    code, out, _ = run(capsys, "--ha-config", "")
    assert code == 2 and out == ""


def test_no_config_message_is_shown(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        scu.main([])
    assert exc.value.code == 2
    assert "at least one of --ntfy-config / --ha-config is required" in capsys.readouterr().err


def test_argparse_errors_do_not_echo_values(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        scu.main(["--bogus=/SECRET/VALUE", "/SECRET/POSITIONAL"])
    assert exc.value.code == 2
    assert "SECRET" not in capsys.readouterr().err


def test_runs_isolated_as_a_script(tmp_path) -> None:
    n = len(DELIVERY)
    ntfy = make_sender(tmp_path, "ntfy", n)
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            str(PERSISTENT / "senders_caught_up.py"),
            "--ntfy-config",
            str(ntfy),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0 and proc.stdout.strip() == f"ntfy: offset={n} size={n} caught_up"
