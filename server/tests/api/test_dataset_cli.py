"""vigie-api dataset stage|list: bounded regular-file read, audited as cli:local."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from vigie_api import cli, dataset_cli, dataset_parse
from vigie_api.schema import open_overrides

FIX = Path(__file__).parent.parent / "fixtures" / "datasets"
KEV = FIX / "kev_small.json"


def run(root, *args: str) -> int:
    return cli.main(["dataset", *args, "--data-dir", str(root)])


def stage_args(path, source="kev", version="2099.01.01") -> list[str]:
    return ["stage", "--source", source, "--file", str(path), "--version", version,
            "--licence", "CC0"]  # fmt: skip


def rows(root, sql: str) -> list[tuple]:
    conn = open_overrides(root / "overrides.db")
    try:
        return [tuple(r) for r in conn.execute(sql)]
    finally:
        conn.close()


def test_stage_then_list(tmp_path, capsys):
    assert run(tmp_path, *stage_args(KEV)) == 0
    (row,) = rows(tmp_path, "SELECT source,entry_count,status,created_by FROM dataset_imports")
    assert row == ("kev", 3, "staged", "cli:local")
    (audit,) = rows(tmp_path, "SELECT principal,action FROM audit_log WHERE action='dataset.stage'")
    assert audit == ("cli:local", "dataset.stage")
    capsys.readouterr()
    assert run(tmp_path, "list") == 0
    out = capsys.readouterr().out
    sha = hashlib.sha256(KEV.read_bytes()).hexdigest()
    assert "kev" in out and "2099.01.01" in out and "staged" in out and sha[:12] in out
    assert sha not in out and "CVE-2021-0001" not in out


def test_list_on_empty_store_is_ok(tmp_path, capsys):
    assert run(tmp_path, "list") == 0
    assert capsys.readouterr().out.strip() == ""


def test_duplicate_stage_exits_1_without_a_second_row(tmp_path, capsys):
    assert run(tmp_path, *stage_args(KEV)) == 0
    assert run(tmp_path, *stage_args(KEV)) == 1
    assert "dataset_already_staged" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(1,)]


def test_malformed_file_exits_2_and_stores_nothing(tmp_path, capsys):
    assert run(tmp_path, *stage_args(FIX / "kev_malformed.json")) == 2
    assert "dataset_invalid" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(0,)]


def test_symlink_is_refused(tmp_path, capsys):
    link = tmp_path / "link.json"
    link.symlink_to(KEV)
    assert run(tmp_path, *stage_args(link)) == 2
    assert "cannot read" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(0,)]


def test_non_regular_files_are_refused(tmp_path, capsys):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for target in (tmp_path, fifo, tmp_path / "missing.json"):
        assert run(tmp_path, *stage_args(target)) == 2
        assert "cannot read" in capsys.readouterr().err


def test_oversized_file_is_refused_before_parsing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dataset_parse, "MAX_INPUT_BYTES", 10)
    assert run(tmp_path, *stage_args(KEV)) == 2
    assert "too large" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(0,)]


def test_the_read_is_bounded_not_slurped(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset_parse, "MAX_INPUT_BYTES", 10)
    sizes = []
    real = os.read
    monkeypatch.setattr(dataset_cli.os, "read", lambda fd, n: sizes.append(n) or real(fd, n))
    assert run(tmp_path, *stage_args(KEV)) == 2
    assert sizes and max(sizes) <= 11


def test_unknown_source_is_an_argument_error(tmp_path):
    args = stage_args(KEV, source="nope")
    with pytest.raises(SystemExit):
        run(tmp_path, *args)


def test_blank_version_is_rejected_with_exit_2(tmp_path, capsys):
    assert run(tmp_path, *stage_args(KEV, version=" ")) == 2
    assert "dataset_invalid" in capsys.readouterr().err
