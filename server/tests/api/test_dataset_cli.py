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


def stage_args(path, source="kev", version="2025.01.01") -> list[str]:
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
    assert "kev" in out and "2025.01.01" in out and "staged" in out and sha[:12] in out
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
    monkeypatch.setattr(dataset_parse, "KEV_MAX_INPUT", 10)
    assert run(tmp_path, *stage_args(KEV)) == 2
    assert "too large" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(0,)]


def test_the_read_is_bounded_not_slurped(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset_parse, "KEV_MAX_INPUT", 10)
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


def test_each_source_is_read_with_its_own_cap(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dataset_parse, "KEV_MAX_INPUT", 10)
    assert run(tmp_path, *stage_args(FIX / "urlhaus_small.csv", source="urlhaus")) == 0
    assert run(tmp_path, *stage_args(KEV)) == 2
    monkeypatch.setattr(dataset_parse, "URLHAUS_MAX_INPUT", 10)
    assert run(tmp_path, *stage_args(FIX / "urlhaus_hosts.csv", source="urlhaus")) == 2
    assert capsys.readouterr().err.count("too large") == 2


def test_the_file_is_opened_without_a_controlling_tty_and_close_on_exec(tmp_path, monkeypatch):
    flags = []
    real = os.open
    monkeypatch.setattr(
        dataset_cli.os,
        "open",
        lambda p, f, *a: (flags.append(f) if str(p) == str(KEV) else 0, real(p, f, *a))[1],
    )
    assert run(tmp_path, *stage_args(KEV)) == 0
    needed = os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY | os.O_CLOEXEC
    assert len(flags) == 1 and flags[0] & needed == needed


def staged_id(root, version="2025.01.01", path=KEV) -> str:
    assert run(root, *stage_args(path, version=version)) == 0
    return rows(root, "SELECT id FROM dataset_imports ORDER BY created_at DESC, rowid DESC")[0][0]


def test_accept_and_reject_exit_codes_and_output(tmp_path, capsys):
    imp = staged_id(tmp_path)
    capsys.readouterr()
    assert run(tmp_path, "accept", imp, "--by", "alice") == 0
    assert f"accepted {imp}" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT status,accepted_by FROM dataset_imports") == [
        ("accepted", "alice")
    ]
    assert run(tmp_path, "accept", imp) == 1  # double accept: conflict
    assert "dataset_not_staged" in capsys.readouterr().err
    assert run(tmp_path, "reject", imp) == 1
    assert run(tmp_path, "accept", "nope") == 1
    assert "dataset_import_not_found" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM audit_log WHERE action='dataset.accept'") == [(1,)]


def test_reject_with_reason_defaults_operator_to_cli_local(tmp_path, capsys):
    imp = staged_id(tmp_path)
    assert run(tmp_path, "reject", imp, "--reason", "bad licence") == 0
    assert f"rejected {imp}" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT status,rejected_by,reject_reason FROM dataset_imports") == [
        ("rejected", "cli:local", "bad licence")
    ]
    (audit,) = rows(
        tmp_path, "SELECT principal,detail FROM audit_log WHERE action='dataset.reject'"
    )
    assert audit[0] == "cli:local" and "bad licence" in audit[1] and "CVE-2021" not in audit[1]


def test_overlong_reason_exits_2(tmp_path, capsys):
    imp = staged_id(tmp_path)
    assert run(tmp_path, "reject", imp, "--reason", "x" * 201) == 2
    assert "dataset_invalid" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT status FROM dataset_imports") == [("staged",)]


def test_accept_refusals_exit_1_and_force_overrides_churn(tmp_path, capsys):
    first = staged_id(tmp_path)
    assert run(tmp_path, "accept", first) == 0
    small = tmp_path / "small.json"
    small.write_text(
        '{"vulnerabilities":[{"cveID":"CVE-2024-1000","vendorProject":"V","product":"P",'
        '"dateAdded":"2024-01-01"}]}'
    )
    older = staged_id(tmp_path, "2024.01.01", small)
    capsys.readouterr()
    assert run(tmp_path, "accept", older) == 1
    assert "dataset_version_older" in capsys.readouterr().err
    small2 = tmp_path / "small2.json"
    small2.write_text(small.read_text().replace('"V"', '"W"'))
    newer = staged_id(tmp_path, "2025.02.01", small2)
    capsys.readouterr()
    assert run(tmp_path, "accept", newer) == 1
    assert "dataset_churn_exceeded" in capsys.readouterr().err
    assert run(tmp_path, "accept", newer, "--force") == 0
    audit = rows(
        tmp_path,
        "SELECT detail FROM audit_log WHERE action='dataset.accept' ORDER BY rowid DESC",
    )[0]
    assert '"force":true' in audit[0]


def test_list_shows_new_statuses(tmp_path, capsys):
    imp = staged_id(tmp_path)
    run(tmp_path, "reject", imp)
    capsys.readouterr()
    assert run(tmp_path, "list") == 0
    assert "rejected" in capsys.readouterr().out


def test_future_version_is_refused_at_stage_with_exit_2(tmp_path, capsys):
    assert run(tmp_path, *stage_args(KEV, version="2099.01.01")) == 2
    assert "future" in capsys.readouterr().err
    assert rows(tmp_path, "SELECT COUNT(*) FROM dataset_imports") == [(0,)]


def test_allow_older_flag_accepts_a_lower_version_and_is_audited(tmp_path, capsys):
    new = tmp_path / "new.json"
    new.write_text(KEV.read_text().replace('"Acme"', '"Acme2"'))
    first = staged_id(tmp_path, "2025.02.01")
    assert run(tmp_path, "accept", first) == 0
    older = staged_id(tmp_path, "2025.01.01", new)
    capsys.readouterr()
    assert run(tmp_path, "accept", older, "--force") == 1
    assert "dataset_version_older" in capsys.readouterr().err
    assert run(tmp_path, "accept", older, "--allow-older") == 0
    last = rows(
        tmp_path, "SELECT detail FROM audit_log WHERE action='dataset.accept' ORDER BY rowid DESC"
    )[0]
    assert '"allow_older":true' in last[0]
