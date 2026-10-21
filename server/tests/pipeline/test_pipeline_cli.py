from __future__ import annotations

import json
import logging

import pytest
from pipeline_helpers import T0, data  # noqa: F401

from vigie_pipeline import cli
from vigie_pipeline.logs import JsonFormatter

NIC = "00:11:22:33:44:55"


def test_run_once_processes_and_exits_zero(data, capsys):
    data.add_batch(neigh=[NIC])
    assert cli.main(["run", "--once", "--data-dir", str(data.root)]) == 0
    assert len(data.q("SELECT * FROM observations")) == 1


def test_data_dir_from_env(data, monkeypatch):
    data.add_batch(neigh=[NIC])
    monkeypatch.setenv("VIGIE_DATA_DIR", str(data.root))
    assert cli.main(["run", "--once"]) == 0
    assert len(data.q("SELECT * FROM observations")) == 1


def test_once_and_loop_are_mutually_exclusive(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--once", "--loop", "5", "--data-dir", str(data.root)])
    with pytest.raises(SystemExit):
        cli.main(["run", "--data-dir", str(data.root)])


def test_loop_repeats_sleeps_and_survives_db_errors(data, monkeypatch):
    calls: list[int] = []
    sleeps: list[float] = []

    def fake_run(config):
        calls.append(1)
        if len(calls) == 1:
            import sqlite3

            raise sqlite3.OperationalError("database is locked")
        return None

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_once", fake_run)
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    assert cli.main(["run", "--loop", "7", "--data-dir", str(data.root)]) == 0
    assert len(calls) == 3 and sleeps == [7, 7, 7]


def test_loop_interval_must_be_positive(data):
    with pytest.raises(SystemExit):
        cli.main(["run", "--loop", "0", "--data-dir", str(data.root)])


def test_json_formatter_emits_structured_fields():
    rec = logging.LogRecord("vigie_pipeline", logging.INFO, "f", 1, "run_complete", None, None)
    rec.fields = {"batches": 3}
    out = json.loads(JsonFormatter().format(rec))
    assert out["event"] == "run_complete" and out["batches"] == 3 and out["level"] == "info"


def test_cli_logs_have_no_qnames(data, capsys):
    data.add_batch(neigh=[NIC], dns=[(NIC, T0)])
    cli.main(["run", "--once", "--data-dir", str(data.root)])
    assert "secret-qname" not in capsys.readouterr().err
