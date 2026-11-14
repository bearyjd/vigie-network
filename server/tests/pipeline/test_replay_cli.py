"""End-to-end replay CLI on the synthetic scenario: report shape, abstentions apart, read-only."""

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from tests.pipeline.replay_fixtures import labels, labels_json, scenario, series_json
from vigie_pipeline.replay.cli import main

pytestmark = pytest.mark.timeout(120)
SMALL = ["--minimum-hours", "6", "--minimum-days", "3"]


@pytest.fixture(scope="module")
def files(tmp_path_factory):
    root = tmp_path_factory.mktemp("replay")
    s, lab = root / "series.json", root / "labels.json"
    s.write_bytes(series_json(scenario().values()))
    lab.write_bytes(labels_json(labels()))
    return s, lab


def run_cli(files, capsys, extra=()):
    code = main(["--series", str(files[0]), "--labels", str(files[1]), *SMALL, *extra])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_report_separates_abstentions_and_reports_each_detector(files, capsys):
    code, out, err = run_cli(files, capsys)
    assert code == 0 and err == ""
    rep = json.loads(out)
    assert rep["policy"]["algorithm"] == "pooled-median-v1"
    up, big = rep["detectors"]["upload_deviation"], rep["detectors"]["large_upload"]
    # backup: first hour is a miss (needs a pair), second is caught; update: a false alert
    assert up["verdicts"]["tp"] == 1 and up["verdicts"]["fn"] == 1 and up["verdicts"]["fp"] == 1
    assert up["alerts"]["true_episodes"] == 1 and up["alerts"]["false_episodes"] == 1
    # sleeping, gap and restart labels abstain; they are not in any verdict count
    assert up["abstained"]["by_reason"]["no_sample"] >= 2
    assert up["abstained"]["labelled_normal"] >= 2
    assert (
        big["verdicts"]["tp"] == 1 and big["precision"] == 1.0 and big["recall"] == round(1 / 3, 6)
    )
    assert big["abstained"]["by_reason"]["unqualified"] >= 1
    assert rep["labels"]["ignore"] == 1 and rep["labels"]["unknown_device"] == 0
    assert up["precision"] != "unknown" and up["coverage"]["evidence_hours"] > 0
    assert str(files[0].parent) not in out


def test_report_is_deterministic_for_shuffled_input_files(files, capsys, tmp_path):
    _, first, _ = run_cli(files, capsys)
    rng = random.Random(3)  # noqa: S311 - a test shuffle
    doc = json.loads(files[0].read_bytes())
    rng.shuffle(doc["devices"])
    for d in doc["devices"]:
        rng.shuffle(d["samples"])
    ldoc = json.loads(files[1].read_bytes())
    rng.shuffle(ldoc["labels"])
    s, lab = tmp_path / "s.json", tmp_path / "l.json"
    s.write_text(json.dumps(doc))
    lab.write_text(json.dumps(ldoc))
    _, second, _ = run_cli((s, lab), capsys)
    assert first == second


def test_inputs_are_never_modified_and_nothing_is_written_beside_them(files, capsys):
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in files}
    listing = sorted(os.listdir(files[0].parent))
    run_cli(files, capsys)
    assert {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in files} == before
    assert sorted(os.listdir(files[0].parent)) == listing


def test_errors_are_fixed_messages_without_paths_or_values(tmp_path, capsys, files):
    secret = tmp_path / "secret-name-dir"
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"version":1,"labels":[{"device":"x y z","hour":1,"verdict":"normal"}]}')
    for args, expect in (
        (["--series", str(secret), "--labels", str(bad)], "replay: cannot read an input file"),
        (["--series", str(files[0]), "--labels", str(bad)], "labels: invalid device id"),
        (
            ["--series", str(files[0]), "--labels", str(files[1]), "--minimum-hours", "0"],
            "replay: policy option outside supported bounds",
        ),
        (["--series", str(tmp_path), "--labels", str(bad)], "replay: cannot read an input file"),
    ):
        assert main(args) == 2
        err = capsys.readouterr().err
        assert err.strip() == expect
        assert "secret-name" not in err and str(tmp_path) not in err and "x y z" not in err


def test_symlink_and_oversize_inputs_are_refused(tmp_path, capsys, files):
    link = tmp_path / "link.json"
    link.symlink_to(files[0])
    assert main(["--series", str(link), "--labels", str(files[1])]) == 2
    assert capsys.readouterr().err.strip() == "replay: cannot read an input file"
    big = tmp_path / "big.json"
    big.write_bytes(b" " * ((4 << 20) + 5))
    assert main(["--series", str(big), "--labels", str(files[1])]) == 2
    assert capsys.readouterr().err.strip() == "series: input too large or unreadable"


def test_tod_strategy_option_runs(files, capsys):
    args = ["--strategy", "tod", "--min-samples-per-cohort", "2", "--min-days-per-cohort", "2"]
    code, out, _ = run_cli(files, capsys, args)
    assert code == 0 and json.loads(out)["policy"]["algorithm"] == "tod-median-v1"


def test_module_entrypoint_runs_in_a_subprocess_without_side_effects(files, tmp_path):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(Path("src").resolve()),
        "TMPDIR": str(tmp_path),
        "VIGIE_DATA_DIR": str(tmp_path / "nope"),
    }
    proc = subprocess.run(  # noqa: S603 - our own interpreter and module
        [
            sys.executable,
            "-m",
            "vigie_pipeline.replay",
            "--series",
            str(files[0]),
            "--labels",
            str(files[1]),
            *SMALL,
        ],
        capture_output=True,
        env=env,
        check=False,
        timeout=100,
    )
    assert proc.returncode == 0, proc.stderr[-300:]
    assert json.loads(proc.stdout)["detectors"]
    assert not (tmp_path / "nope").exists() and list(tmp_path.iterdir()) == []
