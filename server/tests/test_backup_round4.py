from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vigie_api.schema import OVERRIDES_MIGRATIONS, open_overrides
from vigie_ingest.db import INVENTORY_MIGRATIONS, open_inventory
from vigie_pipeline import backup
from vigie_pipeline.backup_cli import main
from vigie_pipeline.schema import apply_pipeline_migrations

SRC = str(Path(backup.__file__).resolve().parents[1])
# pytest-cov would trace the subprocess (more memory, slower): measure the plain interpreter
_ENV = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE", "COVERAGE"))}


@pytest.fixture
def sources(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    inv = open_inventory(src / "inventory.db")
    apply_pipeline_migrations(inv)
    ov = open_overrides(src / "overrides.db")
    yield src / "inventory.db", src / "overrides.db"
    inv.close()
    ov.close()


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    d = tmp_path / "dest"
    d.mkdir()
    d.chmod(0o700)
    return d


def _sql(path: Path, statement: str) -> None:
    c = sqlite3.connect(path)
    c.execute(statement)
    c.commit()
    c.close()


# --- 1: every manifest entry is fully validated ---


def _write_manifest(dest: Path, mutate) -> None:
    manifest = json.loads((dest / "manifest.json").read_text())
    mutate(manifest["files"][0])
    (dest / "manifest.json").write_text(json.dumps(manifest))


def _set(key: str, value):
    return lambda e: e.__setitem__(key, value)


def _drop(key: str):
    return lambda e: e.pop(key)


_BAD_ENTRIES = {
    "sha null": _set("sha256", None),
    "sha missing": _drop("sha256"),
    "sha int": _set("sha256", 5),
    "sha list": _set("sha256", ["a" * 64]),
    "sha uppercase": lambda e: e.__setitem__("sha256", e["sha256"].upper()),
    "sha short": lambda e: e.__setitem__("sha256", e["sha256"][:-1]),
    "sha with newline": lambda e: e.__setitem__("sha256", e["sha256"] + "\n"),
    "size missing": _drop("size"),
    "size mismatch": lambda e: e.__setitem__("size", e["size"] + 1),
    "size bool": _set("size", True),
    "size negative": _set("size", -1),
    "size string": lambda e: e.__setitem__("size", str(e["size"])),
    "name int": _set("name", 7),
}


@pytest.mark.parametrize("label", list(_BAD_ENTRIES))
def test_verify_rejects_a_manifest_entry_that_does_not_pin_hash_and_size(
    sources, dest: Path, label: str
) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    _write_manifest(dest, _BAD_ENTRIES[label])
    with pytest.raises(backup.VerifyError):
        backup.verify(dest)
    assert main(["verify", str(dest)]) == 1


def test_verify_rejects_a_non_object_manifest_entry(sources, dest: Path) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    (dest / "manifest.json").write_text(json.dumps({"files": ["overrides.db"]}))
    with pytest.raises(backup.VerifyError, match="malformed"):
        backup.verify(dest)


# --- 2: the restore hazard the docs warn about ---


def _count(path: Path) -> int:
    conn = open_overrides(path)
    try:
        return conn.execute("SELECT count(*) FROM marker").fetchone()[0]
    finally:
        conn.close()


def test_stale_wal_beside_a_restored_copy_replaces_the_backup_with_live_rows(
    tmp_path: Path,
) -> None:
    """docs/deploy.md: delete overrides.db-wal/-shm/-journal before copying a backup in."""
    live_dir, stash = tmp_path / "live", tmp_path / "stash"
    for d in (live_dir, stash):
        d.mkdir(mode=0o700)
    live = open_overrides(live_dir / "overrides.db")
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.execute("CREATE TABLE marker (n)")
    live.execute("INSERT INTO marker VALUES (0)")
    backup.backup(stash, inventory=None, overrides=live_dir / "overrides.db")
    for n in range(1, 50):  # live writes after the backup was taken
        live.execute("INSERT INTO marker VALUES (?)", (n,))
    stale_wal = (live_dir / "overrides.db-wal").read_bytes()  # what a crash would leave behind
    live.close()

    wrong, right = tmp_path / "wrong", tmp_path / "right"
    for d in (wrong, right):
        d.mkdir(mode=0o700)
        (d / "overrides.db").write_bytes((stash / "overrides.db").read_bytes())
    (wrong / "overrides.db-wal").write_bytes(stale_wal)  # sidecar not deleted first

    assert _count(right / "overrides.db") == 1  # the backup, as intended
    assert _count(wrong / "overrides.db") == 50  # the live rows: the backup was silently lost


# --- 3: CPU rlimit is the real bound ---


def _slow_check_copy(sources, dest: Path, rows: int) -> None:
    backup.backup(dest, inventory=None, overrides=sources[1])
    (dest / "manifest.json").unlink()
    conn = sqlite3.connect(dest / "overrides.db")
    conn.execute(
        "CREATE TABLE slow (x INTEGER CHECK (instr(printf('%.200000c','a')||x, "
        "printf('%.5000c','a')||'b') = 0))"
    )
    conn.execute("PRAGMA ignore_check_constraints=ON")
    conn.executemany("INSERT INTO slow VALUES (?)", [(i,) for i in range(rows)])
    conn.commit()
    conn.close()


_RUN = """
import sys
sys.path.insert(0, {src!r})
import vigie_pipeline.backup_cli as c
c.CPU_SOFT_S, c.CPU_HARD_MARGIN_S = 1, 2
sys.argv = ["vigie-backup", "verify", sys.argv[1], "--no-manifest"]
raise SystemExit(c.run())
"""


def test_a_check_that_burns_cpu_in_one_vm_step_is_stopped_by_the_rlimit(
    sources, dest: Path
) -> None:
    _slow_check_copy(sources, dest, rows=900)  # about 10 s of CPU in one integrity_check step
    t0 = time.monotonic()
    out = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", _RUN.format(src=SRC), str(dest)],
        capture_output=True,
        timeout=8,
        check=False,
        env=_ENV,
    )
    # exit 1 if Python could run the handler, else SIGKILL at the hard limit; never a crash
    assert out.returncode in (1, -9) and b"Traceback" not in out.stderr
    assert time.monotonic() - t0 < 8


def test_cpu_limit_is_set_by_run_with_a_soft_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    import resource
    import signal

    from vigie_pipeline import backup_cli

    calls = {}
    monkeypatch.setattr(resource, "setrlimit", lambda r, lim: calls.setdefault("lim", (r, lim)))
    monkeypatch.setattr(signal, "signal", lambda s, h: calls.setdefault("sig", (s, h)))
    monkeypatch.setattr(sys, "argv", ["vigie-backup", "verify", "/nonexistent-dir-xyz"])
    assert backup_cli.run() == 1
    assert calls["lim"] == (
        resource.RLIMIT_CPU,
        (backup_cli.CPU_SOFT_S, backup_cli.CPU_SOFT_S + backup_cli.CPU_HARD_MARGIN_S),
    )
    assert backup_cli.CPU_SOFT_S == 120
    assert calls["sig"][0] == signal.SIGXCPU
    with pytest.raises(backup.VerifyError, match="CPU budget"):
        calls["sig"][1](signal.SIGXCPU, None)


# --- 4: memory, absolute ---

_MEASURE = """
import resource, sys
sys.path.insert(0, {src!r})
from pathlib import Path
from vigie_pipeline import backup
mode, work = sys.argv[1], Path(sys.argv[2])
dest = work / "dest"
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
if mode == "backup":
    backup.backup(dest, inventory=None, overrides=work / "overrides.db")
else:
    backup.verify(dest)
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(before * 1024, (after - before) * 1024)
"""


def _measure(mode: str, work: Path) -> tuple[float, float]:
    out = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", _MEASURE.format(src=SRC), mode, str(work)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=_ENV,
    )
    assert out.returncode == 0, out.stderr[-300:]
    base, grown = out.stdout.split()
    return float(base), float(grown)


def test_worst_case_peak_at_the_cap_stays_under_400_mib(tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    (work / "dest").mkdir(mode=0o700)
    conn = open_overrides(work / "overrides.db")
    conn.execute("CREATE TABLE pad (b BLOB)")
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 32000) "
        "INSERT INTO pad SELECT randomblob(1000) FROM n"
    )
    conn.close()
    size = (work / "overrides.db").stat().st_size
    assert size > 30 * 1024 * 1024
    mib = 1024 * 1024
    for mode in ("backup", "verify"):
        base, grown = _measure(mode, work)
        projected = base + grown / size * backup.MAX_DB_BYTES
        assert projected < 400 * mib, f"{mode}: {projected / mib:.0f} MiB at the cap"
    assert backup.MAX_DB_BYTES == 96 * mib


# --- 6: one read transaction for the size check and the copy ---


def test_size_check_and_copy_share_one_read_transaction(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[bool] = []
    real = backup._copy_db

    def spy(src: sqlite3.Connection, dst: sqlite3.Connection) -> None:
        seen.append(src.in_transaction)
        real(src, dst)

    monkeypatch.setattr(backup, "_copy_db", spy)
    backup.backup(dest, inventory=None, overrides=sources[1])
    assert seen == [True]


# --- 7: sentinel tables ---


def test_swapped_files_with_the_same_user_version_are_refused(sources, dest: Path) -> None:
    backup.backup(dest, inventory=sources[0], overrides=sources[1])
    (dest / "manifest.json").unlink()
    inv, ov = dest / "inventory.db", dest / "overrides.db"
    inv_bytes, ov_bytes = inv.read_bytes(), ov.read_bytes()
    inv.write_bytes(ov_bytes)  # an overrides database named inventory.db ...
    ov.write_bytes(inv_bytes)  # ... and the other way round
    _sql(inv, f"PRAGMA user_version={len(INVENTORY_MIGRATIONS)}")  # same version as expected
    _sql(ov, f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS)}")
    with pytest.raises(backup.VerifyError, match="devices"):
        backup.verify(dest, require_manifest=False)
    inv.write_bytes(inv_bytes)
    with pytest.raises(backup.VerifyError, match="device_overrides"):
        backup.verify(dest, require_manifest=False)


def test_backup_refuses_swapped_sources_even_with_matching_versions(sources, dest: Path) -> None:
    inv, ov = sources
    _sql(ov, f"PRAGMA user_version={len(INVENTORY_MIGRATIONS)}")
    try:
        with pytest.raises(backup.BackupError, match="devices"):
            backup.backup(dest, inventory=ov, overrides=None)
    finally:
        _sql(ov, f"PRAGMA user_version={len(OVERRIDES_MIGRATIONS)}")


# --- 8: overflow uid only inside a real user namespace ---


def _sticky_nobody_ancestor(monkeypatch, tmp_path: Path, uid_map: str) -> None:
    real = os.lstat

    def lstat(path, *a, **k):
        st = real(path, *a, **k)
        if Path(path) == tmp_path or st.st_mode & 0o1000:  # every sticky dir is "owned" by 4242
            mode = 0o41777 if Path(path) == tmp_path else st.st_mode
            return os.stat_result((mode, st.st_ino, st.st_dev, 2, 4242, 0, 0, 0, 0, 0))
        return st

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(backup, "_overflow_uid", lambda: 4242)
    monkeypatch.setattr(backup, "_read_uid_map", lambda: uid_map)


def test_overflow_uid_is_not_trusted_without_a_user_namespace(
    sources, tmp_path: Path, dest: Path, monkeypatch
) -> None:
    _sticky_nobody_ancestor(monkeypatch, tmp_path, "         0          0 4294967295\n")
    with pytest.raises(backup.BackupError, match="owned by another"):
        backup.backup(dest, inventory=sources[0], overrides=None)


def test_overflow_uid_is_trusted_inside_a_real_user_namespace(
    sources, tmp_path: Path, dest: Path, monkeypatch
) -> None:
    _sticky_nobody_ancestor(monkeypatch, tmp_path, "         0       1000          1\n")
    backup.backup(dest, inventory=sources[0], overrides=None)


# --- 9: budgets ---


def test_trusted_live_source_gets_ten_times_the_budget_and_no_wrong_source_hint(
    sources, dest: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    budgets: list[float] = []
    real = backup._harden

    def spy(conn, budget):
        budgets.append(budget)
        return real(conn, budget)

    monkeypatch.setattr(backup, "_harden", spy)
    backup.backup(dest, inventory=None, overrides=sources[1])
    backup.verify(dest)
    assert budgets == [10 * backup.CHECK_BUDGET_S, backup.CHECK_BUDGET_S]

    def over(*a):
        raise backup.BudgetError("overrides.db check exceeded its budget")

    monkeypatch.setattr(backup, "_check_conn", over)
    other = dest.parent / "d2"
    other.mkdir(mode=0o700)
    with pytest.raises(backup.BackupError) as exc:
        backup.backup(other, inventory=None, overrides=sources[1])
    assert "budget" in str(exc.value) and "wrong or empty" not in str(exc.value)


# --- 5: the documented host-level fallback ---


def test_vacuum_into_of_a_wal_source_verifies_but_a_sqlite_backup_does_not(
    sources, dest: Path, tmp_path: Path
) -> None:
    ok, bad = tmp_path / "ok", tmp_path / "bad"
    for d in (ok, bad):
        d.mkdir(mode=0o700)
    live = sqlite3.connect(sources[1])
    live.execute(f"VACUUM INTO '{ok / 'overrides.db'}'")
    target = sqlite3.connect(bad / "overrides.db")
    live.backup(target)  # what `sqlite3 .backup` does: keeps the WAL header
    target.close()
    live.close()
    assert backup.verify(ok, require_manifest=False)[0]["status"] == "ok"
    with pytest.raises(backup.VerifyError, match="header"):
        backup.verify(bad, require_manifest=False)


# --- final round: the rlimit never raises an inherited limit, -m is bounded too ---


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        ((60, 60), (60, 60)),  # ulimit -t 60: clamp both, never raise
        ((30, -1), (30, 40)),  # a lower soft limit stays; hard becomes soft + margin
        ((-1, -1), (120, 130)),  # unlimited: our limits
        ((200, 300), (120, 130)),
    ],
)
def test_cpu_rlimit_is_clamped_to_the_inherited_limit(
    monkeypatch: pytest.MonkeyPatch, current, expected
) -> None:
    import resource
    import signal

    from vigie_pipeline import backup_cli

    inf = resource.RLIM_INFINITY
    cur = tuple(inf if v == -1 else v for v in current)
    calls: list[tuple] = []
    monkeypatch.setattr(resource, "getrlimit", lambda r: cur)

    def setrlimit(r, lim):
        if cur[1] != inf and lim[1] > cur[1]:
            raise ValueError("current limit exceeds maximum limit")  # what the kernel does
        calls.append(lim)

    monkeypatch.setattr(resource, "setrlimit", setrlimit)
    monkeypatch.setattr(signal, "signal", lambda s, h: None)
    monkeypatch.setattr(sys, "argv", ["vigie-backup", "verify", "/nonexistent-dir-xyz"])
    assert backup_cli.run() == 1
    assert calls == [expected]


def test_python_dash_m_entry_is_cpu_bounded_and_works() -> None:
    env = {**_ENV, "PYTHONPATH": SRC}
    out = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-m", "vigie_pipeline.backup_cli", "--help"],
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert out.returncode == 0 and b"vigie-backup" in out.stdout
    code = (
        "import resource, runpy, sys; sys.argv = ['x', '--help']\n"
        "try:\n"
        "    runpy.run_module('vigie_pipeline.backup_cli', run_name='__main__')\n"
        "except SystemExit:\n"
        "    print(resource.getrlimit(resource.RLIMIT_CPU)[0])\n"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        timeout=20,
        check=False,
        env=env,
    )
    assert out.stdout.split()[-1] == b"120"
