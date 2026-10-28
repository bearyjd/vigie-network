"""Tests for tools/docs_private_info_lint.py. All data here is synthetic placeholders."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "docs_private_info_lint.py"


def _load():
    spec = importlib.util.spec_from_file_location("docs_private_info_lint", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["docs_private_info_lint"] = mod
    spec.loader.exec_module(mod)
    return mod


lint = _load()


def kinds(text: str, words: tuple[str, ...] = ()) -> list[str]:
    return [f.kind for f in lint.scan_text("docs/x.md", text, words, frozenset())]


@pytest.mark.parametrize(
    "addr",
    ["192.168.0.5", "10.1.2.3", "172.16.0.1", "172.31.255.1", "100.64.0.1", "100.127.1.1"],
)
def test_private_and_tailscale_ipv4_flagged(addr: str) -> None:
    assert kinds(f"host {addr} here") == ["private-ip"]


@pytest.mark.parametrize(
    "addr",
    [
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.9",
        "172.15.0.1",
        "172.32.0.1",
        "100.63.0.1",
        "100.128.0.1",
        "8.8.8.8",
        "1.192.168.1.1",
        "010.0.0.1",
    ],
)
def test_documentation_and_public_ipv4_allowed(addr: str) -> None:
    assert kinds(f"host {addr} here") == []


def test_finding_reports_line_number() -> None:
    found = lint.scan_text("docs/x.md", "ok\nok\nip 10.0.0.9\n", (), frozenset())
    assert [(f.path, f.line) for f in found] == [("docs/x.md", 3)]


@pytest.mark.parametrize("mac", ["3c:22:fb:12:34:56", "A0-B1-C2-D3-E4-F5"])
def test_real_looking_mac_flagged(mac: str) -> None:
    assert kinds(f"dev {mac}") == ["mac"]


@pytest.mark.parametrize("mac", ["00:00:5e:00:53:01", "00:00:5E:00:53:01", "02:00:00:aa:bb:cc"])
def test_documentation_macs_allowed(mac: str) -> None:
    assert kinds(f"dev {mac}") == []


@pytest.mark.parametrize("path", ["/home/someone/x", "/var/home/someone/x"])
def test_home_paths_flagged(path: str) -> None:
    assert kinds(f"cd {path}") == ["home-path"]


def test_forbidden_words_case_insensitive_whole_word() -> None:
    assert kinds("Say Zorbo hi", ("zorbo",)) == ["forbidden-word"]
    assert kinds("zorbonic", ("zorbo",)) == []
    assert kinds("Say Zorbo hi", ()) == []


def test_allowed_value_suppresses_exact_match_only() -> None:
    found = lint.scan_text(
        "docs/x.md", "192.168.1.1 and 192.168.1.10", (), frozenset({"192.168.1.1"})
    )
    assert [f.match for f in found] == ["192.168.1.10"]


def test_parse_allowlist_and_glob_matching(tmp_path: Path) -> None:
    f = tmp_path / "allow"
    f.write_text("# c\n\npath tests/fixtures/**  # why\nvalue 192.168.1.1 # default\n")
    globs, values = lint.parse_allowlist(f)
    assert globs == ("tests/fixtures/**",)
    assert values == frozenset({"192.168.1.1"})
    assert lint.is_path_allowed("tests/fixtures/a/b.md", globs)
    assert not lint.is_path_allowed("docs/a.md", globs)


def test_parse_allowlist_rejects_bad_line(tmp_path: Path) -> None:
    f = tmp_path / "allow"
    f.write_text("bogus line\n")
    with pytest.raises(lint.LintError):
        lint.parse_allowlist(f)


def test_scope() -> None:
    assert lint.in_scope("docs/a/b.md")
    assert lint.in_scope("README.md")
    assert lint.in_scope(".trail/learnings/x.md")
    assert not lint.in_scope("server/src/a.py")
    assert not lint.in_scope("docs_other/a.md")


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return tmp_path


def _run(root: Path, *args: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), "--root", str(root), *args],
        capture_output=True,
        text=True,
        env=env or {},
        check=False,
    )


def test_cli_fails_with_file_line_output(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "fine\nip 10.0.0.9\n", "docs/ok.md": "192.0.2.1\n"})
    r = _run(root)
    assert r.returncode == 1
    assert "docs/a.md:2: private-ip: 10.0.0.9" in r.stdout
    assert "ok.md" not in r.stdout


def test_cli_passes_on_clean_repo(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "192.0.2.1\n", "server/x.py": "10.0.0.1\n"})
    assert _run(root).returncode == 0


def test_cli_ignores_untracked_files(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    (root / "docs/new.md").write_text("10.0.0.1\n")
    assert _run(root).returncode == 0


def test_cli_allowlist_path_glob(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/fixtures/a.md": "10.0.0.1\n"})
    allow = tmp_path / "allow.txt"
    allow.write_text("path docs/fixtures/**  # synthetic\n")
    assert _run(root, "--allowlist", str(allow)).returncode == 0


def test_cli_forbidden_words_from_env_and_file(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "hello Zorbo and Quux\n"})
    words = tmp_path / "words.txt"
    words.write_text("# private\nquux\n")
    r = _run(root, "--words-file", str(words), env={"VIGIE_LINT_FORBIDDEN_WORDS": "zorbo"})
    assert r.returncode == 1
    assert "docs/a.md:1: forbidden-word" in r.stdout
    assert r.stdout.count("forbidden-word") == 2
    # Public CI logs must not echo the private words themselves.
    assert "Zorbo" not in r.stdout and "Quux" not in r.stdout


def test_cli_missing_words_file_is_usage_error(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    r = _run(root, "--words-file", str(tmp_path / "nope"))
    assert r.returncode == 2
    assert "nope" in r.stderr


@pytest.mark.parametrize(
    "text",
    ["cd /Users/someone/x", r"dir C:\Users\someone\Desktop", "see ~someone/notes", "p=/home/someone"],
)
def test_other_home_path_forms_flagged(text: str) -> None:
    assert kinds(text) == ["home-path"]


@pytest.mark.parametrize(
    "text",
    [
        "https://host.example/home/foo",
        "https://host.example/Users/foo/bar",
        "see ~/notes and ~ alone",
        "a/b/home/foo",
    ],
)
def test_home_path_false_positives_avoided(text: str) -> None:
    assert kinds(text) == []


@pytest.mark.parametrize("text", ["v10.1.2.3", "version10.1.2.3", "10.0.0.1.5", "10.0.0.1.5.6"])
def test_ipv4_not_matched_inside_versions_or_longer_dotted_runs(text: str) -> None:
    assert kinds(text) == []


def test_leading_zero_ipv4_is_not_flagged() -> None:
    assert kinds("`010.0.0.1` is skipped") == []


def test_mac_allowed_only_in_documentation_range() -> None:
    assert kinds("00:00:5e:00:53:af") == []
    assert kinds("00:00:5e:12:34:56") == ["mac"]


@pytest.mark.parametrize("glob", ["*", "**", "docs/*", "docs/**", "*.md"])
def test_overbroad_allowlist_globs_rejected(tmp_path: Path, glob: str) -> None:
    f = tmp_path / "allow"
    f.write_text(f"path {glob}  # nope\n")
    with pytest.raises(lint.LintError):
        lint.parse_allowlist(f)


def test_exact_and_deep_allowlist_paths_accepted(tmp_path: Path) -> None:
    f = tmp_path / "allow"
    f.write_text("path .trail/learnings/one.md\npath tests/fixtures/**\n")
    globs, _ = lint.parse_allowlist(f)
    assert globs == (".trail/learnings/one.md", "tests/fixtures/**")


def test_cli_skips_binary_files(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    (root / "docs/pic.png").write_bytes(b"10.0.0.1")
    (root / "docs/blob.dat").write_bytes(b"\x89PNG\x00 10.0.0.2 \xff\xfe")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    assert _run(root).returncode == 0


@pytest.mark.parametrize("value", ["", " , ,"])
def test_cli_empty_forbidden_words_env_is_clean_noop(tmp_path: Path, value: str) -> None:
    root = _repo(tmp_path, {"docs/a.md": "hello\n"})
    assert _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": value}).returncode == 0
