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


def test_parse_allowlist_and_exact_path_matching(tmp_path: Path) -> None:
    f = tmp_path / "allow"
    f.write_text("# c\n\npath docs/a/b.md  # why\nvalue 192.168.1.1 # default\n")
    paths, values = lint.parse_allowlist(f)
    assert paths == ("docs/a/b.md",)
    assert values == frozenset({"192.168.1.1"})
    assert lint.is_path_allowed("docs/a/b.md", paths)
    assert not lint.is_path_allowed("docs/a/b.mdx", paths)
    assert not lint.is_path_allowed("docs/a.md", paths)


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
    allow.write_text("path docs/fixtures/a.md  # synthetic\n")
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


@pytest.mark.parametrize(
    "glob",
    ["*", "**", "docs/*", "docs/**", "*.md", ".trail/learnings/**", "docs/spikes/*", "a/b?.md"],
)
def test_wildcard_allowlist_paths_rejected(tmp_path: Path, glob: str) -> None:
    f = tmp_path / "allow"
    f.write_text(f"path {glob}  # nope\n")
    with pytest.raises(lint.LintError):
        lint.parse_allowlist(f)


def test_exact_allowlist_path_accepted(tmp_path: Path) -> None:
    f = tmp_path / "allow"
    f.write_text("path .trail/learnings/one.md  # historical\n")
    paths, _ = lint.parse_allowlist(f)
    assert paths == (".trail/learnings/one.md",)


@pytest.mark.parametrize("line", ["path docs/a.md", "value 192.168.1.1", "path docs/a.md  #   "])
def test_allowlist_entry_without_reason_rejected(tmp_path: Path, line: str) -> None:
    f = tmp_path / "allow"
    f.write_text(line + "\n")
    with pytest.raises(lint.LintError):
        lint.parse_allowlist(f)


def _add(root: Path) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


def test_cli_scans_file_with_nul_byte(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    (root / "docs/nul.md").write_bytes(b"x\x00 10.23.45.67 \x00")
    _add(root)
    r = _run(root)
    assert r.returncode == 1
    assert "docs/nul.md:1: private-ip: 10.23.45.67" in r.stdout


def test_cli_scans_file_with_invalid_utf8(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    (root / "docs/bad.md").write_bytes(b"10.23.45.67\xff\n")
    _add(root)
    r = _run(root)
    assert r.returncode == 1
    assert "docs/bad.md:1: private-ip: 10.23.45.67" in r.stdout


def test_cli_skips_known_binary_suffix(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    (root / "docs/pic.png").write_bytes(b"10.23.45.67")
    _add(root)
    assert _run(root).returncode == 0


@pytest.mark.parametrize("value", ["", " , ,"])
def test_cli_empty_forbidden_words_env_is_clean_noop(tmp_path: Path, value: str) -> None:
    root = _repo(tmp_path, {"docs/a.md": "hello\n"})
    assert _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": value}).returncode == 0


@pytest.mark.parametrize(
    "text", ["_10.23.45.67_", "*10.23.45.67*", "**10.23.45.67**", "10%2E23%2E45%2E67", "10%2e23%2e45%2e67"]
)
def test_ipv4_found_through_markdown_emphasis_and_percent_encoding(text: str) -> None:
    assert kinds(text) == ["private-ip"]


@pytest.mark.parametrize("path", ["/home/Élodie/x", "/Users/李/x", "/var/home/Zoë/"])
def test_non_ascii_home_usernames_flagged(path: str) -> None:
    assert kinds(f"cd {path}") == ["home-path"]


def test_bare_home_directory_mentions_not_flagged() -> None:
    assert kinds("under `/home/` and (/Users/)") == []


@pytest.mark.parametrize("mac", ["3c22.fb12.3456", "3C22.FB12.3456."])
def test_cisco_dotted_mac_flagged(mac: str) -> None:
    assert kinds(f"dev {mac}") == ["mac"]


@pytest.mark.parametrize("mac", ["0000.5e00.5301", "0200.0000.0001"])
def test_cisco_dotted_documentation_and_dummy_macs_allowed(mac: str) -> None:
    assert kinds(f"dev {mac}") == []


def _no_leak(r, word: str = "zorbo") -> None:
    assert word not in (r.stdout + r.stderr).lower()


def test_redaction_covers_path_home_path_and_overlapping_findings(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        {
            "docs/Zorbo.md": "ip 10.0.0.9 and Zorbo at 10.0.0.8\n/home/Zorbo/notes\n",
            "docs/ok.md": "fine\n",
        },
    )
    r = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "zorbo"})
    assert r.returncode == 1
    _no_leak(r)
    assert "docs/<redacted 5 chars>.md:1: private-ip: 10.0.0.9" in r.stdout
    assert "docs/<redacted 5 chars>.md:2: home-path: /home/<redacted 5 chars>" in r.stdout
    assert "10.0.0.8" in r.stdout


def test_redaction_of_error_messages_for_exit_2(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    env = {"VIGIE_LINT_FORBIDDEN_WORDS": "zorbo"}
    missing = _run(root, "--words-file", str(tmp_path / "zorbo-words.txt"), env=env)
    bad_allow = tmp_path / "zorbo-allow"
    bad_allow.write_text("bogus Zorbo line\n")
    bad = _run(root, "--allowlist", str(bad_allow), env=env)
    arg = _run(root, "--zorbo-flag", env=env)
    for r in (missing, bad, arg):
        assert r.returncode == 2
        _no_leak(r)
    assert "<redacted 5 chars>" in missing.stderr


def test_redaction_uses_words_from_file_for_errors(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/Zorbo.md": "10.0.0.9\n"})
    words = tmp_path / "words.txt"
    words.write_text("zorbo\n")
    bad_allow = tmp_path / "zorbo-allow"
    bad_allow.write_text("bogus\n")
    r1 = _run(root, "--words-file", str(words))
    r2 = _run(root, "--words-file", str(words), "--allowlist", str(bad_allow))
    assert (r1.returncode, r2.returncode) == (1, 2)
    _no_leak(r1)
    _no_leak(r2)


def test_redact_function_is_single_pass_and_case_insensitive() -> None:
    assert lint.redact("A ZORBO b zorbo", ("zorbo",)) == "A <redacted 5 chars> b <redacted 5 chars>"
    assert lint.redact("x", ()) == "x"
    assert lint.redact("redacted chars", ("redacted", "chars")) == (
        "<redacted 8 chars> <redacted 5 chars>"
    )


def test_undecodable_words_file_and_allowlist_exit_2_without_traceback(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\xff\xfe\xfa")
    for args in (("--words-file", str(bad)), ("--allowlist", str(bad))):
        r = _run(root, *args)
        assert r.returncode == 2
        assert "Traceback" not in r.stderr
        assert "docs-private-info-lint: error:" in r.stderr
