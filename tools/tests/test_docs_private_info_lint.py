"""Tests for tools/docs_private_info_lint.py. All data here is synthetic placeholders."""

from __future__ import annotations

import html
import importlib.util
import subprocess
import sys
import unicodedata
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


def test_forbidden_words_case_insensitive_letter_boundaries() -> None:
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


@pytest.mark.parametrize("path", ["/home/Zorbö/x", "/Users/佐尔博/x", "/var/home/Quüx/"])
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
    assert "docs/[***].md:1: private-ip: 10.0.0.9" in r.stdout
    assert "docs/[***].md:2: home-path: /home/[***]" in r.stdout
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
    assert "[***]" in missing.stderr


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
    assert lint.redact("A ZORBO b zorbo", ("zorbo",)) == "A [***] b [***]"
    assert lint.redact("x", ()) == "x"
    assert lint.redact("redacted chars", ("redacted", "chars")) == (
        "[***] [***]"
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


@pytest.mark.parametrize("option", ["--words-f", "--words", "--words-fi"])
@pytest.mark.parametrize("equals", [False, True])
def test_abbreviated_words_option_rejected_but_used_for_error_redaction(
    tmp_path: Path, option: str, equals: bool
) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    words = tmp_path / "words.txt"
    words.write_text("zorbo\n")
    args = (f"{option}={words}",) if equals else (option, str(words))
    r = _run(root, *args, "--zorbo-unknown", "zorbo")
    assert r.returncode == 2
    _no_leak(r)


@pytest.mark.parametrize("option", ["--words-f", "--words", "--words-fi", "--roo", "--allow"])
def test_argparse_never_accepts_abbreviated_options(tmp_path: Path, option: str) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    value = tmp_path / "empty.txt"
    value.write_text("")
    assert _run(root, option, str(value)).returncode == 2


def test_canonical_equals_words_option_redacts_parse_errors(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "ok\n"})
    words = tmp_path / "words.txt"
    words.write_text("zorbo\n")
    r = _run(root, f"--words-file={words}", "--zorbo-unknown")
    assert r.returncode == 2
    _no_leak(r)


@pytest.mark.parametrize(
    ("word", "rendered"),
    [
        ("Zorbö", "Zorbo\u0308"),
        ("Zorbo\u0308", "ZORBÖ"),
        ("Zorßo", "ZORSSO"),
        ("zorbo", "Ｚｏｒｂｏ"),
    ],
)
def test_unicode_normalization_matches_and_redacts(word: str, rendered: str) -> None:
    assert kinds(rendered, (word,)) == ["forbidden-word"]
    redacted = lint.redact(f"before {rendered} after", (word,))
    normalized_word = unicodedata.normalize("NFKC", word).casefold()
    assert normalized_word not in unicodedata.normalize("NFKC", redacted).casefold()
    assert "[***]" in redacted


@pytest.mark.parametrize("suffix", ["_notes", "42", ".md", "-notes.md", "/"])
def test_forbidden_word_with_suffix_is_detected(suffix: str) -> None:
    assert kinds(f"zorbo{suffix}", ("zorbo",)) == ["forbidden-word"]


@pytest.mark.parametrize("filename", ["docs/zorbo_notes.md", "docs/zorbo42.png"])
def test_filename_only_forbidden_words_are_detected(tmp_path: Path, filename: str) -> None:
    root = _repo(tmp_path, {filename: "clean content\n"})
    r = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "zorbo"})
    assert r.returncode == 1
    assert "forbidden-word" in r.stdout
    _no_leak(r)


@pytest.mark.parametrize("words", [("redacted", "chars", "finding"), ("[",), ("***",), ("[***]",)])
def test_redaction_marker_never_reintroduces_forbidden_words(words: tuple[str, ...]) -> None:
    result = lint.redact(" ".join(words), words)
    normalized = unicodedata.normalize("NFKC", result).casefold()
    assert all(unicodedata.normalize("NFKC", word).casefold() not in normalized for word in words)


def test_summary_is_redacted(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/a.md": "10.0.0.9\n"})
    r = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "finding,docs"})
    assert r.returncode == 1
    _no_leak(r, "finding")
    _no_leak(r, "docs")


def test_help_redacts_every_output_surface(tmp_path: Path) -> None:
    r = _run(tmp_path, "--help", env={"VIGIE_LINT_FORBIDDEN_WORDS": "root,words,tracked"})
    assert r.returncode == 0
    for word in ("root", "words", "tracked"):
        _no_leak(r, word)


def test_help_uses_fixed_neutral_program_name(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["zorbo-sensitive-script.py"])
    monkeypatch.delenv("VIGIE_LINT_FORBIDDEN_WORDS", raising=False)
    with pytest.raises(SystemExit) as exc:
        lint.main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "zorbo" not in captured.out + captured.err
    assert "docs-private-info-lint" in captured.out


@pytest.mark.parametrize(
    "text",
    [
        "address:3c:22:fb:12:34:56", "(address:3c:22:fb:12:34:56)",
        "mac:3c:22:fb:12:34:56", "MAC:3C:22:FB:12:34:56",
        "id:3c:22:fb:12:34:56", "bssid-3c-22-fb-12-34-56",
        "mac::3c:22:fb:12:34:56",
    ],
)
def test_mac_immediately_after_colon_is_detected(text: str) -> None:
    assert kinds(text) == ["mac"]


@pytest.mark.parametrize(
    "text",
    [
        "aa:3c:22:fb:12:34:56", "3c:22:fb:12:34:56:aa", "ff-3c-22-fb-12-34-56",
        "(aa:3c:22:fb:12:34:56)", "mac:aa:3c:22:fb:12:34:56",
        "aa:bb:3c:22:fb:12:34:56", "ff-aa-3c-22-fb-12-34-56",
    ],
)
def test_mac_is_not_extracted_from_longer_hex_runs(text: str) -> None:
    assert kinds(text) == []


def test_word_patterns_are_compiled_once_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    original = lint.re.compile
    calls: list[str] = []

    def counted(pattern, *args, **kwargs):
        calls.append(pattern)
        return original(pattern, *args, **kwargs)

    monkeypatch.setattr(lint.re, "compile", counted)
    matcher = lint.WordMatcher.build(("zorbo", "quux"))
    assert len(calls) == 2  # Letter-boundary detection and substring redaction.
    for _ in range(3):
        assert lint.scan_text("docs/a.md", "alpha\nbeta\ngamma\n", matcher, frozenset()) == []
        assert lint.redact("zorbonic quux", matcher) == "[***]nic [***]"
    assert len(calls) == 2


@pytest.mark.parametrize("finding_count", [20, 5000])
def test_thousand_words_scan_realistic_two_megabytes_within_ten_seconds(finding_count: int) -> None:
    script = fr"""
import importlib.util
import random
import sys
import time
spec = importlib.util.spec_from_file_location('docs_private_info_lint', {str(TOOL)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
words = tuple('word' + str(i) + 'token' for i in range(1000))
vocabulary = 'system documentation explains network settings with practical examples for operators who maintain services and review changes before release'.split()
rng = random.Random(481)
lines = [' '.join(rng.choices(vocabulary, k=20)) + '.' for _ in range(16000)]
text = '\n'.join(lines)
text = text[:2 * 1024 * 1024]
text += '\n' + '\n'.join(words[i % len(words)] for i in range({finding_count}))
started = time.perf_counter()
matcher = module.WordMatcher.build(words)
findings = module.scan_text('docs/a.md', text, matcher, frozenset())
output = '\n'.join(module.format_finding(finding, matcher) for finding in findings)
assert 'word0token' not in output
elapsed = time.perf_counter() - started
assert len(findings) == {finding_count}, len(findings)
assert elapsed < 10, elapsed
print(f'findings={{len(findings)}} elapsed={{elapsed:.3f}}s bytes={{len(text)}}')
"""
    try:
        r = subprocess.run(
            [sys.executable, "-I", "-c", script], capture_output=True,
            text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("1000-word scan of realistic 2 MiB prose exceeded fifteen seconds")
    assert r.returncode == 0, r.stderr
    print(r.stdout.strip())


def test_hash_inside_word_is_literal_and_whitespace_hash_starts_comment() -> None:
    assert lint._file_words("zorbo#tag\nquux # comment\n# comment\n") == ["zorbo#tag", "quux", ""]


def test_hash_inside_allowlist_path_is_literal(tmp_path: Path) -> None:
    allow = tmp_path / "allow"
    allow.write_text("path docs/zorbo#notes.md # synthetic reason\n")
    assert lint.parse_allowlist(allow)[0] == ("docs/zorbo#notes.md",)


def test_value_allowlist_cannot_suppress_forbidden_words() -> None:
    assert kinds("zorbo", ("zorbo",)) == ["forbidden-word"]
    found = lint.scan_text("docs/a.md", "zorbo", ("zorbo",), frozenset({"zorbo"}))
    assert [f.kind for f in found] == ["forbidden-word"]


@pytest.mark.parametrize("path", ["/mnt/c/Users/zorbo/notes", "/home/.zorbo/notes", "/Users/.zorbo/notes"])
def test_wsl_and_dot_prefixed_home_usernames_are_detected(path: str) -> None:
    assert kinds(path) == ["home-path"]


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("10.23.\u200b45.67", "private-ip"),
        ("10&#46;23&#46;45&#46;67", "private-ip"),
        ("3c&#58;22&#58;fb&#58;12&#58;34&#58;56", "mac"),
        ("/home/\u200bzorbo/notes", "home-path"),
        ("&#47;home&#47;zorbo/notes", "home-path"),
        ("zor\u200bbo", "forbidden-word"),
        ("zor&#98;o", "forbidden-word"),
    ],
)
def test_rendered_addresses_and_words_are_detected(text: str, kind: str) -> None:
    assert kinds(text, ("zorbo",) if kind == "forbidden-word" else ()) == [kind]


@pytest.mark.parametrize(
    "zero_width", ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u034f", "\u200e", "\u202e"]
)
def test_all_zero_width_characters_are_removed(zero_width: str) -> None:
    assert kinds(f"10.23.{zero_width}45.67") == ["private-ip"]
    assert kinds(f"zor{zero_width}bo", ("zorbo",)) == ["forbidden-word"]


@pytest.mark.parametrize("location", ["body", "filename"])
def test_cli_unicode_home_paths_and_filenames_never_leak(tmp_path: Path, location: str) -> None:
    nfd_name = "Zorbo\u0308"
    filename = f"docs/{nfd_name}.md" if location == "filename" else "docs/a.md"
    root = _repo(tmp_path, {filename: f"/home/{nfd_name}/notes\n"})
    r = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "Zorbö"})
    assert r.returncode == 1
    if location == "body":
        assert "forbidden-word" in r.stdout
    else:
        assert "[***]" in r.stdout
    output = unicodedata.normalize("NFKC", r.stdout + r.stderr).casefold()
    assert "zorbö" not in output


@pytest.mark.parametrize("hidden", ["\u200b", "&#8203;"])
def test_zero_width_before_combining_mark_redacts(hidden: str) -> None:
    rendered = f"Zorbo{hidden}\u0308"
    matcher = lint.WordMatcher.build(("Zorbö",))
    assert matcher.matches(f"docs/{rendered}.md") == ["zorbö"]
    redacted = lint.redact(rendered, matcher)
    # Strip the formatting character before normalization, as a renderer does.
    normalized = unicodedata.normalize("NFKC", html.unescape(redacted).replace("\u200b", "")).casefold()
    assert "zorbö" not in normalized


def test_cli_zero_width_combining_unicode_filename_only_never_leaks(tmp_path: Path) -> None:
    root = _repo(tmp_path, {"docs/Zorbo\u200b\u0308.md": "clean body\n"})
    r = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "Zorbö"})
    assert r.returncode == 1
    normalized = unicodedata.normalize("NFKC", (r.stdout + r.stderr).replace("\u200b", "")).casefold()
    assert "zorbö" not in normalized


def test_nested_html_entities_are_decoded_only_once() -> None:
    assert kinds("zor&amp;#98;o", ("zorbo",)) == []


@pytest.mark.parametrize("text", ["elixir", "annual", "maximum", "éeli", "elié", "字max字", "مmaxم"])
def test_forbidden_short_words_do_not_match_inside_unicode_letters(text: str) -> None:
    assert kinds(text, ("eli", "ann", "max")) == []


@pytest.mark.parametrize("text", ["zorbo_x", "zorbo2", "/home/zorbo/", "zorbo.md", "docs/zorbo-notes.md"])
def test_unicode_letter_boundary_includes_paths_digits_and_underscores(text: str) -> None:
    assert "forbidden-word" in kinds(text, ("zorbo",))


def test_redaction_remains_substring_based_for_other_findings() -> None:
    finding = lint.Finding("docs/elixir.md", 1, "private-ip", "10.0.0.9")
    assert lint.format_finding(finding, ("eli",)) == "docs/[***]xir.md:1: private-ip: 10.0.0.9"
    assert "eli" not in lint.redact("docs/ＥＬＩxir.md", ("eli",)).casefold()


@pytest.mark.parametrize(
    "text",
    ["fe80::3c:22:fb:12:34:56", "2001:db8::3c:22:fb:12:34:56", "::3c:22:fb:12:34:56"],
)
def test_mac_is_not_extracted_after_ipv6_double_colon(text: str) -> None:
    assert kinds(text) == []


@pytest.mark.parametrize("text", ["2001:db8:3c:22:fb:12:34:56", "2001:abcd:3c:22:fb:12:34:56"])
def test_mac_is_not_extracted_from_uncompressed_ipv6(text: str) -> None:
    assert kinds(text) == []


def test_changed_words_file_merges_early_and_loaded_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    words = tmp_path / "words.txt"
    words.write_text("earlysecret\n")
    monkeypatch.delenv(lint.WORDS_ENV, raising=False)
    original_load = lint.load_words

    def changed_load(path):
        words.write_text("latersecret\n")
        return original_load(path)

    def findings(root, matcher, paths, values):
        assert matcher.matches("earlysecret latersecret") == ["earlysecret", "latersecret"]
        return [lint.Finding("docs/earlysecret-latersecret.md", 1, "private-ip", "10.0.0.9")]

    monkeypatch.setattr(lint, "load_words", changed_load)
    monkeypatch.setattr(lint, "lint_repo", findings)
    assert lint.main(["--root", str(tmp_path), "--words-file", str(words)]) == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "earlysecret" not in output
    assert "latersecret" not in output
    assert "docs/[***]-[***].md:1: private-ip: 10.0.0.9" in output


def test_force_color_help_has_no_terminal_escapes(tmp_path: Path) -> None:
    result = _run(tmp_path, "--help", env={"FORCE_COLOR": "1"})
    assert result.returncode == 0
    assert "\x1b" not in result.stdout + result.stderr


@pytest.mark.parametrize("hidden", ["\u00ad", "\u034f", "\u200e", "\u202e"])
@pytest.mark.parametrize("location", ["filename", "path", "body"])
def test_cli_formatting_characters_never_hide_or_leak_words(
    tmp_path: Path, hidden: str, location: str,
) -> None:
    name = f"Zorbo{hidden}\u0308"
    filename = {
        "filename": f"docs/{name}.md",
        "path": f"docs/{name}/notes.md",
        "body": "docs/a.md",
    }[location]
    body = f"/home/{name}/notes 10.23.45.67\n" if location == "body" else "clean\n"
    root = _repo(tmp_path, {filename: body})
    result = _run(root, env={"VIGIE_LINT_FORBIDDEN_WORDS": "Zorbö"})
    # Independently emulate rendered output, including CGJ (category Mn).
    visible = "".join(
        ch for ch in result.stdout + result.stderr
        if unicodedata.category(ch) != "Cf" and ch != "\u034f"
    )
    assert "zorbö" not in unicodedata.normalize("NFKC", visible).casefold()
    assert result.returncode == 1
    if location == "body":
        assert "private-ip" in result.stdout


@pytest.mark.parametrize(("word", "text"), [("irem", "İrem"), ("İrem", "irem")])
def test_turkish_dotted_i_matches_and_redacts_in_both_directions(word: str, text: str) -> None:
    assert kinds(text, (word,)) == ["forbidden-word"]
    output = lint.redact(f"docs/{text}.md", (word,))
    assert "irem" not in unicodedata.normalize("NFKC", output).casefold().replace("i\u0307", "i")


@pytest.mark.parametrize("mac", ["00:00:5e:00:53:01", "02:00:00:aa:bb:cc"])
def test_labeled_documentation_and_dummy_macs_remain_allowed(mac: str) -> None:
    assert kinds(f"mac:{mac}") == []
