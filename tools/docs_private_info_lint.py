#!/usr/bin/env python3
r"""Fail when tracked docs hold private household information.

Scope: DOCS ONLY - tracked docs/**, README.md and .trail/learnings/**. Code, tests and
fixtures elsewhere in the repo are deliberately NOT scanned. Flags private-range and
Tailscale IPv4 addresses, MAC addresses (colon, dash and Cisco dotted forms), absolute home
paths (/home, /var/home, /Users, C:\Users, ~name/) and an operator-supplied list of
forbidden words (env VIGIE_LINT_FORBIDDEN_WORDS, comma separated, and/or an untracked
--words-file, one word per line). CI feeds the env var from an optional repo secret the
owner adds; unset is a no-op. The shipped list is empty: never commit real names.

Every diagnostic (paths, matches, error messages) has forbidden words replaced by
`<redacted N chars>` so a public CI log never repeats them.

Allowlist (tools/docs_private_info_lint.allowlist): `path <exact path>` and
`value <literal>`, each with a `# reason`. Wildcard paths are rejected.

Exit codes: 0 clean, 1 findings, 2 usage/IO error. Run as `python3 -I`.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import NoReturn

SCOPE_GLOBS = ("docs/**", "README.md", ".trail/learnings/**")
WORDS_ENV = "VIGIE_LINT_FORBIDDEN_WORDS"
DEFAULT_ALLOWLIST = Path(__file__).resolve().with_name("docs_private_info_lint.allowlist")
# 00:00:5E:00:53 is the IANA documentation range; 02:00:00 is the repo's dummy MAC prefix
# (locally administered, used by fixtures and README examples).
ALLOWED_MAC_PREFIXES = ("00:00:5e:00:53:", "02:00:00:")
# Only these are skipped; every other in-scope file is scanned (NUL / bad UTF-8 included).
BINARY_SUFFIXES = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".avif",
        ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".mp3", ".mp4", ".webm", ".mov",
    }
)  # fmt: skip

_OCTET = r"(0|[1-9]\d{0,2})"
IPV4_RE = re.compile(
    rf"(?<![A-Za-z0-9.]){_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}(?!\d|\.\d)"
)
MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
    r"|(?<![0-9A-Fa-f.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f]|\.[0-9A-Fa-f])"
)
HOME_RE = re.compile(
    r"(?<![\w.\-])/(?:var/home|home|Users)/\w[^\s/]*"
    r"|[A-Za-z]:\\Users\\[^\\\s]+"
    r"|(?<![\w/~])~[^\W\d][\w.-]*/"
)


class LintError(Exception):
    """Usage or I/O problem (exit 2), as opposed to findings (exit 1)."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    match: str


def _is_private_ipv4(octets: tuple[int, ...]) -> bool:
    a, b = octets[0], octets[1]
    return (
        a == 10
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
        or (a == 100 and 64 <= b <= 127)
    )


def _ip_matches(line: str) -> list[str]:
    decoded = line.replace("%2E", ".").replace("%2e", ".")
    found = []
    for m in IPV4_RE.finditer(decoded):
        octets = tuple(int(g) for g in m.groups())
        if all(o <= 255 for o in octets) and _is_private_ipv4(octets):
            found.append(m.group(0))
    return found


def _normalize_mac(raw: str) -> str:
    digits = re.sub(r"[^0-9a-f]", "", raw.lower())
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)) + ":"


def _mac_matches(line: str) -> list[str]:
    return [
        m.group(0)
        for m in MAC_RE.finditer(line)
        if not _normalize_mac(m.group(0)).startswith(ALLOWED_MAC_PREFIXES)
    ]


def _word_matches(line: str, words: tuple[str, ...]) -> list[str]:
    return [
        m.group(0)
        for w in words
        for m in re.finditer(rf"(?<!\w){re.escape(w)}(?!\w)", line, re.IGNORECASE)
    ]


def redact(text: str, words: tuple[str, ...]) -> str:
    """Replace every case-insensitive occurrence of any word, in one pass."""
    if not words:
        return text
    ordered = sorted(words, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(w) for w in ordered), re.IGNORECASE)
    return pattern.sub(lambda m: f"<redacted {len(m.group(0))} chars>", text)


def scan_text(
    path: str, text: str, words: tuple[str, ...], allowed_values: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.split("\n"), start=1):
        hits = (
            [("private-ip", s) for s in _ip_matches(line)]
            + [("mac", s) for s in _mac_matches(line)]
            + [("home-path", m.group(0)) for m in HOME_RE.finditer(line)]
            + [("forbidden-word", s) for s in _word_matches(line, words)]
        )
        findings.extend(
            Finding(path, number, kind, s) for kind, s in hits if s not in allowed_values
        )
    return findings


def _read_utf8(path: Path, what: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise LintError(f"{what} {path} is not valid UTF-8 ({exc.reason})") from exc
    except OSError as exc:
        raise LintError(f"cannot read {what} {path}: {exc.strerror or exc}") from exc


def parse_allowlist(path: Path) -> tuple[tuple[str, ...], frozenset[str]]:
    paths: list[str] = []
    values: list[str] = []
    for number, raw in enumerate(_read_utf8(path, "allowlist").splitlines(), start=1):
        entry, _, reason = raw.partition("#")
        if not entry.strip():
            continue
        parts = entry.split()
        if len(parts) != 2 or parts[0] not in ("path", "value"):
            raise LintError(f"{path}:{number}: expected 'path <path>' or 'value <literal>'")
        if not reason.strip():
            raise LintError(f"{path}:{number}: allowlist entry needs a '# reason'")
        if parts[0] == "path" and any(c in parts[1] for c in "*?["):
            raise LintError(f"{path}:{number}: wildcard path '{parts[1]}' not allowed; use exact paths")
        (paths if parts[0] == "path" else values).append(parts[1])
    return tuple(paths), frozenset(values)


def is_path_allowed(rel: str, paths: tuple[str, ...]) -> bool:
    return rel in paths


def in_scope(rel: str) -> bool:
    return any(fnmatchcase(rel, g) for g in SCOPE_GLOBS)


def _env_words() -> list[str]:
    return [w.strip() for w in os.environ.get(WORDS_ENV, "").split(",")]


def _file_words(text: str) -> list[str]:
    return [ln.split("#", 1)[0].strip() for ln in text.splitlines()]


def _dedupe(words: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(w for w in words if w))


def load_words(words_file: Path | None) -> tuple[str, ...]:
    words = _env_words()
    if words_file is not None:
        words.extend(_file_words(_read_utf8(words_file, "words file")))
    return _dedupe(words)


def best_effort_words(argv: list[str]) -> tuple[str, ...]:
    """Words usable for redacting diagnostics, even when option parsing or reading failed."""
    words = _env_words()
    for i, arg in enumerate(argv):
        target = None
        if arg == "--words-file" and i + 1 < len(argv):
            target = argv[i + 1]
        elif arg.startswith("--words-file="):
            target = arg.split("=", 1)[1]
        if target:
            try:
                words.extend(_file_words(Path(target).read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                pass
    return _dedupe(words)


def tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LintError(f"cannot list tracked files in {root}: {exc}") from exc
    return [p for p in out.split("\0") if p and in_scope(p)]


def _read_scannable(path: Path) -> str | None:
    """File text (undecodable bytes replaced), or None for known-binary suffixes only."""
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        raise LintError(f"cannot read {path}: {exc.strerror or exc}") from exc


def lint_repo(
    root: Path, words: tuple[str, ...], paths: tuple[str, ...], values: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for rel in tracked_files(root):
        if is_path_allowed(rel, paths):
            continue
        text = _read_scannable(root / rel)
        if text is not None:
            findings.extend(scan_text(rel, text, words, values))
    return findings


def format_finding(f: Finding, words: tuple[str, ...] = ()) -> str:
    return redact(f"{f.path}:{f.line}: {f.kind}: {f.match}", words)


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 2 and never echo forbidden words."""

    redact_words: tuple[str, ...] = ()

    def error(self, message: str) -> NoReturn:
        print(redact(f"docs-private-info-lint: error: {message}", self.redact_words), file=sys.stderr)
        sys.exit(2)


def main(argv: list[str]) -> int:
    parser = _Parser(description=(__doc__ or "").split("\n", 1)[0])
    parser.redact_words = best_effort_words(argv)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--words-file", type=Path, default=None)
    args = parser.parse_args(argv)
    words = parser.redact_words
    try:
        paths, values = parse_allowlist(args.allowlist)
        words = load_words(args.words_file)
        findings = lint_repo(args.root, words, paths, values)
    except LintError as exc:
        print(redact(f"docs-private-info-lint: error: {exc}", words), file=sys.stderr)
        return 2
    for f in findings:
        print(format_finding(f, words))
    if findings:
        print(f"docs-private-info-lint: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
