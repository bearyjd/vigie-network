#!/usr/bin/env python3
r"""Fail when tracked docs hold private household information.

Scope: DOCS ONLY - tracked docs/**, README.md and .trail/learnings/**. Code, tests and
fixtures elsewhere in the repo are deliberately NOT scanned. Flags private-range and
Tailscale IPv4 addresses, MAC addresses, absolute home paths (/home, /var/home, /Users,
C:\Users, ~name/) and an operator-supplied list of forbidden words (env
VIGIE_LINT_FORBIDDEN_WORDS, comma separated, and/or an untracked --words-file, one word per
line). CI feeds the env var from an optional repo secret the owner adds; unset is a no-op.
The shipped list is empty: never commit real names. Allowlist (tools/docs_private_info_lint.allowlist): `path <glob>` and `value <literal>`.

Exit codes: 0 clean, 1 findings, 2 usage/IO error. Run as `python3 -I`.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SCOPE_GLOBS = ("docs/**", "README.md", ".trail/learnings/**")
WORDS_ENV = "VIGIE_LINT_FORBIDDEN_WORDS"
DEFAULT_ALLOWLIST = Path(__file__).resolve().with_name("docs_private_info_lint.allowlist")
ALLOWED_MAC_PREFIXES = ("00:00:5e:00:53:", "02:00:00:")
BINARY_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf"})

IPV4_RE = re.compile(
    r"(?<![\w.])(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})(?!\d|\.\d)"
)
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
HOME_RE = re.compile(
    r"(?<![\w.\-])/(?:var/home|home|Users)/[A-Za-z0-9_.-]+"
    r"|[A-Za-z]:\\Users\\[^\\\s]+"
    r"|(?<![\w/~])~[A-Za-z][\w.-]*/"
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
    found = []
    for m in IPV4_RE.finditer(line):
        octets = tuple(int(g) for g in m.groups())
        if all(o <= 255 for o in octets) and _is_private_ipv4(octets):
            found.append(m.group(0))
    return found


def _mac_matches(line: str) -> list[str]:
    return [
        m.group(0)
        for m in MAC_RE.finditer(line)
        if not m.group(0).lower().replace("-", ":").startswith(ALLOWED_MAC_PREFIXES)
    ]


def _word_matches(line: str, words: tuple[str, ...]) -> list[str]:
    return [
        m.group(0)
        for w in words
        for m in re.finditer(rf"(?<!\w){re.escape(w)}(?!\w)", line, re.IGNORECASE)
    ]


def scan_text(
    path: str, text: str, words: tuple[str, ...], allowed_values: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
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


def parse_allowlist(path: Path) -> tuple[tuple[str, ...], frozenset[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LintError(f"cannot read allowlist {path}: {exc}") from exc
    globs: list[str] = []
    values: list[str] = []
    for number, raw in enumerate(lines, start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if len(parts) != 2 or parts[0] not in ("path", "value"):
            raise LintError(f"{path}:{number}: expected 'path <glob>' or 'value <literal>'")
        if parts[0] == "path" and _is_overbroad(parts[1]):
            raise LintError(
                f"{path}:{number}: over-broad glob '{parts[1]}' "
                "(wildcards need 2+ literal leading directories)"
            )
        (globs if parts[0] == "path" else values).append(parts[1])
    return tuple(globs), frozenset(values)


def _is_wild(segment: str) -> bool:
    return any(c in segment for c in "*?[")


def _is_overbroad(glob: str) -> bool:
    segments = glob.split("/")
    if not any(_is_wild(s) for s in segments):
        return False
    leading = [s for s in segments[: next(i for i, s in enumerate(segments) if _is_wild(s))]]
    return len(leading) < 2


def is_path_allowed(rel: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel, g) for g in globs)


def in_scope(rel: str) -> bool:
    return any(fnmatch.fnmatchcase(rel, g) for g in SCOPE_GLOBS)


def load_words(words_file: Path | None) -> tuple[str, ...]:
    words = [w.strip() for w in os.environ.get(WORDS_ENV, "").split(",")]
    if words_file is not None:
        try:
            text = words_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise LintError(f"cannot read words file {words_file}: {exc}") from exc
        words.extend(ln.split("#", 1)[0].strip() for ln in text.splitlines())
    return tuple(dict.fromkeys(w for w in words if w))


def tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LintError(f"cannot list tracked files in {root}: {exc}") from exc
    return [p for p in out.split("\0") if p and in_scope(p)]


def lint_repo(
    root: Path, words: tuple[str, ...], globs: tuple[str, ...], values: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for rel in tracked_files(root):
        if is_path_allowed(rel, globs):
            continue
        text = _read_text(root / rel)
        if text is not None:
            findings.extend(scan_text(rel, text, words, values))
    return findings


def _read_text(path: Path) -> str | None:
    """File text, or None for binary files (known image suffix, NUL bytes, non-UTF-8)."""
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise LintError(f"cannot read {path}: {exc}") from exc
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def format_finding(f: Finding) -> str:
    # Never echo forbidden words: CI logs of a public repo must not repeat private names.
    shown = f"<redacted {len(f.match)} chars>" if f.kind == "forbidden-word" else f.match
    return f"{f.path}:{f.line}: {f.kind}: {shown}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--words-file", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        globs, values = parse_allowlist(args.allowlist)
        findings = lint_repo(args.root, load_words(args.words_file), globs, values)
    except LintError as exc:
        print(f"docs-private-info-lint: error: {exc}", file=sys.stderr)
        return 2
    for f in findings:
        print(format_finding(f))
    if findings:
        print(f"docs-private-info-lint: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
