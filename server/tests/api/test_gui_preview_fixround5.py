"""Fix-round 5: site.py line-splitting parity, lock probe hardening, wedge states, killers.

Throwaway children and ephemeral loopback ports only; nothing signals or binds the fixed preview.
"""

from __future__ import annotations

import pytest
from test_gui_preview_fixround1 import (  # noqa: F401 -- shared fixtures, same module instance
    _venv,
    namespace,
    pidfd_support_for_offline_fixtures,
    preview,
    sandbox_owners,
)
from test_gui_preview_fixround3 import _pth
from test_gui_preview_fixround4 import _refuses

# ------------------------------------ F1: split exactly like site.py (str.splitlines)

SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]


@pytest.mark.parametrize("sep", SEPARATORS)
def test_unicode_line_separators_hide_nothing_from_the_vet(sandbox_owners, tmp_path, sep):
    root, _, site = _venv(tmp_path)  # site.py 3.12+ splitlines(): '#c<sep>import ...' execs
    _pth(site, "e.pth", f"#c{sep}import os;os.getpid()\n")
    _refuses(root)


@pytest.mark.parametrize("sep", SEPARATORS)
def test_unicode_line_separator_before_a_path_is_refused(sandbox_owners, tmp_path, sep):
    root, _, site = _venv(tmp_path)  # 'zz<sep><dir>' puts <dir> on sys.path
    _pth(site, "e.pth", f"zz{sep}{tmp_path / 'missing'}\n")
    _refuses(root)


def test_a_bare_carriage_return_is_refused_not_split(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # M07: older site.py universal newlines split on a lone \r
    (site / "e.pth").write_bytes(f"{tmp_path / 'missing'}\rimport os\n".encode())
    (site / "e.pth").chmod(0o644)
    _refuses(root)


def test_a_leading_space_directory_line_is_refused(sandbox_owners, tmp_path):
    root, _, site = _venv(tmp_path)  # M05
    _pth(site, "e.pth", f" {tmp_path / 'missing'}\n")
    _refuses(root)
