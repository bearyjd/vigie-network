"""Defence in depth for attacker-controlled strings (DHCP/mDNS names) before inventory.db."""

from __future__ import annotations

import unicodedata

MAX_TEXT_CHARS = 256
# Cc: C0/C1/DEL/NUL; Cf: bidi controls, zero-width, BOM; Zl/Zp: U+2028/U+2029.
_STRIPPED = frozenset({"Cc", "Cf", "Zl", "Zp"})


def clean_text(value: str | None) -> str | None:
    """NFC-normalise, drop control/format/line-separator characters, bound to 256 chars."""
    if not value:
        return None
    kept = "".join(c for c in value if unicodedata.category(c) not in _STRIPPED)
    text = unicodedata.normalize("NFC", kept)[:MAX_TEXT_CHARS].strip()
    return text or None
