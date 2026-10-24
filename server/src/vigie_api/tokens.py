"""App-principal bearer tokens: `vgt_<id>.<secret>`; only SHA-256(token) is stored."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass

SCOPE_APP = "app"
SCOPE_RULES = "app rules:write"
VALID_SCOPES = {SCOPE_APP, SCOPE_RULES, "service", "integration", "read-only"}
LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
TOKEN_RE = re.compile(r"^vgt_([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{6,128})$")
_DUMMY_HASH = hashlib.sha256(b"vigie-dummy-token").hexdigest()


@dataclass(frozen=True)
class Principal:
    token_id: str
    scope: str

    @property
    def name(self) -> str:
        return f"{self.scope.split()[0]}:{self.token_id}"

    def require_write(self, *, rules: bool = False) -> None:
        from vigie_api.errors import ApiError

        allowed = self.scope == SCOPE_RULES if rules else self.scope in {SCOPE_APP, SCOPE_RULES}
        if not allowed:
            raise ApiError(403, "forbidden", "token lacks the required write privilege")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(
    conn: sqlite3.Connection,
    label: str | None = None,
    *,
    rules_write: bool = False,
    scope: str = SCOPE_APP,
) -> tuple[str, str]:
    """Insert a new app token and return (id, token). The token is shown once, never stored."""
    if scope not in VALID_SCOPES or (rules_write and scope != SCOPE_APP):
        raise ValueError("invalid token scope or rules privilege")
    scope = SCOPE_RULES if rules_write else scope
    token_id = label if label is not None else secrets.token_hex(4)
    if not LABEL_RE.fullmatch(token_id):
        raise ValueError("token id must match [A-Za-z0-9_-]{1,32}")
    token = f"vgt_{token_id}.{secrets.token_urlsafe(32)}"
    conn.execute(
        "INSERT INTO api_tokens (id, token_hash, scope, revoked) VALUES (?,?,?,0)",
        (token_id, _hash(token), scope),
    )
    return token_id, token


def revoke_token(conn: sqlite3.Connection, token_id: str) -> bool:
    cur = conn.execute("UPDATE api_tokens SET revoked=1 WHERE id=?", (token_id,))
    return cur.rowcount > 0


def verify_token(conn: sqlite3.Connection, presented: str) -> Principal | None:
    """Constant-time check. The hash compare always runs, even for unknown ids."""
    match = TOKEN_RE.fullmatch(presented)
    row = None
    if match:
        row = conn.execute(
            "SELECT id, token_hash, scope, revoked FROM api_tokens WHERE id=?", (match.group(1),)
        ).fetchone()
    stored = row["token_hash"] if row else _DUMMY_HASH
    equal = hmac.compare_digest(stored.encode(), _hash(presented).encode())
    if row is None or not equal or row["revoked"] != 0 or row["scope"] not in VALID_SCOPES:
        return None
    return Principal(token_id=row["id"], scope=row["scope"])


def audit(
    conn: sqlite3.Connection, principal: str, action: str, token_id: str, now_iso: str
) -> None:
    """Record a token lifecycle event. Never carries token material, only the id."""
    conn.execute(
        "INSERT INTO audit_log (id, ts, principal, action, target) VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), now_iso, principal, action, token_id),
    )
