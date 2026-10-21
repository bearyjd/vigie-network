"""TLS for `post`: chain verification always on; optional extra CA and SPKI pin.

The pin is SHA-256 over the DER SubjectPublicKeyInfo of the server certificate, lowercase hex,
exactly what deploy/gen-certs.sh prints as `pin_sha256_hex`. It is checked in addition to normal
chain and hostname verification, never instead of it.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import ssl
from typing import Any

PIN_RE = re.compile(r"[0-9a-fA-F]{64}")
_SEQUENCE, _CONTEXT_0 = 0x30, 0xA0


class TlsError(Exception):
    """A TLS setup or verification problem; the message is safe to show to the user."""


def _tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at buf[off]."""
    tag, first = buf[off], buf[off + 1]
    if first < 0x80:
        start, length = off + 2, first
    else:
        n = first & 0x7F
        start, length = off + 2 + n, int.from_bytes(buf[off + 2 : off + 2 + n], "big")
    if start + length > len(buf):
        raise TlsError("malformed server certificate")
    return tag, start, start + length


def spki_der(cert_der: bytes) -> bytes:
    """Extract the SubjectPublicKeyInfo element from a DER X.509 certificate."""
    try:
        tag, start, _ = _tlv(cert_der, 0)
        tbs_tag, pos, tbs_end = _tlv(cert_der, start)
        if tag != _SEQUENCE or tbs_tag != _SEQUENCE:
            raise TlsError("malformed server certificate")
        elems: list[tuple[int, int]] = []
        while pos < tbs_end:
            t, s, e = _tlv(cert_der, pos)
            elems.append((pos, e))
            if t == _CONTEXT_0 and len(elems) == 1:  # explicit version
                elems.pop()
            pos = e
        # serial, signature, issuer, validity, subject, spki
        begin, end = elems[5]
    except IndexError as exc:
        raise TlsError("malformed server certificate") from exc
    return cert_der[begin:end]


def spki_sha256_hex(cert_der: bytes) -> str:
    return hashlib.sha256(spki_der(cert_der)).hexdigest()


def require_pin(cert_der: bytes, pin_hex: str) -> None:
    actual = spki_sha256_hex(cert_der)
    if not hmac.compare_digest(actual.encode(), pin_hex.lower().encode()):
        raise TlsError("SPKI pin mismatch: the server certificate is not the pinned one")


def _pinned_socket_class(pin_hex: str) -> type[ssl.SSLSocket]:
    class PinnedSSLSocket(ssl.SSLSocket):
        @classmethod
        def _create(cls, *args: Any, **kwargs: Any) -> PinnedSSLSocket:  # type: ignore[override]
            sock = super()._create(*args, **kwargs)  # verified handshake happens here
            try:
                require_pin(sock.getpeercert(binary_form=True) or b"", pin_hex)
            except TlsError as exc:
                sock.close()
                raise ssl.SSLError(str(exc)) from None
            return sock

    return PinnedSSLSocket


def make_context(ca_file: str | None, pin_hex: str | None = None) -> ssl.SSLContext:
    """Default verifying context (honours SSL_CERT_FILE); ca_file replaces the trust anchors.

    With pin_hex, every new TLS connection is checked against the SPKI pin right after the
    (verified) handshake and before any request bytes are sent. Verification is never disabled.
    """
    try:
        ctx = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise TlsError(f"cannot load --ca-file {ca_file}: {exc.__class__.__name__}") from exc
    if pin_hex:
        ctx.sslsocket_class = _pinned_socket_class(pin_hex)  # type: ignore[misc]
    return ctx
