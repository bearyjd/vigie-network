"""Failed-authentication limiter: per source, IPv6 grouped by /64, bounded memory.

Unlike a consuming limiter it can be asked *before* any token lookup whether a source is already
over the limit, so a blocked source costs no database work and learns nothing from the answer.
"""

from __future__ import annotations

import ipaddress
import math
import threading
from collections import deque
from collections.abc import Callable

MAX_SOURCES = 4096
IPV6_PREFIX = 64
_OVERFLOW = "*overflow*"


def source_key(source: str) -> str:
    try:
        addr = ipaddress.ip_address(source)
    except ValueError:
        return source
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/{IPV6_PREFIX}", strict=False))
    return str(addr)


class FailureLimiter:
    def __init__(self, limit: int, window_s: int, clock: Callable[[], float]) -> None:
        self._limit, self._window, self._clock = limit, window_s, clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def retry_after(self, source: str) -> int | None:
        """Seconds until the source may try again, or None when it is under the limit."""
        key = source_key(source)
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key, self._hits.get(_OVERFLOW))
            if hits is None:
                return None
            self._expire(hits, now)
            if len(hits) < self._limit:
                return None
            return max(1, math.ceil(hits[0] + self._window - now))

    def record(self, source: str) -> None:
        key = source_key(source)
        now = self._clock()
        with self._lock:
            if key not in self._hits and len(self._hits) >= MAX_SOURCES:
                self._evict(now)
                if len(self._hits) >= MAX_SOURCES:
                    key = _OVERFLOW
            hits = self._hits.setdefault(key, deque())
            self._expire(hits, now)
            hits.append(now)

    def _expire(self, hits: deque[float], now: float) -> None:
        while hits and hits[0] <= now - self._window:
            hits.popleft()

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= now - self._window]:
            del self._hits[key]
