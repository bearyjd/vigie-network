"""Per-source-IP sliding-window rate limiter (in-memory, thread-safe)."""

from __future__ import annotations

import ipaddress
import threading
from collections import deque
from collections.abc import Callable

MAX_TRACKED_SOURCES = 4096
_EVICT_INTERVAL_S = 1.0


def _source_key(source: str) -> str:
    """IPv6 clients are keyed by /64 (privacy addresses rotate within it)."""
    try:
        addr = ipaddress.ip_address(source)
    except ValueError:
        return source
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_s: int,
        clock: Callable[[], float],
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._limit = limit
        self._window = window_s
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._max_sources = max_sources
        self._last_evict = float("-inf")
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        key = _source_key(source)
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            if key not in self._hits and len(self._hits) >= self._max_sources:
                if now - self._last_evict >= _EVICT_INTERVAL_S:
                    self._last_evict = now
                    self._evict(cutoff)
                if len(self._hits) >= self._max_sources:
                    return False  # table full of live sources: refuse new ones, never grow
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def _evict(self, cutoff: float) -> None:
        stale = [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]
        for key in stale:
            del self._hits[key]
