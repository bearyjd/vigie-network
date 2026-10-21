"""Per-source-IP sliding-window rate limiter (in-memory, thread-safe)."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable

_MAX_TRACKED_SOURCES = 4096


class RateLimiter:
    def __init__(self, limit: int, window_s: int, clock: Callable[[], float]) -> None:
        self._limit = limit
        self._window = window_s
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            if len(self._hits) >= _MAX_TRACKED_SOURCES and source not in self._hits:
                self._evict(cutoff)
            hits = self._hits.setdefault(source, deque())
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
