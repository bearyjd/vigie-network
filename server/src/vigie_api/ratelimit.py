"""Failed-authentication limiter: per source, IPv6 grouped by /64, IPv4-mapped unwrapped.

It counts failed authentications only and bounds memory by evicting the oldest-active sources,
never by pooling new sources into a shared bucket an attacker could saturate.
"""

from __future__ import annotations

import ipaddress
import math
import threading
from collections import deque
from collections.abc import Callable

MAX_SOURCES = 4096
IPV6_PREFIX = 64


def source_key(source: str) -> str:
    try:
        addr = ipaddress.ip_address(source)
    except ValueError:
        return source
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)  # dual-stack listener: key on the real IPv4 client
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
            hits = self._hits.get(key)
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
            hits = self._hits.pop(key, None) or deque()
            self._hits[key] = hits  # re-insert: dict order is least- to most-recently active
            self._expire(hits, now)
            hits.append(now)

    def _expire(self, hits: deque[float], now: float) -> None:
        while hits and hits[0] <= now - self._window:
            hits.popleft()

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= now - self._window]:
            del self._hits[key]
        while len(self._hits) >= MAX_SOURCES:
            del self._hits[next(iter(self._hits))]  # oldest-active first
