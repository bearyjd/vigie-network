"""Sliding-window rate limiter (in-memory, thread-safe).

Keys are chosen by the caller: the claimed collector id when the request headers parse, else the
source address. IPv6 sources use the full address unless `ipv6_prefix` groups them (e.g. 64).
The table is bounded and LRU-ordered. When full, stale keys are swept; failing that the oldest
key is evicted if it has been idle for `_IDLE_EVICT_S`; failing that, new keys share one overflow
bucket with its own limit, so memory never grows. A small LRU allowlist of peers whose requests
passed HMAC verification (`mark_verified`) never uses the overflow bucket: a verified collector
cannot be locked out by an attacker filling the table with spoofed or numerous source addresses.
"""

from __future__ import annotations

import ipaddress
import threading
from collections import OrderedDict, deque
from collections.abc import Callable

MAX_TRACKED_SOURCES = 4096
_EVICT_INTERVAL_S = 1.0
_IDLE_EVICT_S = 30.0
TRUSTED_TTL_S = 3600.0


def _source_key(source: str, ipv6_prefix: int | None) -> str:
    try:
        addr = ipaddress.ip_address(source)
    except ValueError:
        return source
    if addr.version == 6 and ipv6_prefix is not None:
        return str(ipaddress.ip_network(f"{addr}/{ipv6_prefix}", strict=False))
    return str(addr)


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_s: int,
        clock: Callable[[], float],
        max_sources: int = MAX_TRACKED_SOURCES,
        ipv6_prefix: int | None = None,
        trusted_capacity: int = 0,
    ) -> None:
        self._limit = limit
        self._window = window_s
        self._clock = clock
        self._max_sources = max_sources
        self._ipv6_prefix = ipv6_prefix
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._trusted: OrderedDict[str, float] = OrderedDict()  # key -> last verified time
        self._trusted_capacity = trusted_capacity
        self._overflow: deque[float] = deque()
        self._last_evict = float("-inf")
        self._lock = threading.Lock()

    def set_trusted_capacity(self, capacity: int) -> None:
        with self._lock:
            self._trusted_capacity = capacity
            while len(self._trusted) > capacity:
                self._trusted.popitem(last=False)

    def mark_verified(self, source: str) -> None:
        """Remember a peer whose request passed HMAC verification (bounded, LRU, 1 h TTL)."""
        key = _source_key(source, self._ipv6_prefix)
        now = self._clock()
        with self._lock:
            self._trusted.pop(key, None)
            if self._trusted_capacity < 1:
                return
            self._trusted[key] = now
            while len(self._trusted) > self._trusted_capacity:
                self._trusted.popitem(last=False)

    def _is_trusted(self, key: str, now: float) -> bool:
        seen = self._trusted.get(key)
        if seen is None:
            return False
        if now - seen > TRUSTED_TTL_S:
            del self._trusted[key]
            return False
        return True

    def allow(self, source: str) -> bool:
        key = _source_key(source, self._ipv6_prefix)
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            if key in self._hits:
                self._hits.move_to_end(key)
            elif len(self._hits) >= self._max_sources:
                if now - self._last_evict >= _EVICT_INTERVAL_S:
                    self._last_evict = now
                    self._evict(cutoff)
                if len(self._hits) >= self._max_sources:
                    self._make_room(now, force=self._is_trusted(key, now))
                if len(self._hits) >= self._max_sources:
                    return self._admit(self._overflow, now, cutoff)
            return self._admit(self._hits.setdefault(key, deque()), now, cutoff)

    def _make_room(self, now: float, force: bool) -> None:
        """Evict the least recently used key if idle > _IDLE_EVICT_S (or unconditionally)."""
        oldest = next(iter(self._hits))
        hits = self._hits[oldest]
        if force or not hits or now - hits[-1] > _IDLE_EVICT_S:
            del self._hits[oldest]

    def _admit(self, hits: deque[float], now: float, cutoff: float) -> bool:
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
