from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, *, limit: int, window_seconds: float = 60.0) -> int | None:
        now = time.monotonic()
        cutoff = now - window_seconds
        async with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return max(1, math.ceil(events[0] + window_seconds - now))
            events.append(now)
            if len(self._events) > 10_000:
                self._prune(cutoff)
        return None

    def _prune(self, cutoff: float) -> None:
        empty: list[str] = []
        for key, events in self._events.items():
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                empty.append(key)
        for key in empty:
            self._events.pop(key, None)
