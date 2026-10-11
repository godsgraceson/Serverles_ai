from __future__ import annotations

import time
from collections import defaultdict, deque

from sas.config import SASConfig, load_config


class RateLimiter:
    def __init__(self, config: SASConfig | None = None) -> None:
        self.config = config or load_config()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client_id: str, now: float | None = None) -> bool:
        ts = now or time.time()
        window = self._hits[client_id]
        cutoff = ts - 60.0
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self.config.rate_limit_per_minute:
            return False
        window.append(ts)
        return True
