import time
import os
from collections import defaultdict

class RateLimiter:
    def __init__(self, rpm: int = 30):
        self.rpm = rpm
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        now, window = time.time(), time.time() - 60
        self._buckets[key] = [t for t in self._buckets[key] if t > window]
        if len(self._buckets[key]) >= self.rpm:
            return False
        self._buckets[key].append(now)
        return True

rate_limiter = RateLimiter(int(os.getenv("RATE_LIMIT_RPM", "30")))
