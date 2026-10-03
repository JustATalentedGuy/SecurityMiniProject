import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """One process, bounded sliding windows. Production requires a shared Redis store."""

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.windows: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self.lock:
            # Expire inactive entries to avoid unbounded IP-key growth.
            stale = [
                key
                for key, times in self.windows.items()
                if not times or times[-1] <= now - self.window
            ]
            for entry in stale:
                del self.windows[entry]
            window = self.windows[key]
            while window and window[0] <= now - self.window:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True
