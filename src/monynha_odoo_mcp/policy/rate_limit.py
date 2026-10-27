"""Per-process, per-connection concurrency and request budgets.

For horizontally scaled deployments, enforce equivalent shared limits at the gateway.
"""

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from monynha_odoo_mcp.core.errors import McpError


class RateLimiter:
    def __init__(
        self,
        *,
        calls_per_window: int = 60,
        window_seconds: float = 60.0,
        max_concurrent: int = 4,
        wait_seconds: float = 0.1,
    ) -> None:
        if min(calls_per_window, window_seconds, max_concurrent, wait_seconds) <= 0:
            raise ValueError("Rate limits must be positive")
        self.calls_per_window = calls_per_window
        self.window_seconds = window_seconds
        self.wait_seconds = wait_seconds
        self.max_concurrent = max_concurrent
        self._lock = asyncio.Lock()
        self._recent: dict[tuple[str, str, str], deque[float]] = {}
        self._slots: dict[str, asyncio.Semaphore] = {}

    @asynccontextmanager
    async def slot(
        self, principal_id: str, connection_id: str, operation: str
    ) -> AsyncIterator[None]:
        async with self._lock:
            now = time.monotonic()
            key = (principal_id, connection_id, operation)
            recent = self._recent.setdefault(key, deque())
            while recent and recent[0] <= now - self.window_seconds:
                recent.popleft()
            if len(recent) >= self.calls_per_window:
                raise McpError("rate_limited", "Odoo request limit reached; retry later")
            recent.append(now)
            semaphore = self._slots.setdefault(
                connection_id, asyncio.Semaphore(self.max_concurrent)
            )
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=self.wait_seconds)
        except TimeoutError:
            raise McpError("rate_limited", "Odoo connection is busy; retry later") from None
        try:
            yield
        finally:
            semaphore.release()
