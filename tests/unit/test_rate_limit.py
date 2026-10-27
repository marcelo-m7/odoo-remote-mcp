import asyncio

import pytest

from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.rate_limit import RateLimiter


@pytest.mark.asyncio
async def test_rate_limit_is_per_principal_connection_and_operation():
    limiter = RateLimiter(calls_per_window=2, window_seconds=60, max_concurrent=2)
    for _ in range(2):
        async with limiter.slot("alice", "connection-a", "read"):
            pass
    with pytest.raises(McpError) as exc:
        async with limiter.slot("alice", "connection-a", "read"):
            pass
    assert exc.value.code == "rate_limited"
    async with limiter.slot("bob", "connection-a", "read"):
        pass
    async with limiter.slot("alice", "connection-a", "update"):
        pass


@pytest.mark.asyncio
async def test_concurrency_limited_per_connection():
    limiter = RateLimiter(calls_per_window=20, max_concurrent=1, wait_seconds=0.01)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold():
        async with limiter.slot("alice", "connection-a", "read"):
            entered.set()
            await release.wait()

    task = asyncio.create_task(hold())
    try:
        await entered.wait()
        with pytest.raises(McpError) as exc:
            async with limiter.slot("bob", "connection-a", "read"):
                pass
        assert exc.value.code == "rate_limited"
    finally:
        release.set()
        await task
