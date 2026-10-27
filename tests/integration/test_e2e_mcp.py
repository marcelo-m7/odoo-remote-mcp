from contextlib import asynccontextmanager

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.server import create_http_app
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database, create_schema


class FakeVerifier:
    async def verify_token(self, token):
        if token not in {"token-alice", "token-bob"}:
            return None
        subject = token[6:]
        return AccessToken(
            token=token,
            client_id="test-client",
            subject=subject,
            scopes=["mcp:odoo"],
            resource="https://mcp.example/mcp",
        )


class FakeAdapter:
    async def call(self, connection, model, method, payload):
        if method == "search_read":
            return [{"id": 1, "name": connection.id}]
        return True


def settings(allowed_origins=None):
    return Settings(
        mode="http",
        database_url="sqlite+pysqlite:///:memory:",
        oidc_issuer="https://id.example",
        oidc_audience="https://mcp.example/mcp",
        oidc_jwks_url="https://id.example/jwks",
        public_url="https://mcp.example/mcp",
        allowed_origins=allowed_origins or [],
        _env_file=None,
    )


@asynccontextmanager
async def mcp_test_client(allowed_origins=None):
    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    store = SqlConnectionStore(sessions)
    for who in ("alice", "bob"):
        store.add_organization(who)
        store.add_principal(who)
        store.grant_membership(who, who)
        store.add_connection(
            who,
            OdooConnection(
                f"odoo-{who}",
                "https://odoo.example",
                None,
                f"env:MONYNHA_ODOO_KEY_{who.upper()}",
            ),
        )
        store.grant_policy(who, f"odoo-{who}", "read", "res.partner")
    app = create_http_app(
        settings(allowed_origins),
        sessions=sessions,
        verifier=FakeVerifier(),
        adapter=FakeAdapter(),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
        ) as client:
            yield client
    engine.dispose()


async def invoke(client, token, method, params, request_id=1):
    return await client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-11-25",
        },
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
    )


@pytest.mark.asyncio
async def test_authenticated_client_lists_tools_and_searches_mock_odoo():
    async with mcp_test_client() as client:
        response = await invoke(
            client,
            "token-alice",
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1.0"},
            },
        )
        assert response.status_code == 200, response.text
        response = await invoke(client, "token-alice", "tools/list", {}, 2)
        assert response.status_code == 200, response.text
        names = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert "record_search" in names
        response = await invoke(
            client,
            "token-alice",
            "tools/call",
            {
                "name": "record_search",
                "arguments": {"connection_id": "odoo-alice", "model": "res.partner", "domain": []},
            },
            3,
        )
        assert response.status_code == 200, response.text
        assert "odoo-alice" in response.text


@pytest.mark.asyncio
async def test_two_orgs_no_cross_access():
    async with mcp_test_client() as client:
        response = await invoke(
            client,
            "token-alice",
            "tools/call",
            {
                "name": "record_search",
                "arguments": {"connection_id": "odoo-bob", "model": "res.partner", "domain": []},
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result.get("isError") is True
        assert "odoo-bob" not in str(result.get("structuredContent", {}))


@pytest.mark.asyncio
async def test_no_prod_credentials_required():
    async with mcp_test_client() as client:
        response = await invoke(
            client,
            "token-bob",
            "tools/call",
            {
                "name": "record_search",
                "arguments": {"connection_id": "odoo-bob", "model": "res.partner", "domain": []},
            },
        )
        assert response.status_code == 200
        assert "odoo-bob" in response.text


@pytest.mark.asyncio
async def test_health_and_database_readiness():
    async with mcp_test_client() as client:
        assert (await client.get("/healthz")).status_code == 200
        ready = await client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json() == {"ready": True}


@pytest.mark.asyncio
async def test_missing_database_schema_fails_readiness():
    from monynha_odoo_mcp.server import create_http_app

    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    app = create_http_app(settings(), sessions=sessions)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"ready": False}
    engine.dispose()


@pytest.mark.asyncio
async def test_allowlisted_browser_origin_can_use_authenticated_mcp():
    async with mcp_test_client(allowed_origins=["https://trusted.client.example"]) as client:
        allowed = await client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer token-alice",
                "Origin": "https://trusted.client.example",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
        )
        assert allowed.status_code == 200, allowed.text
        denied = await client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer token-alice",
                "Origin": "https://evil.example",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
        )
        assert denied.status_code == 403
