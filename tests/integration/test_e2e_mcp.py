from contextlib import asynccontextmanager

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from monynha_odoo_mcp.audit.store import AuditStore
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.server import create_http_app
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database, create_schema


class FakeVerifier:
    def __init__(self, *, client_id="test-client", scopes=None):
        self.client_id = client_id
        self.scopes = scopes if scopes is not None else ["mcp:odoo"]

    async def verify_token(self, token):
        if token not in {"token-alice", "token-bob"}:
            return None
        subject = token[6:]
        return AccessToken(
            token=token,
            client_id=self.client_id,
            subject=subject,
            scopes=self.scopes,
            resource="https://mcp.example/mcp",
        )


class FakeAdapter:
    async def call(self, connection, model, method, payload):
        if method == "search_read":
            return [{"id": 1, "name": connection.id}]
        return True


def settings(allowed_origins=None, *, provider="generic"):
    return Settings(
        mode="http",
        database_url="sqlite+pysqlite:///:memory:",
        oidc_issuer="https://id.example",
        oidc_audience="https://mcp.example/mcp",
        oidc_jwks_url="https://id.example/jwks",
        public_url="https://mcp.example/mcp",
        allowed_origins=allowed_origins or [],
        oauth_provider=provider,
        oauth_allowed_client_ids=["test-client"] if provider == "supabase" else [],
        _env_file=None,
    )


@asynccontextmanager
async def mcp_test_client(
    allowed_origins=None,
    *,
    provider="generic",
    admitted=True,
    bound=True,
    client_id="test-client",
    yield_store=False,
):
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
        if provider == "supabase" and bound:
            store.bind_external_identity(who, "https://id.example", who)
    if provider == "supabase" and admitted:
        store.set_oauth_client_admission("test-client", enabled=True)
    app = create_http_app(
        settings(allowed_origins, provider=provider),
        sessions=sessions,
        verifier=FakeVerifier(
            client_id=client_id, scopes=["openid"] if provider == "supabase" else None
        ),
        adapter=FakeAdapter(),
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
        ) as client:
            yield (client, store) if yield_store else client
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


@pytest.mark.asyncio
async def test_supabase_oauth_subject_needs_explicit_binding_and_client_admission():
    # An OAuth token with only OIDC scopes must work after private onboarding.
    args = {"connection_id": "odoo-alice", "model": "res.partner", "domain": []}
    async with mcp_test_client(provider="supabase") as client:
        allowed = await invoke(
            client,
            "token-alice",
            "tools/call",
            {
                "name": "record_search",
                "arguments": args,
            },
        )
        assert allowed.status_code == 200, allowed.text
        assert "odoo-alice" in allowed.text

    for blocked_setup in ({"admitted": False}, {"bound": False}, {"client_id": "rogue"}):
        async with mcp_test_client(provider="supabase", **blocked_setup) as client:
            denied = await invoke(
                client,
                "token-alice",
                "tools/call",
                {
                    "name": "record_search",
                    "arguments": args,
                },
            )
            assert denied.status_code in {200, 401, 403}
            assert "odoo-alice" not in str(
                denied.json().get("result", {}).get("structuredContent", {})
            )
            if denied.status_code == 200:
                assert denied.json()["result"].get("isError") is True


@pytest.mark.asyncio
async def test_supabase_client_revocation_drops_access_on_next_request():
    async with mcp_test_client(provider="supabase", yield_store=True) as (client, store):
        first = await invoke(
            client,
            "token-alice",
            "tools/call",
            {
                "name": "connection_list",
                "arguments": {},
            },
        )
        assert first.status_code == 200, first.text
        assert "odoo-alice" in first.text
        store.set_oauth_client_admission("test-client", enabled=False)
        after = await invoke(
            client,
            "token-alice",
            "tools/call",
            {
                "name": "connection_list",
                "arguments": {},
            },
            2,
        )
        assert after.status_code in {200, 401, 403}
        assert "odoo-alice" not in str(after.json().get("result", {}).get("structuredContent", {}))
        if after.status_code == 200:
            assert after.json()["result"].get("isError") is True
        audit_events = AuditStore(store.sessions).list_recent()
        assert any(
            event["operation"] == "oauth_authorize"
            and event["outcome"] == "denied"
            and event["details"].get("client_id") == "test-client"
            for event in audit_events
        )
