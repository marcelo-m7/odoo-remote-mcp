import httpx
import pytest
from pydantic import ValidationError

from monynha_odoo_mcp.server import build_stdio_server, create_http_app
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database


def remote_settings():
    return Settings(
        mode="http",
        database_url="sqlite+pysqlite:///:memory:",
        oidc_issuer="https://id.example",
        oidc_audience="https://mcp.example/mcp",
        oidc_jwks_url="https://id.example/jwks",
        public_url="https://mcp.example/mcp",
        _env_file=None,
    )


@pytest.fixture
def ephemeral_sessions():
    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    yield sessions
    engine.dispose()


def test_remote_service_requires_postgres_outside_injected_tests():
    with pytest.raises(ValueError, match="PostgreSQL"):
        create_http_app(remote_settings())


@pytest.mark.asyncio
async def test_unauthorized_http_never_reaches_tools(ephemeral_sessions):
    app = create_http_app(remote_settings(), sessions=ephemeral_sessions)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_resource_metadata(ephemeral_sessions):
    app = create_http_app(remote_settings(), sessions=ephemeral_sessions)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 200
    metadata = response.json()
    assert metadata["resource"] == "https://mcp.example/mcp"
    assert "https://id.example" in metadata["authorization_servers"]


def test_http_denies_missing_config():
    with pytest.raises(ValidationError):
        Settings(
            mode="http",
            database_url="postgresql+psycopg://db",
            oidc_issuer="https://id.example",
            oidc_audience="mcp",
            oidc_jwks_url="https://id.example/jwks",
            _env_file=None,
        )


def test_http_rejects_insecure_oidc_issuer():
    settings = remote_settings().model_copy(update={"oidc_issuer": "http://id.example"})
    with pytest.raises(ValueError, match="OIDC issuer"):
        create_http_app(settings)


def test_http_rejects_audience_different_from_resource():
    settings = remote_settings().model_copy(update={"oidc_audience": "https://other.example"})
    with pytest.raises(ValueError, match="audience"):
        create_http_app(settings)


@pytest.mark.asyncio
async def test_stdio_uses_local_principal():
    settings = Settings(
        mode="stdio",
        local_principal_id="local-developer",
        local_connection_id="local-odoo",
        local_odoo_url="https://odoo.example",
        local_secret_ref="env:MONYNHA_ODOO_KEY_LOCAL",
        _env_file=None,
    )
    mcp = build_stdio_server(settings)
    tool_names = {tool.name for tool in await mcp.list_tools()}
    assert {"connection_list", "record_search"} <= tool_names
