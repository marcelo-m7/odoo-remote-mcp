"""MCP remote and local transport entry points."""

import asyncio
from contextlib import asynccontextmanager
from typing import NoReturn, cast
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from monynha_odoo_mcp.audit.models import AuditEvent
from monynha_odoo_mcp.audit.store import AuditStore
from monynha_odoo_mcp.auth.oidc import OidcJwtVerifier
from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.connections.store import ConnectionRegistry, StoredConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.odoo.adapter import OdooAdapter
from monynha_odoo_mcp.odoo.json2 import Json2Adapter
from monynha_odoo_mcp.policy.engine import Policy, PolicyEngine
from monynha_odoo_mcp.policy.rate_limit import RateLimiter
from monynha_odoo_mcp.policy.ssrf import guarded_http_client
from monynha_odoo_mcp.secrets import EnvSecretResolver
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database
from monynha_odoo_mcp.tools.registry import register_tools
from monynha_odoo_mcp.tools.service import OdooToolService


def create_http_app(
    settings: Settings,
    *,
    sessions: sessionmaker[Session] | None = None,
    verifier: TokenVerifier | None = None,
    adapter: OdooAdapter | None = None,
) -> Starlette:
    if settings.mode != "http":
        raise ValueError("Expected HTTP settings")
    database_url = settings.database_url
    oidc_issuer = settings.oidc_issuer
    if (
        database_url is None
        or oidc_issuer is None
        or settings.oidc_audience is None
        or settings.oidc_jwks_url is None
        or settings.public_url is None
    ):
        raise ValueError("Remote MCP requires OIDC and PostgreSQL configuration")
    if not str(settings.public_url).startswith("https://"):
        raise ValueError("Remote public URL must use HTTPS")
    if not oidc_issuer.startswith("https://"):
        raise ValueError("OIDC issuer must use HTTPS")
    if not str(settings.oidc_jwks_url).startswith("https://"):
        raise ValueError("OIDC keys must be fetched via HTTPS")
    if settings.oidc_audience != str(settings.public_url):
        raise ValueError("OIDC audience must equal the MCP resource URL")
    if sessions is None and not database_url.startswith("postgresql+psycopg://"):
        raise ValueError("Hosted MCP requires a PostgreSQL psycopg database")

    if sessions is None:
        _, sessions = create_database(database_url)
    odoo_client = guarded_http_client()
    rate_limiter = RateLimiter(
        calls_per_window=settings.calls_per_minute,
        max_concurrent=settings.max_concurrent_per_connection,
    )
    required_scopes = {"mcp:odoo"} if settings.oauth_provider == "generic" else set()
    oidc_verifier = OidcJwtVerifier(
        issuer=oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=str(settings.oidc_jwks_url),
        required_scopes=required_scopes,
        provider=settings.oauth_provider,
        allowed_client_ids=frozenset(settings.oauth_allowed_client_ids),
    )
    auth = AuthSettings(
        issuer_url=cast(AnyHttpUrl, oidc_issuer),
        resource_server_url=cast(AnyHttpUrl, str(settings.public_url)),
        required_scopes=sorted(required_scopes),
        validate_token_resource=True,
    )
    mcp = MCPServer(
        "Monynha Odoo MCP",
        auth=auth,
        token_verifier=verifier or oidc_verifier,
        instructions="Select an authorized connection and respect its Odoo access policies.",
    )

    def scoped_service() -> OdooToolService:
        token = get_access_token()
        if token is None or not token.subject:
            raise McpError("access_denied", "MCP authentication is required")
        store = SqlConnectionStore(sessions)
        principal = Principal(token.subject)
        if settings.oauth_provider == "supabase":

            def deny_oauth_access(reason: str) -> NoReturn:
                # Audit denial without storing the external subject, email or token.
                try:
                    AuditStore(sessions).append(
                        AuditEvent(
                            principal_id="external:unbound",
                            connection_id="oauth",
                            operation="oauth_authorize",
                            outcome="denied",
                            details={"status": reason, "client_id": token.client_id},
                        )
                    )
                except Exception:
                    pass
                raise McpError("access_denied", "Monynha OAuth access is unavailable")

            if (
                not token.client_id
                or token.client_id not in settings.oauth_allowed_client_ids
                or not store.is_oauth_client_admitted(token.client_id)
            ):
                deny_oauth_access("client_not_admitted")
            external_principal = store.resolve_external_principal(oidc_issuer, token.subject)
            if external_principal is None:
                deny_oauth_access("identity_not_onboarded")
            principal = external_principal
        registry = store.load_registry()
        return OdooToolService(
            adapter
            or Json2Adapter(
                odoo_client,
                EnvSecretResolver(),
                timeout=settings.timeout_seconds,
                max_response_bytes=settings.max_response_bytes,
            ),
            registry,
            principal,
            max_results=settings.max_results,
            audit=AuditStore(sessions),
            rate_limiter=rate_limiter,
            writes_enabled=settings.writes_enabled,
            oauth_client_id=token.client_id if settings.oauth_provider == "supabase" else None,
        )

    register_tools(mcp, scoped_service)
    public_parts = urlsplit(str(settings.public_url))
    allowed_origins = [f"{public_parts.scheme}://{public_parts.netloc}", *settings.allowed_origins]
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=settings.max_request_bytes,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[public_parts.netloc],
            allowed_origins=allowed_origins,
        ),
        host=settings.http_host,
    )
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with original_lifespan(application):
            try:
                yield
            finally:
                await odoo_client.aclose()

    app.router.lifespan_context = lifespan

    async def health(_request):
        return JSONResponse({"alive": True})

    async def readiness(_request):
        try:
            with sessions() as session:
                session.execute(text("SELECT 1 FROM organizations LIMIT 1"))
                if settings.oauth_provider == "supabase":
                    # Fail readiness if a deployment skipped the OAuth Alembic migrations.
                    session.execute(text("SELECT 1 FROM external_identities LIMIT 1"))
                    session.execute(text("SELECT 1 FROM oauth_client_admissions LIMIT 1"))
            return JSONResponse({"ready": True})
        except Exception:
            return JSONResponse({"ready": False}, status_code=503)

    app.add_route("/healthz", health, methods=["GET"])
    app.add_route("/readyz", readiness, methods=["GET"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "MCP-Protocol-Version", "Mcp-Session-Id"],
        expose_headers=["Mcp-Session-Id"],
    )
    return app


def build_stdio_server(settings: Settings) -> MCPServer:
    if settings.mode != "stdio":
        raise ValueError("Expected stdio settings")
    if not all(
        (
            settings.local_principal_id,
            settings.local_connection_id,
            settings.local_odoo_url,
            settings.local_secret_ref,
        )
    ):
        raise McpError("invalid_settings", "Local Odoo connection configuration is required")
    assert settings.local_principal_id is not None
    assert settings.local_connection_id is not None
    assert settings.local_odoo_url is not None
    assert settings.local_secret_ref is not None
    principal = Principal(settings.local_principal_id)
    connection = OdooConnection(
        settings.local_connection_id,
        str(settings.local_odoo_url).rstrip("/"),
        None,
        settings.local_secret_ref,
    )
    registry = ConnectionRegistry(
        PolicyEngine([Policy(principal.id, connection.id, frozenset({"read"}), frozenset({"*"}))])
    )
    registry.add(StoredConnection(connection, "local"))
    registry.grant_membership(principal.id, "local")
    client = guarded_http_client()
    limiter = RateLimiter(
        calls_per_window=settings.calls_per_minute,
        max_concurrent=settings.max_concurrent_per_connection,
    )
    mcp = MCPServer("Monynha Odoo MCP")
    register_tools(
        mcp,
        lambda: OdooToolService(
            Json2Adapter(
                client,
                EnvSecretResolver(),
                timeout=settings.timeout_seconds,
                max_response_bytes=settings.max_response_bytes,
            ),
            registry,
            principal,
            max_results=settings.max_results,
            rate_limiter=limiter,
            writes_enabled=settings.writes_enabled,
        ),
    )
    mcp._odoo_client = client  # type: ignore[attr-defined]
    return mcp


def run_stdio(settings: Settings) -> None:
    mcp = build_stdio_server(settings)
    try:
        mcp.run(transport="stdio")
    finally:
        asyncio.run(mcp._odoo_client.aclose())  # type: ignore[attr-defined]


def main() -> None:
    settings = Settings()
    if settings.mode == "stdio":
        run_stdio(settings)
        return
    import uvicorn

    uvicorn.run(
        create_http_app(settings),
        host=settings.http_host,
        port=settings.http_port,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
