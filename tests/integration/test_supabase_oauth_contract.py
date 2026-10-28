"""End-to-end HTTP checks using the actual OIDC JWT verifier and synthetic keys."""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from monynha_odoo_mcp.audit.store import AuditStore
from monynha_odoo_mcp.auth.oidc import OidcJwtVerifier
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.server import create_http_app
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database, create_schema


class ReadOnlyAdapter:
    def __init__(self):
        self.calls = []

    async def call(self, connection, model, method, payload):
        self.calls.append((connection.id, method))
        return [{"id": 1, "display_name": "Synthetic record"}]


@pytest.mark.asyncio
async def test_real_supabase_verifier_allows_only_bound_mcp_access_token():
    now = int(time.time())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "synthetic-key", "use": "sig", "alg": "RS256"})

    def sign(**overrides):
        claims = {
            "iss": "https://identity.example/auth/v1",
            "sub": "external-alice",
            "aud": "https://mcp.example/mcp",
            "client_id": "approved-oauth-client",
            "iat": now,
            "exp": now + 600,
            "scope": "openid email",
            "role": "authenticated",
        }
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "synthetic-key"})

    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    store = SqlConnectionStore(sessions)
    store.add_organization("org-a")
    store.add_principal("internal-alice")
    store.bind_external_identity(
        "internal-alice", "https://identity.example/auth/v1", "external-alice"
    )
    store.grant_membership("internal-alice", "org-a")
    store.add_connection(
        "org-a",
        OdooConnection("odoo-a", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_TEST"),
    )
    store.grant_policy("internal-alice", "odoo-a", "read", "res.partner")
    store.set_oauth_client_admission("approved-oauth-client", enabled=True)
    store.set_oauth_client_admission("another-approved-client", enabled=True)

    settings = Settings(
        mode="http",
        database_url="sqlite+pysqlite:///:memory:",
        oidc_issuer="https://identity.example/auth/v1",
        oidc_audience="https://mcp.example/mcp",
        oidc_jwks_url="https://identity.example/auth/v1/.well-known/jwks.json",
        public_url="https://mcp.example/mcp",
        oauth_provider="supabase",
        oauth_allowed_client_ids=["approved-oauth-client", "another-approved-client"],
        _env_file=None,
    )
    adapter = ReadOnlyAdapter()

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"keys": [jwk]}))
    ) as jwt_client:
        verifier = OidcJwtVerifier(
            issuer="https://identity.example/auth/v1",
            audience="https://mcp.example/mcp",
            jwks_url="https://identity.example/auth/v1/.well-known/jwks.json",
            required_scopes=set(),
            provider="supabase",
            allowed_client_ids=frozenset({"approved-oauth-client", "another-approved-client"}),
            client=jwt_client,
        )
        app = create_http_app(settings, sessions=sessions, verifier=verifier, adapter=adapter)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://mcp.example"
            ) as client:
                metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
                assert metadata.status_code == 200
                assert metadata.json()["resource"] == "https://mcp.example/mcp"
                assert (
                    "https://identity.example/auth/v1" in metadata.json()["authorization_servers"]
                )
                unauthenticated = await client.post(
                    "/mcp",
                    headers={"Accept": "application/json, text/event-stream"},
                    json={"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}},
                )
                assert unauthenticated.status_code == 401
                assert "www-authenticate" in unauthenticated.headers

                async def invoke_bearer(bearer, request_id):
                    return await client.post(
                        "/mcp",
                        headers={
                            "Authorization": f"Bearer {bearer}",
                            "Accept": "application/json, text/event-stream",
                            "MCP-Protocol-Version": "2025-11-25",
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {
                                "name": "record_search",
                                "arguments": {
                                    "connection_id": "odoo-a",
                                    "model": "res.partner",
                                    "domain": [],
                                },
                            },
                        },
                    )

                initialized = await client.post(
                    "/mcp",
                    headers={
                        "Authorization": f"Bearer {sign()}",
                        "Accept": "application/json, text/event-stream",
                        "MCP-Protocol-Version": "2025-11-25",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {"name": "offline-contract-test", "version": "1"},
                        },
                    },
                )
                assert initialized.status_code == 200, initialized.text
                assert initialized.json()["result"]["serverInfo"]["name"]

                valid = await invoke_bearer(sign(), 1)
                assert valid.status_code == 200, valid.text
                assert "Synthetic record" in valid.text
                valid_second_client = await invoke_bearer(
                    sign(client_id="another-approved-client"), 12
                )
                assert valid_second_client.status_code == 200, valid_second_client.text
                assert adapter.calls == [("odoo-a", "search_read")] * 2
                read_audits = [
                    event
                    for event in AuditStore(sessions).list_recent()
                    if event["operation"] == "read"
                ]
                assert {event["details"].get("client_id") for event in read_audits} == {
                    "approved-oauth-client",
                    "another-approved-client",
                }
                assert all(event["principal_id"] == "internal-alice" for event in read_audits)
                assert "external-alice" not in str(read_audits)

                for invalid in (
                    sign(aud="authenticated"),
                    sign(aud="approved-oauth-client"),
                    sign(client_id="unapproved-client"),
                    sign(aud=["authenticated", "https://mcp.example/mcp"]),
                    sign(iss="https://different.example/auth/v1"),
                ):
                    response = await invoke_bearer(invalid, 2)
                    assert response.status_code == 401
                assert adapter.calls == [("odoo-a", "search_read")] * 2

                store.set_oauth_client_admission("approved-oauth-client", enabled=False)
                revoked = await invoke_bearer(sign(), 3)
                assert revoked.status_code == 200
                assert revoked.json()["result"].get("isError") is True
                assert adapter.calls == [("odoo-a", "search_read")] * 2
    engine.dispose()
