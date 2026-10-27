import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from monynha_odoo_mcp.auth.oidc import OidcJwtVerifier, verify_bearer_token
from monynha_odoo_mcp.core.errors import McpError


def make_key(kid="key1"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return key, jwk


def make_token(key, kid, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://id.example",
        "aud": "https://mcp.example/mcp",
        "sub": "alice",
        "iat": now,
        "exp": now + 3600,
        "scope": "mcp:odoo",
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "https://other.example"},
        {"iss": "https://evil.example"},
        {"scope": "other"},
    ],
)
def test_wrong_audience_issuer_scope_rejected(overrides):
    key, jwk = make_key()
    token = make_token(key, "key1", **overrides)
    with pytest.raises(McpError) as exc:
        verify_bearer_token(
            token,
            {"keys": [jwk]},
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            required_scopes={"mcp:odoo"},
        )
    assert exc.value.code == "invalid_token"


def test_valid_token_returns_authenticated_subject():
    key, jwk = make_key()
    token = make_token(key, "key1")
    principal = verify_bearer_token(
        token,
        {"keys": [jwk]},
        issuer="https://id.example",
        audience="https://mcp.example/mcp",
        required_scopes={"mcp:odoo"},
    )
    assert principal.id == "alice"


@pytest.mark.asyncio
async def test_jwks_rotation_supported():
    old_key, old_jwk = make_key("old")
    new_key, new_jwk = make_key("new")
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"keys": [old_jwk] if calls == 1 else [new_jwk]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/keys",
            required_scopes={"mcp:odoo"},
            client=client,
        )
        assert (await verifier.verify_token(make_token(old_key, "old"))).subject == "alice"
        assert (await verifier.verify_token(make_token(new_key, "new"))).subject == "alice"
    assert calls == 2


@pytest.mark.asyncio
async def test_unknown_kids_cannot_amplify_jwks_fetches():
    valid_key, valid_jwk = make_key("trusted")
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"keys": [valid_jwk]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/keys",
            required_scopes={"mcp:odoo"},
            client=client,
        )
        assert await verifier.verify_token(make_token(valid_key, "trusted")) is not None
        unknown_key, _ = make_key("unknown")
        tokens = [make_token(unknown_key, f"unknown-{i}") for i in range(80)]
        results = await __import__("asyncio").gather(*(verifier.verify_token(t) for t in tokens))
        assert all(result is None for result in results)
        assert await verifier.verify_token(make_token(unknown_key, "unknown-0")) is None
    assert calls <= 2


@pytest.mark.asyncio
async def test_failed_initial_jwks_request_is_cooled_down():
    key, _ = make_key()
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/keys",
            required_scopes={"mcp:odoo"},
            client=client,
        )
        for _ in range(20):
            assert await verifier.verify_token(make_token(key, "unknown")) is None
    assert calls == 1
