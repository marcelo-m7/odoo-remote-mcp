import json
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "permitted"),
    [
        ({}, True),
        ({"aud": "authenticated"}, False),
        ({"aud": ["authenticated", "https://mcp.example/mcp"]}, False),
        ({"client_id": "another-client"}, False),
        ({"client_id": ""}, False),
        ({"client_id": None}, False),
        ({"client_id": "monynha-registered-client", "azp": "other"}, False),
        ({"role": "service_role"}, False),
        ({"role": "anon"}, False),
        ({"role": None}, False),
        ({"client_id": "monynha-registered-client", "user_metadata": {"client_id": "other"}}, True),
    ],
)
async def test_supabase_oauth_accepts_only_bound_access_token(changes, permitted):
    # Breaks if an ordinary FACODI audience or unapproved OAuth client is accepted.
    key, jwk = make_key()
    fixture_path = Path(__file__).parent / "fixtures" / "supabase_oauth_claims.json"
    claims = json.loads(fixture_path.read_text(encoding="utf-8"))["mcp_oauth"]
    claims["iss"] = "https://id.example"
    claims.update(changes)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"keys": [jwk]}))
    ) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/jwks",
            required_scopes=set(),
            provider="supabase",
            allowed_client_ids=frozenset({"monynha-registered-client"}),
            client=client,
        )
        result = await verifier.verify_token(make_token(key, "key1", **claims))
    assert (result is not None) is permitted
    if result is not None:
        assert result.subject == "facodi-user-a"
        assert result.client_id == "monynha-registered-client"


@pytest.mark.asyncio
async def test_supabase_oauth_never_uses_subject_as_missing_client_id():
    key, jwk = make_key()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"keys": [jwk]}))
    ) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/jwks",
            required_scopes=set(),
            provider="supabase",
            allowed_client_ids=frozenset({"alice"}),
            client=client,
        )
        assert await verifier.verify_token(make_token(key, "key1", scope="openid")) is None


@pytest.mark.asyncio
async def test_supabase_signature_time_claims_and_es256_keys():
    rsa_key, rsa_jwk = make_key()
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key()))
    ec_jwk.update({"kid": "ec-key", "use": "sig", "alg": "ES256"})
    now = int(time.time())
    valid_claims = {
        "iss": "https://id.example",
        "aud": "https://mcp.example/mcp",
        "sub": "alice",
        "iat": now,
        "exp": now + 600,
        "role": "authenticated",
        "client_id": "monynha-registered-client",
    }
    ec_token = jwt.encode(valid_claims, ec_key, algorithm="ES256", headers={"kid": "ec-key"})
    invalid_key, _ = make_key()
    invalid_tokens = [
        make_token(rsa_key, "key1", **(valid_claims | {"exp": now - 120})),
        make_token(rsa_key, "key1", **(valid_claims | {"iat": now + 120})),
        make_token(rsa_key, "key1", **(valid_claims | {"nbf": now + 120})),
        make_token(rsa_key, "key1", **(valid_claims | {"exp": None})),
        make_token(invalid_key, "key1", **valid_claims),
        jwt.encode(valid_claims, rsa_key, algorithm="RS256"),
    ]
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"keys": [rsa_jwk, ec_jwk]})
        )
    ) as client:
        verifier = OidcJwtVerifier(
            issuer="https://id.example",
            audience="https://mcp.example/mcp",
            jwks_url="https://id.example/jwks",
            required_scopes=set(),
            provider="supabase",
            allowed_client_ids=frozenset({"monynha-registered-client"}),
            client=client,
        )
        assert (await verifier.verify_token(ec_token)).client_id == "monynha-registered-client"
        for token in invalid_tokens:
            assert await verifier.verify_token(token) is None
