"""External OIDC JWT validation and JWKS rotation for remote MCP."""

import asyncio
import time
from typing import Any

import httpx
import jwt
from mcp.server.auth.provider import AccessToken

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.core.errors import McpError

_ALGORITHMS = ["RS256", "ES256"]


def _decode_claims(
    token: str,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
    required_scopes: set[str],
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not isinstance(kid, str) or header.get("alg") not in _ALGORITHMS:
            raise ValueError("Unsupported JWT key")
        matching = [item for item in jwks["keys"] if item.get("kid") == kid]
        if len(matching) != 1:
            raise ValueError("Unknown JWT key")
        public_key = jwt.PyJWK.from_dict(matching[0]).key
        claims = jwt.decode(
            token,
            public_key,
            algorithms=_ALGORITHMS,
            issuer=issuer,
            audience=audience,
            options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            leeway=30,
        )
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise ValueError("Missing subject")
        raw_scopes = claims.get("scope", claims.get("scp", ""))
        scopes = set(raw_scopes.split()) if isinstance(raw_scopes, str) else set(raw_scopes)
        if not required_scopes.issubset(scopes):
            raise ValueError("Missing required scope")
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, IndexError):
        raise McpError("invalid_token", "Access token is invalid") from None


def verify_bearer_token(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    required_scopes: set[str],
) -> Principal:
    claims = _decode_claims(token, jwks, issuer, audience, required_scopes)
    return Principal(claims["sub"])


class OidcJwtVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        required_scopes: set[str],
        client: httpx.AsyncClient | None = None,
        cache_seconds: int = 300,
        unknown_kid_cooldown_seconds: int = 30,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.required_scopes = required_scopes
        self.client = client
        self.cache_seconds = cache_seconds
        self.unknown_kid_cooldown_seconds = unknown_kid_cooldown_seconds
        self._jwks: dict[str, Any] | None = None
        self._loaded_at = 0.0
        self._last_unknown_refresh = float("-inf")
        self._last_failed_refresh = float("-inf")
        self._negative_kids: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def _refresh(self, *, unknown_kid: bool = False) -> dict[str, Any]:
        async with self._lock:
            now = time.monotonic()
            if (
                not unknown_kid
                and self._jwks is not None
                and now - self._loaded_at < self.cache_seconds
            ):
                return self._jwks
            if now - self._last_failed_refresh < self.unknown_kid_cooldown_seconds:
                raise McpError("invalid_token", "OIDC key set is unavailable")
            if unknown_kid:
                if now - self._last_unknown_refresh < self.unknown_kid_cooldown_seconds:
                    return self._jwks or {}
                self._last_unknown_refresh = now
            try:
                if self.client is None:
                    async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
                        response = await client.get(self.jwks_url, timeout=5)
                else:
                    response = await self.client.get(self.jwks_url, timeout=5)
                response.raise_for_status()
                if len(response.content) > 65_536:
                    raise McpError("invalid_token", "OIDC key set is unavailable")
                result = response.json()
                if not isinstance(result, dict) or not isinstance(result.get("keys"), list):
                    raise McpError("invalid_token", "OIDC key set is unavailable")
                if len(result["keys"]) > 100:
                    raise McpError("invalid_token", "OIDC key set is unavailable")
            except (httpx.HTTPError, McpError, ValueError, TypeError):
                self._last_failed_refresh = time.monotonic()
                raise
            self._jwks = result
            self._loaded_at = time.monotonic()
            return result

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (
                header.get("alg") not in _ALGORITHMS
                or not isinstance(kid, str)
                or not 1 <= len(kid) <= 128
            ):
                return None
            if self._jwks is None or time.monotonic() - self._loaded_at > self.cache_seconds:
                await self._refresh()
            try:
                claims = _decode_claims(
                    token, self._jwks or {}, self.issuer, self.audience, self.required_scopes
                )
            except McpError:
                # Unknown kid can indicate planned rotation. Refresh only for a new kid,
                # never for repeated invalid signatures (which could trigger a fetch storm).
                known = {key.get("kid") for key in (self._jwks or {}).get("keys", [])}
                if kid in known:
                    return None
                now = time.monotonic()
                if self._negative_kids.get(kid, 0) > now:
                    return None
                await self._refresh(unknown_kid=True)
                if kid not in {key.get("kid") for key in (self._jwks or {}).get("keys", [])}:
                    if len(self._negative_kids) >= 512:
                        self._negative_kids.pop(next(iter(self._negative_kids)))
                    self._negative_kids[kid] = now + self.unknown_kid_cooldown_seconds
                    return None
                claims = _decode_claims(
                    token, self._jwks or {}, self.issuer, self.audience, self.required_scopes
                )
            raw_scopes = claims.get("scope", claims.get("scp", ""))
            scopes = raw_scopes.split() if isinstance(raw_scopes, str) else list(raw_scopes)
            return AccessToken(
                token=token,
                client_id=str(claims.get("azp", claims["sub"])),
                subject=claims["sub"],
                scopes=scopes,
                expires_at=claims.get("exp"),
                resource=self.audience,
            )
        except (McpError, jwt.PyJWTError, httpx.HTTPError, ValueError, TypeError):
            return None
