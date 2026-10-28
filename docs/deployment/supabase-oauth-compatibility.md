# FACODI Supabase OAuth 2.1 — compatibility and activation gates

The implementation verifies **MCP-specific** Supabase OAuth access tokens. It does not enable the OAuth Server in FACODI and it must never accept ordinary `aud=authenticated` FACODI access tokens as MCP credentials.

## Read-only observations (2026-10-27)

The shared FACODI Supabase project's public endpoints responded as follows:

| Probe | HTTP | Meaning |
| --- | --- | --- |
| `/.well-known/oauth-authorization-server/auth/v1` | `404` | OAuth AS discovery unavailable at the documented URL; **activation blocked** until the feature is configured and verified |
| `/auth/v1/.well-known/jwks.json` | `200` | Signing key discovery reachable; does not independently prove OAuth functionality |
| `/auth/v1/.well-known/openid-configuration` | `200` | OIDC discovery reachable; does not independently prove OAuth functionality |

The project reference and any credentials are intentionally omitted. The probes did **not** enable OAuth, rotate keys, register a client, edit a consent route, or update database objects.

## Contract before enabling remote Supabase mode

1. Confirm the OAuth Server is enabled and `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `issuer`, PKCE S256 and consent routing are actually published.
2. Confirm signed tokens use an asymmetric supported algorithm (RS256/ES256), the correct `iss`, a top-level `client_id`, and a **single `aud` equal to the full MCP resource URL**.
3. Test RFC 8707 `resource` behavior through both authorization and token exchange, or document a securely client/resource-bound alternative. A custom JWT access-token hook must preserve ordinary FACODI tokens and RLS behavior.
4. Check refresh token behavior and whether a token whose client is revoked ceases to access Monynha, even before its JWT expiry.
5. Confirm `SITE_URL` and exact consent route without globally changing FACODI redirects; do not enable dynamic client registration during the pilot.
6. Before any Supabase write, get Marcelo's separate approval of an isolated staging project or explicitly risk-reviewed pilot on the existing project.

The synthetic JSON in `tests/contract/fixtures/` is **not** an example of a minted token. It captures only the documented top-level `client_id` and audience claim shapes and contains no secret or real user identity.

Official references: [OAuth Server](https://supabase.com/docs/guides/auth/oauth-server), [OAuth Flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows), [Token Security](https://supabase.com/docs/guides/auth/oauth-server/token-security).
