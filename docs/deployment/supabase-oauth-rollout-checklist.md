# Supabase FACODI OAuth 2.1 — staged rollout checklist

**Status: blocked for live enablement until separately approved.** This MCP
repository implements only the **resource server** and its private policy
database. It does not act as an OAuth authorization server.

## 1. Local / CI (safe without live credentials)

- [ ] `uv sync --locked --extra dev`, `uv run --locked pytest -q`, Ruff, MyPy.
- [ ] Verify `/mcp` unauthenticated `401`, protected-resource metadata and
  `WWW-Authenticate` discovery under the canonical HTTPS MCP resource URL.
- [ ] Check valid synthetic RS256/ES256 bearer, invalid signature, missing `kid`,
  expiry/future timestamps, issuer mismatch, `aud=authenticated`, mixed audience,
  wrong client ID and project `role=service_role`/`anon` denials.
- [ ] Prove unknown `(iss, sub)` or missing membership/policy cannot list or read
  any connection, including guessed direct connection IDs.
- [ ] Prove client revocation blocks the next call even when its JWT has not expired.
- [ ] Prove `record_create`, `record_update` and central write dispatch send
  zero Odoo requests when `MONYNHA_MCP_WRITES_ENABLED=false`.

## 2. Independent Supabase staging environment (requires approval)

Choose **one** environment with Marcelo before writing anything:

- [ ] Isolated Supabase staging project with comparable OAuth/Auth features; or
- [ ] Explicit, risk-reviewed **restricted FACODI pilot** with documented
  impact, maintenance window and rollback. Reusing FACODI identities in a
  future production system alone does **not** authorize pilot changes.

Then separately approve the Supabase OAuth Server enablement, registered pilot
OAuth client, authorization/consent path, and Custom Access Token Hook. Existing
FACODI `SITE_URL`, login, refresh, password reset and RLS must remain unchanged.
The hook must only change `aud` for positively bound Monynha OAuth grants and
preserve every other mandatory Supabase claim; do not install one until RFC 8707
resource-indicator behavior is verified from authorization through refresh.
If token `aud` remains `authenticated`, **stop**; never loosen the gateway.

## 3. Coolify / private PostgreSQL (no secrets committed)

- [ ] Review the independent [Coolify Compose PR #3](https://github.com/marcelo-m7/odoo-remote-mcp/pull/3) before selecting image, migrations and health routes.
- [ ] Migrate the **Monynha-owned** database to Alembic head (`0003_oauth_client_admissions`). Do not run those migrations in FACODI Supabase PostgreSQL.
- [ ] Set `MONYNHA_MCP_MODE=http`, `MONYNHA_MCP_OAUTH_PROVIDER=supabase`.
- [ ] Set trusted HTTPS `MONYNHA_MCP_OIDC_ISSUER`, `MONYNHA_MCP_OIDC_JWKS_URL`, `MONYNHA_MCP_OIDC_AUDIENCE` and `MONYNHA_MCP_PUBLIC_URL` (last two exactly identical, ending in `/mcp`).
- [ ] Set `MONYNHA_MCP_OAUTH_ALLOWED_CLIENT_IDS` as a JSON array of approved client IDs, and `MONYNHA_MCP_WRITES_ENABLED=false`.
- [ ] Inject `MONYNHA_MCP_DATABASE_URL` and `MONYNHA_ODOO_KEY_*` through Coolify's secret manager. Never inject a Supabase service-role key into this resource server.
- [ ] Using the private `monynha-odoo-admin` CLI, explicitly create/bind known principals, admit pilot clients, grant memberships, add allowed connections and per-model **read** grants. Unbound FACODI users receive zero capabilities.
- [ ] Route HTTPS to port 8000 for **both** `/.well-known/*` and `/mcp`; verify `/healthz` and `/readyz`. Keep the app at one worker unless shared rate limiting is provided.

## 4. End-to-end evidence and rollback (new approval before production)

- [ ] Use an actual OAuth MCP client and PKCE S256 with exact registered redirect URI, `state`, explicit consent and MCP `resource` in authorize/token exchange.
- [ ] Confirm token `iss`, single resource-bound `aud`, top-level admitted `client_id`, signed JWKS `kid`, expiry, refetch after signing-key rotation and refresh-token behavior.
- [ ] Confirm two users, two organizations and one cross-organization member cannot see each other's connections or records; unknown clients and revoked clients fail closed.
- [ ] Confirm two admitted clients of the same user are distinguishable by verified client ID in business-access audit events.
- [ ] Compare FACODI's login/session/refresh/RLS/API behavior **before and after** the hook in staging; do not deploy on failed regression.
- [ ] Run only read-only Odoo staging calls; monitor audit events and ensure tokens, PII and Odoo API keys are absent from logs.
- [ ] Document rollback: revoke Monynha pilot client(s), stop only the MCP Coolify route, restore previous gateway image/config, revert only the Monynha-scoped Supabase hook/client configuration. Never rotate all FACODI signing keys as a Monynha rollback.

**Blocking finding on 2026-10-27:** public OAuth authorization-server discovery returned `404` for FACODI, while public JWKS and OIDC discovery returned `200`. The presence of OIDC/JWKS is **not evidence** that Supabase OAuth 2.1 can currently issue MCP-specific tokens.
