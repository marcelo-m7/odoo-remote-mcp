# Supabase FACODI OAuth 2.1 — Monynha MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate the remote Monynha Odoo MCP with explicitly MCP-bound FACODI Supabase OAuth 2.1 access tokens while keeping all Monynha entitlements and Odoo credentials private and deny-by-default.

**Architecture:** Supabase is the OAuth authorization server only; the existing Python Streamable HTTP MCP remains the resource server and its separate PostgreSQL database owns `(issuer, subject) → principal`, organizations, permissions and admitted OAuth clients. Add a fail-closed Supabase-specific JWT verifier and a global write gate; preserve the existing generic OIDC / stdio paths. Any Supabase hook, OAuth configuration, consent frontend, or production rollout requires a **separate implementation plan and explicit staging authorization**.

**Tech Stack:** Python 3.12, MCP Python SDK, PyJWT + JWKS, Starlette, Pydantic Settings, SQLAlchemy/Alembic, PostgreSQL, pytest/httpx, Docker/Coolify.

**Spec:** `docs/superpowers/specs/2026-10-27-supabase-facodi-oauth21-mcp-design.md` (draft PR #4).

## Global Constraints

- No changes to the live FACODI Supabase project, FACODI frontend, Odoo or Coolify in this plan. Do not migrate or deploy against any external database.
- Never accept `aud=authenticated`, an ID token, a service-role/anon token, a token for another resource or an unadmitted OAuth client. The expected audience remains the canonical HTTPS `MONYNHA_MCP_PUBLIC_URL` ending in `/mcp`.
- Exact `iss` + `sub` form the external identity. Email and mutable user metadata are not authorization inputs; authentication never auto-creates a Monynha principal, membership or connection grant.
- `MONYNHA_MCP_WRITES_ENABLED=false` by default, server-enforced before Odoo calls, including when a stored policy permits writing. `delete` and arbitrary methods remain unavailable.
- Do not weaken legacy generic OIDC checks; only an explicitly configured Supabase OAuth provider may use provider-specific scope parsing, while requiring authenticated client ID, audience and server-managed Monynha grants.
- No OAuth or Odoo bearer/API tokens in logs, returned MCP data, migrations or source control. Keep `MONYNHA_ODOO_KEY_*` in Coolify secrets only.
- No merge and no production deploy from this plan. Implementation changes go to a new branch and draft PR based on `main`; PR #3 (Compose) stays independent until its merge status is verified.

## Review Focus

1. **Wrong audience as an array or string** → deny any ambiguous/multiple-audience token rather than allowing `authenticated` alongside the MCP resource (Task 2 tests).
2. **OAuth `client_id` absent, forged in user metadata or mismatching `azp`** → fail closed without probing Odoo (Task 2 tests).
3. **Same `sub` from a different issuer or unknown `(iss,sub)`** → do not reuse old principal grants; deny until explicit administrative binding (Task 3 tests).
4. **Legacy create/update grants when writes are disabled** → reject at both public service methods and central dispatch with zero adapter calls (Task 4 tests).
5. **An admitted client revoked while its token is unexpired** → next MCP tool access fails, even when JWT verification succeeds (Task 5 tests).

---

### Task 1: Read-only Supabase compatibility probe and contract fixtures

**Files:**
- Create: `docs/deployment/supabase-oauth-compatibility.md`
- Create: `tests/contract/fixtures/supabase_oauth_claims.json`
- Test: `tests/contract/test_supabase_claim_fixtures.py`

**Interfaces:**
- Produces: sanitized claim shapes for the MCP OAuth verifier; a signed-off compatibility checklist (OIDC issuer, discovery endpoints, signing keys, OAuth client-ID claim name, `resource` behavior, audience and refresh-token behavior).
- Blocks: changing Supabase configuration, guessing custom scopes, or relaxing audience verification to compensate for missing provider features.

- [ ] **Step 1: Write fixture tests** asserting fixtures contain no secrets; model an MCP-bound access token, standard FACODI `aud=authenticated` token, absent client ID and mismatched OAuth client; require explicit `iss`, `sub`, `aud`, `exp`, `iat` and `client_id`/documented equivalent.
- [ ] **Step 2: Run** `uv run pytest tests/contract/test_supabase_claim_fixtures.py -q` and confirm the missing fixture fails.
- [ ] **Step 3: Add synthetic fixtures and a read-only probe checklist**; inspect official Supabase OAuth discovery/JWKS and management settings where authorized, recording endpoint/status/claim *shape*, not bearer tokens. If the beta OAuth server or RFC 8707 binding cannot provide a resource-specific token, mark the rollout blocked.
- [ ] **Step 4: Re-run** the fixture test and verify it passes; review the checklist against the latest [Supabase OAuth flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows) and [token security](https://supabase.com/docs/guides/auth/oauth-server/token-security) docs.
- [ ] **Step 5: Commit** `test: characterize Supabase OAuth contract without credentials`.

### Task 2: Fail-closed provider-aware JWT verifier and configuration

**Files:**
- Modify: `src/monynha_odoo_mcp/auth/oidc.py`
- Modify: `src/monynha_odoo_mcp/settings.py`
- Test: `tests/contract/test_remote_auth.py`, `tests/unit/test_settings.py`

**Interfaces:**
- Consumes: fixture contracts from Task 1.
- Produces: `Settings.oauth_provider: Literal["generic", "supabase"] = "generic"`, `Settings.oauth_allowed_client_ids: list[str] = []`; `OidcJwtVerifier(..., provider: Literal["generic", "supabase"] = "generic", allowed_client_ids: frozenset[str] = frozenset())` implementing `verify_token() -> AccessToken | None`. The verifier publishes a validated `AccessToken.client_id`, never falls back to `sub` for client identity.

- [ ] **Step 1: Add failing tests** for a valid signed Supabase-style access token with exact `aud` and permitted client ID; rejection of `aud=authenticated`, mixed audience, missing/unknown `client_id`, spoofed metadata, missing/expired claims and mismatched client claims; generic `mcp:odoo` behavior unchanged.
- [ ] **Step 2: Run** `uv run pytest tests/contract/test_remote_auth.py tests/unit/test_settings.py -q` and observe the new tests fail.
- [ ] **Step 3: Add strict provider-selectable claim extraction** keyed only to a verified, documented top-level OAuth client claim; validate exact singular audience, issuer, signature, `sub`, expiry/iat and allowlist. In Supabase mode, do not equate `openid` to Odoo permission or require unsupported `mcp:odoo`; deny startup if client list is empty.
- [ ] **Step 4: Re-run** these tests; expect all new and existing cases green. Include `unknown kid` rate-limited JWKS refresh tests unchanged.
- [ ] **Step 5: Commit** `feat: verify MCP-bound Supabase OAuth bearer tokens`.

### Task 3: External identities and explicit Monynha onboarding

**Files:**
- Modify: `src/monynha_odoo_mcp/storage/db.py`
- Create: `src/monynha_odoo_mcp/storage/migrations/versions/0002_external_oauth_identities.py`
- Modify: `src/monynha_odoo_mcp/connections/sql_store.py`
- Modify: `src/monynha_odoo_mcp/admin.py`
- Test: `tests/integration/test_storage.py`, `tests/unit/test_admin_audit.py`

**Interfaces:**
- Produces: `ExternalIdentityRow(issuer, subject, principal_id)` with unique `(issuer, subject)` and FK to `principals.id`; `SqlConnectionStore.resolve_external_principal(issuer: str, subject: str) -> Principal | None`; admin-only `bind_external_identity(principal_id: str, issuer: str, subject: str) -> None`. No implicit subject-based fallback.

- [ ] **Step 1: Add failing migration/registry tests:** two issuers with equal `sub` cannot share a binding; unknown identity returns `None`; one existing principal can be explicitly linked without changing membership/policies; duplicate/existing mismatched binding is rejected; unauthorized principal ID denied.
- [ ] **Step 2: Run** `uv run pytest tests/integration/test_storage.py tests/unit/test_admin_audit.py -q` and verify failures.
- [ ] **Step 3: Implement new table, migration and admin command**, keeping the existing principal PK and grants unchanged; do not backfill existing `principal_id=sub` users automatically. Document controlled manual mapping from known principals with audit/change review.
- [ ] **Step 4: Run** migration upgrade/downgrade tests on disposable SQLite and test `PostgreSQL` DDL compatibility; verify prior grants survived upgrade and unbound identities have zero authorization.
- [ ] **Step 5: Commit** `feat: bind external issuer subjects to private principals`.

### Task 4: Central write kill switch, including legacy grants

**Files:**
- Modify: `src/monynha_odoo_mcp/settings.py`
- Modify: `src/monynha_odoo_mcp/tools/service.py`
- Modify: `src/monynha_odoo_mcp/server.py`
- Test: `tests/unit/test_tools.py`, `tests/integration/test_e2e_mcp.py`

**Interfaces:**
- Produces: `Settings.writes_enabled: bool = False`; `OdooToolService(..., writes_enabled: bool = False)`; both remote and stdio constructors explicitly pass this setting; central `_call` refuses side-effect operations before policy lookup/adapter dispatch.

- [ ] **Step 1: Add failing tests** that `record_create` and `record_update` both deny when policy grants them but the flag is false, with `adapter.calls == []` and redacted denied audit. Test a direct `_call(..., operation="create", ...)` invocation and an allowed read request.
- [ ] **Step 2: Run** `uv run pytest tests/unit/test_tools.py tests/integration/test_e2e_mcp.py -q` and confirm the deny cases fail before implementation.
- [ ] **Step 3: Implement default-off gate** in public write methods and in `_call` as defense in depth. Update existing tests that intentionally exercise audited writes to pass `writes_enabled=True`; do not flip the service default or enable writes for remote deployment.
- [ ] **Step 4: Run** the test subset and verify zero Odoo calls during denied writes, including empty or malformed parameters; preserve behavior of allowed reads and explicitly enabled local audit tests.
- [ ] **Step 5: Commit** `security: default all MCP write operations to disabled`.

### Task 5: Request-time client admission, identity mapping and revocation

**Files:**
- Modify: `src/monynha_odoo_mcp/server.py`
- Modify: `src/monynha_odoo_mcp/connections/sql_store.py`
- Modify: `src/monynha_odoo_mcp/storage/db.py`
- Create: `src/monynha_odoo_mcp/storage/migrations/versions/0003_oauth_client_admissions.py`
- Test: `tests/integration/test_transport.py`, `tests/integration/test_storage.py`

**Interfaces:**
- Produces: `OAuthClientAdmissionRow(client_id, enabled)` in private PostgreSQL and `SqlConnectionStore.is_oauth_client_admitted(client_id: str) -> bool`. `create_http_app().scoped_service()` checks a verified `AccessToken.client_id`, a current DB admission, and `(iss, sub)` binding before returning `OdooToolService(Principal(internal_id))`. Other providers retain legacy principal resolution only when explicitly configured and do not gain Supabase membership.

- [ ] **Step 1: Add failing tests** for valid JWT/unbound identity, unadmitted client, revoked client, cross-issuer same-sub collision, two organizations with same connection label, missing membership, and test-token subject different from internal principal ID. Every denial must produce no Odoo adapter calls.
- [ ] **Step 2: Run** `uv run pytest tests/integration/test_transport.py tests/integration/test_storage.py -q` and confirm new cases fail.
- [ ] **Step 3: Add request-time authorization context** without using email, Supabase role or user-provided tenant. Introduce admin-only admission/revocation (no public self-service). Reconcile MCP SDK `AuthSettings.required_scopes` for the Supabase provider with verifier enforcement; `401` discovery remains correct. Ensure list and direct connection access remain membership/policy-gated.
- [ ] **Step 4: Re-run** integration tests; verify a revoked client is blocked even with a cryptographically valid unexpired token; no error reveals a tenant ID, connection secret or bearer token.
- [ ] **Step 5: Commit** `security: enforce Monynha principal and OAuth client admission`.

### Task 6: Documentation and offline cross-layer regression

**Files:**
- Modify: `README.md`, `docs/security.md`, `docs/deployment/coolify.md`
- Modify: `tests/integration/test_transport.py`, `tests/contract/test_remote_auth.py`
- Create: `docs/deployment/supabase-oauth-rollout-checklist.md`

**Interfaces:**
- Produces: exact non-secret Coolify `MONYNHA_MCP_*` environment variable names, procedures for key rotation/revocation/manual identity binding, OAuth discovery checks, and a locked-down staging acceptance and rollback checklist.

- [ ] **Step 1: Add failing contract cases** for `/.well-known/oauth-protected-resource/mcp`, unauthenticated `WWW-Authenticate`, successful authenticated MCP `initialize`, and read-only tool access with a private registry. Assert absent/wrong-client/wrong-audience token never reaches Odoo.
- [ ] **Step 2: Run** `uv run pytest tests/contract tests/integration -q` and observe failures in the new security paths.
- [ ] **Step 3: Update documentation and fixtures** to explain generic OIDC versus Supabase OAuth, required URL/issuer/JWKS/client allowlist, scoped onboarding, secrets, consent prerequisites and explicit write toggle. Verify Compose PR #3 status before recommending Compose-specific deployment config.
- [ ] **Step 4: Run** `uv run pytest -q`, `uv run ruff check .`, `uv run mypy src`, `uv run python -m compileall -q src`; where Docker is available, build image and probe `/healthz`/`/readyz` locally with mock backing services. Store non-secret evidence in the implementation PR.
- [ ] **Step 5: Commit** `docs: operationalize Supabase OAuth MCP security checks`; open a **new draft implementation PR** based on `main`, no merge.

## Separate gated workstreams (not authorized by this code plan)

1. **Supabase OAuth Server / Custom Access Token Hook:** after a read-only discovery report, Marcelo selects either an *isolated staging Supabase project* or explicitly approves a restricted pilot against the existing FACODI project. Then author a separate SQL/config/rollback plan to issue **resource-specific** `aud` only to admitted Monynha clients, while preserving all FACODI JWT/REST/RLS behavior. Never deploy the hook as a workaround for unsupported RFC 8707 semantics; block instead.
2. **FACODI consent frontend:** inspect its current `SITE_URL`/routes first, then plan `authorization_id` preservation, logged-in state, client/redirect/scopes display, approve/deny and CSRF/return URL checks in the actual frontend repository. Any frontend changes get their own draft PR and functional/visual QA.
3. **Full OAuth staging and Coolify rollout:** only after the above two workstreams are separately approved and implemented, use a registered pilot client + PKCE S256 + exact redirect + resource binding to test token issuance, MCP discovery, revocation, cross-org isolation, FACODI regression, Odoo staging read-only calls, restart and rollback. Production needs another explicit approval.

**Handoff gate:** Marcelo reviews this plan and selects the execution method before any MCP product-code changes. No choice of staging environment is implied by approval of the architecture or this plan.
