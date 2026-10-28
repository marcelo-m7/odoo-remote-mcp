# Security model (v0.1 alpha)

The gateway handles powerful Odoo credentials. Treat it as a privileged integration,
not as a general-purpose HTTP proxy. **Do not expose it to production before a security review.**

## Trust boundaries

- MCP clients authenticate with an external OIDC issuer, not with Odoo credentials.
- Access tokens must have a valid RSA/ECDSA signature, issuer, expiration, audience
  equal to the public MCP resource URL and subject. `generic` mode requires
  `mcp:odoo` scope; `supabase` mode requires a verified **top-level** `client_id`
  in both a deployment allowlist and private database admission. Generic FACODI
  tokens with `aud=authenticated` cannot be accepted as MCP tokens. Supabase
  OAuth also requires the signed `role=authenticated` user claim, denying
  `service_role` and `anon` project tokens regardless of other claims.
- In Supabase mode, `(iss, sub)` explicitly maps to a private Monynha principal,
  not the token's email, role or mutable user metadata. Authenticated FACODI
  users never acquire a Monynha principal, membership or Odoo grant automatically.
  Organization membership and model/operation grants remain in private PostgreSQL.
- Odoo API keys are resolved exclusively from `env:MONYNHA_ODOO_KEY_*` references.
  The registry stores references, never key values. Do not mount credential files in Git.
- The user behind the Odoo key should have minimal ACLs and record rules.

## Operation controls

- Tools use an explicit `connection_id`. No shared active connection exists.
- Model-level permissions `read`, `create` and `update` are deny-by-default.
- `MONYNHA_MCP_WRITES_ENABLED=false` globally blocks `create`/`update` before
  any Odoo call even when old policies grant them. A `true` value is an additional
  *necessary*, never sufficient, condition for writing.
- Delete, arbitrary method execution, payment, add-on installation and `sudo` are
  not exposed in v0.1. Local `stdio` grants **read only** by default.
- Every Odoo ORM call is a separate JSON-2 transaction. Multi-step workflows are
  not atomic and must use native Odoo business methods in future versions.
- Writes are not retried automatically after timeouts.
- Writes record a `started` audit event before dispatch; a timeout is
  reported as an uncertain outcome. Confirmed Odoo success is returned even if
  the follow-up audit event cannot be persisted, with an explicit warning.
- Nested Odoo x2many command lists are rejected because they can delete/unlink
  related records through an ordinary create or update grant.
- Read tools select `id` and `display_name` by default; HTTP responses are
  streamed with a default 2 MiB cap. Explicit field selection still requires
  careful Odoo permissions and data classification.

## Outbound and inbound network

- Odoo destinations must use HTTPS, public IPs and port 443. A guarded
  `httpcore` network backend validates DNS answers, dials a vetted IP, preserves
  original TLS SNI and refuses redirects and HTTP proxies. Private instances are
  unsupported without a separately reviewed controlled-egress policy.
- The outbound hook uses a compatibility-sensitive API from HTTPX 0.28/httpcore 1.0;
  dependencies are pinned. Review it when upgrading.
- Incoming HTTP requires bearer tokens through the official MCP SDK middleware
  and checks Host/Origin against the configured public resource URL and a
  separately configured allowlist of trusted HTTPS browser origins.
- Per-process limits apply by principal/connection/operation and by connection
  concurrency. Multiple instances **require shared upstream rate limiting**;
  deployment workers must not bypass local budgets.
- TLS must be terminated at a trusted reverse proxy; configure
  `MONYNHA_MCP_PUBLIC_URL` as the external HTTPS endpoint ending in `/mcp`.
- Serve `/healthz` and `/readyz` without secrets. Do not expose database
  administrative ports publicly.

## Audit and confidentiality

- Audit events record principal, connection, operation, outcome and allowlisted
  metadata. Supabase-mode Odoo operations attribute verified OAuth client ID to
  the private principal; denied client or unbound-identity access records an opaque
  client ID and denial stage without logging the external subject or token.
  No raw records, Odoo tracebacks, prompts or API key values are written.
- The append-only repository method is **not** a database-level immutability
  guarantee; use a dedicated DB role or external immutable sink for regulated uses.
- Configure backup, retention, PII controls, TLS, network egress rules and secret
  rotation before operational deployment. The external API may depend on the Odoo
  pricing plan and instance capabilities.
- A `started` event without a later success/failure requires reconciliation
  against Odoo; gateway logs and the metadata database are not a distributed
  transaction coordinator.

## Validation boundaries

CI uses mocked Odoo responses and disposable SQL stores. Production FACODI and
Boa Vista instances are not part of automated tests. This alpha is not evidence
of compatibility across every Odoo edition or third-party module.

Supabase OAuth Server activation, Custom Access Token Hook installation, and
FACODI consent frontend are **not implemented by this MCP code change**. Live
OAuth discovery returned `404` in the 2026-10-27 read-only probe. Effective
PKCE, RFC 8707 resource binding, correct token audience, live consent route,
FACODI RLS/login regression, and Coolify E2E must be confirmed before rollout.

Report security issues privately to the repository maintainer; do not post
credentials or exploit data in public issues.
