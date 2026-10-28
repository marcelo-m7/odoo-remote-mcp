# Deploy Monynha Odoo MCP on Coolify

**Status:** deployment configuration prepared; live production deployment and
OAuth/Odoo integration remain subject to staging verification. The alpha has no
SaaS onboarding or built-in OAuth identity provider; Supabase can serve as an
**external** OAuth server only after its separate compatibility gates pass.

## Deployment architecture

- **Coolify Git-based Docker Compose Application:** build from the repository's
  `Dockerfile` using `docker-compose.coolify.yml`, in normal managed mode (not Raw).
- **One-click PostgreSQL 17 database:** a separate, private Coolify resource
  with persistent volume, scheduled backups and tested restore procedure.
- **Coolify HTTPS reverse proxy:** expose only the MCP service on internal port
  `8000`; no `ports:` mapping and no publicly exposed PostgreSQL listener.
- **External OIDC/OAuth provider:** the access token audience must be the full
  MCP resource URL. Generic providers require the `mcp:odoo` scope; Supabase
  mode instead requires an explicitly admitted OAuth client and a private
  bound principal, while still rejecting ordinary FACODI access tokens.

The existing `docker-compose.example.yml` bundles PostgreSQL for local or
demonstration setups; it is **not** the production Coolify compose.

## 1. Create the database

1. Create a PostgreSQL 17 resource in Coolify on the selected destination.
2. Keep its port private. Enable database-native scheduled backups and confirm
   that a backup can be restored to a disposable environment.
3. Obtain its **internal** hostname, database, username and password.
4. Ensure the application can reach the database on the private Coolify
   destination network; use Coolify's predefined network setting if they are
   different resources on the same server/network.

Prepare a SQLAlchemy/psycopg connection URL:

```text
postgresql+psycopg://USER:PERCENT_ENCODED_PASSWORD@PRIVATE_DB_HOST:5432/DBNAME
```

Percent-encode reserved URL characters in the password. Never commit the real
connection string or print it in deployment logs.

## 2. Create the application from Git

1. Choose **New Resource → Git Repository** in Coolify.
2. Select the reviewed repository branch (normally `main` **after merge**;
   for pre-production verification, select the specific reviewed feature branch
   or immutable commit).
3. Select **Docker Compose** as the build strategy.
4. Base Directory: `/`; Docker Compose Location: `docker-compose.coolify.yml`.
5. Keep Compose deployment in the normal managed mode; do **not** enable Raw.
6. On **Domains**, point your HTTPS hostname to the `mcp` service on internal
   port `8000`, at the **root** path `/`.

For example, configure the domain for the service as
`https://mcp.example.com:8000`. The suffix is Coolify's internal target port;
public clients still connect with ordinary HTTPS. Do not expose only `/mcp`:
OIDC resource metadata lives under `/.well-known/oauth-protected-resource/mcp`.

## 3. Set environment variables in Coolify

| Variable | Example or requirement |
| --- | --- |
| `MONYNHA_MCP_DATABASE_URL` | Private psycopg PostgreSQL URL from step 1; secret |
| `MONYNHA_MCP_PUBLIC_URL` | `https://mcp.example.com/mcp` |
| `MONYNHA_MCP_OIDC_ISSUER` | `https://issuer.example.com` |
| `MONYNHA_MCP_OIDC_JWKS_URL` | `https://issuer.example.com/.well-known/jwks.json` |
| `MONYNHA_MCP_OAUTH_PROVIDER` | `generic` (default) or `supabase`; selects provider-specific validation |
| `MONYNHA_MCP_OAUTH_ALLOWED_CLIENT_IDS` | JSON array of permitted Supabase OAuth client IDs, e.g. `["pilot-client-id"]`; defaults to `[]` |
| `MONYNHA_MCP_WRITES_ENABLED` | `false` (default); do not enable for the read-only pilot |
| `MONYNHA_MCP_ALLOWED_ORIGINS` | Optional JSON array, e.g. `["https://trusted.example.com"]` |
| `MONYNHA_ODOO_KEY_DEFAULT` | Optional Odoo API key, secret, if referenced by a connection |

`MONYNHA_MCP_OIDC_AUDIENCE` is automatically set to the **same** public
resource URL by the Compose definition. Register this audience with the OIDC
issuer. For `generic` mode, grant the `mcp:odoo` scope to permitted clients.
For `supabase` mode, also require a **single signed `aud` string equal to the
MCP URL** and a signed top-level `client_id` present in both the JSON allowlist
and the private Monynha client-admission database. A standard FACODI token with
`aud=authenticated` is never a substitute. Do not loosen audience validation
to get past an incompatible OAuth setup.

Switching `MONYNHA_MCP_OAUTH_PROVIDER=supabase` with the default empty client
list deliberately **prevents startup**: supply the allowlist only after a
staging OAuth token/consent validation and explicitly admit each corresponding
client using `monynha-odoo-admin oauth-client admit`. Then bind each authorized
user's verified `(issuer, subject)` to a separate Monynha principal using
`monynha-odoo-admin identity bind`, and grant only the necessary memberships,
connections and read policies. Supabase credentials or `service_role` tokens
must never be used as client bearer credentials or stored here.

The shared FACODI Supabase project currently **does not expose the documented
OAuth authorization-server discovery endpoint** (observed `404` on
2026-10-28); this Compose update does **not** activate it. See the
[compatibility contract](supabase-oauth-compatibility.md) and
[staged rollout checklist](supabase-oauth-rollout-checklist.md). Token `aud`
customization, consent routing and RFC 8707 behavior require an isolated,
approved staging experiment and regression checks of existing FACODI login,
refresh and RLS before production.

Do not add real credentials to the Compose file. To support more Odoo instances,
add an explicit `MONYNHA_ODOO_KEY_<NAME>: ${MONYNHA_ODOO_KEY_<NAME>:?}` mapping
to the `mcp.environment` section, save the corresponding secret in Coolify, and
create an authorized connection with `secret_ref=env:MONYNHA_ODOO_KEY_<NAME>`.

## 4. Deploy and initialize

- Deploy from the selected Git commit and inspect the deployment logs. The
  container command runs `alembic upgrade head` **before** starting the MCP
  server. A migration failure prevents service startup.
- Docker and Coolify health checks use `/readyz`, which checks that the database
  schema is reachable. `/healthz` is only a liveness endpoint.
- In the app container's **Terminal**, use `monynha-odoo-admin` to create an
  organization, principal, membership, Odoo connection and read policy as
  documented in the repository README. Avoid broad production grants.

The configuration assumes a **single application worker/replica**. The
in-process rate limiter must be complemented by shared upstream limits before
horizontal scaling. Treat DB migrations as irreversible operational changes
unless an explicit down-migration and restore plan exists.

## 5. Acceptance checks

1. The app is healthy in Coolify and `https://mcp.example.com/readyz` returns
   `{"ready": true}` without leaking database metadata.
2. `https://mcp.example.com/.well-known/oauth-protected-resource/mcp`
   advertises the correct resource and authorization server.
3. An unauthenticated MCP request receives `401`; an authorized OIDC client can
   initialize, list tools and use a permitted Odoo read connection. In Supabase
   mode, test an actual approved client token, and reject standard FACODI
   `aud=authenticated` tokens, unknown/revoked clients and unbound identities.
4. A user outside the connection's organization is denied. The Odoo API key
   never appears in MCP responses or logs. With writes disabled, write tools
   must not send any Odoo requests.
5. Verify database backup and restore, secret rotation, migration behavior and
   rollback strategy in staging before routing production traffic.

Do not rely on a browser-only smoke test as proof that all Odoo ACLs, model
rules, write policies or multi-step workflows work. The existing unit tests
simulate Odoo; a separate authorized Odoo staging run is required.

## References

- [Coolify Docker Compose applications](https://coolify.io/docs/applications/builds/docker-compose)
- [Coolify database resources](https://coolify.io/docs/databases)
- [Coolify persistent storage](https://coolify.io/docs/services/configuration/persistent-storage)
