# Monynha Odoo MCP

An original, open-source and security-focused MCP gateway for Odoo, built in
Python for the Monynha Softwares ecosystem. **v0.1 alpha; review required before
production use.**

The gateway serves MCP over authenticated Streamable HTTP and local `stdio`,
with an Odoo 19 JSON-2 adapter and explicit policies for multiple instances.

## What works

- 11 MCP tools: server info, connection listing/checks, model and field discovery,
  record reading/search/counting/grouping, controlled creation and update.
- Odoo 19 JSON-2 API with bearer API key, database header, typed/redacted errors
  and no automatic write retries. Large responses are stopped while streaming.
- PostgreSQL tenant metadata, memberships, per-model operation grants, audit,
  versioned migration and administrative CLI.
- OAuth protected resource metadata, remote OIDC/JWKS verification and `stdio`.
- Public-destination validation and DNS-pinned outbound HTTPS.
- Compact default record fields, request/concurrency budgets, blocked nested
  x2many write commands and write-intent audit events.

Not yet available: XML-RPC legacy compatibility, generic public methods, record
deletion, business wizards, attachments, multi-step workflows, billing or web UI.
The external JSON-2 API requires a compatible Odoo installation/plan.

## Prerequisites

- Python 3.12+, `uv`, PostgreSQL for remotely hosted environments.
- An external OIDC provider issuing RS256/ES256 tokens with the
  `mcp:odoo` scope and audience equal to the MCP resource URL.
- A dedicated low-privilege Odoo technical user and API key, stored in a
  deployment secret manager.

## Local development and tests

```bash
uv sync --locked --extra dev
uv run --locked ruff check .
uv run --locked ruff format --check src tests
uv run --locked mypy --ignore-missing-imports src/monynha_odoo_mcp
uv run --locked pytest -q
```

CI uses only mock Odoo calls. No production credentials are needed.

## Local `stdio`

Configure the environment in your shell or secret manager (never commit
real values):

```bash
export MONYNHA_MCP_MODE=stdio
export MONYNHA_MCP_LOCAL_PRINCIPAL_ID=local-developer
export MONYNHA_MCP_LOCAL_CONNECTION_ID=my-odoo
export MONYNHA_MCP_LOCAL_ODOO_URL=https://odoo.example.com
export MONYNHA_MCP_LOCAL_SECRET_REF=env:MONYNHA_ODOO_KEY_LOCAL
export MONYNHA_ODOO_KEY_LOCAL=replace-with-a-secret-from-your-vault
uv run --locked monynha-odoo-mcp
```

This local profile starts read-only and uses the same validated Odoo client.
Your MCP host can launch the command via `stdio`.

## Remote HTTP gateway

The public URL must be the full HTTPS resource path, for example
`https://mcp.example.com/mcp`. Supply these environment variables:

| Variable | Meaning |
| --- | --- |
| `MONYNHA_MCP_MODE=http` | Enable remote transport |
| `MONYNHA_MCP_DATABASE_URL` | PostgreSQL SQLAlchemy URL; secret-managed |
| `MONYNHA_MCP_PUBLIC_URL` | Public HTTPS MCP resource URL |
| `MONYNHA_MCP_OIDC_ISSUER` | Trusted external OIDC issuer |
| `MONYNHA_MCP_OIDC_AUDIENCE` | Must equal public URL |
| `MONYNHA_MCP_OIDC_JWKS_URL` | Issuer's HTTPS signing keys |
| `MONYNHA_MCP_HTTP_HOST` | Interface behind reverse proxy, normally `0.0.0.0` |
| `MONYNHA_MCP_ALLOWED_ORIGINS` | Optional JSON array of trusted browser HTTPS origins |
| `MONYNHA_MCP_MAX_RESPONSE_BYTES` | Maximum Odoo response, default 2 MiB |
| `MONYNHA_MCP_CALLS_PER_MINUTE` | Per principal/connection/operation budget, default 60 |
| `MONYNHA_MCP_MAX_CONCURRENT_PER_CONNECTION` | Per-connection in-process limit, default 4 |
| `MONYNHA_ODOO_KEY_<NAME>` | Secret value referenced by each connection |

Before the first launch, run migrations with the same database URL:

```bash
uv run --locked alembic upgrade head
```

Create an organization, principal, membership, connection and read grant
from an administrative shell:

```bash
uv run --locked monynha-odoo-admin organization add --id my-org
uv run --locked monynha-odoo-admin principal add --id oidc-subject
uv run --locked monynha-odoo-admin membership grant --principal oidc-subject --org my-org
uv run --locked monynha-odoo-admin connection add --id my-odoo --org my-org --url https://odoo.example.com --secret-ref env:MONYNHA_ODOO_KEY_LOCAL
uv run --locked monynha-odoo-admin policy grant --principal oidc-subject --connection my-odoo --operation read --model res.partner
uv run --locked monynha-odoo-admin connection test --id my-odoo --principal oidc-subject
```

The CLI stores a *reference* to the API key. Supply its value separately
through an approved secret source. The OIDC token subject must match the
registered principal. Grants for `create` and `update` require deliberate
administrative commands; deletion and nested relational write commands are
unavailable. Non-idempotent writes persist an audit intent before dispatch.
If an Odoo write times out, check its records before retrying.

Run the service only behind HTTPS reverse proxy:

```bash
uv run --locked monynha-odoo-mcp
```

- MCP endpoint: `/mcp`
- OAuth resource metadata: `/.well-known/oauth-protected-resource/mcp`
- Liveness/readiness: `/healthz`, `/readyz`

For a containerized starting point, see `Dockerfile` and
`docker-compose.example.yml`. Apply migrations as a separate deployment
step and inject all secrets through Coolify, Vault or your platform's secret
manager. The rate limiter is in-process: run a single application worker or
enforce shared limits at the reverse proxy/API gateway when scaling to multiple
replicas. Configure browser origins only for clients you trust; that setting
does not replace OIDC authentication.

For Coolify production deployment, use **`docker-compose.coolify.yml`**
instead of the integrated database example. It runs Alembic before starting,
expects a separately managed private PostgreSQL database and delegates HTTPS
domain routing to Coolify without publishing a host port. Follow the
[Coolify deployment guide](docs/deployment/coolify.md) before deploying.

## Architecture, limits and security

- [Architecture design](docs/superpowers/specs/2026-10-27-monynha-odoo-mcp-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-27-monynha-odoo-mcp-v01.md)
- [Threat model and security notes](docs/security.md)
- [Odoo 19 JSON-2 documentation](https://www.odoo.com/documentation/19.0/developer/reference/external_api.html)
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

This project is an independent behavioral implementation. It does not use
private code from third-party MCP services.
