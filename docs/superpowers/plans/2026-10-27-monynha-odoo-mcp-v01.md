# Monynha Odoo MCP v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar um servidor MCP remoto autenticado e uma entrada local `stdio`, com conexões Odoo 19 JSON-2 segregadas, descoberta, leitura, escrita controlada, auditoria e testes verificáveis.

**Architecture:** O núcleo de ferramentas depende de serviços tipados para policy, registry, audit e `OdooAdapter`, nunca do transporte MCP. O modo remoto valida identidade OIDC e resolve organização/conexão por membership persistida. O modo local reusa o mesmo núcleo com principal explícito configurado para o processo.

**Tech Stack:** Python 3.12+, SDK oficial MCP, Pydantic v2, HTTPX, PyJWT/cryptography ou equivalente para JWT/JWKS, PostgreSQL, SQLAlchemy, Alembic, pytest, Docker/ASGI, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-27-monynha-odoo-mcp-design.md`

## Global Constraints

- Odoo 19 usa `POST /json/2/<model>/<method>`, Bearer API key e `X-Odoo-Database` opcional; cada chamada é uma transação independente.
- Remoto-first **não significa HTTP aberto**: sem OIDC/audience/scope válidos, nenhuma ferramenta ou metadata privada pode ser acedida.
- Nunca escrever/ler chaves Odoo em ficheiros Git, base de dados em claro, logs ou respostas MCP; só referências a secrets.
- Todas as operações exigem `connection_id` autorizado; nenhuma conexão “ativa” global compartilhada.
- `record_delete`, métodos arbitrários, importação e ações de negócio ficam indisponíveis na v0.1.
- Testes de integração Odoo apenas em ambiente descartável/staging com autorização explícita; CI sem produção.
- Rejeitar URL interna/privada por padrão, redirecionamentos e DNS rebinding; futura allowlist de infraestrutura é alteração separada.
- O repositório continua MIT; código próprio sem copiar implementação privada do MCP 2.

## File map

```text
pyproject.toml
src/monynha_odoo_mcp/
  __init__.py
  settings.py                      # configuração tipada/fail-closed
  core/{errors,contracts}.py       # contratos e erros estáveis
  odoo/{adapter,json2}.py          # interface, chamadas HTTP, schema
  connections/{models,store}.py    # conexão/organização/membership
  secrets.py                       # resolução de referências a secrets
  policy/{engine,ssrf}.py          # ACL por operação/modelo + saída HTTP
  tools/{service,registry}.py      # casos de uso e registro MCP
  auth/{oidc,principal}.py         # JWT/JWKS, audience, scope
  audit/{models,store}.py          # eventos redigidos e append-only
  storage/{db,migrations/}.py      # PostgreSQL e migrações
  admin.py                         # CLI administrativa
  server.py                        # ASGI/MCP Streamable HTTP e stdio
tests/{unit,contract,integration}/
Dockerfile
docker-compose.example.yml
.github/workflows/ci.yml
README.md
docs/security.md
```

## Review Focus

1. **Troca de organização/conexão por argumento malicioso:** `test_cross_tenant_connection_denied` em Task 3.
2. **URL de Odoo aponta para localhost/metadata/IP privado ou DNS muda:** `test_private_and_rebinding_targets_denied` em Task 3.
3. **JWT com assinatura correta mas audience/issuer/scope errados:** `test_wrong_audience_issuer_scope_rejected` em Task 6.
4. **Timeout/retry de POST que cria duplicados:** `test_create_not_retried_after_timeout` em Task 2.
5. **Erro Odoo contém traceback/API key ou valores sensíveis:** `test_odoo_error_is_redacted` em Task 2 e `test_audit_redacts_secrets` em Task 5.

---

### Task 1: Project foundation and validated configuration

**Files:** Create `pyproject.toml`, `src/monynha_odoo_mcp/__init__.py`, `settings.py`, `core/errors.py`, `core/contracts.py`, `tests/unit/test_settings.py`.

**Interfaces:**
- Produces `Settings(BaseSettings)` com `mode: Literal["http", "stdio"]`, `database_url: str | None`, `oidc_issuer: str | None`, `oidc_audience: str | None`, `secret_prefix: str` e limites HTTP.
- Produces `McpError(code: str, message: str, correlation_id: str | None)` serializável sem dados sensíveis.

- [ ] **Step 1: Write failing tests** `test_http_requires_database_and_oidc`, `test_stdio_allows_local_dev_without_http_auth`, `test_settings_never_repr_secrets`. Assert HTTP sem issuer/audience/database falha antes de bind; stdio aceita config local sem expor segredo.
- [ ] **Step 2: Verify RED** — `pytest -q tests/unit/test_settings.py` deve falhar por símbolos ainda ausentes.
- [ ] **Step 3: Implement minimal packaging/settings/errors** com Python 3.12+ e entry points `monynha-odoo-mcp`, `monynha-odoo-admin`; pin compatível do SDK em lockfile na execução.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/unit/test_settings.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: bootstrap typed MCP configuration"`.

### Task 2: JSON-2 adapter and typed errors

**Files:** Create `odoo/adapter.py`, `odoo/json2.py`, `secrets.py`, `tests/contract/test_json2.py`.

**Interfaces:**
- Consumes `McpError`.
- Produces `OdooConnection(id: str, base_url: str, database: str | None, secret_ref: str)`.
- Produces `OdooAdapter.call(connection: OdooConnection, model: str, method: str, payload: Mapping[str, Any]) -> Any`.
- Produces `Json2Adapter(httpx.AsyncClient, SecretResolver)` implementando `call`; `SecretResolver.resolve(ref: str) -> str` admite somente variáveis de ambiente explicitamente permitidas nesta fase.

- [ ] **Step 1: Write failing contract tests** `test_json2_search_read_path_and_headers` (Bearer e base opcional), `test_json2_named_args_only`, `test_create_not_retried_after_timeout`, `test_odoo_error_is_redacted`, `test_401_and_403_typed`; mock HTTPX e verificar não haver key em `repr`, erros ou logs.
- [ ] **Step 2: Verify RED** — `pytest -q tests/contract/test_json2.py`.
- [ ] **Step 3: Implement adapter** com URL composta internamente, timeouts, `follow_redirects=False`, limite de payload e *nenhum retry automático para writes*. Permitir retry limitado somente para operações de leitura explicitamente classificadas.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/contract/test_json2.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: add secure Odoo 19 JSON-2 adapter"`.

### Task 3: Connection registry, tenancy and outbound target policy

**Files:** Create `connections/models.py`, `connections/store.py`, `policy/engine.py`, `policy/ssrf.py`, `tests/unit/test_connections_policy.py`.

**Interfaces:**
- Consumes `OdooConnection`.
- Produces `Principal(id: str)` e `ConnectionRegistry.get_for_principal(principal: Principal, connection_id: str, operation: str, model: str | None) -> OdooConnection`.
- Produces `OutboundGuard.validate_target(url: str) -> None` e `validate_resolved_peer(host, ip) -> None` com bloqueio IPv4/v6 não públicos; o transporte aplica DNS/IP validado na conexão efetiva.
- Produces `PolicyEngine.authorize(principal, connection_id, operation, model) -> None` com deny-by-default.

- [ ] **Step 1: Write failing tests** `test_cross_tenant_connection_denied`, `test_unlisted_model_denied`, `test_private_and_rebinding_targets_denied`, `test_delete_always_denied`; testar principal da org A contra conexão B mesmo com ID conhecido.
- [ ] **Step 2: Verify RED** — `pytest -q tests/unit/test_connections_policy.py`.
- [ ] **Step 3: Implement registry e guard**; não confiar em `organization_id` de payload MCP, não resolver conexões por índice global; conexão HTTP precisa usar pinning/transport que valide IP final.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/unit/test_connections_policy.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: isolate Odoo connections with explicit policies"`.

### Task 4: ORM service and MCP tool contracts

**Files:** Create `tools/service.py`, `tools/registry.py`, `tests/unit/test_tools.py`, `tests/contract/test_mcp_tools.py`.

**Interfaces:**
- Consumes `OdooAdapter`, `ConnectionRegistry`, `PolicyEngine`, `Principal`.
- Produces `OdooToolService` com métodos assíncronos: `server_info_get`, `connection_list`, `connection_test`, `model_list`, `model_fields_get`, `record_get`, `record_search`, `record_count`, `record_aggregate`, `record_create`, `record_update`.
- Produces `register_tools(mcp_server, service_factory)` cujos contratos Pydantic expõem `connection_id`, limites de paginação, campos e domínios válidos.

- [ ] **Step 1: Write failing tests** `test_search_uses_search_read_and_pages`, `test_grouping_checks_capabilities`, `test_update_requires_policy`, `test_no_delete_or_method_execute_exposed`, `test_mcp_schema_has_connection_id`; verificar que resultados e erros têm formatos estruturados e limites estáveis.
- [ ] **Step 2: Verify RED** — `pytest -q tests/unit/test_tools.py tests/contract/test_mcp_tools.py`.
- [ ] **Step 3: Implement service + registry**; distinguir ferramentas de administração das ferramentas disponíveis para agentes; não aceitar identificadores de conexão escolhidos fora do ACL.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/unit/test_tools.py tests/contract/test_mcp_tools.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: expose policy-checked Odoo ORM tools"`.

### Task 5: Persistent metadata, secret references, audit and admin CLI

**Files:** Create `storage/db.py`, `storage/migrations/`, `audit/models.py`, `audit/store.py`, `admin.py`, `tests/unit/test_admin_audit.py`, `tests/integration/test_storage.py`.

**Interfaces:**
- Consumes `ConnectionRegistry`, `PolicyEngine`, `OdooConnection`.
- Produces `SqlConnectionStore`, `AuditStore.append(event: AuditEvent) -> None` e comandos CLI `connection add/list/test`, `policy grant/revoke`, `principal add` (somente execução administrativa local).
- Separa `secret_ref` de `secret_value`: nunca persistir API key em texto claro.

- [ ] **Step 1: Write failing tests** `test_database_has_tenant_constraints`, `test_secret_values_not_persisted`, `test_audit_redacts_secrets`, `test_cli_rejects_unsafe_url`, `test_connection_roundtrip`.
- [ ] **Step 2: Verify RED** — `pytest -q tests/unit/test_admin_audit.py tests/integration/test_storage.py`.
- [ ] **Step 3: Implement SQLAlchemy/Alembic e CLI**; audit append-only, migrations versionadas, nenhuma aprovação de delete. Testes PostgreSQL via container opcional na CI, com skip explícito quando indisponível localmente.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/unit/test_admin_audit.py tests/integration/test_storage.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: persist tenant metadata and redacted audit events"`.

### Task 6: OIDC protected remote MCP and local stdio

**Files:** Create `auth/oidc.py`, `auth/principal.py`, `server.py`, `tests/contract/test_remote_auth.py`, `tests/integration/test_transport.py`.

**Interfaces:**
- Consumes `Settings`, `Principal`, `OdooToolService`, `SqlConnectionStore`.
- Produces `verify_bearer_token(token: str, jwks, issuer: str, audience: str, required_scopes: set[str]) -> Principal`.
- Produces `create_http_app(settings: Settings) -> ASGIApp` com Streamable HTTP e Protected Resource Metadata, e `run_stdio(settings: Settings)`.

- [ ] **Step 1: Write failing tests** `test_unauthorized_http_never_reaches_tools`, `test_wrong_audience_issuer_scope_rejected`, `test_jwks_rotation_supported`, `test_protected_resource_metadata`, `test_stdio_uses_local_principal`, `test_http_denies_missing_config`.
- [ ] **Step 2: Verify RED** — `pytest -q tests/contract/test_remote_auth.py tests/integration/test_transport.py`.
- [ ] **Step 3: Implement remoto-first** com OIDC externo, assinatura e claims validados, cache JWKS com limite, troca de key via `kid`, TLS no reverse proxy e sem tokens Odoo nas chamadas MCP. Selecionar SDK MCP pin compatível e verificar rotas reais `/mcp` e metadata.
- [ ] **Step 4: Verify GREEN** — `pytest -q tests/contract/test_remote_auth.py tests/integration/test_transport.py`.
- [ ] **Step 5: Commit** — `git commit -m "feat: authenticate Streamable HTTP and stdio MCP clients"`.

### Task 7: Packaging, CI, operational docs and end-to-end verification

**Files:** Create `Dockerfile`, `docker-compose.example.yml`, `.github/workflows/ci.yml`, `docs/security.md`; expand `README.md`; add `tests/integration/test_e2e_mcp.py`.

**Interfaces:**
- Consumes todas as interfaces acima.
- Produces imagem Docker e comandos reproduzíveis para health check, migrações, CLI e transporte MCP.

- [ ] **Step 1: Write failing E2E test** `test_authenticated_client_lists_tools_and_searches_mock_odoo`, `test_two_orgs_no_cross_access`, `test_no_prod_credentials_required`; usar ASGI test client e mock Odoo, sem rede pública.
- [ ] **Step 2: Verify RED** — `pytest -q tests/integration/test_e2e_mcp.py`.
- [ ] **Step 3: Implement deployment files e docs** com exemplo de env usando apenas placeholders, CI lint/typecheck/tests, SBOM/secret scan se a plataforma permitir, health/readiness e guia Coolify não prescritivo.
- [ ] **Step 4: Verify GREEN** — `ruff check .`, `pytest -q`, `python -m build`, `docker build .` quando Docker disponível; registar indisponibilidade honestamente.
- [ ] **Step 5: Commit** — `git commit -m "build: validate and package secure Monynha MCP v0.1"`.

## Self-review e gates

- **Cobertura:** todas as capacidades da v0.1 da especificação têm tarefa; workflows, XML-RPC legado, wizards, SaaS e UI permanecem pós-v0.1.
- **Testes:** cada risco prioritário da secção Review Focus está associado a um caso nominal.
- **Segurança:** não publicar MCP HTTP antes de Task 6; não usar FACODI/Boa Vista como fixtures de CI.
- **Branch:** implementar em branch separada a partir da especificação aprovada; abrir PR de código como draft, sem merge automático.
- **Gate de entrega:** executar testes unit/contract/E2E, rever resultados, reportar limitações e pedir revisão final antes de merge.
