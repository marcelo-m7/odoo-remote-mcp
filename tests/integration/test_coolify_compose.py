"""Guard the Compose boundary Coolify will load from Git."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _coolify_stack():
    with (ROOT / "docker-compose.coolify.yml").open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def test_coolify_exposes_only_mcp_through_its_reverse_proxy():
    services = _coolify_stack()["services"]
    assert set(services) == {"mcp"}
    mcp = services["mcp"]
    assert mcp["build"]["dockerfile"] == "Dockerfile"
    assert "ports" not in mcp
    assert "8000" in mcp["expose"]
    assert mcp["environment"]["MONYNHA_MCP_HTTP_HOST"] == "0.0.0.0"


def test_coolify_requires_external_postgres_oidc_and_runs_migrations_before_start():
    mcp = _coolify_stack()["services"]["mcp"]
    env = mcp["environment"]
    for key in (
        "MONYNHA_MCP_DATABASE_URL",
        "MONYNHA_MCP_PUBLIC_URL",
        "MONYNHA_MCP_OIDC_ISSUER",
        "MONYNHA_MCP_OIDC_JWKS_URL",
    ):
        assert env[key].startswith("${") and ":?" in env[key]
    assert env["MONYNHA_MCP_OIDC_AUDIENCE"] == env["MONYNHA_MCP_PUBLIC_URL"]
    command = " ".join(mcp["command"])
    assert command.index("alembic upgrade head") < command.index("exec monynha-odoo-mcp")


def test_coolify_forwards_oauth_mode_client_allowlist_and_write_gate():
    """Without explicit Coolify variables, the gateway must stay generic/read-only."""
    env = _coolify_stack()["services"]["mcp"]["environment"]

    assert env["MONYNHA_MCP_OAUTH_PROVIDER"] == "${MONYNHA_MCP_OAUTH_PROVIDER:-generic}"
    assert env["MONYNHA_MCP_OAUTH_ALLOWED_CLIENT_IDS"] == (
        "${MONYNHA_MCP_OAUTH_ALLOWED_CLIENT_IDS:-[]}"
    )
    assert env["MONYNHA_MCP_WRITES_ENABLED"] == "${MONYNHA_MCP_WRITES_ENABLED:-false}"


def test_coolify_health_checks_readiness_and_confines_runtime():
    mcp = _coolify_stack()["services"]["mcp"]
    assert "/readyz" in " ".join(mcp["healthcheck"]["test"])
    assert mcp["read_only"] is True
    assert "ALL" in mcp["cap_drop"]
    assert "no-new-privileges:true" in mcp["security_opt"]
    assert mcp["restart"] == "unless-stopped"
