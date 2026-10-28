import pytest
from pydantic import ValidationError

from monynha_odoo_mcp.settings import Settings


def test_http_requires_database_and_oidc():
    with pytest.raises(ValidationError):
        Settings(mode="http", _env_file=None)


def test_stdio_allows_local_dev_without_http_auth():
    settings = Settings(mode="stdio", _env_file=None)
    assert settings.mode == "stdio"
    assert settings.database_url is None


def test_settings_never_repr_secrets():
    with pytest.raises(ValidationError):
        Settings(mode="stdio", odoo_api_key="secret-that-must-not-appear", _env_file=None)


def test_supabase_provider_cannot_start_without_admitted_oauth_client():
    with pytest.raises(ValidationError, match="OAuth client"):
        Settings(
            mode="http",
            database_url="postgresql+psycopg://localhost/example",
            oidc_issuer="https://id.example",
            oidc_audience="https://mcp.example/mcp",
            oidc_jwks_url="https://id.example/jwks",
            public_url="https://mcp.example/mcp",
            oauth_provider="supabase",
            _env_file=None,
        )


def test_remote_and_local_writes_are_disabled_by_default():
    assert Settings(mode="stdio", _env_file=None).writes_enabled is False
