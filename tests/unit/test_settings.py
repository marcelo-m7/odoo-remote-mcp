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
