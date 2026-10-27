"""Configuration which rejects an unsafe remote startup."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MONYNHA_MCP_", extra="forbid")

    mode: Literal["http", "stdio"] = "stdio"
    database_url: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: HttpUrl | None = None
    public_url: HttpUrl | None = None
    local_principal_id: str | None = None
    local_connection_id: str | None = None
    local_odoo_url: HttpUrl | None = None
    local_secret_ref: str | None = None
    secret_prefix: str = "MONYNHA_ODOO_KEY_"
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    timeout_seconds: float = 20.0
    max_results: int = 100
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 2_097_152
    calls_per_minute: int = 60
    max_concurrent_per_connection: int = 4
    allowed_origins: list[str] = []

    @model_validator(mode="after")
    def remote_requires_security_configuration(self) -> "Settings":
        if self.mode == "http" and not all(
            (
                self.database_url,
                self.oidc_issuer,
                self.oidc_audience,
                self.oidc_jwks_url,
                self.public_url,
            )
        ):
            raise ValueError("HTTP mode requires database and OIDC configuration")
        if self.http_port < 1 or self.http_port > 65535:
            raise ValueError("invalid HTTP port")
        if (
            self.timeout_seconds <= 0
            or self.max_results < 1
            or self.max_request_bytes < 1
            or self.max_response_bytes < 1
            or self.calls_per_minute < 1
            or self.max_concurrent_per_connection < 1
        ):
            raise ValueError("limits must be positive")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "*" in origin
            ):
                raise ValueError("allowed_origins must be exact HTTPS origins")
        return self
