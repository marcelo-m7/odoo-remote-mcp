"""Resolve allowlisted secret references at the last possible moment."""

import os
import re
from typing import Protocol

from monynha_odoo_mcp.core.errors import McpError


class SecretResolver(Protocol):
    def resolve(self, ref: str) -> str: ...


class EnvSecretResolver:
    def __init__(self, prefix: str = "MONYNHA_ODOO_KEY_") -> None:
        self.prefix = prefix

    def resolve(self, ref: str) -> str:
        if not ref.startswith("env:"):
            raise McpError("secret_unavailable", "Credential reference is unavailable")
        name = ref[4:]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or not name.startswith(self.prefix):
            raise McpError("secret_unavailable", "Credential reference is unavailable")
        value = os.environ.get(name)
        if not value:
            raise McpError("secret_unavailable", "Credential reference is unavailable")
        return value
