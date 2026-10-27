"""Odoo 19 JSON-2 calls with fail-closed errors and no automatic write retry."""

import json
import re
from collections.abc import Mapping
from typing import Any

import httpx

from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.secrets import SecretResolver

_MODEL_RE = re.compile(r"[a-z_][a-z0-9_.]*\Z")
_METHOD_RE = re.compile(r"[a-z_][a-z0-9_]*\Z")


class Json2Adapter:
    def __init__(
        self,
        client: httpx.AsyncClient,
        secrets: SecretResolver,
        *,
        timeout: float = 20,
        max_response_bytes: int = 2_097_152,
    ) -> None:
        self.client = client
        self.secrets = secrets
        self.timeout = timeout
        if max_response_bytes < 1:
            raise ValueError("Maximum response size must be positive")
        self.max_response_bytes = max_response_bytes

    async def call(
        self, connection: OdooConnection, model: str, method: str, payload: Mapping[str, Any]
    ) -> Any:
        if not _MODEL_RE.fullmatch(model) or not _METHOD_RE.fullmatch(method):
            raise McpError("invalid_arguments", "Invalid Odoo model or method")
        if (
            not isinstance(payload, Mapping)
            or "args" in payload
            or any(not isinstance(key, str) for key in payload)
        ):
            raise McpError("invalid_arguments", "Odoo JSON-2 requires named arguments")
        base = connection.base_url.rstrip("/")
        url = f"{base}/json/2/{model}/{method}"
        headers = {
            "Authorization": f"bearer {self.secrets.resolve(connection.secret_ref)}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "monynha-odoo-mcp/0.1",
        }
        if connection.database:
            headers["X-Odoo-Database"] = connection.database
        try:
            async with self.client.stream(
                "POST",
                url,
                headers=headers,
                json=dict(payload),
                timeout=self.timeout,
                follow_redirects=False,
            ) as response:
                if response.status_code == 401:
                    raise McpError("odoo_unauthorized", "Odoo API credential was rejected")
                if response.status_code == 403:
                    raise McpError("odoo_forbidden", "Odoo denied the requested operation")
                if not 200 <= response.status_code < 300:
                    raise McpError("odoo_error", "Odoo operation failed")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.max_response_bytes:
                        raise McpError(
                            "odoo_response_too_large", "Odoo response exceeds safety limit"
                        )
        except httpx.TimeoutException:
            raise McpError("odoo_timeout", "Odoo did not respond in time") from None
        except httpx.RequestError:
            raise McpError("odoo_unavailable", "Could not connect to Odoo") from None
        try:
            return json.loads(body)
        except ValueError:
            raise McpError("odoo_error", "Odoo returned an invalid response") from None
