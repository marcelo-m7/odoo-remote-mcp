"""Protocol for backend-agnostic Odoo calls."""

from collections.abc import Mapping
from typing import Any, Protocol

from monynha_odoo_mcp.connections.models import OdooConnection


class OdooAdapter(Protocol):
    async def call(
        self, connection: OdooConnection, model: str, method: str, payload: Mapping[str, Any]
    ) -> Any: ...
