"""Typed MCP tool surface; no arbitrary method execution or deletion."""

from collections.abc import Callable
from typing import Any

from mcp.server import MCPServer

from monynha_odoo_mcp.tools.service import OdooToolService


def register_tools(mcp_server: MCPServer, service_factory: Callable[[], OdooToolService]) -> None:
    @mcp_server.tool(name="server_info_get")
    async def server_info_get() -> dict:
        """Show supported backend and version."""
        return (await service_factory().server_info_get()).model_dump()

    @mcp_server.tool(name="connection_list")
    async def connection_list() -> dict:
        """List connections accessible to the authenticated client."""
        return (await service_factory().connection_list()).model_dump()

    @mcp_server.tool(name="connection_test")
    async def connection_test(connection_id: str) -> dict:
        """Check connectivity to an authorized Odoo instance."""
        return (await service_factory().connection_test(connection_id)).model_dump()

    @mcp_server.tool(name="model_list")
    async def model_list(
        connection_id: str, domain: list[Any] | None = None, limit: int = 50
    ) -> dict:
        """Find Odoo models available to this connection."""
        return (await service_factory().model_list(connection_id, domain, limit)).model_dump()

    @mcp_server.tool(name="model_fields_get")
    async def model_fields_get(connection_id: str, model: str) -> dict:
        """Read accessible field definitions of one model."""
        return (await service_factory().model_fields_get(connection_id, model)).model_dump()

    @mcp_server.tool(name="record_get")
    async def record_get(
        connection_id: str, model: str, ids: list[int], fields: list[str] | None = None
    ) -> dict:
        """Read selected Odoo record IDs."""
        return (await service_factory().record_get(connection_id, model, ids, fields)).model_dump()

    @mcp_server.tool(name="record_search")
    async def record_search(
        connection_id: str,
        model: str,
        domain: list[Any] | None = None,
        fields: list[str] | None = None,
        offset: int = 0,
        limit: int = 20,
        order: str | None = None,
    ) -> dict:
        """Search records by Odoo domain and page through the results."""
        return (
            await service_factory().record_search(
                connection_id, model, domain, fields, offset, limit, order
            )
        ).model_dump()

    @mcp_server.tool(name="record_count")
    async def record_count(connection_id: str, model: str, domain: list[Any] | None = None) -> dict:
        """Count Odoo records matching a domain."""
        return (await service_factory().record_count(connection_id, model, domain)).model_dump()

    @mcp_server.tool(name="record_aggregate")
    async def record_aggregate(
        connection_id: str,
        model: str,
        domain: list[Any],
        fields: list[str],
        groupby: list[str],
        offset: int = 0,
        limit: int = 20,
    ) -> dict:
        """Read grouped aggregates via the Odoo ORM."""
        return (
            await service_factory().record_aggregate(
                connection_id, model, domain, fields, groupby, offset, limit
            )
        ).model_dump()

    @mcp_server.tool(name="record_create")
    async def record_create(connection_id: str, model: str, values: dict[str, Any]) -> dict:
        """Create a record only when the connection policy allows it."""
        return (await service_factory().record_create(connection_id, model, values)).model_dump()

    @mcp_server.tool(name="record_update")
    async def record_update(
        connection_id: str, model: str, ids: list[int], values: dict[str, Any]
    ) -> dict:
        """Update records only when the connection policy allows it."""
        return (
            await service_factory().record_update(connection_id, model, ids, values)
        ).model_dump()
