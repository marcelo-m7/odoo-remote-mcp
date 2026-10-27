import pytest
from mcp.server import MCPServer

from monynha_odoo_mcp.tools.registry import register_tools


@pytest.mark.asyncio
async def test_mcp_schema_has_connection_id():
    mcp = MCPServer("Monynha")
    register_tools(mcp, lambda: None)
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert "record_search" in tools
    assert "connection_id" in tools["record_search"].input_schema["required"]
    assert "model" in tools["record_search"].input_schema["required"]


@pytest.mark.asyncio
async def test_no_delete_or_method_execute_exposed():
    mcp = MCPServer("Monynha")
    register_tools(mcp, lambda: None)
    names = {tool.name for tool in await mcp.list_tools()}
    assert "record_delete" not in names
    assert "method_execute" not in names
    assert {"record_create", "record_update", "model_list", "record_aggregate"} <= names
