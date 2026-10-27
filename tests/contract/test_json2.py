import httpx
import pytest

from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.odoo.json2 import Json2Adapter
from monynha_odoo_mcp.secrets import EnvSecretResolver


@pytest.fixture
def connection():
    return OdooConnection(
        id="connection-1",
        base_url="https://odoo.example.org/",
        database="sandbox",
        secret_ref="env:MONYNHA_ODOO_KEY_TEST",
    )


@pytest.fixture
def resolver(monkeypatch):
    monkeypatch.setenv("MONYNHA_ODOO_KEY_TEST", "super-private-api-key")
    return EnvSecretResolver()


@pytest.mark.asyncio
async def test_json2_search_read_path_and_headers(connection, resolver):
    observed = {}

    def handler(request):
        observed["url"] = str(request.url)
        observed["headers"] = dict(request.headers)
        observed["json"] = __import__("json").loads(request.content)
        return httpx.Response(200, json=[{"id": 13, "name": "Example"}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = Json2Adapter(client, resolver)
        rows = await adapter.call(
            connection,
            "res.partner",
            "search_read",
            {"domain": [["name", "ilike", "Exam"]], "fields": ["name"], "limit": 20},
        )

    assert rows == [{"id": 13, "name": "Example"}]
    assert observed["url"] == "https://odoo.example.org/json/2/res.partner/search_read"
    assert observed["headers"]["authorization"] == "bearer super-private-api-key"
    assert observed["headers"]["x-odoo-database"] == "sandbox"
    assert observed["json"] == {
        "domain": [["name", "ilike", "Exam"]],
        "fields": ["name"],
        "limit": 20,
    }


@pytest.mark.asyncio
async def test_json2_named_args_only(connection, resolver):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[]))
    ) as client:
        adapter = Json2Adapter(client, resolver)
        with pytest.raises(McpError) as exc:
            await adapter.call(connection, "res.partner", "search_read", {"args": []})
    assert exc.value.code == "invalid_arguments"


@pytest.mark.asyncio
async def test_create_not_retried_after_timeout(connection, resolver):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("read failed", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = Json2Adapter(client, resolver)
        with pytest.raises(McpError) as exc:
            await adapter.call(
                connection, "res.partner", "create", {"vals_list": [{"name": "Jane"}]}
            )
    assert exc.value.code == "odoo_timeout"
    assert calls == 1


@pytest.mark.asyncio
async def test_odoo_error_is_redacted(connection, resolver):
    response = {
        "name": "odoo.exceptions.AccessError",
        "message": "super-private-api-key denied",
        "debug": "Traceback with PII and super-private-api-key",
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500, json=response))
    ) as client:
        adapter = Json2Adapter(client, resolver)
        with pytest.raises(McpError) as exc:
            await adapter.call(connection, "res.partner", "search_read", {"domain": []})
    assert exc.value.code == "odoo_error"
    assert "super-private-api-key" not in str(exc.value.public())
    assert "Traceback" not in str(exc.value.public())


@pytest.mark.asyncio
@pytest.mark.parametrize("status,code", [(401, "odoo_unauthorized"), (403, "odoo_forbidden")])
async def test_401_and_403_typed(connection, resolver, status, code):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json={"message": "key"}))
    ) as client:
        with pytest.raises(McpError) as exc:
            await Json2Adapter(client, resolver).call(
                connection, "res.partner", "read", {"ids": [1]}
            )
    assert exc.value.code == code


def test_secret_ref_resolver_rejects_unapproved_env_name(monkeypatch):
    monkeypatch.setenv("OTHER_KEY", "do-not-expose")
    with pytest.raises(McpError) as exc:
        EnvSecretResolver().resolve("env:OTHER_KEY")
    assert exc.value.code == "secret_unavailable"


@pytest.mark.asyncio
async def test_json2_stops_streaming_at_response_size_limit(connection, resolver):
    def handler(_request):
        return httpx.Response(200, content=b'"' + b"x" * 2000 + b'"')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = Json2Adapter(client, resolver, max_response_bytes=1024)
        with pytest.raises(McpError) as exc:
            await adapter.call(connection, "res.partner", "read", {"ids": [1]})
    assert exc.value.code == "odoo_response_too_large"
