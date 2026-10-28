import pytest

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.store import ConnectionRegistry, StoredConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.engine import Policy, PolicyEngine
from monynha_odoo_mcp.policy.ssrf import (
    GuardedNetworkBackend,
    OutboundGuard,
    guarded_http_client,
)


def setup_registry():
    policy = PolicyEngine(
        [
            Policy(
                principal_id="alice",
                connection_id="a",
                operations=frozenset({"read", "create", "update"}),
                models=frozenset({"res.partner"}),
            )
        ]
    )
    registry = ConnectionRegistry(policy)
    registry.add(
        StoredConnection(
            connection=OdooConnection("a", "https://a.example", None, "env:MONYNHA_ODOO_KEY_A"),
            organization_id="org-a",
        )
    )
    registry.add(
        StoredConnection(
            connection=OdooConnection("b", "https://b.example", None, "env:MONYNHA_ODOO_KEY_B"),
            organization_id="org-b",
        )
    )
    registry.grant_membership("alice", "org-a")
    return registry


def test_cross_tenant_connection_denied():
    registry = setup_registry()
    with pytest.raises(McpError) as exc:
        registry.get_for_principal(Principal("alice"), "b", "read", "res.partner")
    assert exc.value.code == "access_denied"
    assert [conn.id for conn in registry.list_for_principal(Principal("alice"))] == ["a"]


def test_membership_without_explicit_connection_policy_never_lists_connection():
    # Breaks if membership is accidentally treated as a connection capability.
    registry = ConnectionRegistry(PolicyEngine([]))
    registry.add(
        StoredConnection(
            OdooConnection("hidden", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_A"),
            "org-a",
        )
    )
    registry.grant_membership("alice", "org-a")
    assert registry.list_for_principal(Principal("alice")) == []


def test_unlisted_model_denied():
    registry = setup_registry()
    with pytest.raises(McpError) as exc:
        registry.get_for_principal(Principal("alice"), "a", "read", "account.move")
    assert exc.value.code == "access_denied"


def test_delete_always_denied():
    registry = setup_registry()
    with pytest.raises(McpError) as exc:
        registry.get_for_principal(Principal("alice"), "a", "delete", "res.partner")
    assert exc.value.code == "access_denied"


@pytest.mark.parametrize(
    "url",
    [
        "http://odoo.example",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://user:password@odoo.example",
        "https://odoo.example@127.0.0.1",
    ],
)
def test_private_and_rebinding_targets_denied(url):
    guard = OutboundGuard(resolver=lambda host: ["1.1.1.1"])
    with pytest.raises(McpError) as exc:
        guard.validate_target(url)
    assert exc.value.code == "unsafe_target"


def test_rebinding_peer_rejected_after_public_resolution():
    guard = OutboundGuard(resolver=lambda host: ["1.1.1.1"])
    guard.validate_target("https://safe.example")
    with pytest.raises(McpError) as exc:
        guard.validate_resolved_peer("safe.example", "127.0.0.1")
    assert exc.value.code == "unsafe_target"
    with pytest.raises(McpError):
        guard.validate_resolved_peer("safe.example", "8.8.8.8")
    guard.validate_resolved_peer("safe.example", "1.1.1.1")


def test_dns_private_result_denied():
    guard = OutboundGuard(resolver=lambda host: ["172.16.0.10"])
    with pytest.raises(McpError):
        guard.validate_target("https://odoo.example")


@pytest.mark.asyncio
async def test_guarded_network_backend_pins_public_ip():
    class RecorderBackend:
        connected_host = None

        async def connect_tcp(self, host, port, **kwargs):
            self.connected_host = host
            return object()

    recorder = RecorderBackend()
    backend = GuardedNetworkBackend(
        OutboundGuard(resolver=lambda host: ["1.1.1.1"]),
        network_backend=recorder,
    )
    await backend.connect_tcp("safe.example", 443)
    assert recorder.connected_host == "1.1.1.1"


@pytest.mark.asyncio
async def test_guarded_network_backend_rejects_private_before_socket():
    class RecorderBackend:
        connected = False

        async def connect_tcp(self, host, port, **kwargs):
            self.connected = True
            return object()

    recorder = RecorderBackend()
    backend = GuardedNetworkBackend(
        OutboundGuard(resolver=lambda host: ["169.254.169.254"]),
        network_backend=recorder,
    )
    with pytest.raises(McpError):
        await backend.connect_tcp("unsafe.example", 443)
    assert recorder.connected is False


@pytest.mark.asyncio
async def test_httpx_transport_rejects_private_target_before_network_io():
    async with guarded_http_client() as client:
        with pytest.raises(McpError) as exc:
            await client.post("https://127.0.0.1/json/2/res.partner/search_read", json={})
    assert exc.value.code == "unsafe_target"
