import pytest

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.store import ConnectionRegistry, StoredConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.engine import Policy, PolicyEngine
from monynha_odoo_mcp.tools.service import OdooToolService


class FakeAdapter:
    def __init__(self):
        self.calls = []

    async def call(self, connection, model, method, payload):
        self.calls.append((connection.id, model, method, dict(payload)))
        if method == "search_read":
            return [{"id": 1, "name": "Record"}]
        if method == "read_group":
            return [{"category_id": [2, "Group"], "__count": 3}]
        return True


def make_service(
    operations=frozenset({"read", "create", "update"}), audit=None, writes_enabled=True
):
    policy = PolicyEngine(
        [Policy("alice", "odoo-a", operations, frozenset({"res.partner", "ir.model"}))]
    )
    registry = ConnectionRegistry(policy)
    registry.add(
        StoredConnection(
            OdooConnection("odoo-a", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_A"),
            "tenant-a",
        )
    )
    registry.grant_membership("alice", "tenant-a")
    adapter = FakeAdapter()
    return OdooToolService(
        adapter,
        registry,
        Principal("alice"),
        max_results=50,
        audit=audit,
        writes_enabled=writes_enabled,
    ), adapter


@pytest.mark.asyncio
async def test_search_uses_search_read_and_pages():
    service, adapter = make_service()
    result = await service.record_search(
        "odoo-a",
        "res.partner",
        domain=[["name", "ilike", "Test"]],
        fields=["name"],
        offset=10,
        limit=500,
        order="name asc",
    )
    assert result.data == [{"id": 1, "name": "Record"}]
    assert adapter.calls == [
        (
            "odoo-a",
            "res.partner",
            "search_read",
            {
                "domain": [["name", "ilike", "Test"]],
                "fields": ["name"],
                "offset": 10,
                "limit": 50,
                "order": "name asc",
            },
        )
    ]
    assert result.meta["limit"] == 50


@pytest.mark.asyncio
async def test_grouping_checks_capabilities():
    service, adapter = make_service(operations=frozenset({"create"}))
    with pytest.raises(McpError) as exc:
        await service.record_aggregate("odoo-a", "res.partner", [], ["id:count"], ["category_id"])
    assert exc.value.code == "access_denied"
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_update_requires_policy():
    service, adapter = make_service(operations=frozenset({"read"}))
    with pytest.raises(McpError):
        await service.record_update("odoo-a", "res.partner", [1], {"name": "Updated"})
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_connection_list_has_no_secret_reference():
    service, _ = make_service()
    result = await service.connection_list()
    assert result.data == [{"id": "odoo-a", "base_url": "https://odoo.example"}]
    assert "secret_ref" not in str(result.data)


@pytest.mark.asyncio
async def test_unbounded_read_is_clamped():
    service, adapter = make_service()
    await service.record_get("odoo-a", "res.partner", [1, 2, 3], fields=["name"])
    assert adapter.calls[-1][2] == "read"
    with pytest.raises(McpError) as exc:
        await service.record_get("odoo-a", "res.partner", list(range(55)))
    assert exc.value.code == "invalid_arguments"


@pytest.mark.asyncio
async def test_successful_read_emits_redacted_audit_event():
    class Recorder:
        events = []

        def append(self, event):
            self.events.append(event)

    audit = Recorder()
    service, _ = make_service(audit=audit)
    await service.record_search("odoo-a", "res.partner", [["name", "=", "Sensitive"]])
    assert len(audit.events) == 1
    assert audit.events[0].principal_id == "alice"
    assert audit.events[0].outcome == "success"
    assert "Sensitive" not in str(audit.events[0])


@pytest.mark.asyncio
async def test_denied_update_emits_audit_event():
    class Recorder:
        events = []

        def append(self, event):
            self.events.append(event)

    audit = Recorder()
    service, _ = make_service(operations=frozenset({"read"}), audit=audit)
    with pytest.raises(McpError):
        await service.record_update("odoo-a", "res.partner", [1], {"name": "Private"})
    assert audit.events[0].outcome == "denied"
    assert "Private" not in str(audit.events[0])


@pytest.mark.asyncio
async def test_audit_failure_after_confirmed_create_never_causes_false_failure():
    class FailingRecorder:
        events = []

        def append(self, event):
            if event.outcome == "success":
                raise OSError("database temporarily unavailable")
            self.events.append(event)

    audit = FailingRecorder()
    service, adapter = make_service(audit=audit)
    result = await service.record_create("odoo-a", "res.partner", {"name": "One"})
    assert len(adapter.calls) == 1
    assert audit.events[0].outcome == "started"
    assert result.meta["audit_status"] == "outcome_unknown"


@pytest.mark.asyncio
async def test_write_stops_before_odoo_if_audit_intent_cannot_be_recorded():
    class BrokenAudit:
        def append(self, _event):
            raise OSError("database unavailable")

    service, adapter = make_service(audit=BrokenAudit())
    with pytest.raises(McpError) as exc:
        await service.record_create("odoo-a", "res.partner", {"name": "One"})
    assert exc.value.code == "audit_unavailable"
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_read_defaults_to_small_field_projection():
    service, adapter = make_service()
    await service.record_get("odoo-a", "res.partner", [1])
    assert adapter.calls[-1][3]["fields"] == ["id", "display_name"]
    await service.record_search("odoo-a", "res.partner", domain=[])
    assert adapter.calls[-1][3]["fields"] == ["id", "display_name"]


@pytest.mark.asyncio
async def test_nested_odoo_relational_commands_cannot_bypass_no_delete_policy():
    service, adapter = make_service()
    with pytest.raises(McpError) as exc:
        await service.record_update("odoo-a", "res.partner", [1], {"child_ids": [[2, 4, 0]]})
    assert exc.value.code == "invalid_arguments"
    with pytest.raises(McpError):
        await service.record_create(
            "odoo-a", "res.partner", {"child_ids": [[0, 0, {"name": "Nested"}]]}
        )
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_connection_test_uses_an_authorized_model_not_fixed_partner():
    service, adapter = make_service()
    service.connections.policy.policies = [
        Policy("alice", "odoo-a", frozenset({"read"}), frozenset({"product.product"}))
    ]
    result = await service.connection_test("odoo-a")
    assert result.data == {"reachable": True}
    assert adapter.calls[-1][1:3] == ("product.product", "search_count")


@pytest.mark.asyncio
async def test_write_timeout_is_reported_as_uncertain_not_safe_to_retry():
    class TimeoutAdapter(FakeAdapter):
        async def call(self, connection, model, method, payload):
            self.calls.append((connection.id, model, method, dict(payload)))
            raise McpError("odoo_timeout", "Odoo timed out")

    class Recorder:
        def __init__(self):
            self.events = []

        def append(self, event):
            self.events.append(event)

    recorder = Recorder()
    service, _ = make_service(audit=recorder)
    service.adapter = TimeoutAdapter()
    with pytest.raises(McpError) as exc:
        await service.record_create("odoo-a", "res.partner", {"name": "Uncertain"})
    assert exc.value.code == "write_outcome_unknown"
    assert [event.outcome for event in recorder.events] == ["started", "outcome_unknown"]


@pytest.mark.asyncio
async def test_global_read_only_gate_rejects_legacy_create_and_update_permissions():
    class Recorder:
        def __init__(self):
            self.events = []

        def append(self, event):
            self.events.append(event)

    audit = Recorder()
    service, adapter = make_service(audit=audit, writes_enabled=False)
    with pytest.raises(McpError, match="disabled") as created:
        await service.record_create("odoo-a", "res.partner", {"name": "Must not write"})
    with pytest.raises(McpError, match="disabled") as updated:
        await service.record_update("odoo-a", "res.partner", [1], {"name": "Must not write"})
    assert created.value.code == updated.value.code == "access_denied"
    assert adapter.calls == []
    assert [event.outcome for event in audit.events] == ["denied", "denied"]
    assert "Must not write" not in str(audit.events)
    await service.record_count("odoo-a", "res.partner")
    assert len(adapter.calls) == 1


@pytest.mark.asyncio
async def test_direct_dispatch_cannot_bypass_write_gate():
    service, adapter = make_service(writes_enabled=False)
    with pytest.raises(McpError, match="disabled"):
        await service._call(
            "odoo-a", "res.partner", "create", "create", {"vals_list": [{"name": "No"}]}
        )
    assert adapter.calls == []
