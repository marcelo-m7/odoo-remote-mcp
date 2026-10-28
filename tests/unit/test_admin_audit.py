import pytest

from monynha_odoo_mcp.admin import main
from monynha_odoo_mcp.audit.models import AuditEvent
from monynha_odoo_mcp.audit.store import AuditStore
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.policy.ssrf import OutboundGuard
from monynha_odoo_mcp.storage.db import create_database, create_schema


@pytest.fixture
def store():
    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    yield SqlConnectionStore(sessions), sessions
    engine.dispose()


def test_audit_redacts_secrets(store):
    _, sessions = store
    audit = AuditStore(sessions)
    audit.append(
        AuditEvent(
            principal_id="alice",
            connection_id="odoo-a",
            operation="read",
            outcome="success",
            details={"api_key": "super-private-key", "entity": "res.partner"},
        )
    )
    events = audit.list_recent(limit=10)
    assert events[0]["details"] == {"api_key": "[REDACTED]", "entity": "res.partner"}
    assert "super-private-key" not in str(events)


def test_cli_rejects_unsafe_url(store):
    sql_store, sessions = store
    sql_store.add_organization("org-a")
    code = main(
        [
            "connection",
            "add",
            "--id",
            "odoo-x",
            "--org",
            "org-a",
            "--url",
            "http://127.0.0.1",
            "--secret-ref",
            "env:MONYNHA_ODOO_KEY_X",
        ],
        sessions=sessions,
        guard=OutboundGuard(resolver=lambda host: ["1.1.1.1"]),
    )
    assert code != 0
    assert sql_store.load_registry()._connections == {}


def test_admin_cli_connection_test_is_read_only(store, capsys):
    sql_store, sessions = store
    sql_store.add_organization("org-a")
    sql_store.add_principal("alice")
    sql_store.grant_membership("alice", "org-a")
    from monynha_odoo_mcp.connections.models import OdooConnection

    sql_store.add_connection(
        "org-a", OdooConnection("odoo-a", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_TEST")
    )
    sql_store.grant_policy("alice", "odoo-a", "read", "res.partner")
    calls = []

    class FakeAdapter:
        async def call(self, connection, model, method, payload):
            calls.append((connection.id, model, method, dict(payload)))
            return 2

    code = main(
        ["connection", "test", "--id", "odoo-a", "--principal", "alice"],
        sessions=sessions,
        adapter=FakeAdapter(),
    )
    assert code == 0
    assert calls == [("odoo-a", "res.partner", "search_count", {"domain": []})]
    assert "reachable" in capsys.readouterr().out


def test_admin_cli_can_bind_existing_principal_without_creating_permissions(store):
    sql_store, sessions = store
    sql_store.add_principal("existing")
    assert (
        main(
            [
                "identity",
                "bind",
                "--principal",
                "existing",
                "--issuer",
                "https://issuer.example/auth/v1",
                "--subject",
                "external-user",
            ],
            sessions=sessions,
        )
        == 0
    )
    assert (
        sql_store.resolve_external_principal("https://issuer.example/auth/v1", "external-user").id
        == "existing"
    )
    assert (
        sql_store.load_registry().list_for_principal(
            sql_store.resolve_external_principal("https://issuer.example/auth/v1", "external-user")
        )
        == []
    )


def test_admin_cli_oauth_client_can_be_admitted_and_revoked(store):
    sql_store, sessions = store
    assert main(["oauth-client", "admit", "--id", "pilot"], sessions=sessions) == 0
    assert sql_store.is_oauth_client_admitted("pilot") is True
    assert main(["oauth-client", "revoke", "--id", "pilot"], sessions=sessions) == 0
    assert sql_store.is_oauth_client_admitted("pilot") is False
