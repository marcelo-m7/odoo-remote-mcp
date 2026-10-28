import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.storage.db import create_database, create_schema


@pytest.fixture
def database():
    engine, sessions = create_database("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    yield engine, sessions
    engine.dispose()


def test_database_has_tenant_constraints(database):
    engine, sessions = database
    with pytest.raises(IntegrityError):
        with sessions.begin() as session:
            session.execute(
                text(
                    "INSERT INTO connections (id, organization_id, base_url, secret_ref) "
                    "VALUES ('unknown', 'missing-org', 'https://odoo.example', "
                    "'env:MONYNHA_ODOO_KEY_X')"
                )
            )


def test_secret_values_not_persisted(database, monkeypatch):
    engine, sessions = database
    monkeypatch.setenv("MONYNHA_ODOO_KEY_TEST", "super-private-api-key")
    store = SqlConnectionStore(sessions)
    store.add_organization("a")
    store.add_connection(
        "a", OdooConnection("odoo-a", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_TEST")
    )
    with sessions() as session:
        row = session.execute(
            text("SELECT secret_ref FROM connections WHERE id = 'odoo-a'")
        ).scalar_one()
    assert row == "env:MONYNHA_ODOO_KEY_TEST"
    assert "super-private-api-key" not in row


def test_connection_roundtrip(database):
    _, sessions = database
    store = SqlConnectionStore(sessions)
    store.add_organization("org-a")
    store.add_principal("alice")
    store.grant_membership("alice", "org-a")
    store.add_connection(
        "org-a",
        OdooConnection("odoo-a", "https://odoo.example", None, "env:MONYNHA_ODOO_KEY_TEST"),
    )
    store.grant_policy("alice", "odoo-a", "read", "res.partner")
    registry = store.load_registry()
    conn = registry.get_for_principal(Principal("alice"), "odoo-a", "read", "res.partner")
    assert conn.base_url == "https://odoo.example"
    assert conn.secret_ref == "env:MONYNHA_ODOO_KEY_TEST"


def test_alembic_upgrade_creates_schema(tmp_path):
    db_path = tmp_path / "migration.sqlite"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(config, "head")
    engine, sessions = create_database(f"sqlite:///{db_path}")
    with sessions() as session:
        tables = set(
            session.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'")).scalars()
        )
    assert {
        "organizations",
        "principals",
        "memberships",
        "connections",
        "policies",
        "audit_events",
        "external_identities",
        "oauth_client_admissions",
    } <= tables
    engine.dispose()


def test_external_identity_requires_explicit_issuer_and_subject_binding(database):
    _, sessions = database
    store = SqlConnectionStore(sessions)
    store.add_principal("private-user-1")
    store.add_principal("private-user-2")
    issuer_a = "https://facodi-identity.example/auth/v1"
    issuer_b = "https://other-identity.example/auth/v1"
    assert store.resolve_external_principal(issuer_a, "same-sub") is None
    store.bind_external_identity("private-user-1", issuer_a, "same-sub")
    assert store.resolve_external_principal(issuer_a, "same-sub").id == "private-user-1"
    assert store.resolve_external_principal(issuer_b, "same-sub") is None
    store.bind_external_identity("private-user-2", issuer_b, "same-sub")
    assert store.resolve_external_principal(issuer_b, "same-sub").id == "private-user-2"
    with pytest.raises(McpError, match="already bound"):
        store.bind_external_identity("private-user-2", issuer_a, "same-sub")
    assert store.resolve_external_principal(issuer_a, "same-sub").id == "private-user-1"


def test_external_identity_binding_rejects_nonexistent_principal(database):
    _, sessions = database
    store = SqlConnectionStore(sessions)
    with pytest.raises(McpError, match="not onboarded"):
        store.bind_external_identity("missing", "https://id.example/auth/v1", "user")


def test_oauth_client_admission_can_be_revoked_without_invalidating_jwt(database):
    _, sessions = database
    store = SqlConnectionStore(sessions)
    assert store.is_oauth_client_admitted("client-a") is False
    store.set_oauth_client_admission("client-a", enabled=True)
    assert store.is_oauth_client_admitted("client-a") is True
    assert store.is_oauth_client_admitted("client-b") is False
    store.set_oauth_client_admission("client-a", enabled=False)
    assert store.is_oauth_client_admitted("client-a") is False
