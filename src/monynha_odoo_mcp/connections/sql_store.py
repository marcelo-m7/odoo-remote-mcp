"""SQL-backed connection, membership and policy registry."""

import re

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.store import ConnectionRegistry, StoredConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.engine import Policy, PolicyEngine
from monynha_odoo_mcp.storage.db import (
    ConnectionRow,
    MembershipRow,
    OrganizationRow,
    PolicyRow,
    PrincipalRow,
)


class SqlConnectionStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def add_organization(self, organization_id: str) -> None:
        with self.sessions.begin() as session:
            session.add(OrganizationRow(id=organization_id))

    def add_principal(self, principal_id: str) -> None:
        with self.sessions.begin() as session:
            session.add(PrincipalRow(id=principal_id))

    def grant_membership(self, principal_id: str, organization_id: str) -> None:
        with self.sessions.begin() as session:
            session.merge(MembershipRow(principal_id=principal_id, organization_id=organization_id))

    def add_connection(self, organization_id: str, connection: OdooConnection) -> None:
        if not re.fullmatch(r"env:MONYNHA_ODOO_KEY_[A-Z0-9_]+", connection.secret_ref):
            raise McpError("invalid_arguments", "Connection must use an approved secret reference")
        with self.sessions.begin() as session:
            session.add(
                ConnectionRow(
                    id=connection.id,
                    organization_id=organization_id,
                    base_url=connection.base_url,
                    database=connection.database,
                    secret_ref=connection.secret_ref,
                )
            )

    def grant_policy(
        self, principal_id: str, connection_id: str, operation: str, model: str
    ) -> None:
        if operation not in {"read", "create", "update"}:
            raise McpError("access_denied", "Operation is not available in v0.1")
        with self.sessions.begin() as session:
            session.merge(
                PolicyRow(
                    principal_id=principal_id,
                    connection_id=connection_id,
                    operation=operation,
                    model=model,
                )
            )

    def revoke_policy(
        self, principal_id: str, connection_id: str, operation: str, model: str
    ) -> None:
        with self.sessions.begin() as session:
            entry = session.get(PolicyRow, (principal_id, connection_id, operation, model))
            if entry is not None:
                session.delete(entry)

    def load_registry(self) -> ConnectionRegistry:
        with self.sessions() as session:
            policies = [
                Policy(
                    principal_id=row.principal_id,
                    connection_id=row.connection_id,
                    operations=frozenset({row.operation}),
                    models=frozenset({row.model}),
                )
                for row in session.scalars(select(PolicyRow))
            ]
            registry = ConnectionRegistry(PolicyEngine(policies))
            for connection_row in session.scalars(select(ConnectionRow)):
                registry.add(
                    StoredConnection(
                        connection=OdooConnection(
                            connection_row.id,
                            connection_row.base_url,
                            connection_row.database,
                            connection_row.secret_ref,
                        ),
                        organization_id=connection_row.organization_id,
                    )
                )
            for membership_row in session.scalars(select(MembershipRow)):
                registry.grant_membership(
                    membership_row.principal_id, membership_row.organization_id
                )
        return registry
