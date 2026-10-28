"""SQL-backed connection, membership and policy registry."""

import re
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.store import ConnectionRegistry, StoredConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.engine import Policy, PolicyEngine
from monynha_odoo_mcp.storage.db import (
    ConnectionRow,
    ExternalIdentityRow,
    MembershipRow,
    OAuthClientAdmissionRow,
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

    def resolve_external_principal(self, issuer: str, subject: str) -> Principal | None:
        with self.sessions() as session:
            entry = session.get(ExternalIdentityRow, (issuer, subject))
            return Principal(entry.principal_id) if entry is not None else None

    def bind_external_identity(self, principal_id: str, issuer: str, subject: str) -> None:
        parts = urlsplit(issuer)
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or not 1 <= len(issuer) <= 512
            or not 1 <= len(subject) <= 256
        ):
            raise McpError("invalid_arguments", "Invalid external OAuth identity")
        with self.sessions.begin() as session:
            if session.get(PrincipalRow, principal_id) is None:
                raise McpError("access_denied", "Principal is not onboarded")
            existing = session.get(ExternalIdentityRow, (issuer, subject))
            if existing is not None:
                if existing.principal_id != principal_id:
                    raise McpError("access_denied", "External identity is already bound")
                return
            session.add(
                ExternalIdentityRow(issuer=issuer, subject=subject, principal_id=principal_id)
            )

    def is_oauth_client_admitted(self, client_id: str) -> bool:
        if not client_id:
            return False
        with self.sessions() as session:
            admission = session.get(OAuthClientAdmissionRow, client_id)
            return admission is not None and admission.enabled

    def set_oauth_client_admission(self, client_id: str, *, enabled: bool) -> None:
        if (
            not isinstance(client_id, str)
            or not 1 <= len(client_id) <= 256
            or client_id.strip() != client_id
            or any(char.isspace() for char in client_id)
        ):
            raise McpError("invalid_arguments", "Invalid OAuth client ID")
        with self.sessions.begin() as session:
            session.merge(OAuthClientAdmissionRow(client_id=client_id, enabled=enabled))

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
