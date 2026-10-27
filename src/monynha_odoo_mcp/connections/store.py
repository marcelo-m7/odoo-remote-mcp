"""Connection registry with enforced membership and policies."""

from dataclasses import dataclass

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.policy.engine import PolicyEngine


@dataclass(frozen=True)
class StoredConnection:
    connection: OdooConnection
    organization_id: str


class ConnectionRegistry:
    def __init__(self, policy: PolicyEngine) -> None:
        self.policy = policy
        self._connections: dict[str, StoredConnection] = {}
        self._memberships: set[tuple[str, str]] = set()

    def add(self, entry: StoredConnection) -> None:
        self._connections[entry.connection.id] = entry

    def grant_membership(self, principal_id: str, organization_id: str) -> None:
        self._memberships.add((principal_id, organization_id))

    def list_for_principal(self, principal: Principal) -> list[OdooConnection]:
        return [
            entry.connection
            for entry in self._connections.values()
            if (principal.id, entry.organization_id) in self._memberships
        ]

    def get_for_principal(
        self, principal: Principal, connection_id: str, operation: str, model: str | None
    ) -> OdooConnection:
        entry = self._connections.get(connection_id)
        if entry is None or (principal.id, entry.organization_id) not in self._memberships:
            raise McpError("access_denied", "Connection is unavailable")
        self.policy.authorize(principal, connection_id, operation, model)
        return entry.connection

    def probe_read_model(self, principal: Principal, connection_id: str) -> str:
        """Choose a model already covered by a read grant for a live check."""
        self.get_for_principal(principal, connection_id, "read", None)
        models = sorted(
            model
            for policy in self.policy.policies
            if policy.principal_id == principal.id
            and policy.connection_id == connection_id
            and "read" in policy.operations
            for model in policy.models
            if model != "*"
        )
        return models[0] if models else "res.partner"
