"""Small deny-by-default authorization engine."""

from dataclasses import dataclass

from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.core.errors import McpError


@dataclass(frozen=True)
class Policy:
    principal_id: str
    connection_id: str
    operations: frozenset[str]
    models: frozenset[str]


class PolicyEngine:
    def __init__(self, policies: list[Policy] | None = None) -> None:
        self.policies = list(policies or [])

    def authorize(
        self, principal: Principal, connection_id: str, operation: str, model: str | None
    ) -> None:
        if operation == "delete":
            raise McpError("access_denied", "Operation is not permitted")
        for policy in self.policies:
            if (
                policy.principal_id == principal.id
                and policy.connection_id == connection_id
                and operation in policy.operations
                and (model is None or model in policy.models or "*" in policy.models)
            ):
                return
        raise McpError("access_denied", "Operation is not permitted")
