"""Audit input deliberately excludes raw MCP arguments and Odoo responses."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    principal_id: str
    connection_id: str
    operation: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)
