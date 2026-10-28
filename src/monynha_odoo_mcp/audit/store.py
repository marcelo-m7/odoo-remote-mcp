"""Append-only audit repository with a small allowlist of non-sensitive fields."""

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from monynha_odoo_mcp.audit.models import AuditEvent
from monynha_odoo_mcp.storage.db import AuditRow

_SAFE_KEYS = {"entity", "model", "count", "duration_ms", "correlation_id", "status", "client_id"}


class AuditStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def append(self, event: AuditEvent) -> None:
        safe_details = {
            key: value
            if key in _SAFE_KEYS and isinstance(value, (str, int, float))
            else "[REDACTED]"
            for key, value in event.details.items()
        }
        with self.sessions.begin() as session:
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    principal_id=event.principal_id,
                    connection_id=event.connection_id,
                    operation=event.operation,
                    outcome=event.outcome,
                    details=safe_details,
                )
            )

    def list_recent(self, limit: int = 100) -> list[dict]:
        with self.sessions() as session:
            records = session.scalars(
                select(AuditRow).order_by(AuditRow.created_at.desc()).limit(min(limit, 1000))
            ).all()
            return [
                {
                    "id": row.id,
                    "principal_id": row.principal_id,
                    "connection_id": row.connection_id,
                    "operation": row.operation,
                    "outcome": row.outcome,
                    "details": row.details,
                }
                for row in records
            ]
