"""Connection identifiers and secret references, not credential values."""

from dataclasses import dataclass


@dataclass(frozen=True)
class OdooConnection:
    id: str
    base_url: str
    database: str | None
    secret_ref: str
