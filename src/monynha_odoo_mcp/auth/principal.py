"""Authenticated MCP principal; tenancy is resolved server-side."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str
