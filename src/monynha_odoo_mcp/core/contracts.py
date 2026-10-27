"""Stable envelopes shared by tools and transports."""

from typing import Any

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    data: Any
    meta: dict[str, Any] = Field(default_factory=dict)
