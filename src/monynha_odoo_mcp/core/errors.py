"""Safe errors crossing the MCP boundary."""

from dataclasses import dataclass


@dataclass
class McpError(Exception):
    code: str
    message: str
    correlation_id: str | None = None

    def public(self) -> dict[str, str | None]:
        return {"code": self.code, "message": self.message, "correlation_id": self.correlation_id}
