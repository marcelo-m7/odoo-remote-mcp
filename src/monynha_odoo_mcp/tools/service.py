"""Backend-independent use cases exposed through MCP."""

from typing import Any

from monynha_odoo_mcp import __version__
from monynha_odoo_mcp.audit.models import AuditEvent
from monynha_odoo_mcp.audit.store import AuditStore
from monynha_odoo_mcp.auth.principal import Principal
from monynha_odoo_mcp.connections.store import ConnectionRegistry
from monynha_odoo_mcp.core.contracts import ToolResult
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.odoo.adapter import OdooAdapter
from monynha_odoo_mcp.policy.rate_limit import RateLimiter


class OdooToolService:
    def __init__(
        self,
        adapter: OdooAdapter,
        connections: ConnectionRegistry,
        principal: Principal,
        *,
        max_results: int = 100,
        audit: AuditStore | None = None,
        rate_limiter: RateLimiter | None = None,
        writes_enabled: bool = False,
        oauth_client_id: str | None = None,
    ) -> None:
        self.adapter = adapter
        self.connections = connections
        self.principal = principal
        self.max_results = max_results
        self.audit = audit
        self.rate_limiter = rate_limiter or RateLimiter()
        self.writes_enabled = writes_enabled
        self.oauth_client_id = oauth_client_id

    def _reject_disabled_write(self, connection_id: str, operation: str, model: str) -> None:
        if operation in {"create", "update"} and not self.writes_enabled:
            self._try_audit(connection_id, operation, model, "denied")
            raise McpError("access_denied", "Odoo writes are disabled")

    def _connection(self, connection_id: str, operation: str, model: str | None = None):
        return self.connections.get_for_principal(self.principal, connection_id, operation, model)

    def _page(self, offset: int, limit: int) -> tuple[int, int]:
        if offset < 0 or limit < 1:
            raise McpError("invalid_arguments", "Invalid pagination")
        return offset, min(limit, self.max_results)

    def _ids(self, ids: list[int]) -> list[int]:
        if (
            not ids
            or len(ids) > self.max_results
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in ids)
        ):
            raise McpError("invalid_arguments", "Invalid record identifiers")
        return ids

    def _fields(self, fields: list[str] | None) -> list[str]:
        if fields is None or not fields:
            return ["id", "display_name"]
        if len(fields) > 64 or any(
            not isinstance(field, str) or len(field) > 128 for field in fields
        ):
            raise McpError("invalid_arguments", "Invalid field projection")
        return fields

    def _write_values(self, values: dict[str, Any]) -> None:
        # Odoo x2many command tuples can create/update/unlink/delete other models
        # through an apparently innocuous write grant. Keep v0.1 writes flat.
        def contains_commands(value: Any, *, nested_in_list: bool = False) -> bool:
            if isinstance(value, (list, tuple)):
                if nested_in_list and value and type(value[0]) is int and 0 <= value[0] <= 6:
                    return True
                return any(contains_commands(child, nested_in_list=True) for child in value)
            if isinstance(value, dict):
                return any(contains_commands(child) for child in value.values())
            return False

        if contains_commands(values):
            raise McpError("invalid_arguments", "Nested Odoo relational commands are disabled")

    async def _call(
        self, connection_id: str, model: str, operation: str, method: str, payload: dict
    ) -> ToolResult:
        is_write = operation in {"create", "update"}
        self._reject_disabled_write(connection_id, operation, model)
        try:
            connection = self._connection(connection_id, operation, model)
        except McpError:
            self._try_audit(connection_id, operation, model, "denied")
            raise
        async with self.rate_limiter.slot(self.principal.id, connection_id, operation):
            if is_write:
                # Persist intent before sending a non-idempotent external request.
                try:
                    self._record_audit(connection_id, operation, model, "started")
                except Exception:
                    raise McpError(
                        "audit_unavailable", "Write audit unavailable; no write attempted"
                    ) from None
            try:
                data = await self.adapter.call(connection, model, method, payload)
            except McpError as exc:
                uncertain = is_write and exc.code in {"odoo_timeout", "odoo_unavailable"}
                self._try_audit(
                    connection_id, operation, model, "outcome_unknown" if uncertain else "error"
                )
                if uncertain:
                    raise McpError(
                        "write_outcome_unknown",
                        "Write result uncertain; verify Odoo before retrying",
                    ) from None
                raise
            except Exception:
                self._try_audit(
                    connection_id, operation, model, "outcome_unknown" if is_write else "error"
                )
                raise
        audit_ok = self._try_audit(connection_id, operation, model, "success")
        meta = {"connection_id": connection_id}
        if not audit_ok:
            # The Odoo response is authoritative; never turn confirmed success
            # into an error that could cause the client to repeat a write.
            meta["audit_status"] = "outcome_unknown"
        return ToolResult(data=data, meta=meta)

    def _try_audit(self, connection_id: str, operation: str, model: str, outcome: str) -> bool:
        try:
            self._record_audit(connection_id, operation, model, outcome)
            return True
        except Exception:
            return False

    def _record_audit(self, connection_id: str, operation: str, model: str, outcome: str) -> None:
        if self.audit is not None:
            details = {"model": model}
            if self.oauth_client_id is not None:
                details["client_id"] = self.oauth_client_id
            self.audit.append(
                AuditEvent(
                    principal_id=self.principal.id,
                    connection_id=connection_id,
                    operation=operation,
                    outcome=outcome,
                    details=details,
                )
            )

    async def server_info_get(self) -> ToolResult:
        return ToolResult(
            data={"name": "Monynha Odoo MCP", "version": __version__, "backend": "odoo-json2"},
        )

    async def connection_list(self) -> ToolResult:
        connections = self.connections.list_for_principal(self.principal)
        return ToolResult(
            data=[{"id": c.id, "base_url": c.base_url} for c in connections],
            meta={"count": len(connections)},
        )

    async def connection_test(self, connection_id: str) -> ToolResult:
        model = self.connections.probe_read_model(self.principal, connection_id)
        result = await self._call(connection_id, model, "read", "search_count", {"domain": []})
        return ToolResult(data={"reachable": True}, meta=result.meta)

    async def model_list(
        self, connection_id: str, domain: list[Any] | None = None, limit: int = 50
    ) -> ToolResult:
        _, limit = self._page(0, limit)
        return await self._call(
            connection_id,
            "ir.model",
            "read",
            "search_read",
            {"domain": domain or [], "fields": ["model", "name"], "limit": limit},
        )

    async def model_fields_get(self, connection_id: str, model: str) -> ToolResult:
        return await self._call(
            connection_id,
            model,
            "read",
            "fields_get",
            {"attributes": ["string", "type", "required", "readonly", "relation"]},
        )

    async def record_get(
        self, connection_id: str, model: str, ids: list[int], fields: list[str] | None = None
    ) -> ToolResult:
        payload: dict[str, Any] = {"ids": self._ids(ids), "fields": self._fields(fields)}
        return await self._call(connection_id, model, "read", "read", payload)

    async def record_search(
        self,
        connection_id: str,
        model: str,
        domain: list[Any] | None = None,
        fields: list[str] | None = None,
        offset: int = 0,
        limit: int = 20,
        order: str | None = None,
    ) -> ToolResult:
        offset, limit = self._page(offset, limit)
        payload: dict[str, Any] = {
            "domain": domain or [],
            "offset": offset,
            "limit": limit,
            "fields": self._fields(fields),
        }
        if order is not None:
            payload["order"] = order
        result = await self._call(connection_id, model, "read", "search_read", payload)
        result.meta.update({"offset": offset, "limit": limit})
        return result

    async def record_count(
        self, connection_id: str, model: str, domain: list[Any] | None = None
    ) -> ToolResult:
        return await self._call(
            connection_id, model, "read", "search_count", {"domain": domain or []}
        )

    async def record_aggregate(
        self,
        connection_id: str,
        model: str,
        domain: list[Any],
        fields: list[str],
        groupby: list[str],
        offset: int = 0,
        limit: int = 20,
    ) -> ToolResult:
        offset, limit = self._page(offset, limit)
        if not groupby or not fields:
            raise McpError("invalid_arguments", "Grouping fields are required")
        return await self._call(
            connection_id,
            model,
            "read",
            "read_group",
            {
                "domain": domain,
                "fields": fields,
                "groupby": groupby,
                "offset": offset,
                "limit": limit,
            },
        )

    async def record_create(
        self, connection_id: str, model: str, values: dict[str, Any]
    ) -> ToolResult:
        self._reject_disabled_write(connection_id, "create", model)
        if not values:
            raise McpError("invalid_arguments", "Creation values are required")
        self._write_values(values)
        return await self._call(connection_id, model, "create", "create", {"vals_list": [values]})

    async def record_update(
        self, connection_id: str, model: str, ids: list[int], values: dict[str, Any]
    ) -> ToolResult:
        self._reject_disabled_write(connection_id, "update", model)
        self._ids(ids)
        if not values:
            raise McpError("invalid_arguments", "Update values are required")
        self._write_values(values)
        return await self._call(
            connection_id, model, "update", "write", {"ids": ids, "vals": values}
        )
