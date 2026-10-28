"""Local administrative CLI. Never exposed as an MCP tool."""

import argparse
import asyncio
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session, sessionmaker

from monynha_odoo_mcp.connections.models import OdooConnection
from monynha_odoo_mcp.connections.sql_store import SqlConnectionStore
from monynha_odoo_mcp.core.errors import McpError
from monynha_odoo_mcp.odoo.adapter import OdooAdapter
from monynha_odoo_mcp.policy.ssrf import OutboundGuard
from monynha_odoo_mcp.settings import Settings
from monynha_odoo_mcp.storage.db import create_database


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="monynha-odoo-admin")
    groups = parser.add_subparsers(dest="group", required=True)
    organization = groups.add_parser("organization").add_subparsers(dest="action", required=True)
    organization.add_parser("add").add_argument("--id", required=True)
    principal = groups.add_parser("principal").add_subparsers(dest="action", required=True)
    principal.add_parser("add").add_argument("--id", required=True)
    identity = groups.add_parser("identity").add_subparsers(dest="action", required=True)
    binding = identity.add_parser("bind")
    binding.add_argument("--principal", required=True)
    binding.add_argument("--issuer", required=True)
    binding.add_argument("--subject", required=True)
    clients = groups.add_parser("oauth-client").add_subparsers(dest="action", required=True)
    for action in ("admit", "revoke"):
        clients.add_parser(action).add_argument("--id", required=True)
    membership = groups.add_parser("membership").add_subparsers(dest="action", required=True)
    member_grant = membership.add_parser("grant")
    member_grant.add_argument("--principal", required=True)
    member_grant.add_argument("--org", required=True)
    connections = groups.add_parser("connection").add_subparsers(dest="action", required=True)
    add_connection = connections.add_parser("add")
    add_connection.add_argument("--id", required=True)
    add_connection.add_argument("--org", required=True)
    add_connection.add_argument("--url", required=True)
    add_connection.add_argument("--database")
    add_connection.add_argument("--secret-ref", required=True)
    conn_list = connections.add_parser("list")
    conn_list.add_argument("--principal", required=True)
    conn_test = connections.add_parser("test")
    conn_test.add_argument("--id", required=True)
    conn_test.add_argument("--principal", required=True)
    policies = groups.add_parser("policy").add_subparsers(dest="action", required=True)
    for name in ("grant", "revoke"):
        policy = policies.add_parser(name)
        policy.add_argument("--principal", required=True)
        policy.add_argument("--connection", required=True)
        policy.add_argument("--operation", required=True, choices=("read", "create", "update"))
        policy.add_argument("--model", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    sessions: sessionmaker[Session] | None = None,
    guard: OutboundGuard | None = None,
    adapter: OdooAdapter | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    if sessions is None:
        url = Settings(mode="stdio").database_url
        if not url:
            print("MONYNHA_MCP_DATABASE_URL is required", file=sys.stderr)
            return 2
        _, sessions = create_database(url)
    store = SqlConnectionStore(sessions)
    try:
        if arguments.group == "organization":
            store.add_organization(arguments.id)
        elif arguments.group == "principal":
            store.add_principal(arguments.id)
        elif arguments.group == "identity" and arguments.action == "bind":
            store.bind_external_identity(arguments.principal, arguments.issuer, arguments.subject)
        elif arguments.group == "oauth-client":
            store.set_oauth_client_admission(arguments.id, enabled=arguments.action == "admit")
        elif arguments.group == "membership":
            store.grant_membership(arguments.principal, arguments.org)
        elif arguments.group == "connection" and arguments.action == "add":
            (guard or OutboundGuard()).validate_target(arguments.url)
            store.add_connection(
                arguments.org,
                OdooConnection(
                    arguments.id, arguments.url, arguments.database, arguments.secret_ref
                ),
            )
        elif arguments.group == "connection" and arguments.action == "test":
            from monynha_odoo_mcp.auth.principal import Principal
            from monynha_odoo_mcp.tools.service import OdooToolService

            async def check():
                if adapter is not None:
                    service = OdooToolService(
                        adapter, store.load_registry(), Principal(arguments.principal)
                    )
                    return await service.connection_test(arguments.id)
                from monynha_odoo_mcp.odoo.json2 import Json2Adapter
                from monynha_odoo_mcp.policy.ssrf import guarded_http_client
                from monynha_odoo_mcp.secrets import EnvSecretResolver

                async with guarded_http_client(guard) as client:
                    service = OdooToolService(
                        Json2Adapter(client, EnvSecretResolver()),
                        store.load_registry(),
                        Principal(arguments.principal),
                    )
                    return await service.connection_test(arguments.id)

            result = asyncio.run(check())
            print(f"reachable: {str(result.data['reachable']).lower()}")
        elif arguments.group == "connection":
            from monynha_odoo_mcp.auth.principal import Principal

            for conn in store.load_registry().list_for_principal(Principal(arguments.principal)):
                print(f"{conn.id} {conn.base_url}")
        elif arguments.group == "policy" and arguments.action == "grant":
            store.grant_policy(
                arguments.principal, arguments.connection, arguments.operation, arguments.model
            )
        elif arguments.group == "policy":
            store.revoke_policy(
                arguments.principal, arguments.connection, arguments.operation, arguments.model
            )
        return 0
    except McpError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
