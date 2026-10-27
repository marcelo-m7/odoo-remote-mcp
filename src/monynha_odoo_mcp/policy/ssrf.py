"""URL and DNS checks used before Odoo outbound requests."""

import ipaddress
import re
import socket
import ssl
from collections.abc import Callable
from urllib.parse import urlsplit

import httpcore
import httpx

from monynha_odoo_mcp.core.errors import McpError


def _lookup_public_ips(host: str) -> list[str]:
    return list(
        {str(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    )


class OutboundGuard:
    def __init__(self, resolver: Callable[[str], list[str]] | None = None) -> None:
        self._resolver = resolver or _lookup_public_ips
        self._approved: dict[str, frozenset[str]] = {}

    @staticmethod
    def _assert_public_ip(value: str) -> None:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise McpError("unsafe_target", "Unapproved Odoo network destination") from None
        if not ip.is_global:
            raise McpError("unsafe_target", "Unapproved Odoo network destination")

    def validate_target(self, url: str) -> None:
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError:
            raise McpError("unsafe_target", "Unapproved Odoo network destination") from None
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (port is not None and port != 443)
            or not re.fullmatch(r"[a-z0-9.-]+", host)
            or host.endswith((".localhost", ".local", ".internal"))
            or host in {"localhost", "metadata.google.internal"}
        ):
            raise McpError("unsafe_target", "Unapproved Odoo network destination")
        try:
            literal_ip = ipaddress.ip_address(host)
        except ValueError:
            literal_ip = None
        if literal_ip is not None:
            self._assert_public_ip(host)
            addresses = [host]
        else:
            try:
                addresses = self._resolver(host)
            except (OSError, ValueError):
                raise McpError("unsafe_target", "Unapproved Odoo network destination") from None
            if not addresses:
                raise McpError("unsafe_target", "Unapproved Odoo network destination")
        for ip in addresses:
            self._assert_public_ip(ip)
        self._approved[host] = frozenset(addresses)

    def validate_resolved_peer(self, host: str, ip: str) -> None:
        self._assert_public_ip(ip)
        if ip not in self._approved.get(host.lower().rstrip("."), frozenset()):
            raise McpError("unsafe_target", "Unapproved Odoo network destination")

    def pinned_public_ip(self, host: str) -> str:
        """Resolve, validate every address and choose one for the actual TCP socket."""
        text_host = f"[{host}]" if ":" in host else host
        self.validate_target(f"https://{text_host}")
        return sorted(self._approved[host.lower().rstrip(".")])[0]


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to a vetted IP while preserving TLS SNI for the original host."""

    def __init__(
        self,
        guard: OutboundGuard,
        *,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.guard = guard
        self.network_backend = network_backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        if port != 443:
            raise McpError("unsafe_target", "Unapproved Odoo network destination")
        ip = self.guard.pinned_public_ip(host)
        self.guard.validate_resolved_peer(host, ip)
        return await self.network_backend.connect_tcp(
            ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise McpError("unsafe_target", "Unix sockets are not allowed for Odoo")


def guarded_http_client(guard: OutboundGuard | None = None) -> httpx.AsyncClient:
    """Create an outbound client whose sockets use public, pinned IPs."""
    transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
    # HTTPX 0.28 has no public network-backend injection. This isolated
    # adapter is covered by a real client request test and version pinning.
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl.create_default_context(),
        network_backend=GuardedNetworkBackend(guard or OutboundGuard()),
        retries=0,
        max_connections=20,
        max_keepalive_connections=10,
    )
    return httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False)
