"""
proxy.py — local HTTP reverse proxy for agent LLM API traffic.

Intercepts agent LLM API requests/responses and writes normalized audit events
to a SQLite database via the storage module.

Supports OpenAI, Anthropic, and Google (Gemini) API formats.

Reverse-proxy mode (recommended — works with HTTPS):
    Point your agent's base URL at the proxy:
        ANTHROPIC_BASE_URL=http://127.0.0.1:8081
        OPENAI_BASE_URL=http://127.0.0.1:8081/v1
    The proxy auto-routes to the correct upstream based on path patterns.
    Override upstreams via env vars:
        PANOPTES_UPSTREAM_ANTHROPIC=https://api.anthropic.com
        PANOPTES_UPSTREAM_OPENAI=https://api.openai.com
        PANOPTES_UPSTREAM_GEMINI=https://generativelanguage.googleapis.com

Usage:
    panoptes proxy --port 8081 --db-path ./audit.db

The work is split by side of the exchange: ``_request`` reads what the client
sent, ``_forward`` talks to the upstream, ``_exchange`` runs one exchange from
admission to settlement, ``_hooked`` adds the hook lifecycle, and ``_events``
turns it all into audit events. This module holds the public surface: the
server, its request handler, and the errors and limits callers see.
"""

from __future__ import annotations

import functools
import http.server
import ipaddress
import logging
import os
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
except ModuleNotFoundError as exc:  # pragma: no cover - exercised in a subprocess
    if exc.name != "httpx":
        raise
    raise ModuleNotFoundError(
        "panoptes.proxy needs httpx; install it with "
        "pip install 'panoptes-observe[proxy]'",
        name="httpx",
    ) from exc

import panoptes.providers as _providers
from panoptes._events import (
    DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
    AmbiguousResponseError,
    AuditEventWriter,
    AuditWriteError,
    ResponseInspectionError,
    detect_agent_type,
)
from panoptes._exchange import Lifecycle, ObservedLifecycle, ProxyConfig, serve
from panoptes._forward import (
    HOP_BY_HOP,
    PANOPTES_INTERNAL_HEADERS,
    Forwarder,
    UpstreamBodyTooLarge,
)
from panoptes._forward import upstream_client as _upstream_client
from panoptes._hooked import HookedLifecycle
from panoptes._request import (
    NoUpstreamError,
    ProxyRequestError,
    RequestBodyTooLarge,
    RequestFramingError,
)
from panoptes._server import BoundedThreadingHTTPServer
from panoptes.db import AuditDB
from panoptes.hooks import ProxyHooks, Upstream

__all__ = [
    "DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS",
    "DEFAULT_DISCONNECT_DRAIN_SECONDS",
    "DEFAULT_HOOK_SLOW_SECONDS",
    "DEFAULT_MAX_AUDIT_STREAM_BYTES",
    "DEFAULT_MAX_BUFFERED_RESPONSE_BYTES",
    "DEFAULT_MAX_CONCURRENT_REQUESTS",
    "DEFAULT_MAX_REQUEST_BODY_BYTES",
    "DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE",
    "HOP_BY_HOP",
    "PANOPTES_INTERNAL_HEADERS",
    "AmbiguousResponseError",
    "AuditEventWriter",
    "AuditWriteError",
    "NoUpstreamError",
    "ProxyHandler",
    "ProxyRequestError",
    "ProxyServer",
    "RequestBodyTooLarge",
    "RequestFramingError",
    "ResponseInspectionError",
    "Upstream",
    "UpstreamBodyTooLarge",
    "detect_agent_type",
    "start_proxy",
]

log = logging.getLogger("panoptes")


# Transport limits protect the proxy process itself. A buffered response over
# the limit is refused with a 502. Passthrough streams may continue to the
# client, but their local capture is bounded and explicitly marked incomplete.
DEFAULT_MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_BUFFERED_RESPONSE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_AUDIT_STREAM_BYTES = 8 * 1024 * 1024
DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONCURRENT_REQUESTS = 64
DEFAULT_DISCONNECT_DRAIN_SECONDS = 30.0
DEFAULT_HOOK_SLOW_SECONDS = 5.0
_UPSTREAM_TIMEOUT_SECONDS = 120.0
# stop() waits this long for in-flight exchanges (the upstream read timeout).
_STOP_GRACE_SECONDS = _UPSTREAM_TIMEOUT_SECONDS


def _is_loopback_bind_host(host: str) -> bool:
    """Return whether ``host`` is an explicit loopback bind target."""
    normalized = host.strip().strip("[]").rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        # Do not resolve arbitrary hostnames here. DNS resolution can change,
        # so only explicit loopback literals and localhost are safe defaults.
        return False


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """The HTTP side of the proxy: one instance per client connection.

    It owns the socket and nothing else. ``serve`` runs the exchange and
    talks to this handler as its ``ClientConnection``.
    """

    def __init__(self, *args: Any, config: ProxyConfig, **kwargs: Any) -> None:
        # Set before super().__init__, which handles the request.
        self.config = config
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        serve(self.config, self, "GET")

    def do_POST(self) -> None:
        serve(self.config, self, "POST")

    def log_message(self, fmt: str, *args: Any) -> None:
        """Log without query strings, which may carry a credential."""
        # A timeout is logged before the request line is parsed, so these
        # attributes may not exist yet.
        raw_path = getattr(self, "path", "")
        request_line = getattr(self, "requestline", "")
        safe_path = urlparse(raw_path).path or "/"
        safe_args = list(args)
        if safe_args and request_line and safe_args[0] == request_line:
            safe_args[0] = (
                f"{getattr(self, 'command', '')} {safe_path} "
                f"{getattr(self, 'request_version', '')}"
            ).strip()
        if raw_path and raw_path != safe_path:
            safe_args = [
                value.replace(raw_path, safe_path) if isinstance(value, str) else value
                for value in safe_args
            ]
        log.info(fmt % tuple(safe_args))

    # ClientConnection ---------------------------------------------------

    def send_reply(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def start_stream(self, status: int, headers: Mapping[str, str]) -> None:
        # No Content-Length: the body is close-delimited.
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

    def write_stream(self, chunk: bytes) -> None:
        self.wfile.write(chunk)

    def flush_stream(self) -> None:
        self.wfile.flush()

    def end_stream(self) -> None:
        self.close_connection = True
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ProxyServer:
    """Runs a local HTTP proxy server in a background thread."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        db_path: str | None = None,
        max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES,
        max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
        max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES,
        max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
        client_socket_timeout_seconds: float = DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        pricing: Any = None,
        *,
        hooks: ProxyHooks | None = None,
        db: AuditDB | None = None,
        chain: bool | None = None,
        upstreams: dict[str, Upstream] | None = None,
        disconnect_drain_seconds: float = DEFAULT_DISCONNECT_DRAIN_SECONDS,
        hook_slow_seconds: float = DEFAULT_HOOK_SLOW_SECONDS,
    ) -> None:
        if not _is_loopback_bind_host(host):
            raise ValueError(f"Refusing non-loopback proxy bind host {host!r}")
        if db is not None and db_path is not None:
            raise ValueError("db and db_path are mutually exclusive")
        if hooks is not None and not isinstance(hooks, ProxyHooks):
            raise TypeError("hooks must be a ProxyHooks instance")
        for value, name in (
            (disconnect_drain_seconds, "disconnect_drain_seconds"),
            (hook_slow_seconds, "hook_slow_seconds"),
        ):
            if value < 0:
                raise ValueError(f"{name} must not be negative")
        self.upstreams = self._resolve_upstreams(upstreams)
        self.hooks = hooks
        self.chain = chain
        self.disconnect_drain_seconds = disconnect_drain_seconds
        self.hook_slow_seconds = hook_slow_seconds
        self.host = host
        self.port = port
        self._external_db = db
        self.db_path = db_path if db_path is not None else ":memory:"
        for value, name in (
            (max_request_body_bytes, "max_request_body_bytes"),
            (max_buffered_response_bytes, "max_buffered_response_bytes"),
            (max_audit_stream_bytes, "max_audit_stream_bytes"),
            (max_tool_events_per_exchange, "max_tool_events_per_exchange"),
            (client_socket_timeout_seconds, "client_socket_timeout_seconds"),
            (max_concurrent_requests, "max_concurrent_requests"),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self.max_request_body_bytes = max_request_body_bytes
        self.max_buffered_response_bytes = max_buffered_response_bytes
        self.max_audit_stream_bytes = max_audit_stream_bytes
        self.max_tool_events_per_exchange = max_tool_events_per_exchange
        self.client_socket_timeout_seconds = client_socket_timeout_seconds
        self.max_concurrent_requests = max_concurrent_requests
        self.pricing = pricing
        self._server: BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._db: AuditDB | None = None
        self._http_client: httpx.Client | None = None
        self._tmp_db_path: str | None = None  # set when db_path == ":memory:"
        self.writer: AuditEventWriter | None = None
        self._lifecycle_lock = threading.Lock()

    @staticmethod
    def _resolve_upstreams(
        upstreams: dict[str, Upstream] | None,
    ) -> dict[str, tuple[str, Upstream]]:
        """Validate ``upstreams`` and give each one its name."""
        resolved: dict[str, tuple[str, Upstream]] = {}
        known = {provider.name for provider in _providers.REGISTRY}
        for protocol, upstream in (upstreams or {}).items():
            if protocol not in known:
                raise ValueError(
                    f"Unknown wire protocol {protocol!r}; expected one of "
                    f"{sorted(known)}"
                )
            if not isinstance(upstream, Upstream):
                raise TypeError(f"upstreams[{protocol!r}] must be an Upstream")
            resolved[protocol] = (upstream.name or protocol, upstream)
        return resolved

    def _lifecycle(self) -> Callable[[], Lifecycle]:
        """Hook mode, decided once for every exchange this start serves."""
        if self.hooks is None:
            return ObservedLifecycle
        return functools.partial(
            HookedLifecycle,
            self.hooks,
            slow_seconds=self.hook_slow_seconds,
            drain_seconds=self.disconnect_drain_seconds,
        )

    def start(self) -> int:
        """Start the proxy in a background thread. Returns the listening port."""
        with self._lifecycle_lock:
            return self._start()

    def _start(self) -> int:
        if self._server is not None:
            raise RuntimeError("Proxy server is already running")
        # ProxyServer maps its ``:memory:`` convenience mode to a disposable
        # file. This is a proxy lifecycle choice; AuditDB itself also supports
        # shared in-memory databases.
        if self.db_path == ":memory:":
            fd, self._tmp_db_path = tempfile.mkstemp(suffix=".panoptes.db")
            os.close(fd)
            actual_db_path = self._tmp_db_path
            log.debug("Using temporary DB for :memory: mode: %s", actual_db_path)
        else:
            actual_db_path = self.db_path

        try:
            if self._external_db is not None:
                self._db = self._external_db  # the caller owns it
            else:
                self._db = AuditDB(actual_db_path, chain=self.chain)
            self._http_client = _upstream_client(_UPSTREAM_TIMEOUT_SECONDS)
            self.writer = AuditEventWriter(
                self._db,
                max_tool_events_per_exchange=self.max_tool_events_per_exchange,
                pricing=self.pricing,
            )
            config = ProxyConfig(
                writer=self.writer,
                forwarder=Forwarder(
                    self._http_client,
                    max_buffered_response_bytes=self.max_buffered_response_bytes,
                    max_audit_stream_bytes=self.max_audit_stream_bytes,
                ),
                upstreams=self.upstreams,
                max_request_body_bytes=self.max_request_body_bytes,
                new_lifecycle=self._lifecycle(),
            )
            self._server = BoundedThreadingHTTPServer(
                (self.host, self.port),
                functools.partial(ProxyHandler, config=config),
                client_socket_timeout_seconds=self.client_socket_timeout_seconds,
                max_concurrent_requests=self.max_concurrent_requests,
            )
            self.port = self._server.server_address[1]

            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="panoptes-proxy",
                daemon=True,
            )
            self._thread.start()
        except Exception:
            self._cleanup_resources(start_failed=True)
            raise

        log.info("Panoptes proxy listening on %s:%d", self.host, self.port)
        log.info(
            "Reverse-proxy mode: ANTHROPIC_BASE_URL=http://%s:%d", self.host, self.port
        )
        log.info(
            "Reverse-proxy mode: OPENAI_BASE_URL=http://%s:%d/v1", self.host, self.port
        )
        return self.port

    def stop(self) -> None:
        """Stop the proxy server and release resources."""
        with self._lifecycle_lock:
            self._cleanup_resources(start_failed=False)
        log.info("Panoptes proxy stopped")

    def _cleanup_resources(self, *, start_failed: bool) -> None:
        """Release partially or fully initialized server resources."""
        if self._server is not None:
            if (
                not start_failed
                and self._thread is not None
                and self._thread.is_alive()
            ):
                self._server.shutdown()
            self._server.server_close()
            if not start_failed and not self._server.wait_idle(_STOP_GRACE_SECONDS):
                log.warning(
                    "Stopping with exchanges still in flight after %ss",
                    _STOP_GRACE_SECONDS,
                )
            self._server = None
        if self._thread is not None:
            if self._thread.is_alive():
                self._thread.join(timeout=5)
            self._thread = None
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None
        if self._db is not None:
            if self._db is not self._external_db:
                self._db.close()
            self._db = None
        self.writer = None
        if self._tmp_db_path is not None:
            try:
                os.unlink(self._tmp_db_path)
            except OSError:
                pass
            self._tmp_db_path = None

    @property
    def events(self) -> list[dict]:
        if self._db is not None:
            return self._db.query()
        return []


# ---------------------------------------------------------------------------
# Public start function (called from panoptes.cli)
# ---------------------------------------------------------------------------


def start_proxy(
    port: int = 8081,
    host: str = "127.0.0.1",
    db_path: str = "~/.panoptes/audit.db",
    log_level: str = "INFO",
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES,
    max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
    max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES,
    max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
    client_socket_timeout_seconds: float = DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS,
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    pricing: Any = None,
) -> None:
    """Start the audit proxy server (called from panoptes.cli)."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    db_path_expanded = os.path.expanduser(db_path)
    # port 0 (or None) lets the OS pick a free port; ProxyServer.start()
    # reads the actual bound port back from the socket.
    port = port or 0

    server = ProxyServer(
        host=host,
        port=port,
        db_path=db_path_expanded,
        max_request_body_bytes=max_request_body_bytes,
        max_buffered_response_bytes=max_buffered_response_bytes,
        max_audit_stream_bytes=max_audit_stream_bytes,
        max_tool_events_per_exchange=max_tool_events_per_exchange,
        client_socket_timeout_seconds=client_socket_timeout_seconds,
        max_concurrent_requests=max_concurrent_requests,
        pricing=pricing,
    )
    actual_port = server.start()

    print(f"Panoptes proxy running on http://{host}:{actual_port}")
    print(f"Database: {db_path_expanded}")
    print()
    print("Reverse-proxy mode (recommended — captures HTTPS traffic):")
    print(f"  export ANTHROPIC_BASE_URL=http://{host}:{actual_port}")
    print(f"  export OPENAI_BASE_URL=http://{host}:{actual_port}/v1")
    print()
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()
