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
"""

from __future__ import annotations

import http.cookiejar
import http.server
import ipaddress
import json
import logging
import os
import socket
import tempfile
import threading
import time
from typing import Any
from urllib.parse import unquote_plus, urlparse

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

from panoptes._hooked import (
    HookedExchangeMixin,
    _answer_if_client_present,
    _ExchangeRun,
    _may_have_reached_upstream,
    _report_of,
    _start_drain_timer,
    _upstream_url,
)
from panoptes._events import (  # noqa: F401 — re-exported for callers
    DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
    AmbiguousResponseError,
    AuditEventWriter,
    AuditWriteError,
    ResponseInspectionError,
    _mark_inspection_failure,
    _parse_provider_response,
    _parse_sse_response,
    detect_agent_type,
)
from panoptes._server import BoundedThreadingHTTPServer
from panoptes.db import AuditDB
from panoptes.hooks import (
    QUERY_CREDENTIAL_PARAMS,
    ProxyHooks,
    Upstream,
)
from panoptes.schema import (
    ValidationError,
)

import panoptes.providers as _providers
from panoptes.providers.base import (
    SSEParseError,
    _parse_sse_events,  # noqa: F401 — re-exported for callers
    _strict_json_loads,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

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
# stop() waits this long for in-flight exchanges (the upstream read timeout).
_STOP_GRACE_SECONDS = 120.0

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


# ---------------------------------------------------------------------------
# Upstream routing (reverse-proxy mode)
# ---------------------------------------------------------------------------

_ENV_ANTHROPIC = "PANOPTES_UPSTREAM_ANTHROPIC"
_ENV_OPENAI = "PANOPTES_UPSTREAM_OPENAI"
_ENV_GEMINI = "PANOPTES_UPSTREAM_GEMINI"

_PROVIDER_ENV: dict[str, str] = {
    "anthropic": _ENV_ANTHROPIC,
    "openai": _ENV_OPENAI,
    "gemini": _ENV_GEMINI,
}


class ProxyRequestError(ValueError):
    """A client-visible proxy request error."""

    status_code = 400


class NoUpstreamError(ProxyRequestError):
    """Raised when no upstream can be determined for a reverse-proxy path."""

    status_code = 502


class RequestFramingError(ProxyRequestError):
    """Raised when request-body framing is unsupported or ambiguous."""

    status_code = 400


class RequestBodyTooLarge(ProxyRequestError):
    """Raised before an oversized client body is read."""

    status_code = 413


class UpstreamBodyTooLarge(RuntimeError):
    """Raised when a buffered upstream response exceeds its hard limit."""

    def __init__(
        self,
        limit: int,
        *,
        upstream_status: int | None = None,
        upstream_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(f"upstream response exceeded {limit} bytes")
        self.limit = limit
        self.upstream_status = upstream_status
        self.upstream_headers = upstream_headers or {}


def _parse_upstream_url(url: str, default_scheme: str = "https") -> tuple[str, str, int]:
    """Parse and validate a configured upstream URL.

    Only HTTP(S) upstreams without embedded credentials, query strings, or
    fragments are accepted. A bare hostname remains supported for compatibility.
    """
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"{default_scheme}://{candidate}"
    p = urlparse(candidate)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise NoUpstreamError(f"Unsupported upstream URL scheme: {scheme or '<missing>'}")
    if p.username is not None or p.password is not None:
        raise NoUpstreamError("Upstream URLs must not contain credentials")
    if p.query or p.fragment:
        raise NoUpstreamError("Upstream base URLs must not contain a query or fragment")
    if p.path not in ("", "/"):
        raise NoUpstreamError("Upstream base URLs must not contain a path")
    host = (p.hostname or "").rstrip(".").lower()
    if not host:
        raise NoUpstreamError("Upstream URL is missing a hostname")
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise NoUpstreamError(f"Invalid upstream port: {exc}") from exc
    return scheme, host, port


# ---------------------------------------------------------------------------
# HTTP proxy handler
# ---------------------------------------------------------------------------

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "trailers", "transfer-encoding",
    "upgrade",
})
PANOPTES_INTERNAL_HEADERS = frozenset({
    "x-panoptes-agent",
    "x-panoptes-session",
    "x-panoptes-correlation-id",
})

def _strip_query_credentials(
    path: str,
    names: frozenset[str] = frozenset({"key"}),
    *,
    fold: bool = False,
) -> tuple[str, list[str]]:
    """Remove every credential query parameter, returning the path and values.

    ``names`` are matched after percent-decoding, case-insensitively when
    ``fold`` is set. Other parameters keep their original encoding and order.
    """
    base, sep, query = path.partition("?")
    if not sep:
        return path, []
    query, hash_sep, fragment = query.partition("#")
    kept: list[str] = []
    values: list[str] = []
    for part in query.split("&"):
        name, _, value = part.partition("=")
        decoded = unquote_plus(name)
        if (decoded.lower() if fold else decoded) in names:
            values.append(unquote_plus(value))
        else:
            kept.append(part)
    stripped = base + ("?" + "&".join(kept) if kept else "")
    return stripped + (hash_sep + fragment if hash_sep else ""), values


def _merged_headers(items: Any) -> dict[str, str]:
    """Combine repeated request headers instead of keeping only the last.

    RFC 9110 lets a recipient join repeated fields with commas (Cookie uses
    "; "), so e.g. two ``anthropic-beta`` lines both reach the upstream.
    """
    merged: dict[str, str] = {}
    names: dict[str, str] = {}
    for key, value in items:
        lowered = key.lower()
        if lowered not in names:
            names[lowered] = key
            merged[key] = value
            continue
        first = names[lowered]
        separator = "; " if lowered == "cookie" else ", "
        merged[first] = f"{merged[first]}{separator}{value}"
    return merged


def _upstream_client(timeout: float) -> httpx.Client:
    """An upstream client whose cookie jar never stores anything.

    One client serves every session and token, so a stored ``Set-Cookie``
    would be replayed on other agents' requests and link or leak sessions.
    """
    # httpx logs every request URL at INFO, query string included, and a
    # credentialed URL would land in the log.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    no_cookies = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[])
    )
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        cookies=no_cookies,
    )


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    connection_nominated: set[str] = set()
    for key, value in headers.items():
        if key.lower() != "connection":
            continue
        connection_nominated.update(
            token.strip().lower()
            for token in str(value).split(",")
            if token.strip()
        )
    blocked = HOP_BY_HOP | connection_nominated
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


# Codings httpx always decodes; br and zstd depend on optional packages and
# would otherwise pass through as raw bytes under a stripped header.
_DECODABLE_CONTENT_CODINGS = frozenset({"identity", "gzip", "deflate"})


def _check_content_encoding(headers: Any) -> None:
    """Refuse an upstream body Panoptes cannot decode, inspect, or relay."""
    for value in _header_values(headers, "Content-Encoding"):
        for coding in value.split(","):
            coding = coding.strip().lower()
            if coding and coding not in _DECODABLE_CONTENT_CODINGS:
                raise ResponseInspectionError(
                    f"Unsupported upstream Content-Encoding {coding!r}"
                )


def _decoded_body_headers(
    headers: dict[str, str],
    *,
    streaming: bool,
) -> dict[str, str]:
    """Headers safe to forward after ``httpx.iter_bytes`` decoded the body."""
    filtered = _filter_headers(headers)
    return {
        key: value
        for key, value in filtered.items()
        if key.lower() != "content-encoding"
        and (not streaming or key.lower() != "content-length")
    }


def _header_values(headers: Any, name: str) -> list[str]:
    """Return all values for a header from HTTPMessage-like or mapping objects."""
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        return [str(value) for value in (values or [])]
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        values = get_list(name)
        return [str(value) for value in (values or [])]
    return [
        str(value)
        for key, value in getattr(headers, "items", lambda: [])()
        if str(key).lower() == name.lower()
    ]


def _safe_upstream_label(scheme: str, host: str, port: int, path: str) -> str:
    """Return a log label that cannot expose query-string credentials."""
    return _upstream_url(scheme, host, port, urlparse(path).path or "/")


def _unpersisted_exchange_events(
    req_events: list[dict],
    resp_events: list[dict],
    exchange_ctx: dict,
) -> list[dict]:
    """Avoid duplicating request events already made durable pre-forward."""
    if exchange_ctx.get("_request_events_persisted"):
        return resp_events
    return req_events + resp_events


def _outbound(
    handler: Any,
    headers: dict[str, str],
    path: str,
) -> tuple[dict[str, str], str]:
    """The headers and path to forward: a hook's choice, or the default."""
    run = getattr(handler, "_run", None)
    if run is not None and run.fwd_headers is not None:
        return run.fwd_headers, run.forward_path or path
    return handler._build_fwd_headers(headers), path


class ProxyHandler(HookedExchangeMixin, http.server.BaseHTTPRequestHandler):
    """HTTP reverse-proxy request handler."""

    writer: AuditEventWriter | None = None
    http_client: httpx.Client | None = None  # shared per-server instance
    upstream_timeout: float = 120.0
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES
    max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES
    # Hook seam. ``upstreams`` maps a wire protocol to (name, Upstream).
    hooks: ProxyHooks | None = None
    upstreams: dict[str, tuple[str, Upstream]] = {}
    disconnect_drain_seconds: float = 30.0
    hook_slow_seconds: float = 5.0
    _run: _ExchangeRun | None = None
    _upstream_name: str = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        safe_args = list(args)
        request_line = getattr(self, "requestline", "")
        if safe_args and request_line and safe_args[0] == request_line:
            safe_path = urlparse(getattr(self, "path", "")).path or "/"
            safe_args[0] = (
                f"{getattr(self, 'command', '')} {safe_path} "
                f"{getattr(self, 'request_version', '')}"
            ).strip()
        raw_path = getattr(self, "path", "")
        safe_path = urlparse(raw_path).path or "/"
        if raw_path and raw_path != safe_path:
            safe_args = [
                value.replace(raw_path, safe_path)
                if isinstance(value, str)
                else value
                for value in safe_args
            ]
        log.info(fmt % tuple(safe_args))

    # ------------------------------------------------------------------
    # Target parsing
    # ------------------------------------------------------------------

    def _parse_target(self) -> tuple[str, str, int, str]:
        """Parse the request line into (scheme, host, port, path).

        Requests use origin-form paths and are routed by provider pattern.
        """
        parsed = urlparse(self.path)

        if parsed.scheme or parsed.netloc:
            raise ProxyRequestError(
                "Absolute-form targets are not supported; configure the client "
                "to use Panoptes as its API base URL"
            )

        # Reverse-proxy mode — relative path; consult provider registry
        path = self.path
        if not path.startswith("/"):
            raise ProxyRequestError("Reverse-proxy targets must use origin-form paths")

        for provider in _providers.REGISTRY:
            if provider.matches_path(path):
                # Precedence: upstreams=, then the environment, then the
                # provider's public API.
                configured = getattr(self, "upstreams", {}).get(provider.name)
                env_var = _PROVIDER_ENV.get(provider.name)
                env_val = os.environ.get(env_var) if env_var else None
                self._upstream_name = provider.name
                if configured is not None:
                    self._upstream_name, upstream = configured
                    s, h, p = _parse_upstream_url(upstream.origin)
                elif env_val:
                    s, h, p = _parse_upstream_url(env_val)
                else:
                    s, h, p = _parse_upstream_url(provider.default_upstream)
                return s, h, p, path

        safe_path = urlparse(path).path or "/"
        raise NoUpstreamError(
            f"No supported provider route for path '{safe_path}'"
        )

    # ------------------------------------------------------------------
    # Request body
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        transfer_encoding = _header_values(self.headers, "Transfer-Encoding")
        content_lengths = _header_values(self.headers, "Content-Length")

        if transfer_encoding and content_lengths:
            raise RequestFramingError(
                "Ambiguous request framing: both Transfer-Encoding and Content-Length"
            )
        if transfer_encoding:
            # BaseHTTPRequestHandler does not decode request transfer codings.
            # Treating a chunked body as empty would let opaque bytes reach the
            # next request and can bypass policy inspection.
            raise RequestFramingError(
                "Transfer-Encoding request bodies are not supported"
            )
        if len(content_lengths) > 1:
            raise RequestFramingError("Multiple Content-Length headers are not allowed")
        if not content_lengths:
            return b""

        raw_length = content_lengths[0].strip()
        if not raw_length or "," in raw_length:
            raise RequestFramingError("Ambiguous Content-Length header")
        try:
            content_length = int(raw_length, 10)
        except ValueError as exc:
            raise RequestFramingError("Invalid Content-Length header") from exc
        if content_length < 0:
            raise RequestFramingError("Content-Length must not be negative")

        limit = getattr(
            self, "max_request_body_bytes", DEFAULT_MAX_REQUEST_BODY_BYTES
        )
        if content_length > limit:
            raise RequestBodyTooLarge(
                f"Request body exceeds the {limit}-byte limit"
            )
        if content_length == 0:
            return b""

        try:
            body = self.rfile.read(content_length)
        except OSError as exc:
            raise RequestFramingError("Failed to read the complete request body") from exc
        if len(body) != content_length:
            raise RequestFramingError(
                "Request body ended before the declared Content-Length"
            )
        return body

    # ------------------------------------------------------------------
    # Upstream forwarding
    # ------------------------------------------------------------------

    def _build_fwd_headers(self, headers: dict[str, str]) -> dict[str, str]:
        fwd = {
            key: value
            for key, value in _filter_headers(dict(headers)).items()
            if key.lower() not in PANOPTES_INTERNAL_HEADERS
            and key.lower() not in ("host", "accept-encoding")
        }
        # Replaced case-insensitively: a client's lowercase accept-encoding
        # would otherwise go upstream beside this one and invite br/zstd
        # bodies that reach the client undecoded and the audit unparsed.
        fwd["Accept-Encoding"] = "identity"
        return fwd

    def _get_client(self) -> tuple[httpx.Client, bool]:
        """Return (client, owned). If owned=True, caller must close it."""
        if self.http_client is not None:
            return self.http_client, False
        return _upstream_client(self.upstream_timeout), True

    def _forward_request(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        """Buffered forward: return (status, headers, body_bytes)."""
        fwd_headers, path = _outbound(self, headers, path)
        upstream_url = _upstream_url(scheme, host, port, path)
        safe_label = _safe_upstream_label(scheme, host, port, path)
        report = _report_of(self)
        client, owned = self._get_client()
        limit = getattr(
            self,
            "max_buffered_response_bytes",
            DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
        )
        try:
            with client.stream(
                method, upstream_url, headers=fwd_headers, content=body
            ) as resp:
                report.request_sent = report.answered = True
                report.upstream_status = resp.status_code
                response_headers = dict(resp.headers)
                _check_content_encoding(resp.headers)
                content_lengths = _header_values(resp.headers, "Content-Length")
                transfer_encodings = _header_values(
                    resp.headers, "Transfer-Encoding"
                )
                if content_lengths and transfer_encodings:
                    raise ResponseInspectionError(
                        "Ambiguous upstream response framing"
                    )
                if len(content_lengths) > 1:
                    raise ResponseInspectionError(
                        "Multiple upstream Content-Length headers"
                    )
                if content_lengths:
                    raw_length = content_lengths[0].strip()
                    if not raw_length or "," in raw_length:
                        raise ResponseInspectionError(
                            "Ambiguous upstream Content-Length header"
                        )
                    try:
                        declared_length = int(raw_length, 10)
                    except ValueError as exc:
                        raise ResponseInspectionError(
                            "Invalid upstream Content-Length header"
                        ) from exc
                    if declared_length < 0:
                        raise ResponseInspectionError(
                            "Negative upstream Content-Length header"
                        )
                    if declared_length > limit:
                        report.body_bytes = declared_length
                        raise UpstreamBodyTooLarge(
                            limit,
                            upstream_status=resp.status_code,
                            upstream_headers=response_headers,
                        )

                accumulated = bytearray()
                for chunk in resp.iter_bytes():
                    if not chunk:
                        continue
                    report.body_bytes += len(chunk)
                    if len(accumulated) + len(chunk) > limit:
                        raise UpstreamBodyTooLarge(
                            limit,
                            upstream_status=resp.status_code,
                            upstream_headers=response_headers,
                        )
                    accumulated.extend(chunk)
                return (
                    resp.status_code,
                    _decoded_body_headers(response_headers, streaming=False),
                    bytes(accumulated),
                )
        except UpstreamBodyTooLarge:
            report.upstream_error = True
            raise
        except ResponseInspectionError:
            log.exception("Unsafe upstream response framing from %s", safe_label)
            report.upstream_error = True
            return (
                502,
                {"content-type": "application/json"},
                json.dumps({"error": "Unsafe upstream response framing"}).encode(),
            )
        except httpx.TimeoutException as exc:
            log.error("Upstream timeout: %s %s", method, safe_label)
            report.upstream_error = True
            report.request_sent |= _may_have_reached_upstream(exc)
            return 504, {"content-type": "application/json"}, json.dumps({"error": "Gateway Timeout"}).encode()
        except httpx.ConnectError:
            log.error("Upstream connect error: %s %s", method, safe_label)
            report.upstream_error = True
            return 502, {"content-type": "application/json"}, json.dumps({"error": "Bad Gateway"}).encode()
        except Exception as exc:
            log.exception("Upstream error: %s %s", method, safe_label)
            report.upstream_error = True
            report.request_sent |= _may_have_reached_upstream(exc)
            return 502, {"content-type": "application/json"}, json.dumps({"error": "Bad Gateway"}).encode()
        finally:
            if owned:
                client.close()

    def _forward_streaming(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes, bool]:
        """Relay a stream while keeping a bounded audit capture.

        Sends HTTP status + headers to the client, then streams the body.
        Returns ``(status, headers, accumulated_bytes, audit_truncated)``.
        Truncated bytes are never used for response-side enforcement: any
        enforcement-capable stream takes the bounded pre-delivery path instead.
        """
        fwd_headers, path = _outbound(self, headers, path)
        upstream_url = _upstream_url(scheme, host, port, path)
        safe_label = _safe_upstream_label(scheme, host, port, path)
        report = _report_of(self)
        accumulated = bytearray()
        audit_truncated = False
        audit_limit = getattr(
            self, "max_audit_stream_bytes", DEFAULT_MAX_AUDIT_STREAM_BYTES
        )
        # Hooks owe usage even if the client leaves: keep reading the upstream
        # for a bounded time. Without hooks a disconnect ends the relay as before.
        hooked = getattr(self, "hooks", None) is not None
        drain_seconds = (
            getattr(self, "disconnect_drain_seconds", 30.0) if hooked else 0.0
        )
        client, owned = self._get_client()
        response_started = False

        try:
            with client.stream(method, upstream_url, headers=fwd_headers, content=body) as resp:
                report.request_sent = report.answered = True
                report.upstream_status = resp.status_code
                _check_content_encoding(resp.headers)
                # Send status and headers to client (strip Content-Length — unknown)
                resp_headers = _decoded_body_headers(
                    dict(resp.headers), streaming=True
                )
                self.send_response(resp.status_code)
                for k, v in resp_headers.items():
                    self.send_header(k, v)
                self.end_headers()
                response_started = True

                # Stream body
                drain_deadline: float | None = None
                drain_timer: threading.Timer | None = None
                drain_expired: threading.Event | None = None
                try:
                    for chunk in resp.iter_bytes():
                        if not chunk:
                            continue
                        report.body_bytes += len(chunk)
                        if not audit_truncated:
                            remaining = audit_limit - len(accumulated)
                            if remaining > 0:
                                accumulated.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                audit_truncated = True
                        if drain_deadline is not None:
                            if audit_truncated or time.monotonic() > drain_deadline:
                                audit_truncated = True
                                break
                            continue
                        try:
                            self.wfile.write(chunk)
                        except OSError:
                            if drain_seconds <= 0:
                                raise
                            report.client_gone = True
                            drain_deadline = time.monotonic() + drain_seconds
                            drain_timer, drain_expired = _start_drain_timer(
                                resp, drain_seconds
                            )
                    if not report.client_gone:
                        self.wfile.flush()
                except Exception:
                    audit_truncated = True
                    log.exception("Error mid-stream from %s", safe_label)
                finally:
                    if drain_timer is not None:
                        drain_timer.cancel()
                if drain_expired is not None and drain_expired.is_set():
                    # A cut connection can look like a clean end of stream.
                    audit_truncated = True

                if hooked:
                    # Tell the client the stream is over now; the connection
                    # would otherwise stay open until this handler returns.
                    self._end_client_stream()

                return (
                    resp.status_code,
                    resp_headers,
                    bytes(accumulated),
                    audit_truncated,
                )

        except httpx.TimeoutException as exc:
            log.error("Upstream timeout (streaming): %s %s", method, safe_label)
            report.upstream_error = True
            report.request_sent |= _may_have_reached_upstream(exc)
            if not response_started:
                _answer_if_client_present(self, 504, "Gateway Timeout")
            return 504, {"content-type": "application/json"}, b"", True
        except httpx.ConnectError:
            log.error("Upstream connect error (streaming): %s %s", method, safe_label)
            report.upstream_error = True
            if not response_started:
                _answer_if_client_present(self, 502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b"", True
        except Exception as exc:
            log.exception("Upstream streaming error: %s %s", method, safe_label)
            report.upstream_error = True
            report.request_sent |= _may_have_reached_upstream(exc)
            if not response_started:
                _answer_if_client_present(self, 502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b"", True
        finally:
            if owned:
                client.close()

    def _end_client_stream(self) -> None:
        """Half-close the client connection so a close-delimited body ends."""
        self.close_connection = True
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _send_json_error(self, status: int, message: str, extra: dict | None = None) -> None:
        body: dict[str, Any] = {"error": message}
        if extra:
            body.update(extra)
        body_bytes = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    # ------------------------------------------------------------------
    # Main request handler
    # ------------------------------------------------------------------

    def _serve_request(self, method: str) -> None:
        """Run one proxied request and settle its hooks however it ends."""
        self._exchange_ctx: dict = {}
        self._run = None
        try:
            self._handle_request(method)
        finally:
            self._finish_run()

    def _handle_request(self, method: str) -> None:
        """Handle a proxied request: parse → record → forward → record → respond."""
        t0 = time.monotonic()

        hooks = getattr(self, "hooks", None)
        query_credentials: list[str] = []
        raw_path = ""
        if hooks is not None:
            raw_path = self.path
            # Routing and every recorded path use the stripped form. What is
            # forwarded is the hook's choice (drop_query_credentials()).
            self.path, query_credentials = _strip_query_credentials(
                self.path, QUERY_CREDENTIAL_PARAMS, fold=True
            )

        # 1. Parse target and read body
        try:
            scheme, host, port, path = self._parse_target()
            req_headers = _merged_headers(self.headers.items())
            body = self._read_body()
        except ProxyRequestError as exc:
            self._send_json_error(exc.status_code, str(exc))
            return
        except Exception:
            log.exception("Failed to parse proxy request")
            self.send_error(400, "Bad Request")
            return

        # 2. Parse request body
        req_body: dict | None = None
        if body:
            try:
                req_body = _strict_json_loads(body)
            except (json.JSONDecodeError, ValueError):
                self._send_json_error(
                    400,
                    "Supported provider requests must be unambiguous valid JSON",
                )
                return
            if not isinstance(req_body, dict):
                self._send_json_error(
                    400, "Supported provider requests must contain a JSON object"
                )
                return

        # 3. Build request events
        writer = self.writer
        req_events: list[dict] = []
        exchange_ctx: dict = {}

        if writer:
            try:
                req_events, exchange_ctx = writer.build_request_events(
                    path=path, method=method, req_headers=req_headers,
                    req_body=req_body,
                    hook_mode=hooks is not None,
                )
                self._exchange_ctx = exchange_ctx
            except (ValidationError, SSEParseError, ValueError) as exc:
                log.warning("Rejected invalid proxy audit context: %s", exc)
                self._send_json_error(
                    400, "Request metadata cannot be represented safely"
                )
                return
            except Exception:
                log.exception("Request event construction failed — continuing")
            if hooks is not None:
                run = self._enter_exchange(
                    method=method, path=path, raw_path=raw_path,
                    target=(scheme, host, port), req_headers=req_headers,
                    body=body, req_body=req_body, req_events=req_events,
                    exchange_ctx=exchange_ctx, query_credentials=query_credentials,
                    t0=t0,
                )
                if not self._run_before_forward(run):
                    return
                req_events, exchange_ctx = run.events, run.ctx
                self._exchange_ctx = exchange_ctx
            elif req_events:
                # Make the request intent durable before it leaves the process.
                # A storage outage is logged; it does not stop the request.
                try:
                    writer.write(req_events)
                    exchange_ctx["_request_events_persisted"] = True
                except AuditWriteError:
                    log.exception("Request-intent audit could not be persisted")

        # 4. Forward to upstream (streaming decided by the provider — body
        #    flag for OpenAI/Anthropic, URL path for Gemini)
        handler = (
            self._handle_streaming
            if _providers.detect(path, req_body).is_streaming(path, req_body)
            else self._handle_buffered
        )
        handler(
            method=method, scheme=scheme, host=host, port=port, path=path,
            req_headers=req_headers, body=body, req_body=req_body,
            req_events=req_events, exchange_ctx=exchange_ctx, t0=t0,
        )

    def _handle_streaming(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        req_headers: dict[str, str],
        body: bytes,
        req_body: dict | None,
        req_events: list[dict],
        exchange_ctx: dict,
        t0: float,
    ) -> None:
        """Relay a streamed model response and record it after delivery."""
        writer = self.writer
        resp_status, resp_headers_raw, accumulated, audit_truncated = (
            self._forward_streaming(
                method, scheme, host, port, path, req_headers, body,
            )
        )
        duration_ms = int((time.monotonic() - t0) * 1000)
        run = getattr(self, "_run", None)
        if run is not None:
            self._set_outcome(
                "upstream_error" if run.report.upstream_error else "forwarded",
                resp_status,
            )

        if not writer:
            return

        resp_body: dict | None = None
        inspection_error: str | None = None
        if audit_truncated:
            inspection_error = (
                "Audit capture limit reached during pass-through streaming; "
                "response was not fully inspected"
            )
        elif accumulated:
            try:
                resp_body = _parse_provider_response(
                    accumulated, resp_headers_raw, exchange_ctx
                )
            except ResponseInspectionError as exc:
                inspection_error = str(exc)

        try:
            resp_events = writer.build_response_events(
                path=path, req_body=req_body, resp_status=resp_status,
                resp_headers=resp_headers_raw, resp_body=resp_body,
                duration_ms=duration_ms, exchange_ctx=exchange_ctx,
            )
            if inspection_error:
                _mark_inspection_failure(
                    resp_events,
                    inspection_error,
                    blocked=False,
                    truncated=audit_truncated,
                )
            if run is not None:
                self._note_response(
                    resp_events, exchange_ctx, resp_body,
                    read_in_full=not audit_truncated,
                    inspection_error=inspection_error,
                )
            writer.write(
                _unpersisted_exchange_events(
                    req_events, resp_events, exchange_ctx
                )
            )
        except ValidationError as exc:
            message = (
                "Pass-through response produced invalid audit events after delivery"
            )
            log.warning("%s: %s", message, exc)
            try:
                fallback_events = writer.build_response_events(
                    path=path,
                    req_body=req_body,
                    resp_status=resp_status,
                    resp_headers=resp_headers_raw,
                    resp_body=None,
                    duration_ms=duration_ms,
                    exchange_ctx=exchange_ctx,
                )
                _mark_inspection_failure(
                    fallback_events, f"{message}: {exc}", blocked=False
                )
                writer.write(
                    _unpersisted_exchange_events(
                        req_events, fallback_events, exchange_ctx
                    )
                )
            except Exception:
                log.exception("Failed to persist streaming audit fallback")
        except AuditWriteError:
            log.exception(
                "Pass-through response audit was not durable after delivery"
            )
        except Exception:
            log.exception("Failed to process streaming audit events — continuing")

    def _handle_buffered(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        req_headers: dict[str, str],
        body: bytes,
        req_body: dict | None,
        req_events: list[dict],
        exchange_ctx: dict,
        t0: float,
    ) -> None:
        """Buffered path: forward the whole reply, record it, then deliver it."""
        writer = self.writer

        def build_inspection_failure(
            message: str,
            *,
            status: int,
            headers: dict,
            blocked: bool,
            truncated: bool = False,
        ) -> list[dict]:
            events = writer.build_response_events(
                path=path, req_body=req_body, resp_status=status,
                resp_headers=headers, resp_body=None,
                duration_ms=duration_ms, exchange_ctx=exchange_ctx,
            )
            _mark_inspection_failure(
                events, message, blocked=blocked, truncated=truncated
            )
            return events

        try:
            resp_status, resp_headers_raw, resp_body_bytes = self._forward_request(
                method, scheme, host, port, path, req_headers, body,
            )
        except UpstreamBodyTooLarge as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            self._set_outcome("upstream_error", 502)
            message = (
                "Upstream response denied because it exceeded the "
                f"{exc.limit}-byte inspection limit"
            )
            if writer:
                resp_events = build_inspection_failure(
                    message,
                    status=exc.upstream_status or 502,
                    headers=exc.upstream_headers, blocked=True, truncated=True,
                )
                try:
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, resp_events, exchange_ctx
                        )
                    )
                except AuditWriteError:
                    log.exception(
                        "Oversized-response denial audit was not durable"
                    )
            self._send_json_error(
                502,
                message,
                {"inspection_error": True, "response_too_large": True},
            )
            return

        duration_ms = int((time.monotonic() - t0) * 1000)

        resp_body_parsed: dict | None = None
        inspection_error: str | None = None
        ambiguous_response = False
        if resp_body_bytes:
            try:
                resp_body_parsed = _parse_provider_response(
                    resp_body_bytes, resp_headers_raw, exchange_ctx
                )
            except AmbiguousResponseError as exc:
                inspection_error = str(exc)
                ambiguous_response = True
            except ResponseInspectionError as exc:
                inspection_error = str(exc)

        parse_failed = inspection_error is not None

        if ambiguous_response:
            # Two readings of one object: the client could act on a different
            # one than the audit recorded, so the reply is withheld.
            message = (
                "Upstream response denied because it could not be safely inspected"
            )
            resp_events = build_inspection_failure(
                f"{message}: {inspection_error}",
                status=resp_status, headers=resp_headers_raw, blocked=True,
            )
            resp_status = 502
            resp_body_bytes = json.dumps({
                "error": message,
                "inspection_error": True,
            }).encode()
            resp_headers_raw = {
                "content-type": "application/json",
                "x-panoptes-inspection-blocked": "true",
            }
            try:
                writer.write(  # type: ignore[union-attr]
                    _unpersisted_exchange_events(
                        req_events, resp_events, exchange_ctx
                    )
                )
            except AuditWriteError:
                log.exception(
                    "Uninspectable-response denial audit was not durable"
                )
            inspection_error = None  # denial has already been persisted
            writer = None  # nothing further to record for an opaque body

        if writer:
            resp_events: list[dict] = []
            try:
                resp_events = writer.build_response_events(
                    path=path, req_body=req_body, resp_status=resp_status,
                    resp_headers=resp_headers_raw, resp_body=resp_body_parsed,
                    duration_ms=duration_ms, exchange_ctx=exchange_ctx,
                )
                if inspection_error:
                    _mark_inspection_failure(
                        resp_events, inspection_error, blocked=False
                    )
                run = getattr(self, "_run", None)
                if run is not None:
                    self._note_response(
                        resp_events, exchange_ctx, resp_body_parsed,
                        read_in_full=True,
                        inspection_error="unparsed" if parse_failed else None,
                    )
                writer.write(
                    _unpersisted_exchange_events(
                        req_events, resp_events, exchange_ctx
                    )
                )
            except AuditWriteError:
                log.exception("Response audit could not be persisted")
            except ValidationError as exc:
                message = (
                    "Upstream response denied because its audit events were invalid"
                )
                log.warning("%s: %s", message, exc)
                try:
                    fallback_events = build_inspection_failure(
                        f"{message}: {exc}",
                        status=resp_status, headers=resp_headers_raw, blocked=True,
                    )
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, fallback_events, exchange_ctx
                        )
                    )
                except Exception:
                    log.exception(
                        "Failed to persist invalid response audit fallback"
                    )
                resp_status = 502
                resp_body_bytes = json.dumps({
                    "error": message,
                    "inspection_error": True,
                }).encode()
                resp_headers_raw = {
                    "content-type": "application/json",
                    "x-panoptes-inspection-blocked": "true",
                }
            except Exception as exc:
                log.exception(
                    "Response event construction failed; recording an "
                    "explicit incomplete fallback"
                )
                try:
                    fallback_events = build_inspection_failure(
                        f"Response event construction failed: {exc}",
                        status=resp_status, headers=resp_headers_raw,
                        blocked=False,
                    )
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, fallback_events, exchange_ctx
                        )
                    )
                except Exception:
                    log.exception(
                        "Failed to build the incomplete response fallback"
                    )

        # Send response to client
        run = getattr(self, "_run", None)
        if run is not None:
            self._set_outcome(
                "upstream_error" if run.report.upstream_error else "forwarded",
                resp_status,
            )
        try:
            self.send_response(resp_status)
            filtered_headers = _decoded_body_headers(
                dict(resp_headers_raw), streaming=False
            )
            filtered_headers = {
                key: value
                for key, value in filtered_headers.items()
                if key.lower() != "content-length"
            }
            for key, val in filtered_headers.items():
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(resp_body_bytes)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(resp_body_bytes)
        except OSError:
            if run is None:
                raise
            # The upstream answered; a client that left changes nothing about
            # what Panoptes read.
            log.warning("Client disconnected before the response was written")

    def do_GET(self) -> None:
        self._serve_request("GET")

    def do_POST(self) -> None:
        self._serve_request("POST")

# Kept for callers that imported the private name.
_BoundedThreadingHTTPServer = BoundedThreadingHTTPServer


# ---------------------------------------------------------------------------
# ProxyServer
# ---------------------------------------------------------------------------


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
            raise ValueError(
                f"Refusing non-loopback proxy bind host {host!r}"
            )
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
        self._server: http.server.HTTPServer | None = None
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
                raise TypeError(
                    f"upstreams[{protocol!r}] must be an Upstream"
                )
            resolved[protocol] = (upstream.name or protocol, upstream)
        return resolved

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
            self._http_client = _upstream_client(120.0)
            self.writer = AuditEventWriter(
                self._db,
                max_tool_events_per_exchange=self.max_tool_events_per_exchange,
                pricing=self.pricing,
            )

            _writer = self.writer
            _http_client = self._http_client
            _max_request_body_bytes = self.max_request_body_bytes
            _max_buffered_response_bytes = self.max_buffered_response_bytes
            _max_audit_stream_bytes = self.max_audit_stream_bytes
            _hooks = self.hooks
            _upstreams = self.upstreams
            _drain = self.disconnect_drain_seconds
            _slow = self.hook_slow_seconds

            class _ConfiguredHandler(ProxyHandler):
                writer = _writer
                http_client = _http_client
                max_request_body_bytes = _max_request_body_bytes
                max_buffered_response_bytes = _max_buffered_response_bytes
                max_audit_stream_bytes = _max_audit_stream_bytes
                hooks = _hooks
                upstreams = _upstreams
                disconnect_drain_seconds = _drain
                hook_slow_seconds = _slow

            self._server = _BoundedThreadingHTTPServer(
                (self.host, self.port),
                _ConfiguredHandler,
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
        log.info("Reverse-proxy mode: ANTHROPIC_BASE_URL=http://%s:%d", self.host, self.port)
        log.info("Reverse-proxy mode: OPENAI_BASE_URL=http://%s:%d/v1", self.host, self.port)
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
            if not start_failed and not self._server.wait_idle(
                _STOP_GRACE_SECONDS
            ):
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
        host=host, port=port, db_path=db_path_expanded,
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
