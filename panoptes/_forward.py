"""The upstream side of a proxied exchange.

``Forwarder`` sends one request upstream and reads the reply. A buffered reply
is read whole, within a size limit, before anything reaches the client. A
streamed reply is relayed to the client as it arrives while a bounded copy is
kept for the audit. Either way the forwarder fills a ``ForwardReport`` with
what it observed and never writes an event. Private to the proxy.
"""

from __future__ import annotations

import dataclasses
import http.cookiejar
import json
import logging
import socket
import threading
import time
from collections.abc import Mapping
from typing import Protocol
from urllib.parse import urlparse

import httpx

from panoptes._events import ResponseInspectionError

log = logging.getLogger("panoptes")

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)
PANOPTES_INTERNAL_HEADERS = frozenset(
    {
        "x-panoptes-agent",
        "x-panoptes-session",
        "x-panoptes-correlation-id",
    }
)
# Codings httpx always decodes; br and zstd depend on optional packages and
# would otherwise pass through as raw bytes under a stripped header.
_DECODABLE_CONTENT_CODINGS = frozenset({"identity", "gzip", "deflate"})


@dataclasses.dataclass(frozen=True)
class UpstreamTarget:
    """Where an exchange goes: a validated HTTP(S) origin."""

    scheme: str
    host: str
    port: int

    def url(self, path: str) -> str:
        """The upstream URL for ``path``, keeping IPv6 literal syntax."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}{path}"

    def label(self, path: str) -> str:
        """A URL for logs: the query string, which may hold a key, is dropped."""
        return self.url(urlparse(path).path or "/")


@dataclasses.dataclass(frozen=True)
class Outbound:
    """What is sent upstream: the headers and the path, query included."""

    headers: dict[str, str]
    path: str


@dataclasses.dataclass
class ForwardReport:
    """What the forwarding code observed, for ``Exchange`` to report."""

    request_sent: bool = False
    answered: bool = False  # the upstream sent a response head
    upstream_status: int | None = None  # the status the upstream itself sent
    upstream_error: bool = False  # no usable upstream response
    body_bytes: int = 0
    client_gone: bool = False


@dataclasses.dataclass(frozen=True)
class UpstreamReply:
    """A reply to give the client, and the bytes the audit may inspect."""

    status: int
    headers: dict[str, str]  # safe to relay; the client side sets the length
    body: bytes  # the whole body, or a stream's bounded audit copy
    truncated: bool = False  # ``body`` is not everything the upstream sent
    relayed: bool = False  # the client already has the status and headers


def gateway_error(status: int, message: str) -> UpstreamReply:
    """The reply Panoptes gives when the upstream gave none it can use."""
    return UpstreamReply(
        status,
        {"content-type": "application/json"},
        json.dumps({"error": message}).encode(),
    )


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


class StreamSink(Protocol):
    """Where a streamed reply is relayed: the client connection."""

    def start_stream(self, status: int, headers: Mapping[str, str]) -> None: ...

    def write_stream(self, chunk: bytes) -> None:
        """Write one chunk. Raises ``OSError`` once the client has gone."""

    def flush_stream(self) -> None: ...


def upstream_client(timeout: float) -> httpx.Client:
    """An upstream client that ignores the environment and stores no cookies.

    One client serves every session and token, so a stored ``Set-Cookie``
    would be replayed on other agents' requests and link or leak sessions.
    Shell proxy variables are not routing configuration.
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


def filter_hop_by_hop(headers: Mapping[str, str]) -> dict[str, str]:
    """Drop hop-by-hop headers, including any a ``Connection`` header names."""
    nominated: set[str] = set()
    for key, value in headers.items():
        if key.lower() == "connection":
            nominated.update(
                token.strip().lower() for token in value.split(",") if token.strip()
            )
    blocked = HOP_BY_HOP | nominated
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


def default_outbound_headers(client_headers: Mapping[str, str]) -> dict[str, str]:
    """The client's headers as forwarded when no hook chose others."""
    fwd = {
        key: value
        for key, value in filter_hop_by_hop(client_headers).items()
        if key.lower() not in PANOPTES_INTERNAL_HEADERS
        and key.lower() not in ("host", "accept-encoding")
    }
    # Replaced case-insensitively: a client's lowercase accept-encoding
    # would otherwise go upstream beside this one and invite br/zstd
    # bodies that reach the client undecoded and the audit unparsed.
    fwd["Accept-Encoding"] = "identity"
    return fwd


def relay_headers(upstream_headers: Mapping[str, str]) -> dict[str, str]:
    """Upstream headers safe to relay once httpx has decoded the body.

    The body's encoding is gone and its length is the client side's to set.
    """
    return {
        key: value
        for key, value in filter_hop_by_hop(upstream_headers).items()
        if key.lower() not in ("content-encoding", "content-length")
    }


def check_content_encoding(headers: httpx.Headers) -> None:
    """Refuse an upstream body Panoptes cannot decode, inspect, or relay."""
    for value in headers.get_list("Content-Encoding"):
        for coding in value.split(","):
            coding = coding.strip().lower()
            if coding and coding not in _DECODABLE_CONTENT_CODINGS:
                raise ResponseInspectionError(
                    f"Unsupported upstream Content-Encoding {coding!r}"
                )


def may_have_reached_upstream(exc: BaseException) -> bool:
    """False only for failures that happen before any request byte is written."""
    return not isinstance(
        exc,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.PoolTimeout,
            httpx.UnsupportedProtocol,
            httpx.LocalProtocolError,
            httpx.InvalidURL,
        ),
    )


def start_drain_timer(
    resp: httpx.Response, seconds: float
) -> tuple[threading.Timer, threading.Event]:
    """Cut the upstream read after *seconds*, however silent the upstream is.

    A deadline checked only when a chunk arrives is no bound at all: a stalled
    upstream would hold the request slot until the read timeout.
    """
    expired = threading.Event()
    network_stream = resp.extensions.get("network_stream")
    get_extra = getattr(network_stream, "get_extra_info", None)
    sock = get_extra("socket") if callable(get_extra) else None

    def expire() -> None:
        expired.set()
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
            else:
                resp.close()
        except Exception:
            pass

    timer = threading.Timer(seconds, expire)
    timer.daemon = True
    timer.start()
    return timer, expired


def _declared_length(headers: httpx.Headers) -> int | None:
    """The upstream's single, unambiguous Content-Length, if it sent one."""
    lengths = headers.get_list("Content-Length")
    if lengths and headers.get_list("Transfer-Encoding"):
        raise ResponseInspectionError("Ambiguous upstream response framing")
    if len(lengths) > 1:
        raise ResponseInspectionError("Multiple upstream Content-Length headers")
    if not lengths:
        return None
    raw = lengths[0].strip()
    if not raw or "," in raw:
        raise ResponseInspectionError("Ambiguous upstream Content-Length header")
    try:
        declared = int(raw, 10)
    except ValueError as exc:
        raise ResponseInspectionError("Invalid upstream Content-Length header") from exc
    if declared < 0:
        raise ResponseInspectionError("Negative upstream Content-Length header")
    return declared


class Forwarder:
    """Sends requests upstream over one shared client, within fixed limits."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        max_buffered_response_bytes: int,
        max_audit_stream_bytes: int,
    ) -> None:
        self._client = client
        self._max_buffered = max_buffered_response_bytes
        self._max_audit = max_audit_stream_bytes

    def buffered(
        self,
        method: str,
        target: UpstreamTarget,
        outbound: Outbound,
        body: bytes,
        report: ForwardReport,
    ) -> UpstreamReply:
        """Read the whole reply before the client sees any of it.

        Raises ``UpstreamBodyTooLarge`` past the limit. Any other failure
        becomes a gateway error reply.
        """
        what = f"{method} {target.label(outbound.path)}"
        try:
            with self._client.stream(
                method,
                target.url(outbound.path),
                headers=outbound.headers,
                content=body,
            ) as resp:
                report.request_sent = report.answered = True
                report.upstream_status = resp.status_code
                check_content_encoding(resp.headers)
                declared = _declared_length(resp.headers)
                if declared is not None and declared > self._max_buffered:
                    report.body_bytes = declared
                    raise self._too_large(resp)
                received = bytearray()
                for chunk in resp.iter_bytes():
                    if not chunk:
                        continue
                    report.body_bytes += len(chunk)
                    if len(received) + len(chunk) > self._max_buffered:
                        raise self._too_large(resp)
                    received.extend(chunk)
                return UpstreamReply(
                    resp.status_code, relay_headers(resp.headers), bytes(received)
                )
        except UpstreamBodyTooLarge:
            report.upstream_error = True
            raise
        except Exception as exc:
            return _failure_reply(exc, report, what)

    def stream(
        self,
        method: str,
        target: UpstreamTarget,
        outbound: Outbound,
        body: bytes,
        report: ForwardReport,
        sink: StreamSink,
        *,
        drain_seconds: float,
    ) -> UpstreamReply:
        """Relay the reply as it arrives, keeping a bounded copy for the audit.

        ``drain_seconds`` keeps reading the upstream after the client leaves,
        so usage that is still owed gets recorded. Zero ends the relay.
        A failure before the response head becomes a gateway error reply that
        the caller still has to deliver (``relayed`` is false).
        """
        what = f"{method} {target.label(outbound.path)} (streaming)"
        started = False
        try:
            with self._client.stream(
                method,
                target.url(outbound.path),
                headers=outbound.headers,
                content=body,
            ) as resp:
                report.request_sent = report.answered = True
                report.upstream_status = resp.status_code
                check_content_encoding(resp.headers)
                headers = relay_headers(resp.headers)
                sink.start_stream(resp.status_code, headers)
                started = True
                captured, truncated = self._relay(
                    resp, report, sink, drain_seconds, what
                )
                return UpstreamReply(
                    resp.status_code, headers, captured, truncated, relayed=True
                )
        except Exception as exc:
            reply = _failure_reply(exc, report, what)
            if started:
                # The client has a head already; only the audit sees this.
                return dataclasses.replace(
                    reply, body=b"", truncated=True, relayed=True
                )
            return reply

    def _relay(
        self,
        resp: httpx.Response,
        report: ForwardReport,
        sink: StreamSink,
        drain_seconds: float,
        what: str,
    ) -> tuple[bytes, bool]:
        """Copy the body to the client. Returns the audit copy and whether it
        is incomplete."""
        captured = bytearray()
        truncated = False
        drain_deadline: float | None = None
        drain_timer: threading.Timer | None = None
        drain_expired: threading.Event | None = None
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                report.body_bytes += len(chunk)
                if not truncated:
                    remaining = self._max_audit - len(captured)
                    if remaining > 0:
                        captured.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                if drain_deadline is not None:
                    if truncated or time.monotonic() > drain_deadline:
                        truncated = True
                        break
                    continue
                try:
                    sink.write_stream(chunk)
                except OSError:
                    if drain_seconds <= 0:
                        raise
                    report.client_gone = True
                    drain_deadline = time.monotonic() + drain_seconds
                    drain_timer, drain_expired = start_drain_timer(resp, drain_seconds)
            if not report.client_gone:
                sink.flush_stream()
        except Exception:
            truncated = True
            log.exception("Error mid-stream: %s", what)
        finally:
            if drain_timer is not None:
                drain_timer.cancel()
        if drain_expired is not None and drain_expired.is_set():
            # A cut connection can look like a clean end of stream.
            truncated = True
        return bytes(captured), truncated

    def _too_large(self, resp: httpx.Response) -> UpstreamBodyTooLarge:
        return UpstreamBodyTooLarge(
            self._max_buffered,
            upstream_status=resp.status_code,
            upstream_headers=dict(resp.headers),
        )


def _failure_reply(exc: Exception, report: ForwardReport, what: str) -> UpstreamReply:
    """Report a failed forward and choose the gateway error for it.

    Call from an ``except`` block, so the logged traceback is the failure's.
    """
    report.upstream_error = True
    report.request_sent |= may_have_reached_upstream(exc)
    if isinstance(exc, ResponseInspectionError):
        log.exception("Unsafe upstream response framing: %s", what)
        return gateway_error(502, "Unsafe upstream response framing")
    if isinstance(exc, httpx.TimeoutException):
        log.error("Upstream timeout: %s", what)
        return gateway_error(504, "Gateway Timeout")
    if isinstance(exc, httpx.ConnectError):
        log.error("Upstream connect error: %s", what)
        return gateway_error(502, "Bad Gateway")
    log.exception("Upstream error: %s", what)
    return gateway_error(502, "Bad Gateway")
