"""The client side of a proxied exchange: framing, headers and routing.

``read_request`` turns what a client sent into a ``ProxyRequest``, or raises a
``ProxyRequestError`` that carries the status to answer with. Nothing here
talks to an upstream or builds an event. Private to the proxy.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
from collections.abc import Iterable, Mapping
from email.message import Message
from typing import Any
from urllib.parse import unquote_plus, urlparse

import panoptes.providers as _providers
from panoptes._forward import UpstreamTarget
from panoptes.hooks import Upstream
from panoptes.providers.base import _strict_json_loads

_PROVIDER_ENV: dict[str, str] = {
    "anthropic": "PANOPTES_UPSTREAM_ANTHROPIC",
    "openai": "PANOPTES_UPSTREAM_OPENAI",
    "gemini": "PANOPTES_UPSTREAM_GEMINI",
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


@dataclasses.dataclass(frozen=True)
class ProxyRequest:
    """One client request, read in full and routed."""

    method: str
    path: str  # what routing and every record use
    raw_path: str  # as the client sent it
    query_credentials: tuple[str, ...]  # taken out of ``path``, in order
    target: UpstreamTarget
    upstream_name: str
    header_items: tuple[tuple[str, str], ...]  # as received, repeats kept
    headers: dict[str, str]  # repeats joined, see ``merge_headers``
    body: bytes
    json: dict[str, Any] | None


def read_request(
    *,
    method: str,
    path: str,
    raw_path: str,
    query_credentials: tuple[str, ...],
    headers: Message,
    rfile: io.BufferedIOBase,
    upstreams: Mapping[str, tuple[str, Upstream]],
    max_body_bytes: int,
) -> ProxyRequest:
    """Route the request and read its body. Raises ``ProxyRequestError``."""
    target, upstream_name = route(path, upstreams)
    items = tuple(headers.items())
    body = read_body(headers, rfile, max_body_bytes)
    return ProxyRequest(
        method=method,
        path=path,
        raw_path=raw_path,
        query_credentials=query_credentials,
        target=target,
        upstream_name=upstream_name,
        header_items=items,
        headers=merge_headers(items),
        body=body,
        json=_json_object(body),
    )


def route(
    path: str, upstreams: Mapping[str, tuple[str, Upstream]]
) -> tuple[UpstreamTarget, str]:
    """The upstream and its name for an origin-form request path.

    Precedence: ``upstreams``, then the environment, then the provider's
    public API.
    """
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        raise ProxyRequestError(
            "Absolute-form targets are not supported; configure the client "
            "to use Panoptes as its API base URL"
        )
    if not path.startswith("/"):
        raise ProxyRequestError("Reverse-proxy targets must use origin-form paths")
    for provider in _providers.REGISTRY:
        if not provider.matches_path(path):
            continue
        configured = upstreams.get(provider.name)
        if configured is not None:
            name, upstream = configured
            return parse_upstream_url(upstream.origin), name
        env_var = _PROVIDER_ENV.get(provider.name)
        origin = (os.environ.get(env_var) if env_var else None) or (
            provider.default_upstream
        )
        return parse_upstream_url(origin), provider.name
    raise NoUpstreamError(
        f"No supported provider route for path '{parsed.path or '/'}'"
    )


def parse_upstream_url(url: str, default_scheme: str = "https") -> UpstreamTarget:
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
        raise NoUpstreamError(
            f"Unsupported upstream URL scheme: {scheme or '<missing>'}"
        )
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
    return UpstreamTarget(scheme, host, port)


def strip_query_credentials(
    path: str,
    names: frozenset[str] = frozenset({"key"}),
    *,
    fold: bool = False,
) -> tuple[str, tuple[str, ...]]:
    """Remove every credential query parameter, returning the path and values.

    ``names`` are matched after percent-decoding, case-insensitively when
    ``fold`` is set. Other parameters keep their original encoding and order.
    """
    base, sep, query = path.partition("?")
    if not sep:
        return path, ()
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
    return stripped + (hash_sep + fragment if hash_sep else ""), tuple(values)


def merge_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
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


def read_body(headers: Message, rfile: io.BufferedIOBase, limit: int) -> bytes:
    """Read a Content-Length body of at most ``limit`` bytes, strictly framed."""
    transfer_encoding = headers.get_all("Transfer-Encoding") or []
    content_lengths = headers.get_all("Content-Length") or []

    if transfer_encoding and content_lengths:
        raise RequestFramingError(
            "Ambiguous request framing: both Transfer-Encoding and Content-Length"
        )
    if transfer_encoding:
        # BaseHTTPRequestHandler does not decode request transfer codings.
        # Treating a chunked body as empty would let opaque bytes reach the
        # next request and can bypass policy inspection.
        raise RequestFramingError("Transfer-Encoding request bodies are not supported")
    if len(content_lengths) > 1:
        raise RequestFramingError("Multiple Content-Length headers are not allowed")
    if not content_lengths:
        return b""

    raw_length = str(content_lengths[0]).strip()
    if not raw_length or "," in raw_length:
        raise RequestFramingError("Ambiguous Content-Length header")
    try:
        content_length = int(raw_length, 10)
    except ValueError as exc:
        raise RequestFramingError("Invalid Content-Length header") from exc
    if content_length < 0:
        raise RequestFramingError("Content-Length must not be negative")
    if content_length > limit:
        raise RequestBodyTooLarge(f"Request body exceeds the {limit}-byte limit")
    if content_length == 0:
        return b""

    try:
        body = rfile.read(content_length)
    except OSError as exc:
        raise RequestFramingError("Failed to read the complete request body") from exc
    if len(body) != content_length:
        raise RequestFramingError(
            "Request body ended before the declared Content-Length"
        )
    return body


def _json_object(body: bytes) -> dict[str, Any] | None:
    """The body as one unambiguous JSON object, or None when there is none."""
    if not body:
        return None
    try:
        decoded = _strict_json_loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProxyRequestError(
            "Supported provider requests must be unambiguous valid JSON"
        ) from exc
    if not isinstance(decoded, dict):
        raise ProxyRequestError(
            "Supported provider requests must contain a JSON object"
        )
    return decoded
