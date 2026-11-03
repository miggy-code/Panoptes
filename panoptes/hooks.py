"""Proxy hook contract (see docs/hooks.md).

The proxy observes; a hook decides. This module holds the types a hook sees and
returns. It imports no HTTP client, so it loads without the ``[proxy]`` extra.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator, MutableMapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from panoptes.schema import ValidationError, validate_identifier

__all__ = [
    "CLIENT_CREDENTIAL_HEADERS",
    "QUERY_CREDENTIAL_PARAMS",
    "Exchange",
    "Identity",
    "OUTCOMES",
    "ProxyHooks",
    "Reject",
    "Upstream",
    "User",
]

# Headers a client may present a provider credential in. A hook that injects its
# own key removes these from ``outbound_headers`` first.
CLIENT_CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "x-api-key",
    "x-goog-api-key",
})

# Query parameters treated as credentials, matched case-insensitively after
# percent-decoding. Gemini sends its key this way.
QUERY_CREDENTIAL_PARAMS = frozenset({"key", "api_key", "apikey", "access_token"})

OUTCOMES = frozenset({
    "forwarded",
    "upstream_error",
    "rejected",
    "hook_error",
    "not_forwarded",
    "aborted",
})

# Names the proxy owns and re-applies after the hook returns.
STATIC_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "trailers", "transfer-encoding",
    "upgrade",
})

_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_FORBIDDEN_HEADER_VALUE_CHARS = ("\r", "\n", "\x00")


# ---------------------------------------------------------------------------
# Values a hook returns or assigns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class User:
    """The user an exchange is recorded under."""

    id: str | None = None
    auth_method: str | None = None

    def __post_init__(self) -> None:
        for name in ("id", "auth_method"):
            value = getattr(self, name)
            if value is not None:
                validate_identifier(value, f"user.{name}")


@dataclass(frozen=True)
class Identity:
    """Who an exchange is recorded as.

    Assigned to ``exchange.identity`` as a whole, so a hook never leaves a
    half-updated identity. ``assurance`` is the hook's own label for how it
    established the identity; Panoptes records it and attaches no meaning.
    """

    agent_type: str
    session_id: str
    run_id: str | None = None
    parent_run_id: str | None = None
    user: User | None = None
    assurance: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.agent_type, "agent_type")
        validate_identifier(self.session_id, "session_id")
        for name in ("run_id", "parent_run_id", "assurance"):
            value = getattr(self, name)
            if value is not None:
                validate_identifier(value, name)
        if self.user is not None and not isinstance(self.user, User):
            raise TypeError("Identity.user must be a User or None")


@dataclass(frozen=True)
class Reject:
    """Refuse the request: answer the client and never forward.

    ``body`` is any JSON-serializable object (default ``{"error": reason}``).
    ``reason`` is a short code that Panoptes records and never interprets.
    """

    status: int
    body: Any = None
    reason: str = "rejected"


@dataclass(frozen=True)
class Upstream:
    """A provider origin, optionally named.

    ``url`` is an origin, ``scheme://host[:port]``. A path, query, fragment or
    credentials raise ``ValueError`` so no path prefix can be configured.
    """

    url: str
    name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.url, str):
            raise ValueError("Upstream url must be a string")
        try:
            parsed = urlparse(self.url)
            parsed.port  # noqa: B018 - raises ValueError for a bad port
        except ValueError as exc:
            raise ValueError(f"Invalid upstream url: {exc}") from None
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Upstream url must start with http:// or https://")
        if not parsed.hostname:
            raise ValueError("Upstream url must include a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Upstream url must not contain credentials")
        if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
            raise ValueError(
                "Upstream url must be an origin (scheme://host[:port]); "
                "path prefixes are not supported"
            )
        if self.name is not None:
            try:
                validate_identifier(self.name, "upstream name")
            except ValidationError as exc:
                raise ValueError(str(exc)) from None

    @property
    def origin(self) -> str:
        parsed = urlparse(self.url)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme}://{host}{port}"

    def __repr__(self) -> str:
        return f"Upstream(origin={self.origin!r}, name={self.name!r})"


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


class RequestHeaders:
    """Read-only request headers as received, repeated lines kept.

    Lookup is case-insensitive. ``items()`` keeps received order and case.
    """

    __slots__ = ("_items",)

    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = tuple((str(k), str(v)) for k, v in items)

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self._items if k.lower() == lowered]

    def get(self, name: str, default: str | None = None) -> str | None:
        values = self.get_all(name)
        return values[0] if values else default

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and bool(self.get_all(name))

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[str]:
        return iter([k for k, _ in self._items])

    def __repr__(self) -> str:  # never shows values
        return f"RequestHeaders(<{len(self._items)} headers>)"


class OutboundHeaders(MutableMapping):
    """Case-insensitive mapping of the headers sent upstream.

    Values must be strings without CR, LF or NUL.
    """

    def __init__(self, initial: Any = None) -> None:
        self._data: dict[str, tuple[str, str]] = {}
        if initial is not None:
            for name, value in dict(initial).items():
                self[name] = value

    @staticmethod
    def _check(name: Any, value: Any) -> tuple[str, str]:
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError("Header names must be valid HTTP tokens")
        if not isinstance(value, str) or any(
            char in value for char in _FORBIDDEN_HEADER_VALUE_CHARS
        ):
            raise ValueError(
                f"Header {name!r} must be a string without CR, LF or NUL"
            )
        return name, value

    def __setitem__(self, name: str, value: str) -> None:
        self._check(name, value)
        self._data[name.lower()] = (name, value)

    def __getitem__(self, name: str) -> str:
        return self._data[name.lower()][1]

    def __delitem__(self, name: str) -> None:
        del self._data[name.lower()]

    def __iter__(self) -> Iterator[str]:
        return iter([name for name, _ in self._data.values()])

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._data

    def as_dict(self) -> dict[str, str]:
        return dict(self._data.values())

    def __repr__(self) -> str:  # never shows values
        return f"OutboundHeaders(<{len(self._data)} headers>)"


# ---------------------------------------------------------------------------
# Exchange
# ---------------------------------------------------------------------------

_HOOK_SETTABLE = frozenset({"identity", "outbound_headers", "state"})


class Exchange:
    """One proxied request, passed to both hooks.

    Request fields are read-only. A hook sets ``identity``, ``outbound_headers``
    and ``state`` and may call :meth:`drop_query_credentials`. The remaining
    fields are filled in by the proxy for ``after_exchange``.
    """

    def __init__(
        self,
        *,
        exchange_id: str,
        correlation_id: str,
        correlation_source: str,
        provider: str,
        upstream_name: str,
        upstream_url: str,
        method: str,
        path: str,
        request_headers: RequestHeaders,
        query_credentials: tuple[str, ...],
        request_body: bytes,
        request_json: dict | None,
        request_events: list[dict],
        identity: Identity,
        outbound_headers: OutboundHeaders,
    ) -> None:
        values: dict[str, Any] = {
            "exchange_id": exchange_id,
            "correlation_id": correlation_id,
            "correlation_source": correlation_source,
            "provider": provider,
            "upstream_name": upstream_name,
            "upstream_url": upstream_url,
            "method": method,
            "path": path,
            "request_headers": request_headers,
            "query_credentials": tuple(query_credentials),
            "request_body": request_body,
            "request_json": request_json,
            "request_events": request_events,
            "identity": identity,
            "outbound_headers": outbound_headers,
            "state": {},
            # Filled in for after_exchange.
            "outcome": None,
            "request_sent": False,
            "produced_output": False,
            "status": None,
            "upstream_status": None,
            "complete": False,
            "response_events": [],
            "usage": {},
            "estimated_usd_micros": None,
            "provider_error": False,
            "duration_ms": None,
            "_identity_frozen": False,
            "_identity_assigned": False,
            "_drop_query_credentials": False,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: Any) -> None:
        if name not in _HOOK_SETTABLE:
            raise AttributeError(f"Exchange.{name} is read-only")
        if name == "identity":
            if self._identity_frozen:
                return  # recorded already; later assignments are ignored
            if not isinstance(value, Identity):
                raise TypeError("exchange.identity must be an Identity")
            object.__setattr__(self, "_identity_assigned", True)
        elif name == "outbound_headers":
            value = OutboundHeaders(value)
        elif name == "state" and not isinstance(value, dict):
            raise TypeError("exchange.state must be a dict")
        object.__setattr__(self, name, value)

    def drop_query_credentials(self) -> None:
        """Remove every credential query parameter from the forwarded URL."""
        object.__setattr__(self, "_drop_query_credentials", True)

    # -- proxy-side helpers (not part of the hook contract) -------------------

    def _settle(self, **values: Any) -> None:
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def _freeze_identity(self) -> None:
        object.__setattr__(self, "_identity_frozen", True)

    def __repr__(self) -> str:  # headers, bodies and query credentials omitted
        return (
            f"Exchange(exchange_id={self.exchange_id!r}, "
            f"provider={self.provider!r}, method={self.method!r}, "
            f"path={self.path!r}, outcome={self.outcome!r})"
        )


# ---------------------------------------------------------------------------
# The hooks object
# ---------------------------------------------------------------------------


class ProxyHooks:
    """Base class for a proxy's hooks. Subclass and override what you need.

    One object per proxy. Both methods run in the proxy's request threads and
    may be called concurrently, so they must be thread-safe.
    """

    def before_forward(self, exchange: Exchange) -> Reject | None:
        """Return ``None`` to forward or a :class:`Reject` to refuse."""
        return None

    def after_exchange(self, exchange: Exchange) -> None:
        """Called once for every exchange that entered ``before_forward``."""
        return None


def reject_response(reject: Reject) -> tuple[int, bytes, str]:
    """Validate a :class:`Reject` and return ``(status, body_bytes, reason)``.

    Raises ``ValueError`` for anything a hook may not return.
    """
    if not isinstance(reject, Reject):
        raise ValueError("before_forward must return None or a Reject")
    status = reject.status
    if isinstance(status, bool) or not isinstance(status, int) or not 400 <= status <= 599:
        raise ValueError("Reject.status must be an integer from 400 to 599")
    try:
        validate_identifier(reject.reason, "Reject.reason")
    except ValidationError as exc:
        raise ValueError(str(exc)) from None
    body = reject.body if reject.body is not None else {"error": reject.reason}
    try:
        encoded = json.dumps(body, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Reject.body must be JSON-serializable: {exc}") from None
    return status, encoded, reject.reason


def copy_events(events: list[dict]) -> list[dict]:
    return copy.deepcopy(events)
