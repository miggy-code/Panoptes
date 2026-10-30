"""Base provider interface and shared SSE parsing utilities."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

from panoptes._json import _strict_json_loads


class SSEParseError(ValueError):
    """Raised when an SSE data event cannot be decoded safely.

    LLM provider streams carry JSON in ``data`` fields. Silently dropping a
    malformed event can hide a tool instruction from response-side policy
    enforcement, so callers must be able to distinguish "no event" from
    "uninspectable event".
    """


def _parse_sse_events(data: bytes) -> list[dict]:
    """Parse an SSE byte stream into JSON data objects.

    This follows the EventSource framing rules relevant to provider responses:
    events are delimited by a blank line, repeated ``data`` fields are joined
    with a newline, ``data:`` may have zero or one leading space in its value,
    comments and non-data fields are ignored, and a final unterminated event is
    dispatched at EOF for compatibility with finite HTTP response bodies.

    Malformed UTF-8, malformed JSON, and non-object JSON data are rejected
    instead of being skipped. A skipped chunk is an enforcement bypass when it
    contains the only tool call in a response.
    """
    try:
        # Event streams are UTF-8; utf-8-sig also implements the EventSource
        # rule that a single leading BOM is ignored.
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SSEParseError(f"invalid UTF-8 in SSE stream at byte {exc.start}") from exc

    events: list[dict] = []
    data_lines: list[str] = []
    event_number = 0

    def accumulated_payload_is_complete() -> bool:
        """Whether buffered data already forms one provider JSON event.

        Some provider SDK fixtures (and older Panoptes captures) omit the blank
        EventSource separator and emit one complete JSON ``data`` field per
        line. Dispatching only when the existing payload is independently
        complete preserves that compatibility without silently splitting a
        malformed or genuinely multiline JSON event.
        """
        if not data_lines:
            return False
        payload = "\n".join(data_lines)
        if payload.strip() == "[DONE]":
            return True
        try:
            return isinstance(_strict_json_loads(payload), dict)
        except (json.JSONDecodeError, ValueError):
            return False

    def dispatch() -> None:
        nonlocal data_lines, event_number
        if not data_lines:
            return

        event_number += 1
        payload = "\n".join(data_lines)
        data_lines = []
        if payload.strip() == "[DONE]":
            return

        try:
            parsed = _strict_json_loads(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SSEParseError(
                f"invalid JSON in SSE data event {event_number}: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise SSEParseError(
                f"SSE data event {event_number} must contain a JSON object"
            )
        events.append(parsed)

    # splitlines() also treats several Unicode control characters as line
    # boundaries; EventSource only recognizes CR, LF, and CRLF.
    for line in re.split(r"\r\n|\r|\n", text):
        if line == "":
            dispatch()
            continue
        if line.startswith(":"):
            continue

        if ":" in line:
            field, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""

        if field == "data":
            if accumulated_payload_is_complete():
                dispatch()
            data_lines.append(value)

    dispatch()
    return events


def _route_matches(path: str, routes: tuple[re.Pattern[str], ...]) -> bool:
    """Match the path component, never the query, against an exact route list.

    Substring matching would forward any provider endpoint (batches, files,
    fine-tuning) with an injected key and parse its response as "no tool
    calls", so each provider lists the model-API routes it can inspect.
    """
    route = urlparse(path).path
    return any(pattern.fullmatch(route) for pattern in routes)


def _usage_count(usage: Any, field: str) -> int:
    """A usage counter, or 0 when absent or not a non-negative integer."""
    value = usage.get(field) if isinstance(usage, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _optional_usage_counts(usage: Any, fields: dict[str, str]) -> dict:
    """Preserve valid reported counts, leaving unavailable metrics absent."""
    if not isinstance(usage, dict):
        return {}
    return {name: value for source, name in fields.items()
            if isinstance((value := usage.get(source)), int)
            and not isinstance(value, bool) and value >= 0}


def _empty_request_info() -> dict[str, Any]:
    """Request info returned when there is no parseable request body."""
    return {"model": "unknown", "messages_count": 0, "tools_count": 0, "stream": False}


class Provider(ABC):
    """Abstract base for provider-specific LLM API adapters.

    Each provider encapsulates format detection, upstream routing defaults,
    request/response extraction, and SSE reassembly for one LLM vendor.

    Subclasses must implement the abstract methods; the extraction hooks
    (`estimate_turn_number`, `extract_tool_calls`, `extract_tool_results`,
    `extract_usage`, `is_streaming`) have sensible defaults and only need
    overriding where the vendor's format differs.
    """

    name: str  # e.g. "anthropic", "openai", "gemini"

    @abstractmethod
    def matches_path(self, path: str) -> bool:
        """Return True if this provider handles requests to this path."""

    @abstractmethod
    def matches_body(self, body: dict | None) -> bool:
        """Return True if the request body looks like this provider's format."""

    @property
    @abstractmethod
    def default_upstream(self) -> str:
        """Default upstream base URL (e.g. 'https://api.anthropic.com')."""

    @abstractmethod
    def reassemble_sse(
        self,
        raw_bytes: bytes,
        *,
        path: str | None = None,
    ) -> dict:
        """Reassemble a streaming response into a final response dict.

        ``path`` binds parsing to the requested endpoint when one provider has
        multiple wire protocols. Enforcement callers should always supply it.
        """

    def extract_request_info(
        self, body: dict | None, *, path: str | None = None
    ) -> dict[str, Any]:
        """Extract normalized request info from a request body.

        Returns dict with keys: model, messages_count, tools_count, stream.
        Non-dict bodies yield the empty defaults; dict bodies are delegated
        to the provider-specific _request_info hook. Providers that name the
        model in the route rather than the body fill it in from ``path``.
        """
        info = (
            self._request_info(body)
            if isinstance(body, dict)
            else _empty_request_info()
        )
        if info.get("model") in (None, "unknown") and path:
            info["model"] = self.model_from_path(path) or info.get("model", "unknown")
        return info

    def model_from_path(self, path: str) -> str | None:
        """The model a route names, for providers that put it in the URL."""
        return None

    def _request_info(self, body: dict) -> dict[str, Any]:
        """Provider-specific request info extraction (body is a dict)."""
        return {
            "model": body.get("model", "unknown"),
            "messages_count": len(body.get("messages", [])),
            "tools_count": 0,
            "stream": bool(body.get("stream", False)),
        }

    def is_streaming(self, path: str, body: dict | None) -> bool:
        """Whether this request expects a streaming response.

        Most providers signal streaming with a body flag; providers that use
        the URL (e.g. Gemini's :streamGenerateContent) override this.
        """
        return bool(isinstance(body, dict) and body.get("stream", False))

    def estimate_turn_number(self, body: dict | None) -> int:
        """Estimate conversation turn from assistant messages in the request."""
        if not isinstance(body, dict):
            return 0
        messages = body.get("messages", [])
        return sum(1 for m in messages if isinstance(m, dict) and m.get("role") == "assistant")

    def extract_tool_calls(
        self,
        resp_body: dict,
        *,
        path: str | None = None,
    ) -> list[dict]:
        """Extract tool call events from a response body.

        ``path`` binds extraction to the requested endpoint's response dialect.
        Returns list of dicts with keys: tool_name, parameters, call_id.
        """
        return []

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        """Extract tool result events from a request body.

        Returns list of dicts with keys: tool_name, result, call_id.
        """
        return []

    def extract_requested_tools(self, req_body: dict) -> dict[str, list[str]]:
        """Return complete, policy-safe tool capability summaries.

        Providers should expose security-relevant type/name/target strings from
        the full request instead of asking policy rules to inspect a truncated
        raw-payload presentation.
        """
        return {
            "requested_tools": [],
            "client_side_tools": [],
            "server_side_tools": [],
            "unknown_tool_types": [],
            "requested_tool_targets": [],
        }

    def extract_usage(self, resp_body: dict) -> dict:
        """Extract token usage from a response body.

        Returns dict with keys: tokens_in, tokens_out.
        """
        return {"tokens_in": 0, "tokens_out": 0}


class UnknownProvider(Provider):
    """Fallback provider used when no specific provider matches."""

    name = "unknown"

    def matches_path(self, path: str) -> bool:
        return False

    def matches_body(self, body: dict | None) -> bool:
        return False

    @property
    def default_upstream(self) -> str:
        return ""

    def reassemble_sse(
        self,
        raw_bytes: bytes,
        *,
        path: str | None = None,
    ) -> dict:
        events = _parse_sse_events(raw_bytes)
        if events:
            return events[-1]
        try:
            return _strict_json_loads(raw_bytes)
        except (json.JSONDecodeError, ValueError):
            return {}
