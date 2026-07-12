"""Base provider interface and shared SSE parsing utilities."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any


def _parse_sse_events(data: bytes) -> list[dict]:
    """Parse SSE byte stream into a list of parsed JSON data objects."""
    events: list[dict] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        if line.startswith("data: "):
            payload = line[6:].strip()
            if payload == "[DONE]":
                continue
            try:
                events.append(json.loads(payload))
            except (json.JSONDecodeError, ValueError):
                pass
    return events


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
    def reassemble_sse(self, raw_bytes: bytes) -> dict:
        """Reassemble a streaming response into a final response dict."""

    def extract_request_info(self, body: dict | None) -> dict[str, Any]:
        """Extract normalized request info from a request body.

        Returns dict with keys: model, messages_count, tools_count, stream.
        Non-dict bodies yield the empty defaults; dict bodies are delegated
        to the provider-specific _request_info hook.
        """
        if not isinstance(body, dict):
            return _empty_request_info()
        return self._request_info(body)

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

    def extract_tool_calls(self, resp_body: dict) -> list[dict]:
        """Extract tool call events from a response body.

        Returns list of dicts with keys: tool_name, parameters, call_id.
        """
        return []

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        """Extract tool result events from a request body.

        Returns list of dicts with keys: tool_name, result, call_id.
        """
        return []

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

    def reassemble_sse(self, raw_bytes: bytes) -> dict:
        events = _parse_sse_events(raw_bytes)
        if events:
            return events[-1]
        try:
            return json.loads(raw_bytes)
        except (json.JSONDecodeError, ValueError):
            return {}
