"""Anthropic API provider adapter."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import (
    Provider,
    SSEParseError,
    _parse_sse_events,
    _route_matches,
    _strict_json_loads,
    _usage_count,
    _optional_usage_counts,
)

_ROUTES = (
    re.compile(r"/v1/messages"),
    re.compile(r"/v1/messages/count_tokens"),
)

_INPUT_USAGE_FIELDS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
_USAGE_FIELDS = _INPUT_USAGE_FIELDS + ("output_tokens", "output_tokens_details")


_SERVER_RESULT_TYPES = frozenset({
    "web_search_tool_result",
    "web_fetch_tool_result",
    "code_execution_tool_result",
    "bash_code_execution_tool_result",
    "text_editor_code_execution_tool_result",
    "tool_search_tool_result",
})
_BENIGN_CONTENT_TYPES = frozenset({
    "text",
    "thinking",
    "redacted_thinking",
})


def _anthropic_index(event: dict) -> int:
    index = event.get("index", 0)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise SSEParseError(f"invalid Anthropic content block index: {index!r}")
    return index


def _required_string(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value:
        raise SSEParseError(f"{source} must be a non-empty string")
    return value


class AnthropicProvider(Provider):
    """Adapter for the Anthropic Messages API."""

    name = "anthropic"

    def matches_path(self, path: str) -> bool:
        return _route_matches(path, _ROUTES)

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        if "system" in body:
            return True
        messages = body.get("messages")
        if (
            isinstance(messages, list)
            and messages
            and isinstance(messages[0], dict)
            and isinstance(messages[0].get("content"), list)
        ):
            return True
        return False

    @property
    def default_upstream(self) -> str:
        return "https://api.anthropic.com"

    def _request_info(self, body: dict) -> dict[str, Any]:
        messages = body.get("messages", [])
        tools = body.get("tools")
        return {
            "model": body.get("model", "unknown"),
            "messages_count": len(messages) + (1 if body.get("system") else 0),
            "tools_count": len(tools) if isinstance(tools, list) else 0,
            "stream": bool(body.get("stream", False)),
        }

    def extract_tool_calls(
        self,
        resp_body: dict,
        *,
        path: str | None = None,
    ) -> list[dict]:
        events: list[dict] = []
        content = resp_body.get("content", [])
        if not isinstance(content, list):
            raise SSEParseError("Anthropic response content must be a list")

        results: dict[str, dict] = {}
        for index, block in enumerate(content):
            if not isinstance(block, dict):
                raise SSEParseError(
                    f"Anthropic content block {index} must be an object"
                )
            block_type = block.get("type")
            if not isinstance(block_type, str) or not block_type:
                raise SSEParseError(
                    f"Anthropic content block {index} is missing a type"
                )
            if block_type in _SERVER_RESULT_TYPES:
                tool_use_id = _required_string(
                    block.get("tool_use_id"),
                    source=f"Anthropic {block_type} tool_use_id",
                )
                if tool_use_id in results:
                    raise SSEParseError(
                        f"duplicate Anthropic server result for {tool_use_id!r}"
                    )
                is_error = block.get("is_error", False)
                if not isinstance(is_error, bool):
                    raise SSEParseError(
                        f"Anthropic {block_type} is_error must be a boolean"
                    )
                results[tool_use_id] = {
                    "result": block.get("content"),
                    "is_error": is_error,
                    "result_type": block_type,
                }

        for index, block in enumerate(content):
            block_type = block["type"]
            if block_type in _BENIGN_CONTENT_TYPES or block_type in _SERVER_RESULT_TYPES:
                continue
            if block_type not in ("tool_use", "server_tool_use"):
                raise SSEParseError(
                    f"unsupported Anthropic content block type: {block_type!r}"
                )
            name = _required_string(
                block.get("name"),
                source=f"Anthropic {block_type} name",
            )
            call_id = _required_string(
                block.get("id"),
                source=f"Anthropic {block_type} id",
            )
            parameters = block.get("input", {})
            if not isinstance(parameters, dict):
                raise SSEParseError(
                    f"Anthropic {block_type} input must be an object"
                )
            event = {
                "tool_name": name,
                "parameters": parameters,
                "call_id": call_id,
            }
            if block_type == "server_tool_use":
                result = results.get(call_id)
                event.update({
                    "execution_scope": "provider",
                    "provider_item_type": block_type,
                    "outcome_status": (
                        "error"
                        if result and result["is_error"]
                        else "success" if result else "pending"
                    ),
                    "server_result": result["result"] if result else None,
                    "server_result_type": (
                        result["result_type"] if result else None
                    ),
                })
            events.append(event)
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        events: list[dict] = []
        messages = req_body.get("messages", [])
        if not isinstance(messages, list):
            raise SSEParseError("Anthropic request messages must be a list")
        for message_index, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise SSEParseError(
                    f"Anthropic request message {message_index} must be an object"
                )
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        is_error = block.get("is_error", False)
                        if not isinstance(is_error, bool):
                            raise SSEParseError(
                                "Anthropic tool_result is_error must be a boolean"
                            )
                        events.append({
                            # The wire block correlates by ID but does not
                            # repeat the original tool name.
                            "tool_name": "unknown",
                            "result": block.get("content", ""),
                            "call_id": block.get("tool_use_id") or None,
                            "is_error": is_error,
                        })
        return events

    def extract_requested_tools(self, req_body: dict) -> dict[str, list[str]]:
        requested: list[str] = []
        client_side: list[str] = []
        server_side: list[str] = []
        unknown: list[str] = []
        targets: list[str] = []
        server_prefixes = (
            "web_search",
            "web_fetch",
            "code_execution",
            "bash_code_execution",
            "text_editor_code_execution",
            "tool_search",
        )
        client_prefixes = ("computer", "memory")
        tools = req_body.get("tools", [])
        if tools is None:
            tools = []
        if not isinstance(tools, list):
            raise SSEParseError("Anthropic request tools must be a list")
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise SSEParseError(
                    f"Anthropic request tool {index} must be an object"
                )
            raw_type = tool.get("type")
            name = tool.get("name")
            if raw_type is None:
                if not isinstance(name, str) or not name:
                    raise SSEParseError(
                        f"Anthropic request tool {index} is missing a name"
                    )
                tool_type = "function"
            elif not isinstance(raw_type, str) or not raw_type:
                raise SSEParseError(
                    f"Anthropic request tool {index} has an invalid type"
                )
            else:
                tool_type = raw_type
            label = (
                f"{tool_type}:{name}"
                if isinstance(name, str) and name
                else tool_type
            )
            requested.append(label)
            if tool_type == "function" or tool_type.startswith(client_prefixes):
                client_side.append(label)
            elif tool_type.startswith(server_prefixes):
                server_side.append(label)
            else:
                unknown.append(label)
            for key in ("url", "server_url", "server_name"):
                value = tool.get(key)
                if isinstance(value, str) and value:
                    targets.append(f"{key}:{value}")
        return {
            "requested_tools": requested,
            "client_side_tools": client_side,
            "server_side_tools": server_side,
            "unknown_tool_types": unknown,
            "requested_tool_targets": targets,
        }

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usage", {})
        # input_tokens excludes cached context; count every input token the
        # model processed, or cache-heavy agents record a tiny fraction.
        return {
            "tokens_in": sum(
                _usage_count(usage, field) for field in _INPUT_USAGE_FIELDS
            ),
            "tokens_out": _usage_count(usage, "output_tokens"),
            **_optional_usage_counts(usage, {
                "cache_read_input_tokens": "cached_input_tokens",
                "cache_creation_input_tokens": "cache_creation_input_tokens",
            }),
            **_optional_usage_counts(usage.get("output_tokens_details") if isinstance(usage, dict) else None, {
                "thinking_tokens": "reasoning_tokens",
            }),
        }

    def reassemble_sse(
        self,
        raw_bytes: bytes,
        *,
        path: str | None = None,
    ) -> dict:
        events = _parse_sse_events(raw_bytes)
        if not events:
            raise SSEParseError("Anthropic SSE response contained no JSON data events")
        return _reassemble_anthropic_sse(events)


def _reassemble_anthropic_sse(events: list[dict]) -> dict:
    """Reassemble Anthropic SSE event list into a final message dict."""
    message: dict[str, Any] = {
        "id": None,
        "type": "message",
        "role": "assistant",
        "model": None,
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    content_blocks: dict[int, dict] = {}
    stopped_blocks: set[int] = set()

    for ev in events:
        ev_type = ev.get("type")

        if ev_type == "message_start":
            msg = ev.get("message", {})
            if not isinstance(msg, dict):
                raise SSEParseError("message_start is missing a message object")
            message["id"] = msg.get("id")
            message["model"] = msg.get("model")
            message["stop_reason"] = msg.get("stop_reason")
            usage = msg.get("usage", {})
            if not isinstance(usage, dict):
                raise SSEParseError("message_start usage must be an object")
            for field in _USAGE_FIELDS:
                if field in usage:
                    message["usage"][field] = usage[field]

        elif ev_type == "content_block_start":
            index = _anthropic_index(ev)
            if index in content_blocks:
                raise SSEParseError(
                    f"duplicate content_block_start for index {index}"
                )
            block = ev.get("content_block", {})
            if not isinstance(block, dict):
                raise SSEParseError("content_block_start is missing a content block")
            block_type = block.get("type")
            if not isinstance(block_type, str) or not block_type:
                raise SSEParseError("Anthropic content block is missing a type")
            cb: dict[str, Any] = {"type": block_type}
            if block_type == "text":
                text = block.get("text", "")
                if not isinstance(text, str):
                    raise SSEParseError("Anthropic text block must contain text")
                cb["text"] = text
            elif block_type == "thinking":
                thinking = block.get("thinking", "")
                signature = block.get("signature", "")
                if not isinstance(thinking, str) or not isinstance(signature, str):
                    raise SSEParseError(
                        "Anthropic thinking fields must be strings"
                    )
                cb["thinking"] = thinking
                cb["signature"] = signature
            elif block_type == "redacted_thinking":
                cb["data"] = block.get("data", "")
            elif block_type in ("tool_use", "server_tool_use"):
                cb["id"] = _required_string(
                    block.get("id"),
                    source=f"Anthropic {block_type} id",
                )
                cb["name"] = _required_string(
                    block.get("name"),
                    source=f"Anthropic {block_type} name",
                )
                initial_input = block.get("input", {})
                if not isinstance(initial_input, dict):
                    raise SSEParseError(
                        f"{block_type} input at index {index} must be a JSON object"
                    )
                cb["input"] = dict(initial_input)
                cb["_fragments"] = []
            elif block_type in _SERVER_RESULT_TYPES:
                cb = dict(block)
                cb["type"] = block_type
                _required_string(
                    cb.get("tool_use_id"),
                    source=f"Anthropic {block_type} tool_use_id",
                )
                if "is_error" in cb and not isinstance(cb["is_error"], bool):
                    raise SSEParseError(
                        f"Anthropic {block_type} is_error must be a boolean"
                    )
            else:
                raise SSEParseError(
                    f"unsupported Anthropic content block type: {block_type!r}"
                )
            content_blocks[index] = cb

        elif ev_type == "content_block_delta":
            index = _anthropic_index(ev)
            delta = ev.get("delta", {})
            if index not in content_blocks:
                raise SSEParseError(
                    f"content_block_delta references unknown index {index}"
                )
            if index in stopped_blocks:
                raise SSEParseError(
                    f"content_block_delta followed content_block_stop at index {index}"
                )
            if not isinstance(delta, dict):
                raise SSEParseError("content_block_delta is missing a delta object")
            cb = content_blocks[index]
            dt = delta.get("type")
            if dt == "text_delta" and cb.get("type") == "text":
                text = delta.get("text", "")
                if not isinstance(text, str):
                    raise SSEParseError("text_delta text must be a string")
                cb["text"] = cb.get("text", "") + text
            elif dt == "thinking_delta" and cb.get("type") == "thinking":
                thinking = delta.get("thinking", "")
                if not isinstance(thinking, str):
                    raise SSEParseError("thinking_delta thinking must be a string")
                cb["thinking"] = cb.get("thinking", "") + thinking
            elif dt == "signature_delta" and cb.get("type") == "thinking":
                signature = delta.get("signature", "")
                if not isinstance(signature, str):
                    raise SSEParseError("signature_delta signature must be a string")
                cb["signature"] = cb.get("signature", "") + signature
            elif dt == "input_json_delta" and "_fragments" in cb:
                fragment = delta.get("partial_json", "")
                if not isinstance(fragment, str):
                    raise SSEParseError(
                        "input_json_delta partial_json must be a string"
                    )
                cb["_fragments"].append(fragment)
            else:
                raise SSEParseError(
                    f"delta type {dt!r} is inconsistent with content block {index}"
                )

        elif ev_type == "content_block_stop":
            index = _anthropic_index(ev)
            if index not in content_blocks:
                raise SSEParseError(
                    f"content_block_stop references unknown index {index}"
                )
            if index in stopped_blocks:
                raise SSEParseError(
                    f"duplicate content_block_stop for index {index}"
                )
            cb = content_blocks[index]
            if "_fragments" in cb:
                full_json = "".join(cb["_fragments"])
                try:
                    decoded = _strict_json_loads(full_json) if full_json else {}
                except (json.JSONDecodeError, ValueError) as exc:
                    raise SSEParseError(
                        f"tool input at index {index} is incomplete or invalid JSON"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise SSEParseError(
                        f"tool input at index {index} must be a JSON object"
                    )
                initial_input = cb.get("input", {})
                if initial_input and decoded and initial_input != decoded:
                    raise SSEParseError(
                        f"tool_use input at index {index} contradicted its start event"
                    )
                if decoded:
                    cb["input"] = decoded
                del cb["_fragments"]
            stopped_blocks.add(index)

        elif ev_type == "message_delta":
            delta = ev.get("delta", {})
            if not isinstance(delta, dict):
                raise SSEParseError("message_delta is missing a delta object")
            if "stop_reason" in delta:
                message["stop_reason"] = delta["stop_reason"]
            if "stop_sequence" in delta:
                message["stop_sequence"] = delta["stop_sequence"]
            delta_usage = ev.get("usage", {})
            if not isinstance(delta_usage, dict):
                raise SSEParseError("message_delta usage must be an object")
            # message_delta usage is cumulative and may revise any field.
            for field in _USAGE_FIELDS:
                if field in delta_usage:
                    message["usage"][field] = delta_usage[field]
        elif ev_type in ("ping", "message_stop"):
            continue
        elif ev_type == "error":
            raise SSEParseError("Anthropic stream reported an error event")
        else:
            raise SSEParseError(
                f"unsupported Anthropic stream event type: {ev_type!r}"
            )

    incomplete = sorted(set(content_blocks) - stopped_blocks)
    if incomplete:
        raise SSEParseError(
            "Anthropic stream ended before content_block_stop for "
            + ", ".join(str(index) for index in incomplete)
        )

    # Assemble content blocks in index order
    assembled: list[dict] = []
    for i in sorted(content_blocks.keys()):
        cb = content_blocks[i]
        if cb.get("type") == "text":
            assembled.append({"type": "text", "text": cb.get("text", "")})
        elif cb.get("type") == "thinking":
            assembled.append({
                "type": "thinking",
                "thinking": cb.get("thinking", ""),
                "signature": cb.get("signature", ""),
            })
        elif cb.get("type") == "redacted_thinking":
            assembled.append({
                "type": "redacted_thinking",
                "data": cb.get("data", ""),
            })
        elif cb.get("type") in ("tool_use", "server_tool_use"):
            assembled.append({
                "type": cb["type"],
                "id": cb.get("id", ""),
                "name": cb.get("name", ""),
                "input": cb.get("input", {}),
            })
        elif cb.get("type") in _SERVER_RESULT_TYPES:
            assembled.append(dict(cb))
    message["content"] = assembled
    return message
