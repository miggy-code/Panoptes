"""Anthropic API provider adapter."""

from __future__ import annotations

import json
from typing import Any

from .base import Provider, _parse_sse_events


class AnthropicProvider(Provider):
    """Adapter for the Anthropic Messages API."""

    name = "anthropic"

    def matches_path(self, path: str) -> bool:
        return "/v1/messages" in path

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        if "system" in body:
            return True
        messages = body.get("messages")
        if (
            isinstance(messages, list)
            and messages
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

    def extract_tool_calls(self, resp_body: dict) -> list[dict]:
        events: list[dict] = []
        content = resp_body.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    events.append({
                        "tool_name": block.get("name", "unknown"),
                        "parameters": block.get("input", {}),
                        "call_id": block.get("id", ""),
                    })
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        events: list[dict] = []
        for msg in req_body.get("messages", []):
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        events.append({
                            "tool_name": block.get("tool_use_id", "unknown"),
                            "result": block.get("content", ""),
                            "call_id": block.get("tool_use_id", ""),
                        })
        return events

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usage", {})
        return {
            "tokens_in": usage.get("input_tokens", 0),
            "tokens_out": usage.get("output_tokens", 0),
        }

    def reassemble_sse(self, raw_bytes: bytes) -> dict:
        return _reassemble_anthropic_sse(_parse_sse_events(raw_bytes))


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

    for ev in events:
        ev_type = ev.get("type")

        if ev_type == "message_start":
            msg = ev.get("message", {})
            message["id"] = msg.get("id")
            message["model"] = msg.get("model")
            message["stop_reason"] = msg.get("stop_reason")
            usage = msg.get("usage", {})
            message["usage"]["input_tokens"] = usage.get("input_tokens", 0)
            message["usage"]["output_tokens"] = usage.get("output_tokens", 0)

        elif ev_type == "content_block_start":
            index = ev.get("index", 0)
            block = ev.get("content_block", {})
            block_type = block.get("type", "text")
            cb: dict[str, Any] = {"type": block_type}
            if block_type == "text":
                cb["text"] = block.get("text", "")
            elif block_type == "tool_use":
                cb["id"] = block.get("id", "")
                cb["name"] = block.get("name", "")
                cb["input"] = {}
                cb["_fragments"] = []
            content_blocks[index] = cb

        elif ev_type == "content_block_delta":
            index = ev.get("index", 0)
            delta = ev.get("delta", {})
            if index in content_blocks:
                cb = content_blocks[index]
                dt = delta.get("type")
                if dt == "text_delta":
                    cb["text"] = cb.get("text", "") + delta.get("text", "")
                elif dt == "input_json_delta" and "_fragments" in cb:
                    cb["_fragments"].append(delta.get("partial_json", ""))

        elif ev_type == "content_block_stop":
            index = ev.get("index", 0)
            if index in content_blocks:
                cb = content_blocks[index]
                if "_fragments" in cb:
                    full_json = "".join(cb["_fragments"])
                    try:
                        cb["input"] = json.loads(full_json) if full_json else {}
                    except (json.JSONDecodeError, ValueError):
                        cb["input"] = {"_raw": full_json}
                    del cb["_fragments"]

        elif ev_type == "message_delta":
            delta = ev.get("delta", {})
            if "stop_reason" in delta:
                message["stop_reason"] = delta["stop_reason"]
            if "stop_sequence" in delta:
                message["stop_sequence"] = delta["stop_sequence"]
            delta_usage = ev.get("usage", {})
            if "output_tokens" in delta_usage:
                message["usage"]["output_tokens"] = delta_usage["output_tokens"]

    # Assemble content blocks in index order
    assembled: list[dict] = []
    for i in sorted(content_blocks.keys()):
        cb = content_blocks[i]
        if cb.get("type") == "text":
            assembled.append({"type": "text", "text": cb.get("text", "")})
        elif cb.get("type") == "tool_use":
            assembled.append({
                "type": "tool_use",
                "id": cb.get("id", ""),
                "name": cb.get("name", ""),
                "input": cb.get("input", {}),
            })
    message["content"] = assembled
    return message
