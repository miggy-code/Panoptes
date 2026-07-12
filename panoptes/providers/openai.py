"""OpenAI API provider adapter."""

from __future__ import annotations

import json
from typing import Any

from .base import Provider, _parse_sse_events


class OpenAIProvider(Provider):
    """Adapter for the OpenAI Chat Completions / Responses API."""

    name = "openai"

    def matches_path(self, path: str) -> bool:
        return any(pat in path for pat in ("/chat/completions", "/responses", "/completions", "/models"))

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        return isinstance(body.get("messages"), list)

    @property
    def default_upstream(self) -> str:
        return "https://api.openai.com"

    def _request_info(self, body: dict) -> dict[str, Any]:
        tools = body.get("tools") or body.get("functions")
        return {
            "model": body.get("model", "unknown"),
            "messages_count": len(body.get("messages", [])),
            "tools_count": len(tools) if isinstance(tools, list) else 0,
            "stream": bool(body.get("stream", False)),
        }

    def extract_tool_calls(self, resp_body: dict) -> list[dict]:
        events: list[dict] = []
        for choice in resp_body.get("choices", []):
            message = choice.get("message", {})
            for tc in message.get("tool_calls", []):
                func = tc.get("function", {})
                args = func.get("arguments", "{}")
                try:
                    params = json.loads(args) if isinstance(args, str) else args
                except (json.JSONDecodeError, ValueError):
                    params = {"_raw": args}
                events.append({
                    "tool_name": func.get("name", "unknown"),
                    "parameters": params,
                    "call_id": tc.get("id", ""),
                })
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        events: list[dict] = []
        for msg in req_body.get("messages", []):
            if msg.get("role") == "tool":
                events.append({
                    "tool_name": msg.get("name", "unknown"),
                    "result": msg.get("content", ""),
                    "call_id": msg.get("tool_call_id", ""),
                })
        return events

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usage", {})
        return {
            "tokens_in": usage.get("prompt_tokens", 0),
            "tokens_out": usage.get("completion_tokens", 0),
        }

    def reassemble_sse(self, raw_bytes: bytes) -> dict:
        return _reassemble_openai_sse(_parse_sse_events(raw_bytes))


def _reassemble_openai_sse(chunks: list[dict]) -> dict:
    """Reassemble OpenAI chat completion SSE chunks into a final response dict."""
    result: dict[str, Any] = {
        "id": None,
        "object": "chat.completion",
        "created": None,
        "model": None,
        "choices": [],
        "usage": {},
    }
    choices: dict[int, dict] = {}

    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        result["id"] = result["id"] or chunk.get("id")
        result["model"] = result["model"] or chunk.get("model")
        result["created"] = result["created"] or chunk.get("created")
        if chunk.get("usage"):
            result["usage"] = chunk["usage"]

        for choice in chunk.get("choices", []):
            idx = choice.get("index", 0)
            if idx not in choices:
                choices[idx] = {
                    "index": idx,
                    "message": {"role": "assistant", "content": "", "tool_calls": {}},
                    "finish_reason": None,
                }
            c = choices[idx]
            if choice.get("finish_reason"):
                c["finish_reason"] = choice["finish_reason"]

            delta = choice.get("delta", {})
            if delta.get("role"):
                c["message"]["role"] = delta["role"]
            if delta.get("content"):
                c["message"]["content"] = (c["message"]["content"] or "") + delta["content"]

            for tc_delta in delta.get("tool_calls", []):
                tc_idx = tc_delta.get("index", 0)
                if tc_idx not in c["message"]["tool_calls"]:
                    c["message"]["tool_calls"][tc_idx] = {
                        "index": tc_idx,
                        "id": "",
                        "type": "function",
                        "function": {"name": "", "arguments": ""},
                    }
                tc = c["message"]["tool_calls"][tc_idx]
                if tc_delta.get("id"):
                    tc["id"] = tc["id"] or tc_delta["id"]
                func = tc_delta.get("function", {})
                tc["function"]["name"] += func.get("name", "")
                tc["function"]["arguments"] += func.get("arguments", "")

    for idx in sorted(choices.keys()):
        c = choices[idx]
        tc_dict = c["message"].get("tool_calls", {})
        if tc_dict:
            c["message"]["tool_calls"] = [tc_dict[i] for i in sorted(tc_dict.keys())]
        else:
            del c["message"]["tool_calls"]
        if not c["message"].get("content"):
            c["message"]["content"] = None
        result["choices"].append(c)

    return result
