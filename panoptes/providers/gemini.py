"""Google Gemini API provider adapter."""

from __future__ import annotations

import json
from typing import Any

from .base import Provider


class GeminiProvider(Provider):
    """Adapter for the Google Gemini generateContent / streamGenerateContent API."""

    name = "gemini"

    def matches_path(self, path: str) -> bool:
        return any(
            pat in path
            for pat in ("generateContent", "streamGenerateContent", "/v1beta/", "/v1alpha/")
        )

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        return "contents" in body or "system_instruction" in body

    @property
    def default_upstream(self) -> str:
        return "https://generativelanguage.googleapis.com"

    def _request_info(self, body: dict) -> dict[str, Any]:
        contents = body.get("contents", [])
        tools = body.get("tools")
        return {
            "model": body.get("model", "unknown"),
            "messages_count": len(contents) + (1 if body.get("system_instruction") else 0),
            "tools_count": len(tools) if isinstance(tools, list) else 0,
            # Streaming is signalled by the endpoint path — see is_streaming().
            "stream": False,
        }

    def is_streaming(self, path: str, body: dict | None) -> bool:
        # Gemini streams via the :streamGenerateContent endpoint (optionally
        # with ?alt=sse), not a request-body flag.
        return "streamGenerateContent" in path

    def estimate_turn_number(self, body: dict | None) -> int:
        if not isinstance(body, dict):
            return 0
        contents = body.get("contents", [])
        return sum(1 for c in contents if isinstance(c, dict) and c.get("role") == "model")

    def extract_tool_calls(self, resp_body: dict) -> list[dict]:
        # Gemini tool calls come as functionCall parts in candidates
        events: list[dict] = []
        for candidate in resp_body.get("candidates", []):
            content = candidate.get("content") or {}
            for part in content.get("parts", []):
                if isinstance(part, dict) and "functionCall" in part:
                    fc = part["functionCall"]
                    events.append({
                        "tool_name": fc.get("name", "unknown"),
                        "parameters": fc.get("args", {}),
                        "call_id": "",
                    })
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        # Gemini tool results come as functionResponse parts in contents
        events: list[dict] = []
        for content in req_body.get("contents", []):
            for part in (content.get("parts") or []):
                if isinstance(part, dict) and "functionResponse" in part:
                    fr = part["functionResponse"]
                    events.append({
                        "tool_name": fr.get("name", "unknown"),
                        "result": fr.get("response", ""),
                        "call_id": "",
                    })
        return events

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usageMetadata", {})
        return {
            "tokens_in": usage.get("promptTokenCount", 0),
            "tokens_out": usage.get("candidatesTokenCount", 0),
        }

    def reassemble_sse(self, raw_bytes: bytes) -> dict:
        return _reassemble_gemini_sse(raw_bytes)


def _reassemble_gemini_sse(raw: bytes) -> dict:
    """Reassemble Gemini streaming response bytes into a final response dict."""
    text = raw.decode("utf-8", errors="replace").strip()
    chunks: list[dict] = []

    # Try JSON array first
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            chunks = [c for c in parsed if isinstance(c, dict)]
        elif isinstance(parsed, dict):
            chunks = [parsed]
    except (json.JSONDecodeError, ValueError):
        # Try SSE or newline-delimited JSON
        for line in text.splitlines():
            line = line.strip()
            if not line or line == "[DONE]":
                continue
            if line.startswith("data: "):
                line = line[6:]
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    chunks.append(obj)
            except (json.JSONDecodeError, ValueError):
                pass

    if not chunks:
        return {}

    # Merge parts across chunks: text parts concatenate into one, while
    # functionCall (and any other non-text) parts are kept as-is so that
    # streamed tool calls still show up in the reassembled response.
    text_fragments: list[str] = []
    other_parts: list[dict] = []
    for chunk in chunks:
        for cand in chunk.get("candidates", []):
            for part in (cand.get("content") or {}).get("parts", []):
                if not isinstance(part, dict):
                    continue
                if "text" in part:
                    text_fragments.append(part.get("text", ""))
                else:
                    other_parts.append(part)

    parts: list[dict] = []
    all_text = "".join(text_fragments)
    if all_text:
        parts.append({"text": all_text})
    parts.extend(other_parts)

    last = chunks[-1]
    result: dict[str, Any] = {
        "candidates": [],
        "usageMetadata": last.get("usageMetadata", {}),
    }
    if parts:
        finish_reason = None
        if last.get("candidates"):
            finish_reason = last["candidates"][0].get("finishReason")
        result["candidates"] = [{
            "content": {"parts": parts, "role": "model"},
            "finishReason": finish_reason,
        }]
    return result
