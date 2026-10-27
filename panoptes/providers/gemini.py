"""Google Gemini API provider adapter."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from .base import (
    Provider,
    SSEParseError,
    _parse_sse_events,
    _route_matches,
    _strict_json_loads,
    _usage_count,
)

# Gemini's OpenAI-compatible routes (/v1beta/openai/...) are deliberately
# absent: their payloads are OpenAI-shaped and this parser would see no tools.
_ROUTES = (
    re.compile(r"/v1(?:beta|alpha)?/models/[^/:]+:(?:generateContent|streamGenerateContent)"),
)

_MODEL_IN_ROUTE = re.compile(r"/models/([^/:]+):")

_GEMINI_PART_FIELDS = frozenset({
    "text",
    "inlineData",
    "fileData",
    "functionCall",
    "functionResponse",
    "executableCode",
    "codeExecutionResult",
    "toolCall",
    "toolResponse",
})
_GEMINI_PART_METADATA = frozenset({
    "thought",
    "thoughtSignature",
    "partMetadata",
    "videoMetadata",
})


def _required_text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value:
        raise SSEParseError(f"{source} must be a non-empty string")
    return value


def _optional_id(value: Any, *, source: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise SSEParseError(f"{source} must be a string")
    return value


def _gemini_parts(payload: dict, *, source: str) -> list[dict]:
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        raise SSEParseError(f"{source} candidates must be a list")
    parts: list[dict] = []
    for candidate_index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise SSEParseError(
                f"{source} candidate {candidate_index} must be an object"
            )
        content = candidate.get("content") or {}
        if not isinstance(content, dict):
            raise SSEParseError(
                f"{source} candidate {candidate_index} content must be an object"
            )
        raw_parts = content.get("parts", [])
        if not isinstance(raw_parts, list):
            raise SSEParseError(
                f"{source} candidate {candidate_index} parts must be a list"
            )
        for part_index, part in enumerate(raw_parts):
            if not isinstance(part, dict):
                raise SSEParseError(
                    f"{source} part {part_index} must be an object"
                )
            unknown = set(part) - _GEMINI_PART_FIELDS - _GEMINI_PART_METADATA
            if unknown:
                raise SSEParseError(
                    f"{source} part {part_index} has unsupported fields: "
                    + ", ".join(sorted(str(key) for key in unknown))
                )
            payload_fields = set(part) & _GEMINI_PART_FIELDS
            if len(payload_fields) != 1:
                raise SSEParseError(
                    f"{source} part {part_index} must contain exactly one payload"
                )
            parts.append(part)
    return parts


def _gemini_tool_type(item: dict, *, source: str) -> str:
    value = item.get("toolType", item.get("tool_type", item.get("name")))
    return _required_text(value, source=f"{source} tool type")


def _gemini_tool_parameters(item: dict) -> dict:
    arguments = item.get("args", item.get("arguments"))
    if arguments is not None:
        if not isinstance(arguments, dict):
            raise SSEParseError("Gemini tool call arguments must be an object")
        return dict(arguments)
    return {
        key: value
        for key, value in item.items()
        if key not in {
            "id",
            "toolType",
            "tool_type",
            "name",
            "thoughtSignature",
            "signature",
        }
    }


class GeminiProvider(Provider):
    """Adapter for the Google Gemini generateContent / streamGenerateContent API."""

    name = "gemini"

    def matches_path(self, path: str) -> bool:
        return _route_matches(path, _ROUTES)

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        return "contents" in body or "system_instruction" in body

    @property
    def default_upstream(self) -> str:
        return "https://generativelanguage.googleapis.com"

    def model_from_path(self, path: str) -> str | None:
        match = _MODEL_IN_ROUTE.search(urlparse(path).path)
        return match.group(1) if match else None

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

    def extract_tool_calls(
        self,
        resp_body: dict,
        *,
        path: str | None = None,
    ) -> list[dict]:
        events: list[dict] = []
        parts = _gemini_parts(resp_body, source="Gemini response")
        code_results: dict[str | None, dict] = {}
        tool_results: dict[str | None, dict] = {}
        code_results_without_id: list[dict] = []
        tool_results_without_id: list[dict] = []
        for part in parts:
            if "codeExecutionResult" in part:
                result = part["codeExecutionResult"]
                if not isinstance(result, dict):
                    raise SSEParseError(
                        "Gemini codeExecutionResult must be an object"
                    )
                result_id = _optional_id(
                    result.get("id"),
                    source="Gemini codeExecutionResult id",
                )
                if result_id is None:
                    code_results_without_id.append(result)
                elif result_id in code_results:
                    raise SSEParseError(
                        f"duplicate Gemini code result id {result_id!r}"
                    )
                else:
                    code_results[result_id] = result
            elif "toolResponse" in part:
                result = part["toolResponse"]
                if not isinstance(result, dict):
                    raise SSEParseError("Gemini toolResponse must be an object")
                result_id = _optional_id(
                    result.get("id"),
                    source="Gemini toolResponse id",
                )
                if result_id is None:
                    tool_results_without_id.append(result)
                elif result_id in tool_results:
                    raise SSEParseError(
                        f"duplicate Gemini tool response id {result_id!r}"
                    )
                else:
                    tool_results[result_id] = result

        code_result_index = 0
        tool_result_index = 0
        for part in parts:
            if "functionCall" in part:
                fc = part["functionCall"]
                if not isinstance(fc, dict):
                    raise SSEParseError("Gemini functionCall must be an object")
                name = _required_text(
                    fc.get("name"),
                    source="Gemini functionCall name",
                )
                args = fc.get("args", {})
                if not isinstance(args, dict):
                    raise SSEParseError("Gemini functionCall args must be an object")
                events.append({
                    "tool_name": name,
                    "parameters": args,
                    # Gemini 3 emits an id for correlated function calls;
                    # older responses may omit it. Never fabricate the
                    # universal-schema correlation identifier.
                    "call_id": _optional_id(
                        fc.get("id"),
                        source="Gemini functionCall id",
                    ),
                })
            elif "executableCode" in part:
                code = part["executableCode"]
                if not isinstance(code, dict):
                    raise SSEParseError("Gemini executableCode must be an object")
                call_id = _optional_id(
                    code.get("id"),
                    source="Gemini executableCode id",
                )
                language = _required_text(
                    code.get("language"),
                    source="Gemini executableCode language",
                )
                source_code = _required_text(
                    code.get("code"),
                    source="Gemini executableCode code",
                )
                if call_id is None:
                    result = (
                        code_results_without_id[code_result_index]
                        if code_result_index < len(code_results_without_id)
                        else None
                    )
                    code_result_index += 1
                else:
                    result = code_results.pop(call_id, None)
                outcome = result.get("outcome") if result else None
                events.append({
                    "tool_name": "code_execution",
                    "parameters": {
                        "language": language,
                        "code": source_code,
                    },
                    "call_id": call_id,
                    "execution_scope": "provider",
                    "provider_item_type": "executableCode",
                    "outcome_status": (
                        "success"
                        if outcome == "OUTCOME_OK"
                        else "error"
                        if outcome in (
                            "OUTCOME_FAILED",
                            "OUTCOME_DEADLINE_EXCEEDED",
                        )
                        else "pending"
                    ),
                    "server_result": result.get("output") if result else None,
                    "server_result_type": "codeExecutionResult",
                })
            elif "toolCall" in part:
                call = part["toolCall"]
                if not isinstance(call, dict):
                    raise SSEParseError("Gemini toolCall must be an object")
                call_id = _optional_id(
                    call.get("id"),
                    source="Gemini toolCall id",
                )
                if call_id is None:
                    result = (
                        tool_results_without_id[tool_result_index]
                        if tool_result_index < len(tool_results_without_id)
                        else None
                    )
                    tool_result_index += 1
                else:
                    result = tool_results.pop(call_id, None)
                result_failed = bool(
                    result
                    and (
                        result.get("error")
                        or result.get("status")
                        in ("ERROR", "FAILED", "CANCELLED")
                    )
                )
                events.append({
                    "tool_name": _gemini_tool_type(
                        call,
                        source="Gemini toolCall",
                    ),
                    "parameters": _gemini_tool_parameters(call),
                    "call_id": call_id,
                    "execution_scope": "provider",
                    "provider_item_type": "toolCall",
                    "outcome_status": (
                        "error"
                        if result_failed
                        else "success" if result else "pending"
                    ),
                    "server_result": result,
                    "server_result_type": "toolResponse",
                })
        if (
            code_results
            or tool_results
            or code_result_index < len(code_results_without_id)
            or tool_result_index < len(tool_results_without_id)
        ):
            raise SSEParseError(
                "Gemini response contains an unpaired server tool result"
            )
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        events: list[dict] = []
        contents = req_body.get("contents", [])
        if not isinstance(contents, list):
            raise SSEParseError("Gemini request contents must be a list")
        for content_index, content in enumerate(contents):
            if not isinstance(content, dict):
                raise SSEParseError(
                    f"Gemini request content {content_index} must be an object"
                )
            raw_parts = content.get("parts") or []
            if not isinstance(raw_parts, list):
                raise SSEParseError("Gemini request parts must be a list")
            for part in raw_parts:
                if not isinstance(part, dict):
                    raise SSEParseError("Gemini request part must be an object")
                if "functionResponse" in part:
                    fr = part["functionResponse"]
                    if not isinstance(fr, dict):
                        raise SSEParseError(
                            "Gemini functionResponse must be an object"
                        )
                    events.append({
                        "tool_name": _required_text(
                            fr.get("name"),
                            source="Gemini functionResponse name",
                        ),
                        "result": fr.get("response", ""),
                        "call_id": _optional_id(
                            fr.get("id"),
                            source="Gemini functionResponse id",
                        ),
                        "is_error": bool(fr.get("error")),
                    })
        return events

    def extract_requested_tools(self, req_body: dict) -> dict[str, list[str]]:
        requested: list[str] = []
        client_side: list[str] = []
        server_side: list[str] = []
        unknown: list[str] = []
        targets: list[str] = []
        server_keys = {
            "googleSearch",
            "googleSearchRetrieval",
            "codeExecution",
            "urlContext",
            "googleMaps",
            "enterpriseWebSearch",
            "fileSearch",
        }
        client_keys = {"computerUse"}
        tools = req_body.get("tools", [])
        if tools is None:
            tools = []
        if not isinstance(tools, list):
            raise SSEParseError("Gemini request tools must be a list")
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise SSEParseError(
                    f"Gemini request tool {index} must be an object"
                )
            if not tool:
                raise SSEParseError(f"Gemini request tool {index} is empty")
            for tool_type, config in tool.items():
                if tool_type == "functionDeclarations":
                    if not isinstance(config, list):
                        raise SSEParseError(
                            "Gemini functionDeclarations must be a list"
                        )
                    for declaration_index, declaration in enumerate(config):
                        if not isinstance(declaration, dict):
                            raise SSEParseError(
                                "Gemini function declaration "
                                f"{declaration_index} must be an object"
                            )
                        name = declaration.get("name")
                        if not isinstance(name, str) or not name:
                            raise SSEParseError(
                                "Gemini function declaration is missing a name"
                            )
                        label = f"function:{name}"
                        requested.append(label)
                        client_side.append(label)
                    continue
                label = tool_type
                requested.append(label)
                if tool_type in server_keys:
                    server_side.append(label)
                elif tool_type in client_keys:
                    client_side.append(label)
                else:
                    unknown.append(label)
                if isinstance(config, dict):
                    for key in ("url", "serverUrl", "fileSearchStoreNames"):
                        value = config.get(key)
                        if isinstance(value, str) and value:
                            targets.append(f"{key}:{value}")
                        elif isinstance(value, list):
                            targets.extend(
                                f"{key}:{item}"
                                for item in value
                                if isinstance(item, str) and item
                            )
        tool_config = req_body.get("toolConfig", {})
        if tool_config is None:
            tool_config = {}
        if not isinstance(tool_config, dict):
            raise SSEParseError("Gemini toolConfig must be an object")
        exact_server_visibility = tool_config.get(
            "includeServerSideToolInvocations",
            False,
        )
        if not isinstance(exact_server_visibility, bool):
            raise SSEParseError(
                "Gemini includeServerSideToolInvocations must be a boolean"
            )
        # Code execution always returns executableCode/codeExecutionResult.
        # Other built-ins require this opt-in for exact invocation parts;
        # grounding metadata alone is not a complete action audit.
        if (
            any(label != "codeExecution" for label in server_side)
            and not exact_server_visibility
        ):
            unknown.append(
                "visibility:server_side_invocations_not_requested"
            )
        return {
            "requested_tools": requested,
            "client_side_tools": client_side,
            "server_side_tools": server_side,
            "unknown_tool_types": unknown,
            "requested_tool_targets": targets,
        }

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usageMetadata", {})
        return {
            "tokens_in": _usage_count(usage, "promptTokenCount"),
            # Thinking tokens are billed as output but counted separately.
            "tokens_out": (
                _usage_count(usage, "candidatesTokenCount")
                + _usage_count(usage, "thoughtsTokenCount")
            ),
        }

    def reassemble_sse(
        self,
        raw_bytes: bytes,
        *,
        path: str | None = None,
    ) -> dict:
        return _reassemble_gemini_sse(raw_bytes)


def _reassemble_gemini_sse(raw: bytes) -> dict:
    """Reassemble Gemini streaming response bytes into a final response dict."""
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise SSEParseError(
            f"invalid UTF-8 in Gemini streaming response at byte {exc.start}"
        ) from exc
    chunks: list[dict] = []

    # Try JSON array first
    try:
        parsed = _strict_json_loads(text)
        if isinstance(parsed, list):
            if not all(isinstance(chunk, dict) for chunk in parsed):
                raise SSEParseError(
                    "Gemini streaming JSON array must contain only objects"
                )
            chunks = list(parsed)
        elif isinstance(parsed, dict):
            chunks = [parsed]
        else:
            raise SSEParseError(
                "Gemini streaming response must be a JSON object or array"
            )
    except json.JSONDecodeError:
        # Gemini also supports EventSource framing via ``?alt=sse``.
        chunks = _parse_sse_events(raw)
    except ValueError as exc:
        raise SSEParseError(f"invalid Gemini streaming JSON: {exc}") from exc

    if not chunks:
        raise SSEParseError("Gemini streaming response contained no JSON events")

    # Merge parts across chunks: text parts concatenate into one, while
    # functionCall (and any other non-text) parts are kept as-is so that
    # streamed tool calls still show up in the reassembled response.
    text_fragments: list[str] = []
    other_parts: list[dict] = []
    seen_correlated_parts: dict[tuple[str, str], dict] = {}
    for chunk_index, chunk in enumerate(chunks):
        for part in _gemini_parts(
            chunk,
            source=f"Gemini stream chunk {chunk_index}",
        ):
            if "text" in part:
                text = part["text"]
                if not isinstance(text, str):
                    raise SSEParseError("Gemini text part must be a string")
                text_fragments.append(text)
                continue

            payload_field = next(iter(set(part) & _GEMINI_PART_FIELDS))
            payload = part[payload_field]
            correlated_id = (
                payload.get("id")
                if isinstance(payload, dict)
                else None
            )
            if isinstance(correlated_id, str) and correlated_id:
                key = (payload_field, correlated_id)
                earlier = seen_correlated_parts.get(key)
                if earlier is not None:
                    if earlier != part:
                        raise SSEParseError(
                            "Gemini stream contradicted a correlated tool part"
                        )
                    continue
                seen_correlated_parts[key] = part
            other_parts.append(part)

    parts: list[dict] = []
    all_text = "".join(text_fragments)
    if all_text:
        parts.append({"text": all_text})
    parts.extend(other_parts)

    last = chunks[-1]
    usage = last.get("usageMetadata", {})
    if not isinstance(usage, dict):
        raise SSEParseError("Gemini usageMetadata must be an object")
    result: dict[str, Any] = {
        "candidates": [],
        "usageMetadata": usage,
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
