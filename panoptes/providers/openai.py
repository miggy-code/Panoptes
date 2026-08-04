"""OpenAI API provider adapter."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from .base import (
    Provider,
    SSEParseError,
    _parse_sse_events,
    _strict_json_loads,
)


_CLIENT_ACTION_OUTPUT_TYPES = frozenset({
    "function_call",
    "custom_tool_call",
    "computer_call",
    "local_shell_call",
    "shell_call",
    "apply_patch_call",
})
_SERVER_ACTION_OUTPUT_TYPES = frozenset({
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "mcp_call",
    "mcp_list_tools",
    "mcp_approval_request",
    "tool_search_call",
})
_ACTION_OUTPUT_TYPES = (
    _CLIENT_ACTION_OUTPUT_TYPES | _SERVER_ACTION_OUTPUT_TYPES
)
_ACTION_RESULT_OUTPUT_TYPES = frozenset({
    "shell_call_output",
    "apply_patch_call_output",
})
_NON_ACTION_OUTPUT_TYPES = frozenset({
    "message",
    "reasoning",
    "compaction",
})


def _decode_function_arguments(arguments: Any, *, source: str) -> dict:
    """Return one unambiguous function-argument object."""
    if isinstance(arguments, str):
        try:
            decoded = _strict_json_loads(arguments)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SSEParseError(
                f"{source} has incomplete, duplicate, or invalid arguments"
            ) from exc
    else:
        decoded = arguments
    if not isinstance(decoded, dict):
        raise SSEParseError(f"{source} arguments must be a JSON object")
    return decoded


def _required_text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value:
        raise SSEParseError(f"{source} must be a non-empty string")
    return value


def _optional_call_id(item: dict, *, source: str) -> str | None:
    value = item.get("call_id") or item.get("id")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SSEParseError(f"{source} has an invalid call identifier")
    return value


def _responses_action_parameters(
    item: dict,
    *,
    item_type: str,
    source: str,
) -> dict:
    """Return complete structured policy input for a Responses action item."""
    if item_type == "function_call":
        return _decode_function_arguments(
            item.get("arguments", "{}"),
            source=source,
        )
    if item_type == "custom_tool_call":
        if "input" not in item:
            raise SSEParseError(f"{source} is missing custom tool input")
        return {"input": item["input"]}

    for field in ("action", "operation"):
        if field in item:
            value = item[field]
            if not isinstance(value, dict):
                raise SSEParseError(f"{source} {field} must be an object")
            return dict(value)

    parameters: dict[str, Any] = {}
    if "arguments" in item:
        arguments = item["arguments"]
        if isinstance(arguments, str):
            try:
                arguments = _strict_json_loads(arguments)
            except (json.JSONDecodeError, ValueError) as exc:
                raise SSEParseError(
                    f"{source} has invalid or ambiguous arguments"
                ) from exc
        if not isinstance(arguments, dict):
            raise SSEParseError(f"{source} arguments must be an object")
        parameters.update(arguments)

    # These are the security-relevant inputs used by current hosted-tool
    # output items. Results and generated content are intentionally excluded:
    # they can be large and are not instructions to execute.
    for field in (
        "query",
        "queries",
        "code",
        "input",
        "name",
        "server_label",
        "container_id",
    ):
        if field in item and field not in parameters:
            parameters[field] = item[field]
    return parameters


def _extract_responses_action(item: dict, *, index: int) -> dict | None:
    item_type = item.get("type")
    if not isinstance(item_type, str) or not item_type:
        raise SSEParseError(f"Responses output item {index} is missing a type")
    if item_type in _NON_ACTION_OUTPUT_TYPES:
        return None
    if item_type in _ACTION_RESULT_OUTPUT_TYPES:
        _extract_responses_action_result(item, index=index)
        return None
    if item_type not in _ACTION_OUTPUT_TYPES:
        # A new output-item type may be a new execution primitive. Treating it
        # as harmless would silently weaken enforcement until the adapter is
        # upgraded.
        raise SSEParseError(
            f"unsupported Responses output item type {item_type!r}"
        )

    source = f"Responses {item_type} item {index}"
    if item_type in ("function_call", "custom_tool_call"):
        tool_name = _required_text(item.get("name"), source=f"{source} name")
    elif item_type.startswith("mcp_") and isinstance(item.get("name"), str):
        tool_name = item["name"] or item_type.removesuffix("_call")
    else:
        tool_name = item_type.removesuffix("_call")

    status = item.get("status")
    if status is not None and not isinstance(status, str):
        raise SSEParseError(f"{source} status must be a string")
    execution_scope = (
        "client"
        if item_type in _CLIENT_ACTION_OUTPUT_TYPES
        else "provider"
    )
    if execution_scope == "client" or item_type == "mcp_approval_request":
        outcome_status = "pending"
    elif status in ("failed", "error", "cancelled"):
        outcome_status = "error"
    elif status in ("in_progress", "queued"):
        outcome_status = "pending"
    else:
        # Hosted actions in a completed response have crossed the provider
        # execution boundary even when no per-item status is supplied.
        outcome_status = "success"

    action = {
        "tool_name": tool_name,
        "parameters": _responses_action_parameters(
            item,
            item_type=item_type,
            source=source,
        ),
        "call_id": _optional_call_id(item, source=source),
    }
    # Preserve the long-standing function-call adapter contract. Extended
    # metadata is needed for non-function action types, where the proxy must
    # distinguish a client proposal from an already executed hosted tool.
    if item_type != "function_call":
        action.update({
            "execution_scope": execution_scope,
            "provider_item_type": item_type,
            "outcome_status": outcome_status,
        })
    return action


def _extract_responses_action_result(item: dict, *, index: int) -> dict:
    item_type = item.get("type")
    if item_type not in _ACTION_RESULT_OUTPUT_TYPES:
        raise SSEParseError(
            f"Responses output item {index} is not a supported action result"
        )
    source = f"Responses {item_type} item {index}"
    call_id = _required_text(item.get("call_id"), source=f"{source} call_id")
    status = item.get("status")
    if status is not None and not isinstance(status, str):
        raise SSEParseError(f"{source} status must be a string")
    return {
        "call_id": call_id,
        "status": status,
        "result": item.get("output"),
        "result_type": item_type,
    }


class OpenAIProvider(Provider):
    """Adapter for the OpenAI Chat Completions / Responses API."""

    name = "openai"

    def matches_path(self, path: str) -> bool:
        return any(pat in path for pat in ("/chat/completions", "/responses", "/completions", "/models"))

    def matches_body(self, body: dict | None) -> bool:
        if not isinstance(body, dict):
            return False
        return isinstance(body.get("messages"), list) or "input" in body

    @property
    def default_upstream(self) -> str:
        return "https://api.openai.com"

    def _request_info(self, body: dict) -> dict[str, Any]:
        tools = body.get("tools") or body.get("functions")
        if "input" in body and "messages" not in body:
            input_value = body.get("input")
            messages_count = (
                len(input_value)
                if isinstance(input_value, list)
                else int(input_value is not None)
            )
        else:
            messages_count = len(body.get("messages", []))
        return {
            "model": body.get("model", "unknown"),
            "messages_count": messages_count,
            "tools_count": len(tools) if isinstance(tools, list) else 0,
            "stream": bool(body.get("stream", False)),
        }

    @staticmethod
    def _response_dialect(
        *,
        path: str | None,
        has_responses_shape: bool,
        has_chat_shape: bool,
    ) -> str:
        """Select one response dialect without trusting response-controlled hints."""
        route = urlparse(path).path.rstrip("/") if path else ""
        if route.endswith("/responses") or "/responses/" in route:
            if has_chat_shape:
                raise SSEParseError(
                    "Responses endpoint returned a cross-dialect Chat payload"
                )
            return "responses"
        if route.endswith("/chat/completions") or route.endswith("/completions"):
            if has_responses_shape:
                raise SSEParseError(
                    "Chat Completions endpoint returned a cross-dialect Responses payload"
                )
            return "chat"

        # Backward-compatible/custom-upstream fallback. Ambiguous content is
        # rejected; an untrusted response never gets to choose which evidence
        # the policy layer sees when both dialects are present.
        if has_responses_shape and has_chat_shape:
            raise SSEParseError("OpenAI response mixes Chat and Responses dialects")
        return "responses" if has_responses_shape else "chat"

    def extract_tool_calls(
        self,
        resp_body: dict,
        *,
        path: str | None = None,
    ) -> list[dict]:
        events: list[dict] = []
        dialect = self._response_dialect(
            path=path,
            has_responses_shape="output" in resp_body,
            has_chat_shape="choices" in resp_body,
        )
        if dialect == "responses":
            output = resp_body.get("output", [])
            if not isinstance(output, list):
                raise SSEParseError("Responses output must be a list")
            action_results: dict[tuple[str, str], dict] = {}
            for index, item in enumerate(output):
                if not isinstance(item, dict):
                    raise SSEParseError(
                        f"Responses output item {index} must be an object"
                    )
                item_type = item.get("type")
                if item_type in _ACTION_RESULT_OUTPUT_TYPES:
                    result = _extract_responses_action_result(item, index=index)
                    action_type = item_type.removesuffix("_output")
                    key = (action_type, result["call_id"])
                    if key in action_results:
                        raise SSEParseError(
                            f"duplicate Responses result for {result['call_id']!r}"
                        )
                    action_results[key] = result

            for index, item in enumerate(output):
                action = _extract_responses_action(item, index=index)
                if action is not None:
                    action_type = item["type"]
                    call_id = action.get("call_id")
                    if isinstance(call_id, str):
                        paired_result = action_results.pop(
                            (action_type, call_id),
                            None,
                        )
                    else:
                        paired_result = None
                    if action_type == "shell_call" and paired_result is not None:
                        result_status = paired_result["status"]
                        action.update({
                            "execution_scope": "provider",
                            "outcome_status": (
                                "error"
                                if result_status in (
                                    "failed",
                                    "error",
                                    "cancelled",
                                )
                                else "pending"
                                if result_status in ("queued", "in_progress")
                                else "success"
                            ),
                            "server_result": paired_result["result"],
                            "server_result_type": paired_result["result_type"],
                        })
                    events.append(action)
            if action_results:
                raise SSEParseError(
                    "Responses output contains an unpaired action result"
                )
            return events

        choices = resp_body.get("choices", [])
        if not isinstance(choices, list):
            raise SSEParseError("Chat Completions choices must be a list")
        for choice_index, choice in enumerate(choices):
            if not isinstance(choice, dict):
                raise SSEParseError(
                    f"Chat Completions choice {choice_index} must be an object"
                )
            message = choice.get("message", {})
            if not isinstance(message, dict):
                raise SSEParseError(
                    f"Chat Completions choice {choice_index} message must be an object"
                )
            tool_calls = message.get("tool_calls") or []
            if not isinstance(tool_calls, list):
                raise SSEParseError("Chat Completions tool_calls must be a list")
            for call_index, tc in enumerate(tool_calls):
                if not isinstance(tc, dict) or tc.get("type", "function") != "function":
                    raise SSEParseError(
                        f"Chat Completions tool call {call_index} is not a function object"
                    )
                func = tc.get("function", {})
                if not isinstance(func, dict):
                    raise SSEParseError(
                        f"Chat Completions tool call {call_index} function must be an object"
                    )
                params = _decode_function_arguments(
                    func.get("arguments", "{}"),
                    source=f"Chat Completions tool call {call_index}",
                )
                events.append({
                    "tool_name": func.get("name", "unknown"),
                    "parameters": params,
                    "call_id": tc.get("id") or None,
                })
            legacy_call = message.get("function_call")
            if legacy_call is not None:
                if tool_calls:
                    raise SSEParseError(
                        "Chat Completions message contains both tool_calls and function_call"
                    )
                if not isinstance(legacy_call, dict):
                    raise SSEParseError(
                        "Chat Completions function_call must be an object"
                    )
                events.append({
                    "tool_name": legacy_call.get("name", "unknown"),
                    "parameters": _decode_function_arguments(
                        legacy_call.get("arguments", "{}"),
                        source="Chat Completions legacy function call",
                    ),
                    "call_id": None,
                })
        return events

    def extract_tool_results(self, req_body: dict) -> list[dict]:
        events: list[dict] = []
        input_items = req_body.get("input")
        if isinstance(input_items, list):
            result_types = {
                "function_call_output": "unknown",
                "custom_tool_call_output": "custom",
                "computer_call_output": "computer",
                "shell_call_output": "shell",
                "local_shell_call_output": "local_shell",
                "apply_patch_call_output": "apply_patch",
            }
            for index, item in enumerate(input_items):
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type not in result_types:
                    continue
                call_id = item.get("call_id")
                if not isinstance(call_id, str) or not call_id:
                    raise SSEParseError(
                        f"OpenAI {item_type} item {index} is missing call_id"
                    )
                status = item.get("status")
                if status is not None and not isinstance(status, str):
                    raise SSEParseError(
                        f"OpenAI {item_type} item {index} status must be a string"
                    )
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    name = result_types[item_type]
                events.append({
                    "tool_name": name,
                    "result": item.get("output", ""),
                    "call_id": call_id,
                    "is_error": (
                        status in ("failed", "error", "cancelled")
                        or item.get("error") is not None
                    ),
                })
            if events:
                return events

        for msg in req_body.get("messages", []):
            if isinstance(msg, dict) and msg.get("role") in ("tool", "function"):
                events.append({
                    "tool_name": msg.get("name", "unknown"),
                    "result": msg.get("content", ""),
                    "call_id": msg.get("tool_call_id") or None,
                })
        return events

    def extract_requested_tools(self, req_body: dict) -> dict[str, list[str]]:
        requested: list[str] = []
        client_side: list[str] = []
        server_side: list[str] = []
        unknown: list[str] = []
        targets: list[str] = []
        client_types = {
            "function",
            "custom",
            "computer",
            "computer_use_preview",
            "apply_patch",
            "local_shell",
            "namespace",
        }
        server_types = {
            "web_search",
            "web_search_preview",
            "file_search",
            "code_interpreter",
            "image_generation",
            "mcp",
            "tool_search",
        }
        raw_tools = req_body.get("tools", [])
        if raw_tools is None:
            raw_tools = []
        if not isinstance(raw_tools, list):
            raise SSEParseError("OpenAI request tools must be a list")
        for index, tool in enumerate(raw_tools):
            if not isinstance(tool, dict):
                raise SSEParseError(f"OpenAI request tool {index} must be an object")
            tool_type = tool.get("type")
            if not isinstance(tool_type, str) or not tool_type:
                raise SSEParseError(
                    f"OpenAI request tool {index} is missing a type"
                )
            name = tool.get("name")
            if tool_type == "function" and isinstance(tool.get("function"), dict):
                name = tool["function"].get("name", name)
            label = (
                f"{tool_type}:{name}"
                if isinstance(name, str) and name
                else tool_type
            )
            requested.append(label)
            if tool_type == "shell":
                environment = tool.get("environment")
                if not isinstance(environment, dict):
                    unknown.append("shell:missing_environment")
                else:
                    environment_type = environment.get("type")
                    if not isinstance(environment_type, str):
                        environment_type = ""
                    if environment_type == "local":
                        client_side.append(label)
                    elif environment_type in (
                        "container_auto",
                        "container_reference",
                    ):
                        server_side.append(label)
                    else:
                        unknown.append(
                            f"shell:environment:{environment_type or 'missing'}"
                        )
                    if environment_type:
                        targets.append(f"environment.type:{environment_type}")
                    container_id = environment.get("container_id")
                    if isinstance(container_id, str) and container_id:
                        targets.append(f"container_id:{container_id}")
                    network_policy = environment.get("network_policy")
                    if isinstance(network_policy, dict):
                        allowed_domains = network_policy.get(
                            "allowed_domains", []
                        )
                        if not isinstance(allowed_domains, list):
                            raise SSEParseError(
                                "OpenAI shell allowed_domains must be a list"
                            )
                        for domain in allowed_domains:
                            if isinstance(domain, str) and domain:
                                targets.append(f"allowed_domain:{domain}")
            elif tool_type in client_types:
                client_side.append(label)
            elif tool_type in server_types:
                server_side.append(label)
            else:
                unknown.append(label)
            for key in (
                "server_url",
                "server_label",
                "container",
                "vector_store_ids",
            ):
                value = tool.get(key)
                if isinstance(value, str) and value:
                    targets.append(f"{key}:{value}")
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item:
                            targets.append(f"{key}:{item}")

        legacy_functions = req_body.get("functions", [])
        if legacy_functions is None:
            legacy_functions = []
        if not isinstance(legacy_functions, list):
            raise SSEParseError("OpenAI request functions must be a list")
        for index, function in enumerate(legacy_functions):
            if not isinstance(function, dict):
                raise SSEParseError(
                    f"OpenAI legacy function {index} must be an object"
                )
            name = function.get("name")
            if not isinstance(name, str) or not name:
                raise SSEParseError(
                    f"OpenAI legacy function {index} is missing a name"
                )
            label = f"function:{name}"
            requested.append(label)
            client_side.append(label)

        return {
            "requested_tools": requested,
            "client_side_tools": client_side,
            "server_side_tools": server_side,
            "unknown_tool_types": unknown,
            "requested_tool_targets": targets,
        }

    def extract_usage(self, resp_body: dict) -> dict:
        usage = resp_body.get("usage", {})
        if "input_tokens" in usage or "output_tokens" in usage:
            return {
                "tokens_in": usage.get("input_tokens", 0),
                "tokens_out": usage.get("output_tokens", 0),
            }
        return {
            "tokens_in": usage.get("prompt_tokens", 0),
            "tokens_out": usage.get("completion_tokens", 0),
        }

    def reassemble_sse(
        self,
        raw_bytes: bytes,
        *,
        path: str | None = None,
    ) -> dict:
        events = _parse_sse_events(raw_bytes)
        if not events:
            raise SSEParseError("OpenAI SSE response contained no JSON data events")
        has_responses_shape = any(
            str(event.get("type", "")).startswith("response.")
            or "output" in event
            for event in events
        )
        has_chat_shape = any("choices" in event for event in events)
        dialect = self._response_dialect(
            path=path,
            has_responses_shape=has_responses_shape,
            has_chat_shape=has_chat_shape,
        )
        if dialect == "responses":
            return _reassemble_responses_sse(events)
        return _reassemble_openai_sse(events)


def _output_index(event: dict, fallback: int = 0) -> int:
    """Return a valid Responses output index or reject ambiguous state."""
    index = event.get("output_index", fallback)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise SSEParseError(f"invalid Responses output_index: {index!r}")
    return index


def _arguments_equal(left: Any, right: Any) -> bool:
    """Compare function arguments semantically when both sides are JSON strings."""
    if left == right:
        return True
    if isinstance(left, str) and isinstance(right, str):
        try:
            return _strict_json_loads(left) == _strict_json_loads(right)
        except (json.JSONDecodeError, ValueError, TypeError):
            return False
    return False


def _merge_function_call(
    earlier: dict,
    later: dict,
    *,
    source: str,
) -> dict:
    """Monotonically merge two representations of one function call.

    Security-relevant identity or argument contradictions are rejected instead
    of letting a later event overwrite what enforcement already observed.
    """
    if earlier.get("type") not in (None, "", "function_call"):
        raise SSEParseError(f"{source} changed an output item into a function call")
    if later.get("type") not in (None, "", "function_call"):
        raise SSEParseError(f"{source} changed a function call into another item type")

    merged = dict(earlier)
    for field in ("id", "call_id", "name"):
        old = earlier.get(field)
        new = later.get(field)
        if old not in (None, "") and new not in (None, "") and old != new:
            raise SSEParseError(
                f"{source} contradicted function-call {field}: {old!r} != {new!r}"
            )
        if old in (None, "") and new not in (None, ""):
            merged[field] = new

    old_arguments = earlier.get("arguments")
    new_arguments = later.get("arguments")
    if (
        old_arguments not in (None, "")
        and new_arguments not in (None, "")
        and not _arguments_equal(old_arguments, new_arguments)
    ):
        raise SSEParseError(f"{source} contradicted function-call arguments")
    if old_arguments in (None, "") and new_arguments not in (None, ""):
        merged["arguments"] = new_arguments

    for key, value in later.items():
        if key not in merged:
            merged[key] = value
    merged["type"] = "function_call"
    return merged


def _merge_action_item(
    earlier: dict,
    later: dict,
    *,
    source: str,
) -> dict:
    """Monotonically merge two representations of one action output item."""
    earlier_type = earlier.get("type")
    later_type = later.get("type")
    if earlier_type == "function_call" or later_type == "function_call":
        return _merge_function_call(earlier, later, source=source)
    if earlier_type not in _ACTION_OUTPUT_TYPES:
        raise SSEParseError(f"{source} targeted a non-action output item")
    if later_type not in (None, "", earlier_type):
        raise SSEParseError(
            f"{source} changed action type {earlier_type!r} to {later_type!r}"
        )

    merged = dict(earlier)
    immutable_fields = (
        "id",
        "call_id",
        "name",
        "action",
        "operation",
        "arguments",
        "input",
        "query",
        "queries",
        "code",
        "server_label",
        "container_id",
    )
    for field in immutable_fields:
        old = earlier.get(field)
        new = later.get(field)
        if old not in (None, "", [], {}) and new not in (None, "", [], {}):
            equal = (
                _arguments_equal(old, new)
                if field == "arguments"
                else old == new
            )
            if not equal:
                raise SSEParseError(
                    f"{source} contradicted {earlier_type} field {field!r}"
                )
        if old in (None, "", [], {}) and new not in (None, "", [], {}):
            merged[field] = new

    # Status may advance monotonically as execution completes. Preserve the
    # latest status while keeping action identity and inputs immutable.
    if later.get("status") is not None:
        if not isinstance(later["status"], str):
            raise SSEParseError(f"{source} action status must be a string")
        merged["status"] = later["status"]
    for key, value in later.items():
        if key not in merged:
            merged[key] = value
    merged["type"] = earlier_type
    return merged


def _validate_function_call(item: dict, *, source: str) -> None:
    """Require a complete, inspectable Responses API function call."""
    if not isinstance(item.get("name"), str) or not item["name"]:
        raise SSEParseError(f"{source} function call is missing a name")
    _decode_function_arguments(
        item.get("arguments"),
        source=f"{source} function call",
    )


def _validate_responses_output_item(item: dict, *, index: int) -> None:
    """Validate a final output item and reject unknown execution surfaces."""
    _extract_responses_action(item, index=index)


def _matching_final_action(
    streamed: dict,
    index: int,
    final_output: list[dict],
) -> int | None:
    """Find a corresponding final action without trusting positional overwrite."""
    streamed_type = streamed.get("type")
    identifiers = {
        value
        for value in (streamed.get("call_id"), streamed.get("id"))
        if isinstance(value, str) and value
    }
    identity_matches: list[int] = []
    if identifiers:
        for final_index, item in enumerate(final_output):
            if item.get("type") != streamed_type:
                continue
            final_identifiers = {
                value
                for value in (item.get("call_id"), item.get("id"))
                if isinstance(value, str) and value
            }
            if identifiers & final_identifiers:
                identity_matches.append(final_index)
        if len(identity_matches) > 1:
            raise SSEParseError("final response duplicated a streamed function call")
        if identity_matches:
            return identity_matches[0]

    if (
        index < len(final_output)
        and final_output[index].get("type") == streamed_type
    ):
        return index
    return None


def _reassemble_responses_sse(events: list[dict]) -> dict:
    """Reassemble Responses API events with monotonic tool-call evidence."""
    response: dict[str, Any] = {"object": "response", "output": [], "usage": {}}
    streamed_output: dict[int, dict] = {}
    started: set[int] = set()
    item_done: set[int] = set()
    arguments_done: set[int] = set()
    custom_input_done: set[int] = set()
    final_response: dict | None = None

    for event in events:
        event_type = event.get("type")
        if event_type in ("response.created", "response.in_progress"):
            partial = event.get("response")
            if not isinstance(partial, dict):
                raise SSEParseError(f"{event_type} is missing a response object")
            response.update({
                key: value
                for key, value in partial.items()
                if key != "output"
            })
        elif event_type == "response.output_item.added":
            index = _output_index(event, len(streamed_output))
            item = event.get("item")
            if not isinstance(item, dict):
                raise SSEParseError("response.output_item.added is missing an item")
            if index in started:
                raise SSEParseError(
                    f"duplicate response.output_item.added for output index {index}"
                )
            started.add(index)
            streamed_output[index] = dict(item)
        elif event_type == "response.output_item.done":
            index = _output_index(event, len(streamed_output))
            item = event.get("item")
            if not isinstance(item, dict):
                raise SSEParseError("response.output_item.done is missing an item")
            if index in item_done:
                raise SSEParseError(
                    f"duplicate response.output_item.done for output index {index}"
                )
            existing = streamed_output.get(index)
            existing_type = existing.get("type") if existing is not None else None
            item_type = item.get("type")
            if existing is not None and (
                existing_type in _ACTION_OUTPUT_TYPES
                or item_type in _ACTION_OUTPUT_TYPES
            ):
                if existing_type not in _ACTION_OUTPUT_TYPES:
                    raise SSEParseError(
                        "response.output_item.done changed a non-action item "
                        "into an action"
                    )
                streamed_output[index] = _merge_action_item(
                    existing, item, source="response.output_item.done"
                )
            elif (
                existing is not None
                and existing_type not in (None, "")
                and item_type not in (None, "", existing_type)
            ):
                raise SSEParseError(
                    "response.output_item.done changed an output item type"
                )
            else:
                streamed_output[index] = dict(item)
            started.add(index)
            item_done.add(index)
        elif event_type == "response.function_call_arguments.delta":
            index = _output_index(event)
            if index in item_done or index in arguments_done:
                raise SSEParseError(
                    f"function-call arguments continued after completion at index {index}"
                )
            delta = event.get("delta")
            if not isinstance(delta, str):
                raise SSEParseError("function-call argument delta must be a string")
            item = streamed_output.setdefault(
                index, {"type": "function_call", "arguments": ""}
            )
            if item.get("type") != "function_call":
                raise SSEParseError(
                    f"function-call arguments targeted non-call output index {index}"
                )
            existing_arguments = item.get("arguments", "")
            if not isinstance(existing_arguments, str):
                raise SSEParseError("function-call arguments changed representation")
            item["arguments"] = existing_arguments + delta
            started.add(index)
        elif event_type == "response.function_call_arguments.done":
            index = _output_index(event)
            if index in arguments_done:
                raise SSEParseError(
                    f"duplicate function-call arguments completion at index {index}"
                )
            arguments = event.get("arguments")
            if not isinstance(arguments, str):
                raise SSEParseError(
                    "response.function_call_arguments.done is missing arguments"
                )
            existing = streamed_output.setdefault(
                index, {"type": "function_call", "arguments": ""}
            )
            streamed_output[index] = _merge_function_call(
                existing,
                {"type": "function_call", "arguments": arguments},
                source="response.function_call_arguments.done",
            )
            started.add(index)
            arguments_done.add(index)
        elif event_type == "response.custom_tool_call_input.delta":
            index = _output_index(event)
            if index in item_done or index in custom_input_done:
                raise SSEParseError(
                    f"custom-tool input continued after completion at index {index}"
                )
            delta = event.get("delta")
            if not isinstance(delta, str):
                raise SSEParseError("custom-tool input delta must be a string")
            item = streamed_output.setdefault(
                index, {"type": "custom_tool_call", "input": ""}
            )
            if item.get("type") != "custom_tool_call":
                raise SSEParseError(
                    f"custom-tool input targeted non-custom output index {index}"
                )
            existing_input = item.get("input", "")
            if not isinstance(existing_input, str):
                raise SSEParseError("custom-tool input changed representation")
            item["input"] = existing_input + delta
            started.add(index)
        elif event_type == "response.custom_tool_call_input.done":
            index = _output_index(event)
            if index in custom_input_done:
                raise SSEParseError(
                    f"duplicate custom-tool input completion at index {index}"
                )
            input_value = event.get("input")
            if not isinstance(input_value, str):
                raise SSEParseError(
                    "response.custom_tool_call_input.done is missing input"
                )
            existing = streamed_output.setdefault(
                index, {"type": "custom_tool_call", "input": ""}
            )
            streamed_output[index] = _merge_action_item(
                existing,
                {"type": "custom_tool_call", "input": input_value},
                source="response.custom_tool_call_input.done",
            )
            started.add(index)
            custom_input_done.add(index)
        elif event_type == "response.completed":
            completed = event.get("response")
            if not isinstance(completed, dict):
                raise SSEParseError("response.completed is missing a response object")
            if final_response is not None:
                raise SSEParseError("duplicate response.completed event")
            final_response = dict(completed)

    if final_response is not None:
        response.update(final_response)
        raw_final_output = final_response.get("output", [])
        if not isinstance(raw_final_output, list) or not all(
            isinstance(item, dict) for item in raw_final_output
        ):
            raise SSEParseError("response.completed output must be a list of objects")
        final_output = [dict(item) for item in raw_final_output]
    else:
        final_output = [
            dict(streamed_output[index]) for index in sorted(streamed_output)
        ]

    # Output indices are part of the Responses stream protocol. A completed
    # response cannot rewrite an item at a previously announced index into a
    # different kind of evidence.
    for index, streamed in streamed_output.items():
        if index >= len(final_output):
            continue
        streamed_type = streamed.get("type")
        final_type = final_output[index].get("type")
        if (
            streamed_type not in (None, "")
            and final_type not in (None, "", streamed_type)
        ):
            raise SSEParseError(
                f"response.completed changed output type at index {index}"
            )

    for index in sorted(streamed_output):
        streamed = streamed_output[index]
        if streamed.get("type") not in _ACTION_OUTPUT_TYPES:
            continue
        match = _matching_final_action(streamed, index, final_output)
        if match is None:
            completed_by_delta = (
                index in arguments_done or index in custom_input_done
            )
            if index not in item_done and not completed_by_delta:
                raise SSEParseError(
                    f"incomplete streamed action at output index {index}"
                )
            _validate_responses_output_item(streamed, index=index)
            final_output.append(dict(streamed))
            continue

        merged = _merge_action_item(
            streamed,
            final_output[match],
            source="response.completed",
        )
        _validate_responses_output_item(merged, index=match)
        final_output[match] = merged

    for index in sorted(streamed_output):
        streamed = streamed_output[index]
        if streamed.get("type") not in _ACTION_RESULT_OUTPUT_TYPES:
            continue
        if index < len(final_output):
            continue
        if index not in item_done:
            raise SSEParseError(
                f"incomplete streamed action result at output index {index}"
            )
        _validate_responses_output_item(streamed, index=index)
        final_output.append(dict(streamed))

    for index, item in enumerate(final_output):
        _validate_responses_output_item(item, index=index)

    response["output"] = final_output
    return response


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

        chunk_choices = chunk.get("choices", [])
        if not isinstance(chunk_choices, list):
            raise SSEParseError("Chat Completions stream choices must be a list")
        for choice in chunk_choices:
            if not isinstance(choice, dict):
                raise SSEParseError(
                    "Chat Completions stream choice must be an object"
                )
            idx = choice.get("index", 0)
            if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
                raise SSEParseError(
                    f"invalid Chat Completions choice index: {idx!r}"
                )
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
            if not isinstance(delta, dict):
                raise SSEParseError(
                    "Chat Completions stream delta must be an object"
                )
            if delta.get("role"):
                c["message"]["role"] = delta["role"]
            if delta.get("content"):
                if not isinstance(delta["content"], str):
                    raise SSEParseError(
                        "Chat Completions content delta must be a string"
                    )
                c["message"]["content"] = (c["message"]["content"] or "") + delta["content"]

            tool_call_deltas = delta.get("tool_calls") or []
            if not isinstance(tool_call_deltas, list):
                raise SSEParseError(
                    "Chat Completions tool-call delta must be a list"
                )
            if tool_call_deltas and delta.get("function_call") is not None:
                raise SSEParseError(
                    "Chat Completions delta contains both tool_calls and function_call"
                )
            for tc_delta in tool_call_deltas:
                if not isinstance(tc_delta, dict):
                    raise SSEParseError(
                        "Chat Completions tool-call delta must be an object"
                    )
                tc_idx = tc_delta.get("index", 0)
                if (
                    isinstance(tc_idx, bool)
                    or not isinstance(tc_idx, int)
                    or tc_idx < 0
                ):
                    raise SSEParseError(
                        f"invalid Chat Completions tool-call index: {tc_idx!r}"
                    )
                if tc_idx not in c["message"]["tool_calls"]:
                    c["message"]["tool_calls"][tc_idx] = {
                        "index": tc_idx,
                        "id": "",
                        "type": "function",
                        "function": {"name": "", "arguments": ""},
                    }
                tc = c["message"]["tool_calls"][tc_idx]
                call_type = tc_delta.get("type")
                if call_type not in (None, "", "function"):
                    raise SSEParseError(
                        f"unsupported Chat Completions tool-call type: {call_type!r}"
                    )
                new_id = tc_delta.get("id")
                if new_id:
                    if not isinstance(new_id, str):
                        raise SSEParseError(
                            "Chat Completions tool-call id must be a string"
                        )
                    if tc["id"] and tc["id"] != new_id:
                        raise SSEParseError(
                            "Chat Completions stream contradicted a tool-call id"
                        )
                    tc["id"] = new_id
                func = tc_delta.get("function", {})
                if not isinstance(func, dict):
                    raise SSEParseError(
                        "Chat Completions tool-call function delta must be an object"
                    )
                name_delta = func.get("name", "")
                argument_delta = func.get("arguments", "")
                if not isinstance(name_delta, str) or not isinstance(
                    argument_delta, str
                ):
                    raise SSEParseError(
                        "Chat Completions function deltas must be strings"
                    )
                tc["function"]["name"] += name_delta
                tc["function"]["arguments"] += argument_delta

            legacy_delta = delta.get("function_call")
            if legacy_delta is not None:
                if not isinstance(legacy_delta, dict):
                    raise SSEParseError(
                        "Chat Completions function_call delta must be an object"
                    )
                if c["message"]["tool_calls"]:
                    raise SSEParseError(
                        "Chat Completions mixed tool_calls and function_call"
                    )
                legacy = c["message"].setdefault(
                    "function_call", {"name": "", "arguments": ""}
                )
                name_delta = legacy_delta.get("name", "")
                argument_delta = legacy_delta.get("arguments", "")
                if not isinstance(name_delta, str) or not isinstance(
                    argument_delta, str
                ):
                    raise SSEParseError(
                        "Chat Completions legacy function deltas must be strings"
                    )
                legacy["name"] += name_delta
                legacy["arguments"] += argument_delta

    for idx in sorted(choices.keys()):
        c = choices[idx]
        tc_dict = c["message"].get("tool_calls", {})
        if tc_dict:
            c["message"]["tool_calls"] = [tc_dict[i] for i in sorted(tc_dict.keys())]
            for call_index, tool_call in enumerate(c["message"]["tool_calls"]):
                if not tool_call["id"]:
                    raise SSEParseError(
                        f"Chat Completions tool call {call_index} is missing an id"
                    )
                _validate_function_call(
                    tool_call["function"],
                    source=f"Chat Completions tool call {call_index}",
                )
        else:
            del c["message"]["tool_calls"]
        legacy_call = c["message"].get("function_call")
        if legacy_call is not None:
            _validate_function_call(
                legacy_call,
                source="Chat Completions legacy",
            )
        if not c["message"].get("content"):
            c["message"]["content"] = None
        result["choices"].append(c)

    return result
