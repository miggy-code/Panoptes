"""Security regressions at provider-parser and universal-schema boundaries."""

import pytest

from panoptes.providers.base import SSEParseError, _strict_json_loads
from panoptes.providers.anthropic import AnthropicProvider
from panoptes.providers.gemini import GeminiProvider
from panoptes.providers.openai import OpenAIProvider
from panoptes.proxy import AuditEventWriter


class _UnusedDB:
    """Event construction does not write, but the writer requires a DB object."""


def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers():
    with pytest.raises(ValueError, match="duplicate"):
        _strict_json_loads('{"action":{"target":"safe","target":"prod"}}')

    with pytest.raises(ValueError, match="non-finite"):
        _strict_json_loads('{"temperature":NaN}')


def test_openai_legacy_function_call_is_inspected_in_buffered_and_streamed_forms():
    provider = OpenAIProvider()
    buffered = {
        "choices": [{
            "message": {
                "role": "assistant",
                "function_call": {
                    "name": "terminal",
                    "arguments": '{"command":"rm -rf /"}',
                },
            },
        }],
    }
    assert provider.extract_tool_calls(buffered) == [{
        "tool_name": "terminal",
        "parameters": {"command": "rm -rf /"},
        "call_id": None,
    }]

    streamed = (
        b'data: {"choices":[{"index":0,"delta":{"function_call":'
        b'{"name":"terminal","arguments":"{\\\"command\\\":"}}}]}\n\n'
        b'data: {"choices":[{"index":0,"delta":{"function_call":'
        b'{"arguments":"\\\"rm -rf /\\\"}"}},"finish_reason":"function_call"}]}\n\n'
        b"data: [DONE]\n\n"
    )
    reassembled = provider.reassemble_sse(streamed)
    assert provider.extract_tool_calls(reassembled)[0]["parameters"] == {
        "command": "rm -rf /",
    }


def test_openai_function_argument_parser_rejects_ambiguous_objects():
    response = {
        "choices": [{
            "message": {
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "terminal",
                        "arguments": (
                            '{"command":"echo safe","command":"rm -rf /"}'
                        ),
                    },
                }],
            },
        }],
    }
    with pytest.raises(SSEParseError, match="duplicate"):
        OpenAIProvider().extract_tool_calls(response)


def test_openai_buffered_dialect_is_bound_to_requested_endpoint():
    disguised_chat = {
        "output": [],
        "choices": [{
            "message": {
                "tool_calls": [{
                    "id": "call_hidden",
                    "type": "function",
                    "function": {
                        "name": "terminal",
                        "arguments": '{"command":"rm -rf /"}',
                    },
                }],
            },
        }],
    }
    provider = OpenAIProvider()
    with pytest.raises(SSEParseError, match="cross-dialect"):
        provider.extract_tool_calls(
            disguised_chat,
            path="/v1/chat/completions",
        )

    writer = AuditEventWriter(_UnusedDB())
    request = {"model": "gpt-test", "messages": []}
    _, exchange = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=request,
        run_id="chat-dialect-run",
    )
    with pytest.raises(SSEParseError, match="cross-dialect|mixes"):
        writer.build_response_events(
            path="/v1/chat/completions",
            req_body=request,
            resp_status=200,
            resp_headers={"content-type": "application/json"},
            resp_body=disguised_chat,
            duration_ms=5,
            exchange_ctx=exchange,
        )


def test_openai_stream_dialect_is_bound_to_requested_endpoint():
    disguised_chat = (
        b'data: {"type":"response.foo","choices":[{"index":0,"delta":'
        b'{"tool_calls":[{"index":0,"id":"call_hidden","type":"function",'
        b'"function":{"name":"terminal","arguments":"{\\\"command\\\":'
        b'\\\"rm -rf /\\\"}"}}]}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    with pytest.raises(SSEParseError, match="cross-dialect"):
        OpenAIProvider().reassemble_sse(
            disguised_chat,
            path="/v1/chat/completions",
        )


def test_openai_responses_actions_cover_client_and_provider_execution_surfaces():
    response = {
        "output": [
            {
                "type": "custom_tool_call",
                "id": "ct_1",
                "call_id": "call_custom",
                "name": "grammar_runner",
                "input": "DROP TABLE audit_events",
                "status": "completed",
            },
            {
                "type": "computer_call",
                "id": "cc_1",
                "call_id": "call_computer",
                "action": {"type": "click", "x": 20, "y": 40},
                "status": "completed",
            },
            {
                "type": "web_search_call",
                "id": "ws_1",
                "action": {"type": "search", "query": "private credentials"},
                "status": "completed",
            },
            {"type": "message", "role": "assistant", "content": []},
        ],
    }
    calls = OpenAIProvider().extract_tool_calls(
        response,
        path="/v1/responses",
    )
    assert calls[0] == {
        "tool_name": "grammar_runner",
        "parameters": {"input": "DROP TABLE audit_events"},
        "call_id": "call_custom",
        "execution_scope": "client",
        "provider_item_type": "custom_tool_call",
        "outcome_status": "pending",
    }
    assert calls[1]["tool_name"] == "computer"
    assert calls[1]["parameters"] == {"type": "click", "x": 20, "y": 40}
    assert calls[1]["execution_scope"] == "client"
    assert calls[2]["tool_name"] == "web_search"
    assert calls[2]["execution_scope"] == "provider"
    assert calls[2]["outcome_status"] == "success"

    with pytest.raises(SSEParseError, match="unsupported Responses output"):
        OpenAIProvider().extract_tool_calls(
            {"output": [{"type": "future_remote_execution_call"}]},
            path="/v1/responses",
        )


def test_openai_custom_tool_stream_is_monotonic_and_cannot_be_erased():
    stream = (
        b'data: {"type":"response.output_item.added","output_index":0,'
        b'"item":{"type":"custom_tool_call","id":"ct_1",'
        b'"call_id":"call_1","name":"terminal","input":""}}\n\n'
        b'data: {"type":"response.custom_tool_call_input.delta",'
        b'"output_index":0,"delta":"rm -"}\n\n'
        b'data: {"type":"response.custom_tool_call_input.delta",'
        b'"output_index":0,"delta":"rf /"}\n\n'
        b'data: {"type":"response.custom_tool_call_input.done",'
        b'"output_index":0,"input":"rm -rf /"}\n\n'
        b'data: {"type":"response.output_item.done","output_index":0,'
        b'"item":{"type":"custom_tool_call","id":"ct_1",'
        b'"call_id":"call_1","name":"terminal","input":"rm -rf /"}}\n\n'
        b'data: {"type":"response.completed","response":{"id":"resp_1",'
        b'"output":[{"type":"custom_tool_call","id":"ct_1",'
        b'"call_id":"call_1","name":"terminal","input":"rm -rf /"}]}}\n\n'
    )
    provider = OpenAIProvider()
    response = provider.reassemble_sse(stream, path="/v1/responses")
    calls = provider.extract_tool_calls(response, path="/v1/responses")
    assert calls[0]["parameters"] == {"input": "rm -rf /"}

    erased = (
        b'data: {"type":"response.output_item.added","output_index":0,'
        b'"item":{"type":"computer_call","id":"cc_1","action":'
        b'{"type":"click","x":1,"y":2}}}\n\n'
        b'data: {"type":"response.completed","response":{"output":'
        b'[{"type":"message","role":"assistant","content":[]}]}}\n\n'
    )
    with pytest.raises(SSEParseError, match="changed output type"):
        provider.reassemble_sse(erased, path="/v1/responses")


def test_openai_shell_distinguishes_hosted_execution_from_local_proposal():
    provider = OpenAIProvider()
    hosted_request = provider.extract_requested_tools({
        "tools": [{
            "type": "shell",
            "environment": {
                "type": "container_auto",
                "network_policy": {
                    "allowed_domains": ["pypi.org"],
                },
            },
        }],
    })
    assert hosted_request["server_side_tools"] == ["shell"]
    assert hosted_request["client_side_tools"] == []
    assert "allowed_domain:pypi.org" in (
        hosted_request["requested_tool_targets"]
    )

    local_request = provider.extract_requested_tools({
        "tools": [{"type": "shell", "environment": {"type": "local"}}],
    })
    assert local_request["client_side_tools"] == ["shell"]

    calls = provider.extract_tool_calls(
        {
            "output": [
                {
                    "type": "shell_call",
                    "call_id": "shell-1",
                    "action": {"commands": ["cat /etc/passwd"]},
                    "status": "completed",
                },
                {
                    "type": "shell_call_output",
                    "call_id": "shell-1",
                    "status": "completed",
                    "output": [{"stdout": "root:x:0:0", "exit_code": 0}],
                },
            ],
        },
        path="/v1/responses",
    )
    assert calls[0]["execution_scope"] == "provider"
    assert calls[0]["outcome_status"] == "success"
    assert calls[0]["server_result_type"] == "shell_call_output"

    local_results = provider.extract_tool_results({
        "input": [
            {
                "type": "shell_call_output",
                "call_id": "local-shell-1",
                "status": "failed",
                "output": [{"stderr": "permission denied", "exit_code": 1}],
            },
            {
                "type": "apply_patch_call_output",
                "call_id": "patch-1",
                "status": "completed",
                "output": "Done",
            },
        ],
    })
    assert local_results[0]["tool_name"] == "shell"
    assert local_results[0]["is_error"] is True
    assert local_results[1]["tool_name"] == "apply_patch"
    assert local_results[1]["is_error"] is False

    with pytest.raises(SSEParseError, match="unpaired action result"):
        provider.extract_tool_calls(
            {
                "output": [{
                    "type": "shell_call_output",
                    "call_id": "hidden-shell",
                    "status": "completed",
                    "output": [],
                }],
            },
            path="/v1/responses",
        )


def test_anthropic_extended_thinking_stream_remains_inspectable():
    stream = (
        b'data: {"type":"message_start","message":{"id":"msg_1",'
        b'"model":"claude-test","usage":{"input_tokens":4}}}\n\n'
        b'data: {"type":"content_block_start","index":0,"content_block":'
        b'{"type":"thinking","thinking":"","signature":""}}\n\n'
        b'data: {"type":"content_block_delta","index":0,"delta":'
        b'{"type":"thinking_delta","thinking":"considering"}}\n\n'
        b'data: {"type":"content_block_delta","index":0,"delta":'
        b'{"type":"signature_delta","signature":"signed"}}\n\n'
        b'data: {"type":"content_block_stop","index":0}\n\n'
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
        b'"usage":{"output_tokens":3}}\n\n'
    )
    response = AnthropicProvider().reassemble_sse(
        stream,
        path="/v1/messages",
    )
    assert response["content"] == [{
        "type": "thinking",
        "thinking": "considering",
        "signature": "signed",
    }]


def test_anthropic_server_tools_and_error_results_are_not_silently_skipped():
    provider = AnthropicProvider()
    response = {
        "content": [
            {
                "type": "server_tool_use",
                "id": "srvtoolu_1",
                "name": "web_search",
                "input": {"query": "production credentials"},
            },
            {
                "type": "web_search_tool_result",
                "tool_use_id": "srvtoolu_1",
                "content": [{"type": "web_search_result", "url": "https://example.test"}],
                "is_error": False,
            },
        ],
    }
    calls = provider.extract_tool_calls(response)
    assert calls[0]["parameters"] == {"query": "production credentials"}
    assert calls[0]["execution_scope"] == "provider"
    assert calls[0]["outcome_status"] == "success"
    assert calls[0]["server_result_type"] == "web_search_tool_result"

    results = provider.extract_tool_results({
        "messages": [{
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "toolu_1",
                "content": "permission denied",
                "is_error": True,
            }],
        }],
    })
    assert results == [{
        "tool_name": "unknown",
        "result": "permission denied",
        "call_id": "toolu_1",
        "is_error": True,
    }]

    with pytest.raises(SSEParseError, match="unsupported Anthropic content"):
        provider.extract_tool_calls({
            "content": [{"type": "future_remote_execution"}],
        })


def test_anthropic_server_tool_stream_reassembles_for_inspection():
    stream = (
        b'data: {"type":"message_start","message":{"id":"msg_1",'
        b'"model":"claude-test","usage":{"input_tokens":2}}}\n\n'
        b'data: {"type":"content_block_start","index":0,"content_block":'
        b'{"type":"server_tool_use","id":"srvtoolu_1",'
        b'"name":"web_search","input":{}}}\n\n'
        b'data: {"type":"content_block_delta","index":0,"delta":'
        b'{"type":"input_json_delta","partial_json":"{\\\"query\\\":'
        b'\\\"secrets\\\"}"}}\n\n'
        b'data: {"type":"content_block_stop","index":0}\n\n'
        b'data: {"type":"content_block_start","index":1,"content_block":'
        b'{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1",'
        b'"content":[]}}\n\n'
        b'data: {"type":"content_block_stop","index":1}\n\n'
        b'data: {"type":"message_stop"}\n\n'
    )
    provider = AnthropicProvider()
    response = provider.reassemble_sse(stream, path="/v1/messages")
    calls = provider.extract_tool_calls(response)
    assert calls[0]["parameters"] == {"query": "secrets"}
    assert calls[0]["outcome_status"] == "success"


def test_provider_request_tool_capabilities_are_structured_before_forwarding():
    openai_tools = OpenAIProvider().extract_requested_tools({
        "tools": [
            {"type": "function", "name": "weather"},
            {
                "type": "mcp",
                "server_label": "crm",
                "server_url": "https://mcp.example.test/api",
            },
            {"type": "future_dangerous_tool"},
        ],
    })
    assert openai_tools["client_side_tools"] == ["function:weather"]
    assert openai_tools["server_side_tools"] == ["mcp"]
    assert openai_tools["unknown_tool_types"] == ["future_dangerous_tool"]
    assert "server_url:https://mcp.example.test/api" in (
        openai_tools["requested_tool_targets"]
    )

    anthropic_tools = AnthropicProvider().extract_requested_tools({
        "tools": [
            {"name": "weather", "input_schema": {"type": "object"}},
            {"type": "web_search_20250305", "name": "web_search"},
        ],
    })
    assert anthropic_tools["client_side_tools"] == ["function:weather"]
    assert anthropic_tools["server_side_tools"] == [
        "web_search_20250305:web_search",
    ]

    gemini_tools = GeminiProvider().extract_requested_tools({
        "tools": [
            {"functionDeclarations": [{"name": "weather"}]},
            {"codeExecution": {}},
        ],
    })
    assert gemini_tools["client_side_tools"] == ["function:weather"]
    assert gemini_tools["server_side_tools"] == ["codeExecution"]

    hidden_gemini_tools = GeminiProvider().extract_requested_tools({
        "tools": [{"googleSearch": {}}],
    })
    assert (
        "visibility:server_side_invocations_not_requested"
        in hidden_gemini_tools["unknown_tool_types"]
    )
    visible_gemini_tools = GeminiProvider().extract_requested_tools({
        "tools": [{"googleSearch": {}}],
        "toolConfig": {"includeServerSideToolInvocations": True},
    })
    assert visible_gemini_tools["unknown_tool_types"] == []


def test_gemini_tools_cross_the_universal_schema_without_fake_empty_ids():
    writer = AuditEventWriter(_UnusedDB())
    request = {
        "contents": [{
            "role": "user",
            "parts": [{
                "functionResponse": {
                    "name": "weather",
                    "response": {"temperature": 21},
                },
            }],
        }],
    }
    request_events, exchange = writer.build_request_events(
        path="/v1beta/models/gemini-test:generateContent",
        method="POST",
        req_headers={},
        req_body=request,
        run_id="gemini-run",
    )
    tool_result = next(
        event for event in request_events if event["event_type"] == "tool_result"
    )
    assert tool_result["action"].get("call_id") is None

    response = {
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{
                    "functionCall": {
                        "name": "weather",
                        "args": {"city": "Lima"},
                    },
                }],
            },
        }],
    }
    response_events = writer.build_response_events(
        path="/v1beta/models/gemini-test:generateContent",
        req_body=request,
        resp_status=200,
        resp_headers={"content-type": "application/json"},
        resp_body=response,
        duration_ms=5,
        exchange_ctx=exchange,
    )
    tool_call = next(
        event for event in response_events if event["event_type"] == "tool_call"
    )
    assert tool_call["action"].get("call_id") is None
    assert tool_call["action"]["parameters"] == {"city": "Lima"}

    provider = GeminiProvider()
    correlated_call = provider.extract_tool_calls({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "id": "gemini-call-1",
                        "name": "weather",
                        "args": {"city": "Lima"},
                    },
                }],
            },
        }],
    })
    assert correlated_call[0]["call_id"] == "gemini-call-1"


def test_gemini_server_tool_and_code_execution_parts_are_audited():
    provider = GeminiProvider()
    response = {
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    {
                        "executableCode": {
                            "id": "code-1",
                            "language": "PYTHON",
                            "code": "print(open('/etc/passwd').read())",
                        },
                    },
                    {
                        "codeExecutionResult": {
                            "id": "code-1",
                            "outcome": "OUTCOME_OK",
                            "output": "root:x:0:0",
                        },
                    },
                    {
                        "toolCall": {
                            "id": "search-1",
                            "toolType": "GOOGLE_SEARCH",
                            "queries": ["production secrets"],
                        },
                    },
                    {
                        "toolResponse": {
                            "id": "search-1",
                            "toolType": "GOOGLE_SEARCH",
                            "searchSuggestions": [],
                        },
                    },
                ],
            },
        }],
    }
    calls = provider.extract_tool_calls(response)
    assert calls[0]["tool_name"] == "code_execution"
    assert calls[0]["parameters"]["code"].startswith("print(open")
    assert calls[0]["execution_scope"] == "provider"
    assert calls[0]["outcome_status"] == "success"
    assert calls[1]["tool_name"] == "GOOGLE_SEARCH"
    assert calls[1]["parameters"] == {"queries": ["production secrets"]}
    assert calls[1]["server_result_type"] == "toolResponse"

    with pytest.raises(SSEParseError, match="unsupported fields"):
        provider.extract_tool_calls({
            "candidates": [{
                "content": {
                    "parts": [{"futureRemoteExecution": {"command": "rm -rf /"}}],
                },
            }],
        })


def test_gemini_stream_rejects_correlated_tool_rewrites():
    stream = (
        b'[{"candidates":[{"content":{"parts":[{"functionCall":'
        b'{"id":"call-1","name":"safe","args":{"path":"/tmp"}}}]}}]},'
        b'{"candidates":[{"content":{"parts":[{"functionCall":'
        b'{"id":"call-1","name":"unsafe","args":{"path":"/"}}}]}}]}]'
    )
    with pytest.raises(SSEParseError, match="contradicted"):
        GeminiProvider().reassemble_sse(
            stream,
            path="/v1beta/models/gemini:streamGenerateContent",
        )
