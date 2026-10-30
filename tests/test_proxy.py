"""Tests for panoptes.proxy.

Covers:
  - Shared run_id across events in one exchange
  - Reverse-proxy path routing
  - SSE reassembly for Anthropic and OpenAI formats
  - Pre-flight policy blocking
"""

import io
import json
import os
import tempfile
import time
import uuid
from email.message import Message

import pytest

from panoptes.proxy import (
    AuditWriteError,
    AuditEventWriter,
    ProxyHandler,
    ProxyServer,
    RequestBodyTooLarge,
    RequestFramingError,
    UpstreamBodyTooLarge,
    _filter_headers,
    _parse_sse_response,
    detect_agent_type,
)
from panoptes.providers import detect as detect_provider
from panoptes.providers.base import SSEParseError, _parse_sse_events
from panoptes.providers.anthropic import (
    AnthropicProvider,
    _reassemble_anthropic_sse,
)
from panoptes.providers.openai import (
    OpenAIProvider,
    _reassemble_openai_sse,
)
from panoptes.schema import ValidationError


# ---------------------------------------------------------------------------
# Minimal in-memory DB stub for unit tests
# ---------------------------------------------------------------------------

class _AuditDBStub:
    """Simple in-memory list store used in proxy unit tests."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def insert_event(self, event: dict) -> None:
        self.events.append(event)

    def query(self, _filters: dict | None = None) -> list[dict]:
        return list(self.events)


def test_provider_detection_prefers_routed_path_and_handles_malformed_messages():
    anthropic = detect_provider(
        "/v1/messages",
        {"model": "claude-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert anthropic.name == "anthropic"

    malformed = detect_provider("/custom", {"messages": ["not-a-mapping"]})
    assert malformed.name == "openai"


def test_openai_responses_api_extracts_calls_results_and_usage():
    provider = OpenAIProvider()
    request = {
        "model": "gpt-test",
        "input": [{
            "type": "function_call_output",
            "call_id": "call_123",
            "output": "sunny",
        }],
        "tools": [{"type": "function", "name": "weather"}],
    }
    response = {
        "object": "response",
        "output": [{
            "id": "fc_123",
            "type": "function_call",
            "call_id": "call_123",
            "name": "weather",
            "arguments": '{"city":"Lima"}',
        }],
        "usage": {"input_tokens": 20, "output_tokens": 7},
    }

    assert provider.extract_request_info(request)["messages_count"] == 1
    assert provider.extract_tool_results(request)[0]["call_id"] == "call_123"
    assert provider.extract_tool_calls(response)[0] == {
        "tool_name": "weather",
        "parameters": {"city": "Lima"},
        "call_id": "call_123",
    }
    assert provider.extract_usage(response) == {"tokens_in": 20, "tokens_out": 7}


def test_proxy_binds_openai_tool_extraction_to_requested_dialect():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "gpt-test", "messages": []}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
    )

    with pytest.raises(SSEParseError, match="cross-dialect"):
        writer.build_response_events(
            path="/v1/chat/completions",
            req_body=req_body,
            resp_status=200,
            resp_headers={},
            resp_body={
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "hidden",
                    "arguments": "{}",
                }],
            },
            duration_ms=20,
            exchange_ctx=exchange_ctx,
        )


def test_openai_responses_stream_uses_completed_response():
    completed = {
        "id": "resp_123",
        "object": "response",
        "output": [{
            "type": "function_call",
            "call_id": "call_123",
            "name": "weather",
            "arguments": '{"city":"Lima"}',
        }],
        "usage": {"input_tokens": 20, "output_tokens": 7},
    }
    raw = (
        "event: response.completed\n"
        f"data: {json.dumps({'type': 'response.completed', 'response': completed})}\n\n"
    ).encode()

    assert OpenAIProvider().reassemble_sse(raw) == completed


def test_agent_identity_requires_evidence_not_provider_guessing():
    body = {"model": "gpt-test", "messages": []}
    assert detect_agent_type("/v1/chat/completions", {}, body) == "unknown"
    assert detect_agent_type(
        "/v1beta/models/gemini-pro:generateContent",
        {},
        {"contents": []},
    ) == "unknown"
    assert detect_agent_type(
        "/v1/chat/completions",
        {"user-agent": "openai-codex/1.0"},
        body,
    ) == "codex"


def test_sse_parser_honors_eventsource_framing_and_multiline_data():
    raw = (
        b": keepalive\r\n"
        b"event: message\r\n"
        b"data:{\"kind\":\r\n"
        b"data: \"tool\"}\r\n"
        b"\r\n"
        b"data: {\"sequence\": 2}\n\n"
    )

    assert _parse_sse_events(raw) == [
        {"kind": "tool"},
        {"sequence": 2},
    ]


def test_sse_parser_surfaces_malformed_or_ambiguous_events():
    with pytest.raises(SSEParseError, match="invalid JSON"):
        _parse_sse_events(
            b'data: {"safe": true\n'
            b'data: {"hidden_tool": true}\n\n'
        )

    with pytest.raises(SSEParseError, match="invalid UTF-8"):
        _parse_sse_events(b"data: \xff\n\n")


def test_request_body_framing_and_size_are_strict():
    class _Handler:
        max_request_body_bytes = 4

        def __init__(self, headers, body=b""):
            self.headers = headers
            self.rfile = io.BytesIO(body)

    duplicate = Message()
    duplicate.add_header("Content-Length", "1")
    duplicate.add_header("Content-Length", "1")
    with pytest.raises(RequestFramingError, match="Multiple"):
        ProxyHandler._read_body(_Handler(duplicate, b"x"))

    chunked = Message()
    chunked.add_header("Transfer-Encoding", "chunked")
    with pytest.raises(RequestFramingError, match="not supported"):
        ProxyHandler._read_body(_Handler(chunked, b"1\r\nx\r\n0\r\n\r\n"))

    oversized = Message()
    oversized.add_header("Content-Length", "5")
    with pytest.raises(RequestBodyTooLarge):
        ProxyHandler._read_body(_Handler(oversized, b"12345"))

    incomplete = Message()
    incomplete.add_header("Content-Length", "4")
    with pytest.raises(RequestFramingError, match="ended before"):
        ProxyHandler._read_body(_Handler(incomplete, b"12"))


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "proxy.local"])
def test_proxy_rejects_non_loopback_bind_without_explicit_opt_in(host):
    with pytest.raises(ValueError, match="Refusing non-loopback"):
        ProxyServer(host=host, port=0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"client_socket_timeout_seconds": 0},
        {"max_concurrent_requests": 0},
        {"max_tool_events_per_exchange": 0},
    ],
)
def test_proxy_rejects_nonpositive_resource_limits(kwargs):
    with pytest.raises(ValueError, match="must be positive"):
        ProxyServer(port=0, **kwargs)


def test_proxy_start_failure_releases_partial_resources(monkeypatch):
    def _fail_server(*args, **kwargs):
        raise OSError("bind failed")

    monkeypatch.setattr(
        "panoptes.proxy._BoundedThreadingHTTPServer",
        _fail_server,
    )
    server = ProxyServer(port=0)

    with pytest.raises(OSError, match="bind failed"):
        server.start()

    assert server._server is None
    assert server._thread is None
    assert server._http_client is None
    assert server._db is None
    assert server._tmp_db_path is None
    assert server.writer is None


def test_handler_owned_http_client_ignores_proxy_environment(monkeypatch):
    captured = {}
    sentinel = object()

    def _client(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr("panoptes.proxy.httpx.Client", _client)

    class _Handler:
        http_client = None
        upstream_timeout = 12.0

    client, owned = ProxyHandler._get_client(_Handler())
    assert client is sentinel
    assert owned is True
    assert captured["trust_env"] is False


def test_proxy_does_not_merge_headerless_requests_into_one_session():
    writer = AuditEventWriter(_AuditDBStub())
    _, first = writer.build_request_events(
        path="/v1/chat/completions", method="POST", req_headers={},
        req_body={"model": "gpt-test", "messages": []}, run_id="run-1",
    )
    _, second = writer.build_request_events(
        path="/v1/chat/completions", method="POST", req_headers={},
        req_body={"model": "gpt-test", "messages": []}, run_id="run-2",
    )
    _, explicit = writer.build_request_events(
        path="/v1/chat/completions", method="POST",
        req_headers={"x-panoptes-session": "session-explicit"},
        req_body={"model": "gpt-test", "messages": []}, run_id="run-3",
    )

    assert first["session_id"] != second["session_id"]
    assert explicit["session_id"] == "session-explicit"


def test_proxy_does_not_forward_internal_identity_headers():
    class _Handler:
        def _build_fwd_headers(self, headers):
            return ProxyHandler._build_fwd_headers(self, headers)

    forwarded = _Handler()._build_fwd_headers({
        "Host": "localhost",
        "Authorization": "Bearer upstream-token",
        "X-Panoptes-Agent": "codex",
        "x-panoptes-session": "session-1",
    })

    assert forwarded["Authorization"] == "Bearer upstream-token"
    assert not any(key.lower().startswith("x-panoptes-") for key in forwarded)


# ---------------------------------------------------------------------------
# Shared run_id
# ---------------------------------------------------------------------------


def test_shared_run_id():
    """All events from a single exchange must share the same run_id."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_abc", "type": "function",
                 "function": {"name": "bash", "arguments": '{"cmd": "ls"}'}}
            ]},
            {"role": "tool", "tool_call_id": "call_abc", "name": "bash", "content": "file.txt"},
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [{"message": {"role": "assistant", "content": "Done", "tool_calls": []}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25},
    }

    events = writer.write_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        resp_status=200,
        resp_headers={"content-type": "application/json"},
        resp_body=resp_body,
        duration_ms=150,
    )

    assert len(events) >= 3, f"Expected at least 3 events, got {len(events)}"
    run_ids = {e["agent"]["run_id"] for e in events}
    assert len(run_ids) == 1, f"Expected 1 run_id across all events, got {run_ids}"


# ---------------------------------------------------------------------------
# turn_number in context
# ---------------------------------------------------------------------------


def test_turn_number_in_context():
    """Events should carry turn_number = count of assistant messages in request."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": "Hello"},
            {"role": "user", "content": "How are you?"},
            {"role": "assistant", "content": "Good"},
            {"role": "user", "content": "Bye"},
        ],
        "stream": False,
    }

    req_events, ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=uuid.uuid4().hex,
    )

    assert ctx["turn_number"] == 2, f"Expected turn_number=2, got {ctx['turn_number']}"
    for e in req_events:
        assert e["context"]["turn_number"] == 2


# ---------------------------------------------------------------------------
# call_id on tool events
# ---------------------------------------------------------------------------


def test_call_id_on_tool_events():
    """tool_call and tool_result events must populate action.call_id."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {"role": "tool", "tool_call_id": "call_xyz", "name": "read_file", "content": "data"},
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [{"message": {"role": "assistant", "tool_calls": [
            {"id": "call_new", "type": "function",
             "function": {"name": "write_file", "arguments": '{"path": "/tmp/x"}'}}
        ]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }

    run_id = uuid.uuid4().hex
    req_events, ctx = writer.build_request_events(
        path="/v1/chat/completions", method="POST",
        req_headers={}, req_body=req_body, run_id=run_id,
    )
    resp_events = writer.build_response_events(
        path="/v1/chat/completions", req_body=req_body,
        resp_status=200, resp_headers={}, resp_body=resp_body,
        duration_ms=100, exchange_ctx=ctx,
    )

    tool_results = [e for e in req_events if e["event_type"] == "tool_result"]
    assert tool_results, "Expected tool_result event"
    assert tool_results[0]["action"]["call_id"] == "call_xyz"

    tool_calls = [e for e in resp_events if e["event_type"] == "tool_call"]
    assert tool_calls, "Expected tool_call event"
    assert tool_calls[0]["action"]["call_id"] == "call_new"
    assert tool_calls[0]["outcome"]["status"] == "pending"
    assert "execution was not observed" in tool_calls[0]["outcome"]["summary"]


def test_proxy_redacts_tool_result_before_summary_truncation():
    private_key = (
        "-----BEGIN PRIVATE KEY-----"
        + ("A" * 800)
        + "-----END PRIVATE KEY-----"
    )
    writer = AuditEventWriter(_AuditDBStub())
    events, _ = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body={
            "model": "gpt-test",
            "messages": [{
                "role": "tool",
                "tool_call_id": "call-secret",
                "name": "read_secret",
                "content": private_key,
            }],
        },
    )
    tool_result = next(
        event for event in events if event["event_type"] == "tool_result"
    )
    summary = tool_result["outcome"]["summary"]
    assert "BEGIN PRIVATE KEY" not in summary
    assert "A" * 50 not in summary
    assert "[REDACTED PRIVATE KEY]" in summary
    assert tool_result["action"]["result"] == "[REDACTED PRIVATE KEY]"
    assert tool_result["action"]["result_complete"] is True


def test_request_event_exposes_complete_tool_capability_summary():
    writer = AuditEventWriter(_AuditDBStub())
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={
            "model": "gpt-test",
            "input": "search",
            "tools": [
                {"type": "function", "name": "local_tool"},
                {"type": "web_search_preview"},
                {
                    "type": "mcp",
                    "server_label": "docs",
                    "server_url": "https://mcp.example.test",
                },
            ],
        },
    )

    action = events[0]["action"]
    assert action["requested_tools"] == [
        "function:local_tool",
        "web_search_preview",
        "mcp",
    ]
    assert action["client_side_tools"] == ["function:local_tool"]
    assert action["server_side_tools"] == ["web_search_preview", "mcp"]
    assert (
        "server_url:https://mcp.example.test"
        in action["requested_tool_targets"]
    )


def test_request_tool_capability_count_is_bounded():
    writer = AuditEventWriter(
        _AuditDBStub(),
        max_tool_events_per_exchange=1,
    )
    with pytest.raises(ValidationError, match="per-exchange limit"):
        writer.build_request_events(
            path="/v1/responses",
            method="POST",
            req_headers={},
            req_body={
                "model": "gpt-test",
                "input": "search",
                "tools": [
                    {"type": "function", "name": "one"},
                    {"type": "function", "name": "two"},
                ],
            },
        )


def test_provider_hosted_action_records_upstream_execution_truth():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "gpt-test", "input": "search"}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        path="/v1/responses",
        req_body=req_body,
        resp_status=200,
        resp_headers={},
        resp_body={
            "object": "response",
            "output": [{
                "id": "ws_1",
                "type": "web_search_call",
                "status": "completed",
                "action": {"query": "Panoptes"},
            }],
        },
        duration_ms=20,
        exchange_ctx=exchange_ctx,
    )

    tool_call = next(
        event for event in events if event["event_type"] == "tool_call"
    )
    assert tool_call["action"]["execution_scope"] == "provider"
    assert tool_call["action"]["provider_item_type"] == "web_search_call"
    assert tool_call["outcome"]["status"] == "success"
    assert "completed upstream" in tool_call["outcome"]["summary"]


def test_provider_hosted_result_is_redacted_and_bounded():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "claude-test", "messages": []}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/messages",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        path="/v1/messages",
        req_body=req_body,
        resp_status=200,
        resp_headers={},
        resp_body={
            "content": [
                {
                    "type": "server_tool_use",
                    "id": "srv_1",
                    "name": "web_search",
                    "input": {"query": "Panoptes"},
                },
                {
                    "type": "web_search_tool_result",
                    "tool_use_id": "srv_1",
                    "content": "result-" + ("x" * 1000),
                },
            ],
        },
        duration_ms=20,
        exchange_ctx=exchange_ctx,
    )

    tool_call = next(
        event for event in events if event["event_type"] == "tool_call"
    )
    assert tool_call["outcome"]["status"] == "success"
    assert len(tool_call["action"]["server_result_summary"]) == 500
    assert tool_call["action"]["server_result_complete"] is False
    assert "server_result" not in tool_call["action"]


def test_protocols_without_call_ids_remain_valid():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {
        "model": "gemini-test",
        "contents": [{"role": "user", "parts": [{"text": "weather"}]}],
    }
    _, exchange_ctx = writer.build_request_events(
        path="/v1beta/models/gemini-test:generateContent",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        path="/v1beta/models/gemini-test:generateContent",
        req_body=req_body,
        resp_status=200,
        resp_headers={},
        resp_body={
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {
                            "name": "weather",
                            "args": {"city": "Lima"},
                        },
                    }],
                },
            }],
        },
        duration_ms=20,
        exchange_ctx=exchange_ctx,
    )

    tool_call = next(
        event for event in events if event["event_type"] == "tool_call"
    )
    assert tool_call["action"]["call_id"] is None
    assert tool_call["action"]["target"] is None


# ---------------------------------------------------------------------------
# Reverse-proxy routing
# ---------------------------------------------------------------------------


def test_reverse_proxy_routing():
    """_parse_target routes relative paths to correct upstreams."""
    class MockHandler:
        """Minimal mock that satisfies _parse_target's attribute accesses."""
        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()

    # Anthropic
    h.path = "/v1/messages"
    scheme, host, port, path = h._parse_target()
    assert host == "api.anthropic.com", f"Got {host}"
    assert scheme == "https"
    assert port == 443
    assert path == "/v1/messages"

    # Anthropic with query string
    h.path = "/v1/messages?beta=true"
    scheme, host, port, path = h._parse_target()
    assert host == "api.anthropic.com"
    assert "?" in path

    # OpenAI chat completions
    h.path = "/v1/chat/completions"
    scheme, host, port, path = h._parse_target()
    assert host == "api.openai.com", f"Got {host}"

    # OpenAI models
    h.path = "/v1/models"
    scheme, host, port, path = h._parse_target()
    assert host == "api.openai.com"

    # Gemini generateContent
    h.path = "/v1beta/models/gemini-pro:generateContent"
    scheme, host, port, path = h._parse_target()
    assert "googleapis" in host, f"Got {host}"

    # Gemini streamGenerateContent
    h.path = "/v1beta/models/gemini-pro:streamGenerateContent"
    scheme, host, port, path = h._parse_target()
    assert "googleapis" in host

    # Absolute-form targets are never accepted by the reverse proxy.
    h.path = "http://api.openai.com/v1/chat/completions"
    with pytest.raises(ValueError, match="Absolute-form"):
        h._parse_target()


def test_reverse_proxy_no_upstream_raises():
    """Unmatched provider paths are rejected."""
    from panoptes.proxy import NoUpstreamError

    class MockHandler:
        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()
    h.path = "/unknown/endpoint"
    with pytest.raises(NoUpstreamError):
        h._parse_target()


def test_proxy_errors_and_request_logs_do_not_expose_query_secrets(caplog):
    from panoptes.proxy import NoUpstreamError

    class MockHandler:
        path = "/unknown/endpoint?key=gemini-secret"
        requestline = "POST /unknown/endpoint?key=gemini-secret HTTP/1.1"
        command = "POST"
        request_version = "HTTP/1.1"

        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()
    with pytest.raises(NoUpstreamError) as exc_info:
        h._parse_target()
    assert "gemini-secret" not in str(exc_info.value)

    caplog.set_level("INFO", logger="panoptes")
    ProxyHandler.log_message(h, '"%s" %s %s', h.requestline, "502", "-")
    assert "gemini-secret" not in caplog.text
    assert "/unknown/endpoint" in caplog.text


# ---------------------------------------------------------------------------
# SSE parsing — Anthropic
# ---------------------------------------------------------------------------


def _anthropic_sse_bytes(text_content: str = "Hello world!") -> bytes:
    """Build synthetic Anthropic SSE stream bytes."""
    words = text_content.split(" ")
    lines = [
        b'event: message_start',
        (
            b'data: {"type":"message_start","message":{"id":"msg_xxx","type":"message",'
            b'"role":"assistant","content":[],"model":"claude-opus-4-5",'
            b'"stop_reason":null,"stop_sequence":null,'
            b'"usage":{"input_tokens":25,"output_tokens":1}}}'
        ),
        b'',
        b'event: content_block_start',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'',
    ]
    for i, word in enumerate(words):
        sep = " " if i < len(words) - 1 else ""
        delta_text = word + sep
        lines.append(b'event: content_block_delta')
        lines.append(
            json.dumps({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": delta_text}}).encode()
            .replace(b'"', b'"')
        )
        lines.append(b'')
    lines += [
        b'event: content_block_stop',
        b'data: {"type":"content_block_stop","index":0}',
        b'',
        b'event: message_delta',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
        b'',
        b'event: message_stop',
        b'data: {"type":"message_stop"}',
    ]
    return b'\n'.join(lines)


def test_sse_parsing_anthropic_text():
    """Anthropic SSE: text content blocks are reassembled correctly."""
    sse = b"\n".join([
        b'event: message_start',
        b'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":1}}}',
        b'',
        b'event: content_block_start',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'',
        b'event: content_block_delta',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}',
        b'',
        b'event: content_block_delta',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world!"}}',
        b'',
        b'event: content_block_stop',
        b'data: {"type":"content_block_stop","index":0}',
        b'',
        b'event: message_delta',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
        b'',
        b'event: message_stop',
        b'data: {"type":"message_stop"}',
    ])

    events = _parse_sse_events(sse)
    # Should parse: message_start, content_block_start, 2x delta, content_block_stop, message_delta, message_stop
    assert len(events) >= 5, f"Expected ≥5 parsed events, got {len(events)}"

    result = _reassemble_anthropic_sse(events)
    assert result["type"] == "message"
    assert result["role"] == "assistant"
    assert result["model"] == "claude-opus-4-5"
    assert result["stop_reason"] == "end_turn"
    assert len(result["content"]) == 1
    assert result["content"][0]["type"] == "text"
    assert result["content"][0]["text"] == "Hello world!"
    assert result["usage"]["input_tokens"] == 25
    assert result["usage"]["output_tokens"] == 10


def test_sse_parsing_anthropic_tool_use():
    """Anthropic SSE: tool_use blocks with input_json_delta reassemble correctly."""
    sse = b"\n".join([
        b'data: {"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":1}}}',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_abc","name":"calculator","input":{}}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"expr\\""}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":": \\"2+2\\"}"}}',
        b'data: {"type":"content_block_stop","index":0}',
        b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":50}}',
        b'data: {"type":"message_stop"}',
    ])

    events = _parse_sse_events(sse)
    result = _reassemble_anthropic_sse(events)

    assert len(result["content"]) == 1
    block = result["content"][0]
    assert block["type"] == "tool_use"
    assert block["id"] == "toolu_abc"
    assert block["name"] == "calculator"
    assert block["input"] == {"expr": "2+2"}, f"Got {block['input']}"
    assert result["usage"]["input_tokens"] == 100
    assert result["usage"]["output_tokens"] == 50


def test_sse_parsing_anthropic_via_parse_sse_response():
    """_parse_sse_response dispatches to Anthropic reassembly for 'anthropic' format."""
    sse = b"\n".join([
        b'data: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":1}}}',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}',
        b'data: {"type":"content_block_stop","index":0}',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}',
        b'data: {"type":"message_stop"}',
    ])
    result = _parse_sse_response(sse, "anthropic")
    assert result is not None
    assert result["content"][0]["text"] == "Hi"
    assert result["usage"]["output_tokens"] == 3


@pytest.mark.parametrize(
    "events",
    [
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": "harmless"},
            },
        ],
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"command":"kubectl delete',
                },
            },
        ],
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"command":"kubectl delete',
                },
            },
            {"type": "content_block_stop", "index": 0},
        ],
    ],
)
def test_anthropic_reassembly_rejects_overwrite_and_incomplete_tool_blocks(events):
    raw = b"".join(
        b"data:" + json.dumps(event).encode() + b"\n\n"
        for event in events
    )
    with pytest.raises(SSEParseError):
        AnthropicProvider().reassemble_sse(raw)


# ---------------------------------------------------------------------------
# SSE parsing — OpenAI
# ---------------------------------------------------------------------------


def test_sse_parsing_openai_text():
    """OpenAI SSE: text content chunks reassemble correctly."""
    sse = b"\n".join([
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":" world!"},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}',
        b'data: [DONE]',
    ])

    events = _parse_sse_events(sse)
    assert len(events) == 4, f"Expected 4 parsed chunks (ignoring [DONE]), got {len(events)}"

    result = _reassemble_openai_sse(events)
    assert result["id"] == "chatcmpl-x"
    assert result["model"] == "gpt-4"
    assert len(result["choices"]) == 1
    assert result["choices"][0]["message"]["content"] == "Hello world!"
    assert result["choices"][0]["finish_reason"] == "stop"
    assert result["usage"]["prompt_tokens"] == 10
    assert result["usage"]["completion_tokens"] == 5


def test_sse_parsing_openai_tool_calls():
    """OpenAI SSE: tool_call arguments accumulate correctly across chunks."""
    sse = b"\n".join([
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"calculator","arguments":""}}]},"finish_reason":null}]}',
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"expr\\""}}]},"finish_reason":null}]}',
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":": \\"2+2\\"}"}}]},"finish_reason":"tool_calls"}]}',
        b'data: [DONE]',
    ])

    events = _parse_sse_events(sse)
    result = _reassemble_openai_sse(events)

    assert len(result["choices"]) == 1
    msg = result["choices"][0]["message"]
    assert "tool_calls" in msg, f"No tool_calls in message: {msg}"
    assert len(msg["tool_calls"]) == 1
    tc = msg["tool_calls"][0]
    assert tc["id"] == "call_abc"
    assert tc["function"]["name"] == "calculator"
    parsed_args = json.loads(tc["function"]["arguments"])
    assert parsed_args == {"expr": "2+2"}, f"Got {parsed_args}"


def test_sse_parsing_openai_via_parse_sse_response():
    """_parse_sse_response dispatches to OpenAI reassembly for 'openai' format."""
    sse = b"\n".join([
        b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}',
        b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1}}',
        b'data: [DONE]',
    ])
    result = _parse_sse_response(sse, "openai")
    assert result is not None
    assert result["choices"][0]["message"]["content"] == "Hi"


def _responses_sse(*events: dict) -> bytes:
    return b"".join(
        b"data:" + json.dumps(event).encode() + b"\n\n"
        for event in events
    )


def test_openai_responses_final_event_cannot_erase_streamed_tool_call():
    call = {
        "id": "fc_danger",
        "type": "function_call",
        "call_id": "call_danger",
        "name": "terminal",
        "arguments": "",
    }
    completed_call = {
        **call,
        "arguments": '{"command":"kubectl delete namespace production"}',
    }
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": call,
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 0,
            "delta": '{"command":"kubectl delete namespace production"}',
        },
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_call,
        },
        {
            "type": "response.completed",
            "response": {
                "id": "resp_1",
                "object": "response",
                "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
    )

    provider = OpenAIProvider()
    response = provider.reassemble_sse(raw)
    calls = provider.extract_tool_calls(response)
    assert len(calls) == 1
    assert calls[0]["tool_name"] == "terminal"
    assert calls[0]["parameters"]["command"].endswith("production")


def test_openai_responses_rejects_final_tool_call_contradiction():
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": "",
            },
        },
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": '{"command":"rm -rf /"}',
            },
        },
        {
            "type": "response.completed",
            "response": {
                "object": "response",
                "output": [{
                    "id": "fc_1",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "calculator",
                    "arguments": '{"expr":"2+2"}',
                }],
            },
        },
    )
    with pytest.raises(SSEParseError, match="contradicted"):
        OpenAIProvider().reassemble_sse(raw)


def test_openai_responses_rejects_incomplete_function_call_stream():
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": "",
            },
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 0,
            "delta": '{"command":"rm -rf',
        },
    )
    with pytest.raises(SSEParseError, match="incomplete"):
        OpenAIProvider().reassemble_sse(raw)


@pytest.mark.parametrize(
    ("path", "request_body", "response_headers", "response_body"),
    [
        (
            "/v1/chat/completions",
            {"model": "gpt-test", "messages": [], "stream": True},
            {"content-type": "text/event-stream"},
            b'data: {"choices": []}\n\ndata: {not-json}\n\n',
        ),
        (
            "/custom/generate",
            {"payload": "opaque"},
            {"content-type": "application/json"},
            b'{"possibly_hidden_tool_call": true}',
        ),
    ],
)
def test_buffering_enforcement_denies_uninspectable_responses(
    path, request_body, response_headers, response_body
):
    from panoptes.policy import PolicyResult

    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    class _BlockingCapableEngine:
        has_blocking_policies = True

        def check_event(self, event):
            return PolicyResult(action="allow")

    writer.policy_engine = _BlockingCapableEngine()
    req_events, exchange_ctx = writer.build_request_events(
        path=path,
        method="POST",
        req_headers={},
        req_body=request_body,
        run_id="inspection-run",
    )

    class _Handler:
        def __init__(self):
            self.writer = writer
            self.wfile = io.BytesIO()
            self.status = None
            self.headers = []

        def _forward_request(self, *args, **kwargs):
            return 200, response_headers, response_body

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            self.headers.append((key, value))

        def end_headers(self):
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path=path,
        req_headers={},
        body=json.dumps(request_body).encode(),
        req_body=request_body,
        req_events=req_events,
        exchange_ctx=exchange_ctx,
        t0=time.monotonic(),
    )

    assert handler.status == 502
    denial = json.loads(handler.wfile.getvalue())
    assert denial["inspection_error"] is True
    assert handler.wfile.getvalue() != response_body
    response_event = next(
        event for event in db.events if event["event_type"] == "model_response"
    )
    assert response_event["outcome"]["status"] == "blocked"
    assert response_event["context"]["capture"]["inspection_status"] == "blocked"


def test_buffered_and_stream_audit_bodies_are_bounded():
    class _Response:
        status_code = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_bytes(self):
            yield b"abc"
            yield b"def"

    class _Client:
        def stream(self, *args, **kwargs):
            return _Response()

    class _BufferedHandler:
        http_client = _Client()
        max_buffered_response_bytes = 5

        def _get_client(self):
            return self.http_client, False

        def _build_fwd_headers(self, headers):
            return ProxyHandler._build_fwd_headers(self, headers)

    with pytest.raises(UpstreamBodyTooLarge):
        ProxyHandler._forward_request(
            _BufferedHandler(),
            "POST",
            "https",
            "api.openai.com",
            443,
            "/v1/responses",
            {},
            b"{}",
        )

    class _StreamingHandler(_BufferedHandler):
        max_audit_stream_bytes = 4

        def __init__(self):
            self.wfile = io.BytesIO()

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            pass

        def end_headers(self):
            pass

    streaming = _StreamingHandler()
    status, _, audit_bytes, truncated = ProxyHandler._forward_streaming(
        streaming,
        "POST",
        "https",
        "api.openai.com",
        443,
        "/v1/responses",
        {},
        b"{}",
    )
    assert status == 200
    assert audit_bytes == b"abcd"
    assert truncated is True
    assert streaming.wfile.getvalue() == b"abcdef"


def test_decoded_response_headers_and_connection_nominated_headers_are_removed():
    filtered = _filter_headers({
        "Connection": "X-Internal, Keep-Alive",
        "X-Internal": "must-not-cross",
        "Keep-Alive": "timeout=5",
        "Content-Type": "application/json",
    })
    assert "Connection" not in filtered
    assert "X-Internal" not in filtered
    assert "Keep-Alive" not in filtered
    assert filtered["Content-Type"] == "application/json"

    class _Response:
        status_code = 200
        headers = {
            "content-type": "application/json",
            "content-encoding": "gzip",
            "content-length": "2",
        }

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_bytes(self):
            # httpx exposes decoded bytes here even when upstream headers still
            # describe the encoded representation.
            yield b"{}"

    class _Client:
        def stream(self, *args, **kwargs):
            return _Response()

    class _Handler:
        http_client = _Client()
        max_buffered_response_bytes = 100

        def _get_client(self):
            return self.http_client, False

        def _build_fwd_headers(self, headers):
            return ProxyHandler._build_fwd_headers(self, headers)

    _, headers, body = ProxyHandler._forward_request(
        _Handler(),
        "POST",
        "https",
        "api.openai.com",
        443,
        "/v1/responses",
        {},
        b"{}",
    )
    assert body == b"{}"
    assert all(key.lower() != "content-encoding" for key in headers)

    class _StreamingHandler(_Handler):
        max_audit_stream_bytes = 100

        def __init__(self):
            self.wfile = io.BytesIO()
            self.sent_headers = []

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            self.sent_headers.append((key, value))

        def end_headers(self):
            pass

    streaming = _StreamingHandler()
    _, returned_headers, _, _ = ProxyHandler._forward_streaming(
        streaming,
        "POST",
        "https",
        "api.openai.com",
        443,
        "/v1/responses",
        {},
        b"{}",
    )
    assert all(
        key.lower() not in {"content-encoding", "content-length"}
        for key, _ in streaming.sent_headers
    )
    assert all(
        key.lower() not in {"content-encoding", "content-length"}
        for key in returned_headers
    )


def test_fail_closed_without_policy_engine_denies_and_records_provenance():
    writer = AuditEventWriter(
        _AuditDBStub(), policy_failure_mode="fail_closed"
    )
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={"model": "gpt-test", "input": "hello"},
    )
    result = writer.check_policies(events)
    assert result.action == "block"
    assert result.violated_policies[0]["policy_name"] == "policy_engine_error"
    assert events[0]["context"]["policy"]["action"] == "block"


def test_proxy_policy_aggregation_preserves_matches_and_snapshot():
    from panoptes.policy import PolicyResult

    writer = AuditEventWriter(_AuditDBStub())

    class _Engine:
        has_blocking_policies = False

        def check_event(self, event):
            return PolicyResult(
                action="allow",
                matched_policies=[{
                    "policy_name": "explicit-allow",
                    "action": "allow",
                    "reason": "test",
                    "message": "allowed",
                }],
                policy_snapshot_id="snapshot-123",
            )

    writer.policy_engine = _Engine()
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={"model": "gpt-test", "input": "hello"},
    )
    result = writer.check_policies(events)
    assert result.policy_snapshot_id == "snapshot-123"
    assert result.matched_policies[0]["policy_name"] == "explicit-allow"
    assert events[0]["context"]["policy"]["snapshot_id"] == "snapshot-123"
    assert (
        events[0]["context"]["policy"]["matched_policies"][0]["policy_name"]
        == "explicit-allow"
    )


def test_proxy_batches_source_and_policy_violation_atomically(tmp_path):
    class _BatchDB:
        def __init__(self):
            self.batches = []

        def insert_events(self, events):
            self.batches.append(list(events))

        def insert_event(self, event):
            raise AssertionError("atomic batch path should be used")

    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "deny.yaml").write_text(
        "\n".join([
            'name: "deny-test-model"',
            "enabled: true",
            "rule:",
            "  event_type: model_request",
            "  conditions:",
            '    - field: "action.model"',
            '      operator: "=="',
            '      value: "gpt-test"',
            "action: block",
            'message: "test model denied"',
        ]),
        encoding="utf-8",
    )
    db = _BatchDB()
    writer = AuditEventWriter(db, policies_dir=str(policies))
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={"model": "gpt-test", "input": "hello"},
    )

    result = writer.check_policies(events)

    assert result.action == "block"
    assert db.batches == []
    assert [event["event_type"] for event in events] == [
        "model_request",
        "policy_violation",
    ]
    assert (
        events[1]["context"]["policy_snapshot_id"]
        == result.policy_snapshot_id
    )

    writer.write(events)
    assert len(db.batches) == 1
    assert [event["event_type"] for event in db.batches[0]] == [
        "model_request",
        "policy_violation",
    ]


@pytest.mark.parametrize(
    ("failure_mode", "expected_action"),
    [("fail_open", "warn"), ("fail_closed", "block")],
)
def test_unknown_requested_tool_type_never_silently_allows(
    failure_mode, expected_action
):
    db = _AuditDBStub()
    writer = AuditEventWriter(db, policy_failure_mode=failure_mode)
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={
            "model": "gpt-test",
            "input": "future tool",
            "tools": [{"type": "future_remote_execution"}],
        },
    )

    result = writer.check_policies(events)
    writer.write(events)

    assert result.action == expected_action
    assert any(
        violation["policy_name"] == "unknown_requested_tool_type"
        for violation in result.violated_policies
    )
    stored_source = next(
        event for event in db.events if event["event_type"] == "model_request"
    )
    assert stored_source["context"]["policy"]["action"] == expected_action
    assert any(
        violation["policy_name"] == "unknown_requested_tool_type"
        for violation in stored_source["context"]["policy"][
            "violated_policies"
        ]
    )


def test_proxy_validates_normalized_identity_before_policy_or_forwarding():
    writer = AuditEventWriter(_AuditDBStub())
    with pytest.raises(ValidationError, match="control characters"):
        writer.build_request_events(
            path="/v1/responses",
            method="POST",
            req_headers={"x-panoptes-session": "attacker\nforged"},
            req_body={"model": "gpt-test", "input": "hello"},
        )


def test_proxy_rejects_duplicate_request_object_keys_before_forwarding():
    class _Handler:
        headers = {}
        writer = AuditEventWriter(_AuditDBStub())

        def __init__(self):
            self.forwarded = False
            self.error = None

        def _parse_target(self):
            return "https", "api.openai.com", 443, "/v1/responses"

        def _read_body(self):
            return (
                b'{"model":"gpt-safe","model":"gpt-confused",'
                b'"input":"hello"}'
            )

        def _send_json_error(self, status, message, extra=None):
            self.error = (status, message, extra)

        def _handle_buffered(self, **kwargs):
            self.forwarded = True

    handler = _Handler()
    ProxyHandler._handle_request(handler, "POST")

    assert handler.forwarded is False
    assert handler.error[0] == 400
    assert "unambiguous" in handler.error[1]


def test_buffered_proxy_rejects_duplicate_response_keys_before_delivery():
    db = _AuditDBStub()
    writer = AuditEventWriter(db)
    req_body = {"model": "gpt-test", "input": "hello"}
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    exchange_ctx["_request_events_persisted"] = True
    ambiguous = (
        b'{"object":"response","output":[],'
        b'"output":[{"type":"function_call","name":"hidden",'
        b'"arguments":"{}"}]}'
    )

    class _Handler:
        def __init__(self):
            self.writer = writer
            self.wfile = io.BytesIO()
            self.status = None
            self.headers = []

        def _forward_request(self, *args, **kwargs):
            return 200, {"content-type": "application/json"}, ambiguous

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            self.headers.append((key, value))

        def end_headers(self):
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path="/v1/responses",
        req_headers={},
        body=json.dumps(req_body).encode(),
        req_body=req_body,
        req_events=req_events,
        exchange_ctx=exchange_ctx,
        t0=time.monotonic(),
    )

    assert handler.status == 502
    assert handler.wfile.getvalue() != ambiguous
    response_event = next(
        event for event in db.events if event["event_type"] == "model_response"
    )
    assert response_event["outcome"]["status"] == "blocked"
    assert response_event["context"]["capture"]["response_delivered"] is False


@pytest.mark.parametrize(
    ("failure_mode", "expected_status", "expected_outcome"),
    [
        ("fail_open", 200, "error"),
        ("fail_closed", 503, "blocked"),
    ],
)
def test_response_event_construction_failure_gets_explicit_fallback(
    failure_mode, expected_status, expected_outcome, monkeypatch
):
    db = _AuditDBStub()
    writer = AuditEventWriter(db, policy_failure_mode=failure_mode)
    req_body = {"model": "gpt-test", "input": "hello"}
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    exchange_ctx["_request_events_persisted"] = True

    def _fail_extraction(self, resp_body, *, path=None):
        raise RuntimeError("provider extraction exploded")

    monkeypatch.setattr(
        OpenAIProvider,
        "extract_tool_calls",
        _fail_extraction,
    )
    upstream = b'{"object":"response","output":[]}'

    class _Handler:
        def __init__(self):
            self.writer = writer
            self.wfile = io.BytesIO()
            self.status = None

        def _forward_request(self, *args, **kwargs):
            return 200, {"content-type": "application/json"}, upstream

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            pass

        def end_headers(self):
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path="/v1/responses",
        req_headers={},
        body=json.dumps(req_body).encode(),
        req_body=req_body,
        req_events=req_events,
        exchange_ctx=exchange_ctx,
        t0=time.monotonic(),
    )

    assert handler.status == expected_status
    response_event = next(
        event for event in db.events if event["event_type"] == "model_response"
    )
    assert response_event["outcome"]["status"] == expected_outcome
    assert (
        response_event["context"]["capture"]["inspection_status"]
        == ("blocked" if failure_mode == "fail_closed" else "incomplete")
    )
    if failure_mode == "fail_open":
        assert handler.wfile.getvalue() == upstream
    else:
        assert handler.wfile.getvalue() != upstream


def test_audit_writer_raises_when_batch_and_fallback_cannot_persist_all_events():
    class _FailingDB:
        def insert_events(self, events):
            raise OSError("batch unavailable")

        def insert_event(self, event):
            raise OSError("single insert unavailable")

    writer = AuditEventWriter(_FailingDB())
    with pytest.raises(AuditWriteError, match="Failed to persist"):
        writer.write([{"event_id": "one"}, {"event_id": "two"}])


@pytest.mark.parametrize(
    ("policy_action", "expected_status"),
    [("allow", 503), ("block", 403)],
)
def test_fail_closed_never_forwards_without_durable_request_audit(
    policy_action, expected_status
):
    from panoptes.policy import PolicyResult

    class _FailingDB:
        def insert_event(self, event):
            raise OSError("audit storage unavailable")

    writer = AuditEventWriter(
        _FailingDB(), policy_failure_mode="fail_closed"
    )

    class _Engine:
        has_blocking_policies = True

        def check_event(self, event):
            if policy_action == "block":
                return PolicyResult(
                    action="block",
                    violated_policies=[{
                        "policy_name": "deny-test",
                        "message": "blocked",
                    }],
                )
            return PolicyResult(action="allow")

    writer.policy_engine = _Engine()

    class _Handler:
        headers = {}

        def __init__(self):
            self.writer = writer
            self.forwarded = False
            self.error = None

        def _parse_target(self):
            return "https", "api.openai.com", 443, "/v1/responses"

        def _read_body(self):
            return json.dumps({
                "model": "gpt-test",
                "input": "hello",
            }).encode()

        def _send_json_error(self, status, message, extra=None):
            self.error = (status, message, extra)

        def _handle_buffered(self, **kwargs):
            self.forwarded = True

    handler = _Handler()
    ProxyHandler._handle_request(handler, "POST")
    assert handler.forwarded is False
    assert handler.error[0] == expected_status
    if policy_action == "block":
        assert handler.error[2]["audit_persisted"] is False


# ---------------------------------------------------------------------------
# Pre-flight policy blocking
# ---------------------------------------------------------------------------


def test_preflight_block_prevents_forward():
    """Pre-flight check: blocked request events should be returned as 'block' without forwarding."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    # Stub policy engine that always blocks
    class _BlockingEngine:
        def check_event(self, event):
            from panoptes.policy import PolicyResult
            return PolicyResult(
                action="block",
                violated_policies=[{"policy_name": "test_block", "message": "Blocked for testing"}],
                warnings=["Blocked for testing"],
            )

    writer.policy_engine = _BlockingEngine()

    req_body = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Do something bad"}],
        "stream": False,
    }

    run_id = uuid.uuid4().hex
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=run_id,
    )

    # Pre-flight check
    policy_result = writer.check_policies(req_events)
    assert policy_result.action == "block", f"Expected block, got {policy_result.action}"
    assert len(policy_result.violated_policies) > 0

    # Simulate handler writing events on block (no response events written)
    writer.write(req_events)

    # Verify events written to DB share the run_id
    stored = db.query()
    assert len(stored) > 0
    for e in stored:
        assert e["agent"]["run_id"] == run_id, (
            f"run_id mismatch: expected {run_id}, got {e['agent']['run_id']}"
        )

    # No response events written (we blocked pre-flight)
    assert all(e["event_type"] != "model_response" for e in stored), (
        "model_response event should not be written on pre-flight block"
    )


def test_preflight_block_records_request_as_not_forwarded():
    from panoptes.policy import PolicyResult

    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    class _BlockingEngine:
        def check_event(self, event):
            return PolicyResult(
                action="block",
                violated_policies=[{
                    "policy_name": "deny-request",
                    "message": "request denied",
                }],
            )

    writer.policy_engine = _BlockingEngine()

    class _Handler:
        headers = {}

        def __init__(self):
            self.writer = writer
            self.forwarded = False
            self.error = None

        def _parse_target(self):
            return "https", "api.openai.com", 443, "/v1/responses"

        def _read_body(self):
            return json.dumps({
                "model": "gpt-test",
                "input": "hello",
            }).encode()

        def _send_json_error(self, status, message, extra=None):
            self.error = (status, message, extra)

        def _handle_buffered(self, **kwargs):
            self.forwarded = True

    handler = _Handler()
    ProxyHandler._handle_request(handler, "POST")

    assert handler.forwarded is False
    assert handler.error[0] == 403
    request_event = next(
        event for event in db.events if event["event_type"] == "model_request"
    )
    assert request_event["outcome"]["status"] == "blocked"
    assert (
        request_event["context"]["capture"]["upstream_forwarded"] is False
    )
    assert (
        request_event["context"]["capture"]["delivery_status"]
        == "blocked_before_upstream"
    )


def test_buffered_postflight_block_records_response_and_tool_call_withheld():
    from panoptes.policy import PolicyResult

    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    class _BlockingEngine:
        has_blocking_policies = True

        def check_event(self, event):
            return PolicyResult(
                action="block",
                violated_policies=[{
                    "policy_name": "deny-response",
                    "message": "response denied",
                }],
            )

    writer.policy_engine = _BlockingEngine()
    req_body = {"model": "gpt-test", "input": "call a tool"}
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id="withheld-response-run",
    )
    exchange_ctx["_request_events_persisted"] = True
    upstream_body = json.dumps({
        "object": "response",
        "output": [{
            "id": "fc_123",
            "type": "function_call",
            "call_id": "call_123",
            "name": "terminal",
            "arguments": '{"command":"dangerous"}',
        }],
    }).encode()

    class _Handler:
        def __init__(self):
            self.writer = writer
            self.wfile = io.BytesIO()
            self.status = None
            self.headers = []

        def _forward_request(self, *args, **kwargs):
            return 200, {"content-type": "application/json"}, upstream_body

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            self.headers.append((key, value))

        def end_headers(self):
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path="/v1/responses",
        req_headers={},
        body=json.dumps(req_body).encode(),
        req_body=req_body,
        req_events=req_events,
        exchange_ctx=exchange_ctx,
        t0=time.monotonic(),
    )

    assert handler.status == 403
    assert handler.wfile.getvalue() != upstream_body
    by_type = {event["event_type"]: event for event in db.events}
    assert by_type["model_response"]["outcome"]["status"] == "blocked"
    assert by_type["tool_call"]["outcome"]["status"] == "blocked"
    for event_type in ("model_response", "tool_call"):
        capture = by_type[event_type]["context"]["capture"]
        assert capture["response_delivered"] is False
        assert capture["delivery_status"] == "withheld"


def test_preflight_allow_writes_all_events():
    """When policies allow, both request and response events are written."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)  # no policy engine — always allows

    req_body = {
        "model": "claude-opus-4-5",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": False,
    }
    resp_body = {
        "id": "msg_ok",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Hi there"}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }

    run_id = uuid.uuid4().hex
    req_events, ctx = writer.build_request_events(
        path="/v1/messages", method="POST",
        req_headers={}, req_body=req_body, run_id=run_id,
    )
    policy_result = writer.check_policies(req_events)
    assert policy_result.action == "allow"

    resp_events = writer.build_response_events(
        path="/v1/messages", req_body=req_body,
        resp_status=200, resp_headers={}, resp_body=resp_body,
        duration_ms=200, exchange_ctx=ctx,
    )
    writer.write(req_events + resp_events)

    stored = db.query()
    types = [e["event_type"] for e in stored]
    assert "model_request" in types
    assert "model_response" in types

    # All share the same run_id
    run_ids = {e["agent"]["run_id"] for e in stored}
    assert len(run_ids) == 1
    assert run_ids.pop() == run_id


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def test_upstream_client_never_stores_cookies():
    """One client serves every session, so it must not replay Set-Cookie."""
    import httpx

    from panoptes.proxy import _upstream_client

    client = _upstream_client(5.0)
    try:
        request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        response = httpx.Response(
            200, headers={"set-cookie": "sess=SECRET; Path=/"}, request=request
        )
        client.cookies.extract_cookies(response)
        assert len(client.cookies.jar) == 0
    finally:
        client.close()


def test_forwarded_accept_encoding_is_replaced_case_insensitively():
    fwd = ProxyHandler._build_fwd_headers(
        None, {"accept-encoding": "gzip, br", "content-type": "application/json"}
    )
    assert [k for k in fwd if k.lower() == "accept-encoding"] == ["Accept-Encoding"]
    assert fwd["Accept-Encoding"] == "identity"


def test_undecodable_upstream_content_encoding_is_refused():
    from panoptes.proxy import ResponseInspectionError, _check_content_encoding

    _check_content_encoding({"Content-Encoding": "gzip"})
    _check_content_encoding({})
    for coding in ("br", "zstd", "gzip, br"):
        with pytest.raises(ResponseInspectionError):
            _check_content_encoding({"Content-Encoding": coding})


def test_repeated_request_headers_are_combined():
    from panoptes.proxy import _merged_headers

    merged = _merged_headers([
        ("anthropic-beta", "beta-one"),
        ("Anthropic-Beta", "beta-two"),
        ("Cookie", "a=1"),
        ("cookie", "b=2"),
    ])
    assert merged == {"anthropic-beta": "beta-one, beta-two", "Cookie": "a=1; b=2"}


def test_usage_counts_cached_and_thinking_tokens():
    from panoptes.providers.gemini import GeminiProvider

    usage = AnthropicProvider().extract_usage({"usage": {
        "input_tokens": 3,
        "cache_read_input_tokens": 90_000,
        "cache_creation_input_tokens": 5_000,
        "output_tokens": 7,
    }})
    assert usage == {"tokens_in": 95_003, "tokens_out": 7,
                     "cached_input_tokens": 90_000, "cache_creation_input_tokens": 5_000}

    stream = (
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"m",'
        b'"model":"claude-x","usage":{"input_tokens":3,"cache_read_input_tokens":10,'
        b'"output_tokens":1}}}\n\n'
        b'event: message_delta\ndata: {"type":"message_delta","delta":'
        b'{"stop_reason":"end_turn"},"usage":{"output_tokens":9,'
        b'"cache_read_input_tokens":20}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    message = _reassemble_anthropic_sse(_parse_sse_events(stream))
    assert AnthropicProvider().extract_usage(message) == {
        "tokens_in": 23, "tokens_out": 9, "cached_input_tokens": 20,
    }

    gemini = GeminiProvider()
    assert gemini.extract_usage({"usageMetadata": {
        "promptTokenCount": 3, "candidatesTokenCount": 1, "thoughtsTokenCount": 500,
    }}) == {"tokens_in": 3, "tokens_out": 501, "reasoning_tokens": 500}
    assert gemini.extract_request_info(
        {"contents": []},
        path="/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
    )["model"] == "gemini-2.5-pro"


def test_optional_provider_usage_breakdowns_and_streaming():
    from panoptes.providers.anthropic import AnthropicProvider, _reassemble_anthropic_sse
    from panoptes.providers.openai import OpenAIProvider
    from panoptes.providers.gemini import GeminiProvider
    from panoptes.providers.base import _parse_sse_events

    assert OpenAIProvider().extract_usage({"usage": {
        "input_tokens": 10, "output_tokens": 8,
        "input_tokens_details": {"cached_tokens": 4},
        "output_tokens_details": {"reasoning_tokens": 5},
    }}) == {"tokens_in": 10, "tokens_out": 8, "cached_input_tokens": 4, "reasoning_tokens": 5}
    assert OpenAIProvider().extract_usage({"usage": {
        "prompt_tokens": 10, "completion_tokens": 8,
        "completion_tokens_details": {"reasoning_tokens": 0},
    }})["reasoning_tokens"] == 0
    assert "reasoning_tokens" not in GeminiProvider().extract_usage({"usageMetadata": {"thoughtsTokenCount": True}})
    stream = (b'event: message_start\ndata: {"type":"message_start","message":{"content":[],"usage":{"input_tokens":2,"output_tokens":1}}}\n\n'
              b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9,"output_tokens_details":{"thinking_tokens":6}}}\n\n'
              b'event: message_stop\ndata: {"type":"message_stop"}\n\n')
    assert AnthropicProvider().extract_usage(_reassemble_anthropic_sse(_parse_sse_events(stream)))["reasoning_tokens"] == 6
